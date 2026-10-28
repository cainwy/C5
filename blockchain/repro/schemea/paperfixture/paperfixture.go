//	recomposition        : Eq.(21) z_i = Σ v_j·2^{jp}
package paperfixture

import (
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"time"

	schemeacore "c5full/internal/mpc/schemea"

	"c5full/blockchain/bridge"
	"c5full/blockchain/fabric/chaincode/model"
	"c5full/blockchain/repro/schemea/paperdecrypt"
	"c5full/blockchain/tests/harness"
)

var ShareMod, _ = new(big.Int).SetString(
	"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)

type PaperSAFixture struct {
	Fixture *harness.SAFixture
	Params  *schemeacore.Params
	Ring    *paperdecrypt.KeyRing
	Secret *big.Int
	Shares []*big.Int
	Counts paperdecrypt.ActorCounts
	Costs  []harness.SAServerCost
}

//	servers    : n_servers
//	groupCheck : "off" | "qr"
func Build(pid schemeacore.ProfileID, servers, mClients, tShare int,
	x, y *big.Int, groupCheck, seed string) (*PaperSAFixture, error) {
	if servers < 1 || mClients < 1 || tShare < 1 || tShare > servers {
		return nil, fmt.Errorf("paperfixture: bad actor counts n=%d m=%d t=%d", servers, mClients, tShare)
	}
	if x == nil || y == nil {
		return nil, fmt.Errorf("paperfixture: nil workload input")
	}
	base, err := schemeacore.NewProfile(pid)
	if err != nil {
		return nil, err
	}
	if base.NumChunks != 8 {
		return nil, fmt.Errorf("paperfixture: expected w=8, got %d", base.NumChunks)
	}
	width := bridge.WidthForPrimeBits(base.PrimeBits)

	rng := harness.NewHashSeedReader("bc::sapaper::" + seed)
	ring, err := paperdecrypt.NewKeyRing(base.P, base.G, mClients, rng)
	if err != nil {
		return nil, err
	}

	p := &schemeacore.Params{
		P: base.P, G: base.G, H: ring.H, S: nil,
		K: base.K, ChunkBits: base.ChunkBits, NumChunks: base.NumChunks, PrimeBits: base.PrimeBits,
	}

	secret := new(big.Int).Mul(x, y)
	secret.Mod(secret, ShareMod)
	shares, err := paperdecrypt.ShamirShare(secret, tShare, servers, ShareMod, rng)
	if err != nil {
		return nil, err
	}

	fx := &harness.SAFixture{
		Schema: "c5-blockchain-schemea-fixture-v1", TaskID: "sa-paper-" + seed,
		ProfileID: string(pid), PrimeBits: p.PrimeBits,
		K: p.K, ChunkBits: p.ChunkBits, W: p.NumChunks,
		GroupCheck: groupCheck, Servers: servers,
		PHex:         bridge.EncodeSchemeAElement(p.P, width),
		GHex:         bridge.EncodeSchemeAElement(p.G, width),
		HHex:         bridge.EncodeSchemeAElement(ring.H, width),
		GeneratedUTC: time.Now().UTC().Format(time.RFC3339),
		Notes: "paper-faithful: h = prod g^{s_i} over m clients (DKG semantics); public values only " +
			"(ciphertexts, ZKPoC, commitments), with no plaintext shares and no client keys",
	}
	rec := &model.SchemeATaskRecord{
		Schema: model.SchemaID, TaskID: fx.TaskID,
		ProfileID: string(pid), PrimeBits: p.PrimeBits,
		PHex: fx.PHex, GHex: fx.GHex, HHex: fx.HHex,
		K: p.K, ChunkBits: p.ChunkBits, W: p.NumChunks,
		GroupCheck: groupCheck, Servers: servers,
		ExpectedCommitmentsHex: make([]string, servers),
		PublishedByServers:     true,
	}

	order := new(big.Int).Sub(p.P, big.NewInt(1))
	costs := make([]harness.SAServerCost, 0, servers)
	for i := 0; i < servers; i++ {
		ri := randScalar(order, rng)
		tProc := time.Now()
		cts, ls := p.EncryptShareR(shares[i], ri, rng)
		pfs := make([]*schemeacore.ZKPoC, len(cts))
		vs := p.Split(shares[i])
		for j := range cts {
			pfs[j] = p.MakeZKPoC(cts[j].C0, cts[j].C1, vs[j], ls[j], order, rng)
		}
		procNS := time.Since(tProc).Nanoseconds()

		sub, err := bridge.SubmissionFromEncrypt(fx.TaskID, i+1, cts, pfs, width)
		if err != nil {
			return nil, err
		}
		subJSON, err := json.Marshal(sub)
		if err != nil {
			return nil, err
		}
		payload, err := model.CanonicalSchemeAOutputBytes(sub, width)
		if err != nil {
			return nil, err
		}
		tVer := time.Now()
		for j := range pfs {
			if !p.VerifyZKPoC(pfs[j], order) {
				return nil, fmt.Errorf("paperfixture: ZKPoC self-check failed at server %d", i+1)
			}
		}
		verNS := time.Since(tVer).Nanoseconds()

		gz := new(big.Int).Exp(p.G, shares[i], p.P)
		hr := new(big.Int).Exp(p.H, ri, p.P)
		cShare := gz.Mul(gz, hr)
		cShare.Mod(cShare, p.P)
		rec.ExpectedCommitmentsHex[i] = bridge.EncodeSchemeAElement(cShare, width)

		fx.Outputs = append(fx.Outputs, harness.SAOutput{
			ServerIndex: i + 1, SubmissionJSON: string(subJSON),
			PayloadHex: hexEncode(payload), PayloadBytes: len(payload),
			ExpectedCommitmentHex: rec.ExpectedCommitmentsHex[i],
			ZKPoCBytes:            len(pfs) * 7 * width, CtsBytes: len(cts) * 2 * width,
		})
		costs = append(costs, harness.SAServerCost{ProcessingNS: procNS, VerifyNS: verNS})
	}
	recJSON, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	fx.TaskRecordJSON = string(recJSON)

	return &PaperSAFixture{
		Fixture: fx, Params: p, Ring: ring, Secret: secret, Shares: shares,
		Costs: costs,
		Counts: paperdecrypt.ActorCounts{
			NServers: servers, TSecretSharing: tShare, MClients: mClients,
			DecryptPartials: mClients,
		},
	}, nil
}

type DecryptSummary struct {
	Zs                  []*big.Int
	PartialsPerProduct  int
	PartitionsPerServer int
	TotalPartials       int
	DLOGNS              int64
	Eq20NS              int64
	PartialsNS          int64
	RecombineNS         int64
	ServerDecryptNS []int64
	DLOGMode        string
}

func (pf *PaperSAFixture) DecryptServerShares(dlogBoundBits int) (*DecryptSummary, error) {
	return pf.decryptServerShares(0, func(cts []paperdecrypt.Ciphertext) (*paperdecrypt.DecryptResult, error) {
		return pf.Ring.DecryptPartitions(cts, pf.Params.ChunkBits, dlogBoundBits)
	})
}

func (pf *PaperSAFixture) DecryptServerSharesWithTable(tbl *paperdecrypt.BabyGiantTable) (*DecryptSummary, error) {
	return pf.decryptServerShares(0, func(cts []paperdecrypt.Ciphertext) (*paperdecrypt.DecryptResult, error) {
		return pf.Ring.DecryptPartitionsWithTable(cts, pf.Params.ChunkBits, tbl)
	})
}

func (pf *PaperSAFixture) DecryptServerSharesWithTableLimit(tbl *paperdecrypt.BabyGiantTable,
	limit int) (*DecryptSummary, error) {
	return pf.decryptServerShares(limit, func(cts []paperdecrypt.Ciphertext) (*paperdecrypt.DecryptResult, error) {
		return pf.Ring.DecryptPartitionsWithTable(cts, pf.Params.ChunkBits, tbl)
	})
}

func (pf *PaperSAFixture) decryptServerShares(limit int,
	dec func([]paperdecrypt.Ciphertext) (*paperdecrypt.DecryptResult, error)) (*DecryptSummary, error) {

	if limit <= 0 || limit > len(pf.Fixture.Outputs) {
		limit = len(pf.Fixture.Outputs)
	}
	sum := &DecryptSummary{PartialsPerProduct: pf.Ring.M}
	sum.Zs = make([]*big.Int, 0, limit)
	for i := 0; i < limit; i++ {
		sub, err := pf.Fixture.Submission(i)
		if err != nil {
			return nil, err
		}
		cts, _, err := bridge.DecodeSchemeAOutput(sub, pf.Fixture.Width())
		if err != nil {
			return nil, err
		}
		wrapped := make([]paperdecrypt.Ciphertext, len(cts))
		for j, c := range cts {
			wrapped[j] = paperdecrypt.Ciphertext{C0: c.C0, C1: c.C1}
		}
		t0 := time.Now()
		res, err := dec(wrapped)
		if err != nil {
			return nil, err
		}
		sum.ServerDecryptNS = append(sum.ServerDecryptNS, time.Since(t0).Nanoseconds())
		if err := res.AssertEq20Participants(pf.Ring.M); err != nil {
			return nil, err
		}
		sum.PartialsPerProduct = res.PartialsPerProduct
		sum.PartitionsPerServer = res.Partitions
		sum.TotalPartials += res.TotalPartials
		sum.DLOGNS += res.DLOGNS
		sum.Eq20NS += res.Eq20NS
		sum.PartialsNS += res.PartialsNS
		sum.RecombineNS += res.RecombineNS
		sum.DLOGMode = res.DLOGMode
		sum.Zs = append(sum.Zs, res.Z)
	}
	return sum, nil
}

func (pf *PaperSAFixture) Reconstruct(zs []*big.Int, tShare, takeFirst int) (*big.Int, error) {
	if takeFirst <= 0 || takeFirst > len(zs) {
		takeFirst = len(zs)
	}
	idx := make([]int, takeFirst)
	sub := make([]*big.Int, takeFirst)
	for i := 0; i < takeFirst; i++ {
		idx[i] = i + 1
		sub[i] = zs[i]
	}
	return paperdecrypt.LagrangeReconstruct(sub, idx, tShare, ShareMod)
}

// ---- helpers --------------------------------------------------------------

func randScalar(mod *big.Int, rng io.Reader) *big.Int {
	w := (mod.BitLen() + 7) / 8
	buf := make([]byte, w+8)
	if _, err := io.ReadFull(rng, buf); err != nil {
		panic("paperfixture: rng read failed: " + err.Error())
	}
	x := new(big.Int).SetBytes(buf)
	x.Mod(x, new(big.Int).Sub(mod, big.NewInt(2)))
	return x.Add(x, big.NewInt(1))
}

func hexEncode(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0xf])
	}
	return string(out)
}
