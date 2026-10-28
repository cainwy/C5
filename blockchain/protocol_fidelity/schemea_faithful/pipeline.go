package schemeafaithful


import (
	"io"
	"math/big"
	"time"
)

type PipelineConfig struct {
	T, N, M int
	Mode    TripleMode
	ElGamal ElGamalConfig    // k/p/w
	ZK      ZKPoCConfig
	Group   *Group
}

type PipelineResult struct {
	Valid       bool
	Z           *big.Int
	ZExpected   *big.Int
	ZShares     []*big.Int
	DerivedCZ   []*big.Int
	FirstReject string
	StageMs     StageTiming
}

type StageTiming struct {
	DistributeMs  float64 `json:"distribute_ms"`
	ComputeMs     float64 `json:"compute_ms"`
	EncryptMs     float64 `json:"encrypt_ms"`
	OnChainMs     float64 `json:"onchain_ms"`
	DecryptMs     float64 `json:"decrypt_ms"`
	ReconstructMs float64 `json:"reconstruct_ms"`
	TotalMs       float64 `json:"total_ms"`
	ProcessVerify float64 `json:"process_verify_ms"` // b+c+d+e
	DecryptPhase  float64 `json:"decrypt_phase_ms"`  // f+g
}

func RunE2E(cfg PipelineConfig, x, y *big.Int, r io.Reader) (*PipelineResult, error) {
	g := cfg.Group
	mod := g.ScalarMod()
	res := &PipelineResult{}
	t0 := time.Now()
	defer func() { res.StageMs.TotalMs = msOf(time.Since(t0)) }()
	mark := t0
	lap := func() float64 {
		d := msOf(time.Since(mark))
		mark = time.Now()
		return d
	}

	hKP, err := g.NewKeyPair(r)
	if err != nil {
		return nil, err
	}
	h := hKP.H
	keyset, err := NewDecryptKeySet(hKP.S, cfg.M, g, r)
	if err != nil {
		return nil, err
	}
	rp, err := g.NewResharePoly(cfg.T, h, r)
	if err != nil {
		return nil, err
	}
	st := NewContractState(g, h, rp)
	_ = lap()

	rx, err := RandScalar(mod, r)
	if err != nil {
		return nil, err
	}
	ry, err := RandScalar(mod, r)
	if err != nil {
		return nil, err
	}
	xSet, err := g.VSSShare(x, rx, h, cfg.T, cfg.N, r)
	if err != nil {
		return nil, err
	}
	ySet, err := g.VSSShare(y, ry, h, cfg.T, cfg.N, r)
	if err != nil {
		return nil, err
	}
	for i := 0; i < cfg.N; i++ {
		key, err := NewChannelKey(256, r)
		if err != nil {
			return nil, err
		}
		sealed, err := key.Seal(xSet.Shares[i].S.Bytes())
		if err != nil {
			return nil, err
		}
		pt, err := key.Open(sealed)
		if err != nil {
			return nil, err
		}
		if new(big.Int).SetBytes(pt).Cmp(xSet.Shares[i].S) != 0 {
			return nil, errf(ErrChannel, "channel roundtrip mismatch")
		}
		sxi := polyEval(xSet.Gc, big.NewInt(int64(i+1)), mod)
		syi := polyEval(ySet.Gc, big.NewInt(int64(i+1)), mod)
		st.CX[i+1] = g.Commit(h, xSet.Shares[i].S, sxi)
		st.CY[i+1] = g.Commit(h, ySet.Shares[i].S, syi)
	}

	tr, err := g.MakeTriple(cfg.T, cfg.N, cfg.Mode, h, r)
	if err != nil {
		return nil, err
	}
	for i := 0; i < cfg.N; i++ {
		st.CA[i+1] = tr.CA[i]
		st.CB[i+1] = tr.CB[i]
		st.CC[i+1] = tr.CC[i]
		st.RA[i+1] = tr.RA[i]
		st.RB[i+1] = tr.RB[i]
	}
	res.StageMs.DistributeMs = lap()

	zShares := make([]*big.Int, cfg.N)
	zBlinds := make([]*big.Int, cfg.N)
	muls := make([]*MulIntermediates, cfg.N)
	dRec, err := Reconstruct(shareDiff(xSet, tr.A, cfg.T, mod), mod)
	if err != nil {
		return nil, err
	}
	eRec, err := Reconstruct(shareDiff(ySet, tr.B, cfg.T, mod), mod)
	if err != nil {
		return nil, err
	}
	for i := 0; i < cfg.N; i++ {
		xi := xSet.Shares[i].S
		yi := ySet.Shares[i].S
		ai := tr.A.Shares[i].S
		bi := tr.B.Shares[i].S
		di, ei := MulReveal(xi, yi, ai, bi, mod)
		rxi := polyEval(xSet.Gc, big.NewInt(int64(i+1)), mod)
		ryi := polyEval(ySet.Gc, big.NewInt(int64(i+1)), mod)
		rdi := new(big.Int).Sub(rxi, tr.RA[i])
		rdi.Mod(rdi, mod)
		rei := new(big.Int).Sub(ryi, tr.RB[i])
		rei.Mod(rei, mod)
		muls[i] = &MulIntermediates{Server: i + 1, D: di, E: ei, RD: rdi, RE: rei}
		de := new(big.Int).Mul(dRec, eRec)
		dei, rdei := g.DeShare(rp, de, i+1)
		zi, zri := g.MulLocal(tr.C.Shares[i].S, ai, bi, dRec, eRec, dei, tr.RA[i], tr.RB[i], tr.RC[i], rdei)
		zShares[i] = zi
		zBlinds[i] = zri
	}
	res.StageMs.ComputeMs = lap()

	encShares := make([]*EncryptedShare, cfg.N)
	for i := 0; i < cfg.N; i++ {
		es, err := g.EncryptShare(h, zShares[i], zBlinds[i], cfg.ElGamal, r)
		if err != nil {
			return nil, err
		}
		encShares[i] = es
	}
	res.StageMs.EncryptMs = lap()

	dGlob, eGlob, err := st.ReconstructGlobals(muls, cfg.T, mod)
	if err != nil {
		return nil, err
	}
	for i := 0; i < cfg.N; i++ {
		for j, ct := range encShares[i].Cts {
			pf, err := g.MakeZKPoC(h, ct, encShares[i].Vs[j], encShares[i].ls[j], cfg.ZK, r)
			if err != nil {
				return nil, err
			}
			ok, err := g.VerifyZKPoC(h, ct, pf, cfg.ZK)
			if err != nil || !ok {
				res.FirstReject = "ZKPoC"
				return res, nil
			}
		}
		cz, err := st.DeriveMulCommitmentG(muls[i], dGlob, eGlob)
		if err != nil {
			res.FirstReject = "Eq16/17"
			return res, nil
		}
		res.DerivedCZ = append(res.DerivedCZ, cz)
		ok, err := st.VerifyCiphertextAgainstCommitment(i+1, encShares[i].Cts, cfg.ElGamal)
		if err != nil || !ok {
			res.FirstReject = "Eq18"
			return res, nil
		}
	}
	res.StageMs.OnChainMs = lap()

	var table *FullTable
	if cfg.ElGamal.ChunkBits <= 16 {
		table, err = g.NewFullTable(cfg.ElGamal.ChunkBits)
		if err != nil {
			return nil, err
		}
	}
	vrecs := make([]*big.Int, cfg.N)
	for i := 0; i < cfg.N; i++ {
		vs := make([]*big.Int, len(encShares[i].Cts))
		for j, ct := range encShares[i].Cts {
			partials := make([]*big.Int, cfg.M)
			for k := 0; k < cfg.M; k++ {
				partials[k] = g.PartialDecrypt(ct, keyset.Shares[k])
			}
			v, err := g.RecoverPartition(ct, partials, cfg.ElGamal.ChunkBits, table)
			if err != nil {
				return nil, err
			}
			vs[j] = v
		}
		vrecs[i] = g.Recombine(vs, cfg.ElGamal)
		if vrecs[i].Cmp(zShares[i]) != 0 {
			return nil, errf(ErrDecrypt, "recovered z_i != local z_i (server %d)", i+1)
		}
	}
	res.StageMs.DecryptMs = lap()

	idxs := make([]*Share, cfg.T)
	for i := 0; i < cfg.T; i++ {
		idxs[i] = &Share{J: i + 1, S: vrecs[i]}
	}
	z, err := Reconstruct(idxs, mod)
	if err != nil {
		return nil, err
	}
	res.StageMs.ReconstructMs = lap()
	res.StageMs.ProcessVerify = res.StageMs.ComputeMs + res.StageMs.EncryptMs + res.StageMs.OnChainMs
	res.StageMs.DecryptPhase = res.StageMs.DecryptMs + res.StageMs.ReconstructMs
	expect := new(big.Int).Mul(x, y)
	expect.Mod(expect, mod)
	res.Valid = z.Cmp(expect) == 0
	res.Z = z
	res.ZExpected = expect
	res.ZShares = zShares
	if !res.Valid {
		res.FirstReject = "ReconstructMismatch"
	}
	return res, nil
}

func msOf(d time.Duration) float64 { return float64(d.Microseconds()) / 1000.0 }

func shareDiff(vSet *ShareSet, tSet *ShareSet, count int, mod *big.Int) []*Share {
	out := make([]*Share, count)
	for i := 0; i < count; i++ {
		di := new(big.Int).Sub(vSet.Shares[i].S, tSet.Shares[i].S)
		di.Mod(di, mod)
		out[i] = &Share{J: i + 1, S: di}
	}
	return out
}
