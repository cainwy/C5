package harness


import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"c5full/internal/mpc/schemea"

	"c5full/blockchain/bridge"
	"c5full/blockchain/fabric/chaincode/model"
)

type SAOutput struct {
	ServerIndex    int    `json:"server_index"`
	SubmissionJSON string `json:"submission_json"`
	PayloadHex     string `json:"payload_hex"`
	PayloadBytes   int    `json:"payload_bytes"`
	ExpectedCommitmentHex string `json:"expected_commitment_hex"`
	ZKPoCBytes     int    `json:"zkpoc_bytes"`
	CtsBytes       int    `json:"cts_bytes"`
}

type SAFixture struct {
	Schema       string `json:"schema"`
	TaskID       string `json:"task_id"`
	ProfileID    string `json:"profile_id"`
	PrimeBits    int    `json:"prime_bits"`
	K, ChunkBits, W int
	GroupCheck   string `json:"group_membership_check"`
	Servers      int    `json:"servers"`
	TaskRecordJSON string `json:"task_record_json"`
	Outputs      []SAOutput `json:"outputs"`
	PHex, GHex, HHex string
	GeneratedUTC string `json:"generated_utc"`
	Notes        string `json:"notes"`
}

type SAServerCost struct {
	ProcessingNS int64 `json:"processing_ns"`
	VerifyNS     int64 `json:"verify_ns"`
}

func BuildSchemeAFixture(pid schemea.ProfileID, servers int, groupCheck, seed string) (*SAFixture, error) {
	fx, _, _, err := buildSchemeAFixture(pid, servers, groupCheck, seed, false)
	return fx, err
}

func BuildSchemeAFixtureWithParams(pid schemea.ProfileID, servers int, groupCheck, seed string) (*SAFixture, *schemea.Params, error) {
	fx, p, _, err := buildSchemeAFixture(pid, servers, groupCheck, seed, false)
	return fx, p, err
}

func BuildSchemeAFixtureWithCost(pid schemea.ProfileID, servers int, groupCheck, seed string) (*SAFixture, *schemea.Params, []SAServerCost, error) {
	return buildSchemeAFixture(pid, servers, groupCheck, seed, true)
}

func buildSchemeAFixture(pid schemea.ProfileID, servers int, groupCheck, seed string, collectCost bool) (*SAFixture, *schemea.Params, []SAServerCost, error) {
	if servers < 1 {
		return nil, nil, nil, fmt.Errorf("harness: servers must be >= 1")
	}
	p, err := schemea.NewProfile(pid)
	if err != nil {
		return nil, nil, nil, err
	}
	if p.NumChunks != 8 {
		return nil, nil, nil, fmt.Errorf("harness: expected w=8, got %d", p.NumChunks)
	}
	width := bridge.WidthForPrimeBits(p.PrimeBits)

	fx := &SAFixture{
		Schema: "c5-blockchain-schemea-fixture-v1", TaskID: "sa-" + seed,
		ProfileID: string(pid), PrimeBits: p.PrimeBits,
		K: p.K, ChunkBits: p.ChunkBits, W: p.NumChunks,
		GroupCheck: groupCheck, Servers: servers,
		PHex: bridge.EncodeSchemeAElement(p.P, width),
		GHex: bridge.EncodeSchemeAElement(p.G, width),
		HHex: bridge.EncodeSchemeAElement(p.H, width),
		GeneratedUTC: time.Now().UTC().Format(time.RFC3339),
		Notes: "只含公开量：密文 r、ZKPoC 与公开承诺；不含 (z,r,v,l) 明文",
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

	rng := NewHashSeedReader("bc::sa::" + seed)
	order := new(big.Int).Sub(p.P, big.NewInt(1))
	costs := make([]SAServerCost, 0, servers)
	for i := 0; i < servers; i++ {
		zi := new(big.Int).SetInt64(int64(1000 + i*37))
		ri := randScalarFromReader(rng, new(big.Int).Sub(order, big.NewInt(1)))

		var tProc, tVer time.Time
		if collectCost {
			tProc = time.Now()
		}
		cts, ls := p.EncryptShareR(zi, ri, rng)
		pfs := make([]*schemea.ZKPoC, len(cts))
		vs := p.Split(zi)
		for j := range cts {
			pfs[j] = p.MakeZKPoC(cts[j].C0, cts[j].C1, vs[j], ls[j], order, rng)
		}
		var procNS int64
		if collectCost {
			procNS = time.Since(tProc).Nanoseconds()
			tVer = time.Now()
		}
		sub, err := bridge.SubmissionFromEncrypt(fx.TaskID, i+1, cts, pfs, width)
		if err != nil {
			return nil, nil, nil, err
		}
		subJSON, err := json.Marshal(sub)
		if err != nil {
			return nil, nil, nil, err
		}
		payload, err := model.CanonicalSchemeAOutputBytes(sub, width)
		if err != nil {
			return nil, nil, nil, err
		}
		gz := new(big.Int).Exp(p.G, zi, p.P)
		hr := new(big.Int).Exp(p.H, ri, p.P)
		cShare := gz.Mul(gz, hr)
		cShare.Mod(cShare, p.P)
		rec.ExpectedCommitmentsHex[i] = bridge.EncodeSchemeAElement(cShare, width)

		if collectCost {
			var verNS int64
			for j := range pfs {
				if !p.VerifyZKPoC(pfs[j], order) {
					return nil, nil, nil, fmt.Errorf("harness: ZKPoC self-check failed at server %d chunk %d", i+1, j)
				}
			}
			prod := big.NewInt(1)
			for j := range cts {
				exp := new(big.Int).Lsh(big.NewInt(1), uint(j*p.ChunkBits))
				term := new(big.Int).Exp(cts[j].C1, exp, p.P)
				prod.Mul(prod, term)
				prod.Mod(prod, p.P)
			}
			_ = prod
			verNS = time.Since(tVer).Nanoseconds()
			costs = append(costs, SAServerCost{ProcessingNS: procNS, VerifyNS: verNS})
		}

		fx.Outputs = append(fx.Outputs, SAOutput{
			ServerIndex: i + 1, SubmissionJSON: string(subJSON),
			PayloadHex: hexEncode(payload), PayloadBytes: len(payload),
			ExpectedCommitmentHex: rec.ExpectedCommitmentsHex[i],
			ZKPoCBytes: len(pfs) * 7 * width, CtsBytes: len(cts) * 2 * width,
		})
	}
	recJSON, err := json.Marshal(rec)
	if err != nil {
		return nil, nil, nil, err
	}
	fx.TaskRecordJSON = string(recJSON)
	return fx, p, costs, nil
}

func (fx *SAFixture) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(fx, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func LoadSAFixture(path string) (*SAFixture, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var fx SAFixture
	if err := json.Unmarshal(b, &fx); err != nil {
		return nil, err
	}
	if fx.TaskID == "" || len(fx.Outputs) == 0 {
		return nil, fmt.Errorf("harness: scheme A fixture incomplete")
	}
	return &fx, nil
}

func (fx *SAFixture) TaskRecord() (*model.SchemeATaskRecord, error) {
	var rec model.SchemeATaskRecord
	if err := json.Unmarshal([]byte(fx.TaskRecordJSON), &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func (fx *SAFixture) Submission(i int) (*model.SchemeAOutputSubmission, error) {
	var sub model.SchemeAOutputSubmission
	if err := json.Unmarshal([]byte(fx.Outputs[i].SubmissionJSON), &sub); err != nil {
		return nil, err
	}
	return &sub, nil
}

func (fx *SAFixture) Width() int { return bridge.WidthForPrimeBits(fx.PrimeBits) }

// ---- helpers --------------------------------------------------------------

func randScalarFromReader(r interface{ Read(p []byte) (int, error) }, mod *big.Int) *big.Int {
	w := (mod.BitLen() + 7) / 8
	buf := make([]byte, w+8)
	if _, err := r.Read(buf); err != nil {
		panic("harness: rng read failed")
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