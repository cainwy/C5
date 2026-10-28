package harness


import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"path/filepath"
	"time"

	"c5full/internal/c5/host"
	"c5full/internal/c5/m1"
	"c5full/internal/c5/params"

	"c5full/blockchain/bridge"
	"c5full/blockchain/fabric/chaincode/model"
)

func hexOfPoint(d *m1.Delivery) string {
	return hex.EncodeToString(host.EncodePoint(d.R, false))
}

func filepathToSlash(p string) string { return filepath.ToSlash(p) }

type BottomProvenance struct {
	N                 int      `json:"n"`
	F                 int      `json:"f"`
	L                 int      `json:"l"`
	XHex              string   `json:"x_hex"`
	YHex              string `json:"y_hex"`
	ExpectedProd      string `json:"expected_x_times_y_mod_q_hex"`
	BundleInvariantOK bool   `json:"bundle_invariant_ok"`
	BottomTraceSHA256 string `json:"bottom_trace_sha256,omitempty"`
	OutputHex         []string `json:"output_hex"`
	TauLen            int    `json:"tau_len"`
	MaskCtxLen        int    `json:"maskctx_len"`
	AlphaHex          string `json:"alpha_hex"`
	NoSyntheticOutput bool   `json:"no_synthetic_output_poly"`
	Notes             string `json:"notes"`
}

func BuildC5FixtureFromBottomMPC(prover *m1.Prover, artifactsDir, taskID string, n, f, L int, x, y *big.Int, seed string) (*C5Fixture, *BottomProvenance, error) {
	return buildC5FixtureFromBottomMPC(prover, artifactsDir, taskID, n, f, L, x, y, seed, f+1)
}

func BuildC5FixtureWithDeliveries(prover *m1.Prover, artifactsDir, taskID string, n, f, L int, x, y *big.Int, seed string, want int) (*C5Fixture, *BottomProvenance, error) {
	if want < 1 {
		want = 1
	}
	if want > n {
		return nil, nil, fmt.Errorf("harness: want deliveries %d > n %d（索引会重复，链上会拒绝）", want, n)
	}
	return buildC5FixtureFromBottomMPC(prover, artifactsDir, taskID, n, f, L, x, y, seed, want)
}

func buildC5FixtureFromBottomMPC(prover *m1.Prover, artifactsDir, taskID string, n, f, L int, x, y *big.Int, seed string, wantDeliveries int) (*C5Fixture, *BottomProvenance, error) {
	if prover == nil || prover.Pk == nil {
		return nil, nil, fmt.Errorf("harness: canonical prover with PK is required")
	}
	baseRNG := NewHashSeedReader("bc::bottom::" + seed)
	bundle, tr, err := m1.ComposeBundleTrace(n, f, x, y, baseRNG)
	if err != nil {
		return nil, nil, fmt.Errorf("bottom MPC abort: %w", err)
	}
	if bad := m1.VerifyBundleInvariant(bundle); bad != -1 {
		return nil, nil, fmt.Errorf("bottom invariant violated at server %d", bad)
	}
	cfg := m1.ReceiverConfig{ReceiverX: big.NewInt(0xE2E0), Authorized: true, MakeSyntheticPoP: true}
	tk, err := m1.NewTaskFromCommittedOutput(bundle, cfg, NewHashSeedReader("bc::rcv::"+seed))
	if err != nil {
		return nil, nil, fmt.Errorf("adapter reject: %w", err)
	}
	maskLen := len(tk.MaskCtxFor(1))
	if maskLen != prover.MaskCtxLen {
		return nil, nil, fmt.Errorf("profile drift: maskctx len %d != prover profile %d (canonical tau 长度必须匹配)", maskLen, prover.MaskCtxLen)
	}
	prov := &BottomProvenance{
		N: n, F: f, L: L,
		XHex: hex.EncodeToString(x.Bytes()), YHex: hex.EncodeToString(y.Bytes()),
		BundleInvariantOK: true,
		TauLen:            len(tk.Seed),
		MaskCtxLen:        maskLen,
		AlphaHex:          hex.EncodeToString(tk.Alpha),
		NoSyntheticOutput: true,
		Notes:             "Aout/z_i/rho_i 来自 bottom committed-output bundle，未使用 NewOutputPoly 合成",
	}
	prod := new(big.Int).Mod(new(big.Int).Mul(x, y), params.Q)
	prov.ExpectedProd = hex.EncodeToString(prod.Bytes())
	if tr != nil {
		h := tr.Hash()
		prov.BottomTraceSHA256 = hex.EncodeToString(h[:])
	}
	prov.OutputHex = make([]string, len(bundle.Output))
	for i, v := range bundle.Output {
		prov.OutputHex[i] = hex.EncodeToString(v.Bytes())
	}
	if tk.Alpha == nil || prov.TauLen != 12 {
		return nil, nil, fmt.Errorf("canonical tau 长度必须为 12 hex 字符，实得 %d", prov.TauLen)
	}

	fx, err := serializeTaskFixtureN(prover, artifactsDir, taskID, tk, wantDeliveries)
	if err != nil {
		return nil, nil, err
	}
	if len(fx.Deliveries) != wantDeliveries {
		return nil, nil, fmt.Errorf("harness: built %d deliveries, want %d", len(fx.Deliveries), wantDeliveries)
	}
	fx.Notes += " | bottom_mpc=true tau_len=" + fmt.Sprint(prov.TauLen)
	return fx, prov, nil
}

func serializeTaskFixtureN(prover *m1.Prover, artifactsDir, taskID string, t *m1.Task, want int) (*C5Fixture, error) {
	t.EndorseAll()
	certIdx := make([]int, 0, t.N-t.F)
	for i := 0; i < t.N-t.F; i++ {
		certIdx = append(certIdx, i)
	}
	cert, err := bridge.CertificateFromTask(t, certIdx)
	if err != nil {
		return nil, err
	}
	cert.TaskID = taskID
	cert.CertHash = bridge.CertHash(cert)

	rec, err := bridge.PublicTaskRecordFromTask(t, taskID, "bc-c5-l1-507", vkHashOf(artifactsDir), prover.MaskCtxLen, prover.Constraints())
	if err != nil {
		return nil, err
	}
	recJSON, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	certJSON, err := json.Marshal(cert)
	if err != nil {
		return nil, err
	}
	fx := &C5Fixture{
		Schema: "c5-blockchain-fixture-v1", TaskID: taskID,
		N: t.N, F: t.F, L: t.L, Seed: t.Seed,
		MaskCtxLen: prover.MaskCtxLen, Constraints: prover.Constraints(),
		VKHash: vkHashOf(artifactsDir), ArtifactsDir: filepathToSlash(artifactsDir),
		TaskRecordJSON: string(recJSON), CertJSON: string(certJSON),
		GeneratedUTC: time.Now().UTC().Format(time.RFC3339),
		Notes:        "fixture 仅含 public 数据；witness (s_i, Z_i, z_i, rho_i) 不落盘",
	}
	for i := 0; i < want; i++ {
		d := t.MakeDeliveryWithRNG(i, NewHashSeedReader(fmt.Sprintf("bc::%s::del:%d", taskID, i)))
		_, pb, _, err := prover.Prove(t, d)
		if err != nil {
			return nil, err
		}
		d.Proof = pb
		d.HasProof = true
		d.Sig = nil
		t.SignWithProof(d)
		if !m1.VerifyDeliverySignature(t, d) {
			return nil, fmt.Errorf("harness: delivery signature self-check failed for server %d", i)
		}
		payload, err := model.CanonicalDeliveryBytes(d.I+1, hexOfPoint(d), hexOfScalars(d.C), hex.EncodeToString(d.Sig), hex.EncodeToString(d.Proof))
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(payload)
		fx.Deliveries = append(fx.Deliveries, C5Delivery{
			Index: d.I + 1, PayloadHex: hex.EncodeToString(payload), PayloadBytes: len(payload),
			ProofBytes: len(d.Proof), SigBytes: len(d.Sig), PayloadSHA256: hex.EncodeToString(sum[:]),
		})
	}
	if t.F+2 <= t.N {
		mi := t.F + 1
		md := t.MakeDeliveryWithRNG(mi, NewHashSeedReader(fmt.Sprintf("bc::%s::mal:%d", taskID, mi)))
		garbage := make([]byte, len(dbytesOfProver(prover)))
		for j := range garbage {
			garbage[j] = 0x5A
		}
		md.Proof = garbage
		md.HasProof = true
		md.Sig = nil
		t.SignWithProof(md)
		if !m1.VerifyDeliverySignature(t, md) {
			return nil, fmt.Errorf("harness: malicious fixture signature self-check failed")
		}
		mp, err := model.CanonicalDeliveryBytes(md.I+1, hexOfPoint(md), hexOfScalars(md.C), hex.EncodeToString(md.Sig), hex.EncodeToString(md.Proof))
		if err != nil {
			return nil, err
		}
		msum := sha256.Sum256(mp)
		fx.Malicious = &C5Delivery{
			Index: md.I + 1, PayloadHex: hex.EncodeToString(mp), PayloadBytes: len(mp),
			ProofBytes: len(md.Proof), SigBytes: len(md.Sig), PayloadSHA256: hex.EncodeToString(msum[:]),
		}
	}
	return fx, nil
}

func dbytesOfProver(_ *m1.Prover) []byte { return make([]byte, 292) }