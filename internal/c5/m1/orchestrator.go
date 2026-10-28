package m1

// M1 honest end-to-end orchestration (M3-3). Drives the full synthetic pipeline:
// committed state -> certificate/finality -> delivery -> Compiled-C -> Groth16
// proof -> public verification -> distinct-index collection -> recovery.

import (
	"math/big"
	"time"
)

// E2EResult captures the machine-readable outcome of one end-to-end run.
type E2EResult struct {
	N, F, L        int
	Seed           string
	Constraints    int
	SetupS         float64
	ProveS         []float64 // per delivered server
	VerifyS        float64
	Output         []string // authoritative output (hex)
	Recovered      []string // recovered output (hex)
	Accepted       []int    // distinct accepted server indices
	Status         string
	RecoveredOK    bool
	TotalS         float64
}

// RunE2E executes the honest end-to-end flow and returns the structured result.
// It delivers from exactly f+1 honest servers (the minimum recoverable set).
func RunE2E(n, f, L int, seed string) (*E2EResult, error) {
	start := time.Now()
	t, err := NewTask(n, f, L, seed)
	if err != nil {
		return nil, err
	}

	// ---- certificate + finality ------------------------------------------
	t.EndorseAll()
	certIndices := make([]int, 0, n-f)
	certSigs := make([][]byte, 0, n-f)
	for i := 0; i < n-f; i++ {
		certIndices = append(certIndices, i)
		certSigs = append(certSigs, t.Endorsements[i])
	}
	rec := &DeliveryRecord{CertIndices: certIndices, CertSigs: certSigs}
	if r := t.VerifyCert(certIndices, certSigs); !r.IsOK() {
		return nil, &m1Error{"cert verify failed: " + r.Reason}
	}
	t.Finality.Finalize(hexOf(t.Alpha))
	if r := t.VerifyFinalized(); !r.IsOK() {
		return nil, &m1Error{"finality failed"}
	}

	// ---- proof setup ------------------------------------------------------
	maskCtxLen := len(t.MaskCtxFor(1))
	setupStart := time.Now()
	p, err := NewProver(L, maskCtxLen)
	if err != nil {
		return nil, err
	}
	setupS := time.Since(setupStart).Seconds()

	// ---- delivery + prove from f+1 honest servers ------------------------
	deliveries := make([]*Delivery, 0, f+1)
	res := &E2EResult{N: n, F: f, L: L, Seed: seed, Constraints: p.Constraints(), SetupS: setupS}
	proveStart := time.Now()
	for i := 0; i < f+1; i++ {
		d := t.MakeDelivery(i)
		ps := time.Now()
		_, proofBytes, _, err := p.Prove(t, d)
		if err != nil {
			return nil, err
		}
		d.Proof = proofBytes
		d.HasProof = true
		t.SignWithProof(d)
		res.ProveS = append(res.ProveS, time.Since(ps).Seconds())
		deliveries = append(deliveries, d)
	}
	proveTotal := time.Since(proveStart).Seconds()
	_ = proveTotal

	// ---- public verification + collection + recovery ---------------------
	verifyStart := time.Now()
	recResult := t.CollectAndRecover(p, rec, deliveries)
	res.VerifyS = time.Since(verifyStart).Seconds()
	res.Status = string(recResult.Status)

	// accepted indices (re-derive via explicit per-delivery VerifyDel)
	for _, d := range deliveries {
		if r := t.VerifyDel(p, rec, d); r.IsOK() {
			res.Accepted = append(res.Accepted, d.I)
		}
	}

	want := t.OutputValues()
	res.Output = bigVecHex(want)
	if recResult.IsOK() {
		res.Recovered = bigVecHex(recResult.Value.([]*big.Int))
		res.RecoveredOK = vecEqual(want, recResult.Value.([]*big.Int))
	}
	res.TotalS = time.Since(start).Seconds()
	return res, nil
}

func bigVecHex(v []*big.Int) []string {
	out := make([]string, len(v))
	for i, x := range v {
		out[i] = hexOf(x.Bytes())
	}
	return out
}

func vecEqual(a, b []*big.Int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Cmp(b[i]) != 0 {
			return false
		}
	}
	return true
}
