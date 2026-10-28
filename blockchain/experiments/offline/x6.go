// x6.go implements the functional validation of the evaluation section: reject paths, threshold recovery and subset consistency.
package offline


import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"path/filepath"
	"sort"
	"time"

	"c5full/internal/c5/m1"
	"c5full/internal/c5/params"
)

type x6RejectCase struct {
	Case        string  `json:"case"`
	Stage       string  `json:"reject_stage"`
	Rejected    bool    `json:"rejected"`
	VerifyMsMed float64 `json:"verify_ms_median"`
	VerifyMsP95 float64 `json:"verify_ms_p95"`
	Reps        int     `json:"reps"`
	Reason      string  `json:"reason,omitempty"`
	MutationOK  bool    `json:"mutation_ok,omitempty"`
	TrialsMs   []float64  `json:"trials_ms,omitempty"`
	TrialsStat StatTrials `json:"trials_stat,omitempty"`
}

type x6SubsetDetail struct {
	Indices    []int  `json:"indices"`
	OutputHash string `json:"output_hash"`
	Recovered  bool   `json:"recovered"`
}

type x6SubsetConsistency struct {
	NScanned map[string]struct {
		Trials   int  `json:"trials"`
		AllEqual bool `json:"all_equal"`
		Mode     string `json:"mode"` // exhaustive | seeded-random
		Details []x6SubsetDetail `json:"details,omitempty"`
	} `json:"per_n"`
	Seed string `json:"seed,omitempty"`
}

type x6Result struct {
	Schema       string          `json:"schema"`
	ExperimentID string          `json:"experiment_id"`
	N            int             `json:"n"`
	F            int             `json:"f"`
	Rejects      []x6RejectCase  `json:"rejects"`
	Subsets      x6SubsetConsistency `json:"subset_consistency"`
	Withholding  struct {
		FAvailable   string `json:"f_available_status"`
		FPlus1Status string `json:"f_plus_1_status"`
	} `json:"withholding"`
	MeasuredBy   string `json:"measured_by"`
	GeneratedUTC string `json:"generated_utc"`
}

func rejectStageOf(t *m1.Task, p *m1.Prover, rec *m1.DeliveryRecord, d *m1.Delivery) (bool, string, float64) {
	t0 := time.Now()
	r := t.VerifyDel(p, rec, d)
	el := time.Since(t0).Seconds() * 1000
	if r.IsOK() {
		return false, "ACCEPT", el
	}
	switch r.Status {
	case m1.StatusFinalityPending:
		return true, "finality", el
	case m1.StatusInsufficientThreshold:
		return true, "cert_threshold", el
	}
	switch r.Reason {
	case m1.RejectInvalidIndex:
		return true, "index", el
	case m1.RejectInvalidSignature:
		return true, "signature", el
	case m1.RejectInvalidProof:
		return true, "groth16-proof", el
	}
	return true, "reject:" + r.Reason, el
}

func measureRejects(t *m1.Task, p *m1.Prover, rec *m1.DeliveryRecord, d *m1.Delivery, reps int) (string, float64, float64, StatTrials) {
	stages := make([]string, reps)
	times := make([]float64, reps)
	for rep := 0; rep < reps; rep++ {
		rejected, stage, el := rejectStageOf(t, p, rec, d)
		if !rejected {
			panic("X6: malicious delivery accepted")
		}
		stages[rep] = stage
		times[rep] = el
	}
	med, p95 := medP95(append([]float64(nil), times...))
	for _, s := range stages {
		if s != stages[0] {
			panic("X6: inconsistent reject stage across reps")
		}
	}
	return stages[0], med, p95, newStatMS(times, false)
}

func RunX6(outDir string, reps int) {
	const n, f, L = 9, 4, 1
	x, y := big.NewInt(0x1234567), big.NewInt(0x89abcde)
	bundle, _, _, _, err := m1.ComposeBundleTimed(n, f, x, y, newHashSeed("x6-bottom"), m1.BottomBundleOpts{})
	must(err)
	cfg := m1.ReceiverConfig{ReceiverX: big.NewInt(0xE2E0), Authorized: true, MakeSyntheticPoP: true}
	t, err := m1.NewTaskFromCommittedOutput(bundle, cfg, newHashSeed("x6-rcv"))
	must(err)
	t.EndorseAll()
	if !t.Finality.Finalize(hexOfAlpha(t.Alpha)) {
		panic("X6: finalize failed")
	}
	maskLen := len(t.MaskCtxFor(1))
	prov, err := m1.NewProver(L, maskLen)
	must(err)
	certIdx := make([]int, 0, n-f)
	certSigs := make([][]byte, 0, n-f)
	for i := 0; i < n-f; i++ {
		certIdx = append(certIdx, i)
		certSigs = append(certSigs, t.Endorsements[i])
	}
	rec := &m1.DeliveryRecord{CertIndices: certIdx, CertSigs: certSigs}

	res := &x6Result{Schema: "c5-auditfix-measurement-v1", ExperimentID: "X6", N: n, F: f,
		MeasuredBy:   "in-process (pure Go, no Fabric)",
		GeneratedUTC: timeNowUTC()}

	honest := map[int]*m1.Delivery{}
	for i := 0; i < n; i++ {
		d := t.MakeDelivery(i)
		_, pb, _, err := prov.Prove(t, d)
		must(err)
		d.Proof = pb
		d.HasProof = true
		d.Sig = nil
		t.SignWithProof(d)
		honest[i] = d
	}

	{
		d1 := t.MakeDelivery(0)
		_, pb1, _, err := prov.Prove(t, d1)
		must(err)
		d1.Proof = pb1
		d1.HasProof = true
		d1.Sig = nil
		orig := new(big.Int).Set(d1.C[0])
		d1.C[0] = new(big.Int).Add(d1.C[0], big.NewInt(1))
		d1.C[0].Mod(d1.C[0], params.Q)
		mutationOK := d1.C[0].Cmp(orig) != 0 &&
			new(big.Int).Sub(d1.C[0], orig).Mod(new(big.Int).Sub(d1.C[0], orig), params.Q).Cmp(big.NewInt(1)) == 0
		t.SignWithProof(d1)
		stage, med, p95, stat := measureRejects(t, prov, rec, d1, reps)
		res.Rejects = append(res.Rejects, x6RejectCase{
			Case: "wrong_ciphertext_offset_plus1", Stage: stage, Rejected: true,
			VerifyMsMed: med, VerifyMsP95: p95, Reps: reps, MutationOK: mutationOK,
			TrialsMs: stat.Trials, TrialsStat: stat,
		})
	}

	{
		d2 := t.MakeDelivery(1)
		d2.Proof = make([]byte, 292)
		for j := range d2.Proof {
			d2.Proof[j] = 0x5A
		}
		d2.HasProof = true
		d2.Sig = nil
		t.SignWithProof(d2)
		stage, med, p95, stat := measureRejects(t, prov, rec, d2, reps)
		res.Rejects = append(res.Rejects, x6RejectCase{
			Case: "garbage_proof", Stage: stage, Rejected: true,
			VerifyMsMed: med, VerifyMsP95: p95, Reps: reps,
			TrialsMs: stat.Trials, TrialsStat: stat,
		})
	}

	{
		d3 := t.MakeDelivery(2)
		_, pb3, _, err := prov.Prove(t, d3)
		must(err)
		d3.Proof = pb3
		d3.HasProof = true
		d3.Sig = nil
		t.SignWithProof(d3)
		d3.Sig[5] ^= 0x01
		stage, med, p95, stat := measureRejects(t, prov, rec, d3, reps)
		res.Rejects = append(res.Rejects, x6RejectCase{
			Case: "flipped_signature_bit", Stage: stage, Rejected: true,
			VerifyMsMed: med, VerifyMsP95: p95, Reps: reps,
			TrialsMs: stat.Trials, TrialsStat: stat,
		})
	}

	{
		d4 := t.MakeDelivery(3)
		_, pb4, _, err := prov.Prove(t, d4)
		must(err)
		d4.Proof = pb4
		d4.HasProof = true
		d4.Sig = nil
		t.SignWithProof(d4)
		d4.I = n + 5
		stage, med, p95, stat := measureRejects(t, prov, rec, d4, reps)
		res.Rejects = append(res.Rejects, x6RejectCase{
			Case: "unregistered_index", Stage: stage, Rejected: true,
			VerifyMsMed: med, VerifyMsP95: p95, Reps: reps,
			TrialsMs: stat.Trials, TrialsStat: stat,
		})
	}

	{
		col := m1.NewCollector()
		_ = col.Add(0)
		r2 := col.Add(0)
		dupRejected := r2.Status == m1.StatusReject && r2.Reason == m1.RejectDuplicateForCollection
		res.Rejects = append(res.Rejects, x6RejectCase{
			Case: "duplicate_index_collection", Stage: "collector", Rejected: dupRejected,
			VerifyMsMed: 0, VerifyMsP95: 0, Reps: 1,
			Reason: m1.RejectDuplicateForCollection,
		})
	}

	{
		sub := map[int]*m1.Delivery{}
		for i := 0; i < f; i++ {
			sub[i] = honest[i]
		}
		rf := t.Recover(sub)
		res.Withholding.FAvailable = string(rf.Status)
		sub[f] = honest[f]
		rf1 := t.Recover(sub)
		if !rf1.IsOK() {
			panic("X6: f+1 recovery must succeed")
		}
		res.Withholding.FPlus1Status = string(rf1.Status) // OK
	}

	{
		res.Subsets.NScanned = map[string]struct {
			Trials   int  `json:"trials"`
			AllEqual bool `json:"all_equal"`
			Mode     string `json:"mode"`
			Details  []x6SubsetDetail `json:"details,omitempty"`
		}{}
		scan := func(n2, f2 int, mode string, limit int, seedStr string) {
			x2, y2 := big.NewInt(0x1234567), big.NewInt(0x89abcde)
			b2, _, _, _, err := m1.ComposeBundleTimed(n2, f2, x2, y2, newHashSeed("x6-sub"+seedStr), m1.BottomBundleOpts{})
			must(err)
			tk2, err := m1.NewTaskFromCommittedOutput(b2, cfg, newHashSeed("x6-sub-rcv"+seedStr))
			must(err)
			tk2.EndorseAll()
			ml := len(tk2.MaskCtxFor(1))
			p2, err := m1.NewProver(1, ml)
			must(err)
			hs := map[int]*m1.Delivery{}
			for i := 0; i < n2; i++ {
				d := tk2.MakeDelivery(i)
				_, pb, _, err := p2.Prove(tk2, d)
				must(err)
				d.Proof = pb
				d.HasProof = true
				d.Sig = nil
				tk2.SignWithProof(d)
				hs[i] = d
			}
			ref := ""
			allEqual := true
			trials := 0
			var details []x6SubsetDetail
			visit := func(sub map[int]*m1.Delivery) {
				r := tk2.Recover(sub)
				if !r.IsOK() {
					panic("X6: subset recovery failed")
				}
				vec := ""
				for _, v := range r.Value.([]*big.Int) {
					vec += v.String() + ","
				}
				idxs := make([]int, 0, len(sub))
				for i := range sub {
					idxs = append(idxs, i)
				}
				sort.Ints(idxs)
				details = append(details, x6SubsetDetail{
					Indices: idxs, OutputHash: sha256HexStr(vec), Recovered: true,
				})
				if trials == 0 {
					ref = vec
				} else if vec != ref {
					allEqual = false
				}
				trials++
			}
			if mode == "exhaustive" {
				maskLimit := 1 << uint(n2)
				for m := 0; m < maskLimit; m++ {
					if popcount(m) == f2+1 {
						sub := map[int]*m1.Delivery{}
						for i := 0; i < n2; i++ {
							if m&(1<<uint(i)) != 0 {
								sub[i] = hs[i]
							}
						}
						visit(sub)
						if trials >= limit && limit > 0 {
							break
						}
					}
				}
			} else {
				seen := map[string]bool{}
				for tries := 0; trials < limit && tries < limit*50; tries++ {
					h := newHashSeed(seedStr + "::subset::" + itoa(tries))
					sub := map[int]*m1.Delivery{}
					cnt := 0
					for i := 0; i < n2 && cnt < f2+1; i++ {
						var b [1]byte
						h.Read(b[:])
						if b[0]%2 == 0 || n2-i == f2+1-cnt {
							sub[i] = hs[i]
							cnt++
						}
					}
					if cnt != f2+1 {
						continue
					}
					key := ""
					for i := range sub {
						key += itoa(i) + ","
					}
					if seen[key] {
						continue
					}
					seen[key] = true
					visit(sub)
				}
			}
			res.Subsets.NScanned[itoa(n2)] = struct {
				Trials   int    `json:"trials"`
				AllEqual bool   `json:"all_equal"`
				Mode     string `json:"mode"`
				Details  []x6SubsetDetail `json:"details,omitempty"`
			}{Trials: trials, AllEqual: allEqual, Mode: mode, Details: details}
		}
		scan(3, 1, "exhaustive", 0, "x6-sub-n3")
		scan(5, 2, "exhaustive", 0, "x6-sub-n5")
		scan(9, 4, "exhaustive", 0, "x6-sub-n9")
		scan(15, 7, "seeded-random", 100, "x6-sub-n15-seed-20260930")
		res.Subsets.Seed = "x6-sub-n15-seed-20260930"
	}

	writeJSON(filepath.Join(outDir, "selftest_matrix.json"), res)
}

func popcount(m int) int {
	c := 0
	for m != 0 {
		c += m & 1
		m >>= 1
	}
	return c
}

func sha256HexStr(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func itoa(x int) string { return fmtInt(x) }

func fmtInt(x int) string {
	if x == 0 {
		return "0"
	}
	neg := x < 0
	if neg {
		x = -x
	}
	buf := [20]byte{}
	pos := len(buf)
	for x > 0 {
		pos--
		buf[pos] = byte('0' + x%10)
		x /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
