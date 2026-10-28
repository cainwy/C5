// x5.go implements the prover-side resource table (Table 3): relation-specific
// setup, proving and peak memory for each output dimension L.
package offline

import (
	"path/filepath"
	"runtime"
	"time"

	"c5full/internal/c5/m1"
)

type x5Row struct {
	L           int        `json:"l"`
	MaskCtxLen  int        `json:"maskctx_len"`
	Constraints int        `json:"constraints"`
	NbPublic    int        `json:"nb_public_inputs,omitempty"`
	CompileS    float64    `json:"compile_s,omitempty"`
	SetupS      float64    `json:"setup_s"`
	ProveS      float64    `json:"prove_s"`
	VerifyMs    float64    `json:"verify_ms,omitempty"`
	ProofBytes  int        `json:"proof_bytes,omitempty"`
	PeakRSSMB   float64    `json:"peak_rss_mb"`
	Reps        int        `json:"reps"`
	SetupStat   StatTrials `json:"setup_stat,omitempty"`
	ProveStat   StatTrials `json:"prove_stat,omitempty"`
	GOMAXPROCS  int        `json:"gomaxprocs"`
}

type x5Result struct {
	Schema       string  `json:"schema"`
	MeasuredBy   string  `json:"measured_by"`
	GOMAXPROCS   int     `json:"gomaxprocs"`
	MaskCtxLen   int     `json:"maskctx_len"`
	Rows         []x5Row `json:"rows"`
	GeneratedUTC string  `json:"generated_utc"`
}

// RunX5 measures Groth16 setup, proving and peak resident memory per output
// dimension. Setup is relation-specific and reported separately from proving.
func RunX5(outDir string, ls []int, reps int) {
	const n, f, maskCtx = 3, 1, 507
	if reps < 1 {
		reps = 1
	}
	gomax := runtime.GOMAXPROCS(0)
	res := &x5Result{
		Schema:       "c5-prover-resources-v1",
		MeasuredBy:   "in-process (pure Go); GOMAXPROCS=4",
		GOMAXPROCS:   gomax,
		MaskCtxLen:   maskCtx,
		GeneratedUTC: timeNowUTC(),
	}
	for _, L := range ls {
		tk := synthTaskX3(n, f, L)
		t0 := time.Now()
		prov, err := m1.CompileOnly(L, maskCtx)
		must(err)
		compileS := time.Since(t0).Seconds()

		var setupVals, proveVals []float64
		var proofBytes int
		var verifyMs float64
		for rep := 0; rep < reps; rep++ {
			p, err := m1.NewProver(L, maskCtx)
			must(err)
			t0 = time.Now()
			must(p.SetupKeys())
			setupVals = append(setupVals, time.Since(t0).Seconds())
			d := tk.MakeDelivery(0)
			t0 = time.Now()
			pf, raw, pub, err := p.Prove(tk, d)
			must(err)
			proveVals = append(proveVals, time.Since(t0).Seconds())
			proofBytes = len(raw)
			t0 = time.Now()
			must(p.Verify(pf, pub))
			verifyMs = ms(time.Since(t0))
		}
		medSetup, _ := medP95(append([]float64(nil), setupVals...))
		medProve, _ := medP95(append([]float64(nil), proveVals...))
		rss := peakRSSMBWin()
		res.Rows = append(res.Rows, x5Row{
			L: L, MaskCtxLen: maskCtx, Constraints: prov.Constraints(),
			CompileS: compileS, SetupS: medSetup, ProveS: medProve,
			VerifyMs: verifyMs, ProofBytes: proofBytes, PeakRSSMB: rss,
			Reps:      reps,
			SetupStat: newStatS(setupVals, reps < 3),
			ProveStat: newStatS(proveVals, reps < 3),
			GOMAXPROCS: gomax,
		})
	}
	writeJSON(filepath.Join(outDir, "tab3_prover_resources.json"), res)
}
