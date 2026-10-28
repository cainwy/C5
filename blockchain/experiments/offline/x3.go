// x3.go implements the proof-organisation ablation of Fig. 3: B1 issues one
// proof per output coordinate, B2 keeps a single proof over the output vector.
// Only the circuit size and the serialized proof size are reported, because the
// two organisations verify the same delivery relation.
package offline

import (
	"fmt"
	"path/filepath"
	"time"

	"c5full/internal/c5/m1"
)

type x3Row struct {
	Mode        string  `json:"mode"`
	L           int     `json:"l"`
	ProofCount  int     `json:"proof_count"`
	ProofBytes  int     `json:"proof_bytes_total"`
	Constraints int     `json:"constraints_per_proof"`
	TotalCons   int     `json:"constraints_total"`
	CompileS    float64 `json:"compile_s"`
	CompileStat StatTrials `json:"compile_stat"`
	Provenance  string  `json:"provenance"`
}

type x3Result struct {
	Schema       string  `json:"schema"`
	N            int     `json:"n"`
	F            int     `json:"f"`
	MaskCtxLen   int     `json:"maskctx_len"`
	ProofBytes   int     `json:"proof_bytes_single"`
	Rows         []x3Row `json:"rows"`
	MeasuredBy   string  `json:"measured_by"`
	GeneratedUTC string  `json:"generated_utc"`
}

// RunX3 compiles both proof organisations for L in {1,2,4} and reports the total
// number of constraints and the total serialized proof size.
func RunX3(outDir string, ls []int, proofBytes int) {
	const n, f, maskCtx = 3, 1, 507
	if proofBytes <= 0 {
		proofBytes = 292
	}
	if len(ls) == 0 {
		ls = []int{1, 2, 4}
	}
	res := &x3Result{
		Schema: "c5-proof-organization-v1", N: n, F: f, MaskCtxLen: maskCtx,
		ProofBytes:   proofBytes,
		MeasuredBy:   "in-process circuit compilation (pure Go); proof size is the serialized Groth16 proof of the canonical relation",
		GeneratedUTC: timeNowUTC(),
	}
	for _, L := range ls {
		t0 := time.Now()
		prov, err := m1.CompileOnly(L, maskCtx)
		must(err)
		el := time.Since(t0).Seconds()
		res.Rows = append(res.Rows, x3Row{
			Mode: "B2 (single proof)", L: L,
			ProofCount: 1, ProofBytes: proofBytes,
			Constraints: prov.Constraints(), TotalCons: prov.Constraints(),
			CompileS: el, CompileStat: newStatS([]float64{el}, true),
			Provenance: "measured",
		})
	}
	for _, L := range ls {
		t0 := time.Now()
		prov, err := m1.CompileOnly(1, maskCtx)
		must(err)
		el := time.Since(t0).Seconds()
		res.Rows = append(res.Rows, x3Row{
			Mode: "B1 (per coordinate)", L: L,
			ProofCount: L, ProofBytes: L * proofBytes,
			Constraints: prov.Constraints(), TotalCons: L * prov.Constraints(),
			CompileS: el, CompileStat: newStatS([]float64{el}, true),
			Provenance: "measured",
		})
	}
	writeJSON(filepath.Join(outDir, "fig3_proof_organization.json"), res)
	fmt.Printf("FIG3 rows=%d\n", len(res.Rows))
}
