package circuit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"

	"c5full/internal/c5/host"
)

// these helpers live only in *_test.go so they may be used across tests.

func emptyRdElL(L, maskCtxLen int) *RdEl {
	return &RdEl{
		L:       L,
		C:       make([]sw_emulated.AffinePoint[emulated.Secp256k1Fp], L),
		Cpt:     make([]emulated.Element[emulated.Secp256k1Fr], L),
		MaskCtx: make([]uints.U8, maskCtxLen),
		Zs:      make([]emulated.Element[emulated.Secp256k1Fr], L),
		Rhos:    make([]emulated.Element[emulated.Secp256k1Fr], L),
	}
}

// benchWitness builds a full R_del witness for an L-output instance.
// C_j is the outer-compiled EvalCom(Aout[j], xi) == Pedersen(zlist[j],rholist[j]).
func benchWitness(inst *host.Instance) *RdEl {
	L := inst.L
	C := make([]sw_emulated.AffinePoint[emulated.Secp256k1Fp], L)
	Cpt := make([]emulated.Element[emulated.Secp256k1Fr], L)
	Zs := make([]emulated.Element[emulated.Secp256k1Fr], L)
	Rhos := make([]emulated.Element[emulated.Secp256k1Fr], L)
	for j := 0; j < L; j++ {
		Cp := host.Pedersen(inst.Zlist[j], inst.Rholist[j])
		C[j] = *pAff(Cp.X.BigInt(new(big.Int)), Cp.Y.BigInt(new(big.Int)))
		Cpt[j] = emulated.ValueOf[emulated.Secp256k1Fr](inst.Clist[j])
		Zs[j] = emulated.ValueOf[emulated.Secp256k1Fr](inst.Zlist[j])
		Rhos[j] = emulated.ValueOf[emulated.Secp256k1Fr](inst.Rholist[j])
	}
	return &RdEl{
		L:       L,
		PKR:     *pAff(inst.PKR.X.BigInt(new(big.Int)), inst.PKR.Y.BigInt(new(big.Int))),
		R:       *pAff(inst.R.X.BigInt(new(big.Int)), inst.R.Y.BigInt(new(big.Int))),
		C:       C,
		Cpt:     Cpt,
		MaskCtx: uints.NewU8Array(inst.MaskCtx),
		S:       emulated.ValueOf[emulated.Secp256k1Fr](inst.S),
		Zs:      Zs,
		Rhos:    Rhos,
	}
}

// benchRow is one (L,f) configuration record.
type benchRow struct {
	L               int     `json:"L"`
	F               int     `json:"f"`
	Constraints     int     `json:"constraints"`
	NbPublic        int     `json:"nb_public_inputs"`
	PublicBytes     int     `json:"public_input_bytes"`
	LogAoutBytes    int     `json:"logical_aout_bytes"`
	MaskCtxBytes    int     `json:"maskctx_bytes"`
	OuterPrecomputeMs float64 `json:"outer_Aout_to_Ci_ms"`
}

// backendTrait is the heavy per-L backend measurement (identical across f).
type backendTrait struct {
	L           int     `json:"L"`
	Constraints int     `json:"constraints"`
	CompileS    float64 `json:"compile_s"`
	SetupS      float64 `json:"setup_s"`
	ProveS      float64 `json:"prove_s"`
	VerifyMs    float64 `json:"verify_ms"`
	ProofB      int     `json:"proof_bytes"`
	PKB         int     `json:"pk_bytes"`
	VKB         int     `json:"vk_bytes"`
	Result      string  `json:"result"`
}

func outerPrecomputeMs(inst *host.Instance) float64 {
	tt := time.Now()
	for j := 0; j < inst.L; j++ {
		host.Pedersen(inst.Zlist[j], inst.Rholist[j])
	}
	return time.Since(tt).Seconds() * 1000
}

// measureCompile records compile-only metrics for a (L,f) configuration.
func measureCompile(L, f int, seed int) (*benchRow, error) {
	inst, err := host.SynthInstance(L, f, seed, 1, 0)
	if err != nil {
		return nil, err
	}
	w := benchWitness(inst)
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, emptyRdElL(L, len(inst.MaskCtx)))
	if err != nil {
		return nil, err
	}
	sec, err := frontend.NewWitness(w, ecc.BLS12_381.ScalarField())
	if err != nil {
		return nil, err
	}
	pub, err := sec.Public()
	if err != nil {
		return nil, err
	}
	row := &benchRow{
		L:                 L, F: f,
		Constraints:       ccs.GetNbConstraints(),
		NbPublic:          ccs.GetNbPublicVariables(),
		PublicBytes:       witnessLen(pub),
		LogAoutBytes:      len(host.EncodeAout(inst.Aout)),
		MaskCtxBytes:      len(inst.MaskCtx),
		OuterPrecomputeMs: outerPrecomputeMs(inst),
	}
	return row, nil
}

// runBackend runs the heavy per-L Groth16 backend (setup/prove/verify) for L
// using the f=1 instance, returning full traits.
func runBackend(L, seed int) (*backendTrait, error) {
	inst, err := host.SynthInstance(L, 1, seed, 1, 0)
	if err != nil {
		return nil, err
	}
	bt := &backendTrait{L: L, Result: "PASS"}
	tt := time.Now()
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, emptyRdElL(L, len(inst.MaskCtx)))
	if err != nil {
		return nil, err
	}
	bt.CompileS = time.Since(tt).Seconds()
	bt.Constraints = ccs.GetNbConstraints()
	tt = time.Now()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}
	bt.SetupS = time.Since(tt).Seconds()
	// prove+verify
	w := benchWitness(inst)
	sec, err := frontend.NewWitness(w, ecc.BLS12_381.ScalarField())
	if err != nil {
		return nil, err
	}
	tt = time.Now()
	pf, err := groth16.Prove(ccs, pk, sec)
	if err != nil {
		return nil, err
	}
	bt.ProveS = time.Since(tt).Seconds()
	pub, err := sec.Public()
	if err != nil {
		return nil, err
	}
	tt = time.Now()
	if err := groth16.Verify(pf, vk, pub); err != nil {
		return nil, err
	}
	bt.VerifyMs = time.Since(tt).Seconds() * 1000
	var b bytes.Buffer
	n, _ := pf.WriteTo(&b)
	bt.ProofB = int(n)
	var pkb, vkb bytes.Buffer
	n, _ = pk.WriteTo(&pkb)
	bt.PKB = int(n)
	n, _ = vk.WriteTo(&vkb)
	bt.VKB = int(n)
	return bt, nil
}

// TestBenchmarkConstraints (M6 quick pass): compile-only metrics for all 12
func TestBenchmarkConstraints(t *testing.T) {
	rows := make([]*benchRow, 0, 12)
	for _, L := range []int{1, 2, 4, 8} {
		for _, f := range []int{1, 2, 4} {
			r, err := measureCompile(L, f, 20260903)
			if err != nil {
				t.Fatalf("compile L=%d f=%d: %v", L, f, err)
			}
			rows = append(rows, r)
			t.Logf("L=%d f=%d constraints=%d public=%d(%dB) aout=%dB precompute=%.2fms",
				r.L, r.F, r.Constraints, r.NbPublic, r.PublicBytes, r.LogAoutBytes, r.OuterPrecomputeMs)
		}
	}
	if b, err := json.MarshalIndent(rows, "", "  "); err == nil {
		save(t, "benchmark/m6_constraints_matrix.json", b)
	}
}

// the per-L heavies run in separate test processes to isolate OOM/timeout.
func TestBenchmarkBackendL1(t *testing.T) { benchBackendL(t, 1) }
func TestBenchmarkBackendL2(t *testing.T) { benchBackendL(t, 2) }
func TestBenchmarkBackendL4(t *testing.T) { benchBackendL(t, 4) }
func TestBenchmarkBackendL8(t *testing.T) { benchBackendL(t, 8) }

func benchBackendL(t *testing.T, L int) {
	bt, err := runBackend(L, 20260903)
	if err != nil {
		t.Fatalf("L=%d backend failed: %v", L, err)
	}
	t.Logf("L=%d: compile=%.1fs setup=%.1fs prove=%.1fs verify=%.1fms constraints=%d proof=%dB pk=%dB vk=%dB",
		L, bt.CompileS, bt.SetupS, bt.ProveS, bt.VerifyMs, bt.Constraints, bt.ProofB, bt.PKB, bt.VKB)
	if b, err := json.MarshalIndent(bt, "", "  "); err == nil {
		save(t, fmt.Sprintf("benchmark/m6_backend_L%d_f1.json", L), b)
	}
}