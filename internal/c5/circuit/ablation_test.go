package circuit

import (
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

func emptyDirect(L, f, maskCtxLen int) *RdElDirect {
	aout := make([][]sw_emulated.AffinePoint[emulated.Secp256k1Fp], L)
	for i := range aout {
		aout[i] = make([]sw_emulated.AffinePoint[emulated.Secp256k1Fp], f+1)
	}
	return &RdElDirect{
		F:       f,
		Aout:    aout,
		Cpt:     make([]emulated.Element[emulated.Secp256k1Fr], L),
		MaskCtx: make([]uints.U8, maskCtxLen),
		Zs:      make([]emulated.Element[emulated.Secp256k1Fr], L),
		Rhos:    make([]emulated.Element[emulated.Secp256k1Fr], L),
	}
}

func directWitness(inst *host.Instance) *RdElDirect {
	L, f := inst.L, inst.F
	aout := make([][]sw_emulated.AffinePoint[emulated.Secp256k1Fp], L)
	for j := 0; j < L; j++ {
		aout[j] = make([]sw_emulated.AffinePoint[emulated.Secp256k1Fp], f+1)
		for k := 0; k <= f; k++ {
			A := inst.Aout[j][k]
			aout[j][k] = *pAff(A.X.BigInt(new(big.Int)), A.Y.BigInt(new(big.Int)))
		}
	}
	return &RdElDirect{
		F:       f,
		Aout:    aout,
		Xi:      emulated.ValueOf[emulated.Secp256k1Fr](inst.Xi),
		PKR:     *pAff(inst.PKR.X.BigInt(new(big.Int)), inst.PKR.Y.BigInt(new(big.Int))),
		R:       *pAff(inst.R.X.BigInt(new(big.Int)), inst.R.Y.BigInt(new(big.Int))),
		Cpt:     []emulated.Element[emulated.Secp256k1Fr]{emulated.ValueOf[emulated.Secp256k1Fr](inst.Clist[0])},
		MaskCtx: uints.NewU8Array(inst.MaskCtx),
		S:       emulated.ValueOf[emulated.Secp256k1Fr](inst.S),
		Zs:      []emulated.Element[emulated.Secp256k1Fr]{emulated.ValueOf[emulated.Secp256k1Fr](inst.Zlist[0])},
		Rhos:    []emulated.Element[emulated.Secp256k1Fr]{emulated.ValueOf[emulated.Secp256k1Fr](inst.Rholist[0])},
	}
}

type ablationRow struct {
	Mode       string    `json:"mode"`
	L          int       `json:"L"`
	F          int       `json:"f"`
	Constraints int      `json:"constraints"`
	NbPublic   int       `json:"nb_public_inputs"`
	PublicBytes int      `json:"public_input_bytes"`
	SetupS     *float64  `json:"setup_s,omitempty"`
	ProveS     *float64  `json:"prove_s,omitempty"`
	VerifyMs   *float64  `json:"verify_ms,omitempty"`
}

func measureAblation(mode string, L, f int, seed int) (*ablationRow, error) {
	inst, err := host.SynthInstance(L, f, seed, 1, 0)
	if err != nil {
		return nil, err
	}
	var constraints, npub, pbytes int
	if mode == "direct" {
		w := directWitness(inst)
		cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, emptyDirect(L, f, len(inst.MaskCtx)))
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
		constraints, npub, pbytes = cs.GetNbConstraints(), cs.GetNbPublicVariables(), witnessLen(pub)
	} else {
		constraints, npub, pbytes, err = hostedCompiledCompile(inst)
		if err != nil {
			return nil, err
		}
	}
	return &ablationRow{Mode: mode, L: L, F: f, Constraints: constraints, NbPublic: npub, PublicBytes: pbytes}, nil
}

// hostedCompiledCompile returns (constraints,nbPublic,pubbytes) for the
// Compiled-C circuit without depending on the benchmark helpers.
func hostedCompiledCompile(inst *host.Instance) (int, int, int, error) {
	w := benchWitness(inst)
	cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, emptyRdElL(inst.L, len(inst.MaskCtx)))
	if err != nil {
		return 0, 0, 0, err
	}
	sec, err := frontend.NewWitness(w, ecc.BLS12_381.ScalarField())
	if err != nil {
		return 0, 0, 0, err
	}
	pub, err := sec.Public()
	if err != nil {
		return 0, 0, 0, err
	}
	return cs.GetNbConstraints(), cs.GetNbPublicVariables(), witnessLen(pub), nil
}

// TestAblationConstraints (M7): compile-only comparison of Compiled-C vs
// Direct-Aout across the L in {1,2}, f in {1,2} ablation grid.
func TestAblationConstraints(t *testing.T) {
	grid := []struct{ L, f int }{{1, 1}, {1, 2}, {2, 1}, {2, 2}}
	rows := make([]*ablationRow, 0, len(grid)*2)
	for _, g := range grid {
		dr, err := measureAblation("direct", g.L, g.f, 20260903)
		if err != nil {
			t.Fatalf("direct L=%d f=%d: %v", g.L, g.f, err)
		}
		cr, err := measureAblation("compiled", g.L, g.f, 20260903)
		if err != nil {
			t.Fatalf("compiled L=%d f=%d: %v", g.L, g.f, err)
		}
		rows = append(rows, dr, cr)
		t.Logf("L=%d f=%d compiled constraints=%d pub=%d | direct constraints=%d pub=%d",
			g.L, g.f, cr.Constraints, cr.NbPublic, dr.Constraints, dr.NbPublic)
	}
	if b, err := json.MarshalIndent(rows, "", "  "); err == nil {
		save(t, "ablation/m7_ablation_constraints.json", b)
	}
}

// TestDirectAoutL1F1 (M7): one real Direct-Aout proof (L=1 f=1) to prove the
// Direct-Aout path is genuinely satisfiable end-to-end.
func TestDirectAoutL1F1(t *testing.T) {
	inst, err := host.SynthInstance(1, 1, 20260903, 1, 0)
	if err != nil {
		t.Fatalf("SynthInstance: %v", err)
	}
	w := directWitness(inst)
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, emptyDirect(1, 1, len(inst.MaskCtx)))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("Direct-Aout L=1 f=1 constraints=%d", ccs.GetNbConstraints())
	tt := time.Now()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	sec, err := frontend.NewWitness(w, ecc.BLS12_381.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	pub, err := sec.Public()
	if err != nil {
		t.Fatalf("public: %v", err)
	}
	tp := time.Now()
	pf, err := groth16.Prove(ccs, pk, sec)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	if err := groth16.Verify(pf, vk, pub); err != nil {
		t.Fatalf("verify: %v", err)
	}
	t.Logf("Direct-Aout honest PASS: setup=%.1fs prove=%.1fs verify=OK",
		time.Since(tt).Seconds(), time.Since(tp).Seconds())
	save(t, "ablation/m7_directaout_L1_f1_pass.json", []byte(fmt.Sprintf(
		`{"mode":"direct","result":"PASS","L":1,"f":1,"constraints":%d,"setup_s":%.1f,"prove_s":%.1f}`,
		ccs.GetNbConstraints(), time.Since(tt).Seconds(), time.Since(tp).Seconds())))
}