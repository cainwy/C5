package circuit

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"

	"c5full/internal/c5/host"
)

func pAff(x, y *big.Int) *sw_emulated.AffinePoint[emulated.Secp256k1Fp] {
	return &sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
		X: emulated.ValueOf[emulated.Secp256k1Fp](x),
		Y: emulated.ValueOf[emulated.Secp256k1Fp](y),
	}
}

// rdelWitness builds a full R_del (L=1) witness from a real host instance.
// R2 is honored by feeding the outer-compiled C (== EvalCom(Aout,xi)).
func rdelWitness(inst *host.Instance) *RdEl {
	C := make([]sw_emulated.AffinePoint[emulated.Secp256k1Fp], 1)
	// C = EvalCom(Aout[0], Xi) == Pedersen(zlist[0], rholist[0]) (outer compiler)
	Cp := host.Pedersen(inst.Zlist[0], inst.Rholist[0])
	C[0] = *pAff(Cp.X.BigInt(new(big.Int)), Cp.Y.BigInt(new(big.Int)))
	Cpt := []emulated.Element[emulated.Secp256k1Fr]{
		emulated.ValueOf[emulated.Secp256k1Fr](inst.Clist[0]),
	}
	return &RdEl{
		L:       1,
		PKR:     *pAff(inst.PKR.X.BigInt(new(big.Int)), inst.PKR.Y.BigInt(new(big.Int))),
		R:       *pAff(inst.R.X.BigInt(new(big.Int)), inst.R.Y.BigInt(new(big.Int))),
		C:       C,
		Cpt:     Cpt,
		MaskCtx: uints.NewU8Array(inst.MaskCtx),
		S:       emulated.ValueOf[emulated.Secp256k1Fr](inst.S),
		Zs:      []emulated.Element[emulated.Secp256k1Fr]{emulated.ValueOf[emulated.Secp256k1Fr](inst.Zlist[0])},
		Rhos:    []emulated.Element[emulated.Secp256k1Fr]{emulated.ValueOf[emulated.Secp256k1Fr](inst.Rholist[0])},
	}
}

// emptyRdEl returns an all-zero template pre-sized to L=1 with the instance's
// maskCtx byte length, so the schema registers the exact witness sizes.
func emptyRdEl(maskCtxLen int) *RdEl {
	return &RdEl{
		L:       1,
		C:       make([]sw_emulated.AffinePoint[emulated.Secp256k1Fp], 1),
		Cpt:     make([]emulated.Element[emulated.Secp256k1Fr], 1),
		MaskCtx: make([]uints.U8, maskCtxLen),
		Zs:      make([]emulated.Element[emulated.Secp256k1Fr], 1),
		Rhos:    make([]emulated.Element[emulated.Secp256k1Fr], 1),
	}
}

// TestRdElFull (M4/M5 L=1 f=1): full R_del inner circuit.
//   - honest witness (matching the real instance) proves & verifies;
//   - R1/R3/R4/R5 negative mutations are consistently rejected.
// R2 is not inside the circuit by design (Compiled-C): the honest C here is
// exactly the outer compiler's EvalCom(Aout,xi) result (see host.CompiledStatement).
func TestRdElFull(t *testing.T) {
	inst, err := host.SynthInstance(1, 1, 20260903, 1, 0)
	if err != nil {
		t.Fatalf("SynthInstance: %v", err)
	}
	empty := emptyRdEl(len(inst.MaskCtx))
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, empty)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("R_del (L=1,f=1) constraints=%d public=%d secret=%d",
		ccs.GetNbConstraints(), ccs.GetNbPublicVariables(), ccs.GetNbSecretVariables())
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	// --- honest: prove + verify -------------------------------------------------
	good := rdelWitness(inst)
	sec, err := frontend.NewWitness(good, ecc.BLS12_381.ScalarField())
	if err != nil {
		t.Fatalf("honest witness: %v", err)
	}
	pub, err := sec.Public()
	if err != nil {
		t.Fatalf("honest public: %v", err)
	}
	pf, err := groth16.Prove(ccs, pk, sec)
	if err != nil {
		t.Fatalf("honest prove: %v", err)
	}
	if err := groth16.Verify(pf, vk, pub); err != nil {
		t.Fatalf("honest verify failed: %v", err)
	}
	t.Log("R_del honest proof accepted (R1,R3,R4,R5 in-circuit; R2 outer)")

	// --- R1: wrong s -------------------------------------------------------------
	wrongS := rdelWitness(inst)
	wrongS.S = emulated.ValueOf[emulated.Secp256k1Fr](new(big.Int).Add(inst.S, big.NewInt(1)))
	if err := expectReject(ccs, pk, wrongS); err != nil {
		t.Fatalf("wrong s not rejected (R1): %v", err)
	}
	// --- R3: wrong z -------------------------------------------------------------
	wrongZ := rdelWitness(inst)
	wrongZ.Zs[0] = emulated.ValueOf[emulated.Secp256k1Fr](new(big.Int).Add(inst.Zlist[0], big.NewInt(1)))
	if err := expectReject(ccs, pk, wrongZ); err != nil {
		t.Fatalf("wrong z not rejected (R3): %v", err)
	}
	// --- R3: wrong rho ------------------------------------------------------------
	wrongRho := rdelWitness(inst)
	wrongRho.Rhos[0] = emulated.ValueOf[emulated.Secp256k1Fr](new(big.Int).Add(inst.Rholist[0], big.NewInt(1)))
	if err := expectReject(ccs, pk, wrongRho); err != nil {
		t.Fatalf("wrong rho not rejected (R3): %v", err)
	}
	// --- R5: modified public c -----------------------------------------------------
	wrongC := rdelWitness(inst)
	wrongC.Cpt[0] = emulated.ValueOf[emulated.Secp256k1Fr](new(big.Int).Add(inst.Clist[0], big.NewInt(1)))
	if err := expectReject(ccs, pk, wrongC); err != nil {
		t.Fatalf("modified c not rejected (R5): %v", err)
	}
	// --- R4: context mutation (modified public MaskCtx) ----------------------------
	wrongCtx := rdelWitness(inst)
	mut := append([]byte{}, inst.MaskCtx...)
	mut[0] ^= 0x01
	wrongCtx.MaskCtx = uints.NewU8Array(mut)
	if err := expectReject(ccs, pk, wrongCtx); err != nil {
		t.Fatalf("context mutation not rejected (R4): %v", err)
	}
	// --- R1: zero s ----------------------------------------------------------------
	zeroS := rdelWitness(inst)
	zeroS.S = emulated.ValueOf[emulated.Secp256k1Fr](big.NewInt(0))
	if err := expectReject(ccs, pk, zeroS); err != nil {
		t.Fatalf("zero s not rejected (R1): %v", err)
	}
}

// TestRdElSizes (evidence): compile-only, quickly reports full-circuit metrics.
func TestRdElSizes(t *testing.T) {
	inst, err := host.SynthInstance(1, 1, 20260903, 1, 0)
	if err != nil {
		t.Fatalf("SynthInstance: %v", err)
	}
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, emptyRdEl(len(inst.MaskCtx)))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("R_del sizes: constraints=%d nbPublic=%d nbSecret=%d",
		ccs.GetNbConstraints(), ccs.GetNbPublicVariables(), ccs.GetNbSecretVariables())
}

func expectReject(ccs constraint.ConstraintSystem, pk groth16.ProvingKey, w frontend.Circuit) error {
	sec, err := frontend.NewWitness(w, ecc.BLS12_381.ScalarField())
	if err != nil {
		return err
	}
	if pf, err := groth16.Prove(ccs, pk, sec); err == nil {
		_ = pf
		return &notRejectedErr{}
	}
	return nil
}

type notRejectedErr struct{}

func (*notRejectedErr) Error() string { return "expected witness to be rejected" }