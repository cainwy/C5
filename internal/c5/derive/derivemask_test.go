package derive

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"

	"c5full/internal/c5/host"
)

// testCtx is a short, fixed, deterministic mask context used for this M3
// isolation test (documented as a test vector). The three ends (sender host,
// circuit, receiver host) hash exactly these bytes.
var testCtx = []byte("C5-AP2-M3-derivemask-ctx-0000000000000000")

// pAff converts a host (gnark-crypto) affine point to an emulated point.
func pAff(x, y *big.Int) *sw_emulated.AffinePoint[emulated.Secp256k1Fp] {
	return &sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
		X: emulated.ValueOf[emulated.Secp256k1Fp](x),
		Y: emulated.ValueOf[emulated.Secp256k1Fp](y),
	}
}

// witness builds a concrete Derivemask witness from host values.
func witness(Z *secp256k1.G1Affine, maskCtx []byte, j int, k *big.Int) Derivemask {
	return Derivemask{
		MaskCtxLen: len(maskCtx),
		Z:          *pAff(Z.X.BigInt(new(big.Int)), Z.Y.BigInt(new(big.Int))),
		MaskCtx:    uints.NewU8Array(maskCtx),
		J:          j,
		K:          emulated.ValueOf[emulated.Secp256k1Fr](k),
	}
}

// TestDerivemaskThreeEnd (M3/M4): sender host == circuit == receiver host.
// It compiles/setups once, proves+verifies the honest witness (matching the
// host DeriveMask), then asserts wrong K / wrong ctx / wrong j are rejected.
func TestDerivemaskThreeEnd(t *testing.T) {
	// receiver key and shared point come from a real instance.
	inst, err := host.SynthInstance(1, 1, 20260903, 1, 0)
	if err != nil {
		t.Fatalf("SynthInstance: %v", err)
	}
	j := 1 // 1-based output index (matches host.DeriveMask usage)

	// HOST (sender / receiver share the same F_q element).
	kHost, err := host.DeriveMask(inst.Z, testCtx, j)
	if err != nil {
		t.Fatalf("host DeriveMask: %v", err)
	}

	// Compile once using an empty template. Slices must be pre-sized to the
	// exact witness length so the schema registers the same number of inputs.
	empty := &Derivemask{
		MaskCtxLen: len(testCtx),
		MaskCtx:    make([]uints.U8, len(testCtx)),
	}
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, empty)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	// --- honest: circuit mask must equal host mask (three-end equality) ---
	good := witness(inst.Z, testCtx, j, kHost)
	secret, err := frontend.NewWitness(&good, ecc.BLS12_381.ScalarField())
	if err != nil {
		t.Fatalf("good witness: %v", err)
	}
	public, err := secret.Public()
	if err != nil {
		t.Fatalf("public witness: %v", err)
	}
	pf, err := groth16.Prove(ccs, pk, secret)
	if err != nil {
		t.Fatalf("prove(good): %v", err)
	}
	if err := groth16.Verify(pf, vk, public); err != nil {
		t.Fatalf("verify(good) failed: %v", err)
	}
	t.Logf("three-end DeriveMask consistent: k=%x", kHost)

	// --- negative: wrong claimed K ----------------------------------------
	badK := witness(inst.Z, testCtx, j, new(big.Int).Add(kHost, big.NewInt(1)))
	if err := expectReject(ccs, pk, &badK); err != nil {
		t.Fatalf("wrong K not rejected: %v", err)
	}
	// --- negative: context mutation (flip first mask byte) ----------------
	mutCtx := append([]byte{}, testCtx...)
	mutCtx[0] ^= 0x01
	badCtx := witness(inst.Z, mutCtx, j, kHost)
	if err := expectReject(ccs, pk, &badCtx); err != nil {
		t.Fatalf("context mutation not rejected: %v", err)
	}
	// --- negative: wrong output index j ------------------------------------
	badJ := witness(inst.Z, testCtx, j+1, kHost)
	if err := expectReject(ccs, pk, &badJ); err != nil {
		t.Fatalf("wrong j not rejected: %v", err)
	}
}

// TestDerivemaskSizes (evidence): compile-only, reports constraints / gates
// and public+secret input counts for the DeriveMask isolation circuit.
func TestDerivemaskSizes(t *testing.T) {
	empty := &Derivemask{
		MaskCtxLen: len(testCtx),
		MaskCtx:    make([]uints.U8, len(testCtx)),
	}
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, empty)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("DeriveMask L=%d: constraints=%d nbPublic=%d nbSecret=%d",
		len(testCtx), ccs.GetNbConstraints(), ccs.GetNbPublicVariables(), ccs.GetNbSecretVariables())
}

// expectReject tries to prove a (satisfiably-expected-unsat) witness and
// requires prove to fail.
func expectReject(ccs constraint.ConstraintSystem, pk groth16.ProvingKey, w frontend.Circuit) error {
	sec, err := frontend.NewWitness(w, ecc.BLS12_381.ScalarField())
	if err != nil {
		return err
	}
	pf, err := groth16.Prove(ccs, pk, sec)
	if err != nil {
		return nil // correctly rejected
	}
	_ = pf
	return &notRejectedErr{}
}

type notRejectedErr struct{}

func (*notRejectedErr) Error() string { return "expected witness to be rejected" }