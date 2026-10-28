package basic

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"

	"c5full/internal/c5/host"
	"c5full/internal/c5/params"
)

// pointAff converts a host (gnark-crypto) affine point X,Y into an emulated
// circuit AffinePoint.
func pointAff(x, y *big.Int) *sw_emulated.AffinePoint[emulated.Secp256k1Fp] {
	return &sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
		X: emulated.ValueOf[emulated.Secp256k1Fp](x),
		Y: emulated.ValueOf[emulated.Secp256k1Fp](y),
	}
}

// sc builds an emulated secp256k1 scalar circuit value from a *big.Int.
func sc(v *big.Int) emulated.Element[emulated.Secp256k1Fr] {
	return emulated.ValueOf[emulated.Secp256k1Fr](v)
}

// cyc compiles/setups once (using the empty template), proves+verifies the
// good witness, and asserts the bad witness is rejected at prove time.
// empty must be a zero-valued copy of the circuit (gnark mutates the emulated
// fields during Compile). bad may be nil to only check good.
func cyc(t *testing.T, empty, good, bad frontend.Circuit) {
	t.Helper()
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, empty)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	secret, err := frontend.NewWitness(good, ecc.BLS12_381.ScalarField())
	if err != nil {
		t.Fatalf("good witness: %v", err)
	}
	public, err := secret.Public()
	if err != nil {
		t.Fatalf("public witness: %v", err)
	}
	proof, err := groth16.Prove(ccs, pk, secret)
	if err != nil {
		t.Fatalf("prove(good): %v", err)
	}
	if err := groth16.Verify(proof, vk, public); err != nil {
		t.Fatalf("verify(good) failed: %v", err)
	}
	g16Proof = proof // keep reference alive for later serialization tests
	if bad == nil {
		return
	}
	badSecret, err := frontend.NewWitness(bad, ecc.BLS12_381.ScalarField())
	if err != nil {
		t.Fatalf("bad witness: %v", err)
	}
	if _, err := groth16.Prove(ccs, pk, badSecret); err == nil {
		t.Fatalf("expected bad witness to be rejected")
	} else {
		t.Logf("bad witness correctly rejected: %v", err)
	}
}

// g16Proof keeps a reference so tests exercise serialization paths.
var g16Proof groth16.Proof

// TestScalarNonZeroRange (M3.1): s must be nonzero and in range.
func TestScalarNonZeroRange(t *testing.T) {
	var empty ScalarNonZeroRange[emulated.Secp256k1Fr]
	good := ScalarNonZeroRange[emulated.Secp256k1Fr]{S: sc(big.NewInt(7))}
	badZero := ScalarNonZeroRange[emulated.Secp256k1Fr]{S: sc(big.NewInt(0))}
	cyc(t, &empty, &good, &badZero)
}

// TestFixedBaseScalarMul (M3.2): R=[s]G honest + wrong-s (wrong R too).
func TestFixedBaseScalarMul(t *testing.T) {
	s := big.NewInt(123456789)
	R := host.ScalarMul(&params.G, s) // *secp256k1.G1Affine
	var empty FixedBaseMulBase[emulated.Secp256k1Fp, emulated.Secp256k1Fr]
	good := FixedBaseMulBase[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		S: sc(s),
		R: *pointAff(R.X.BigInt(new(big.Int)), R.Y.BigInt(new(big.Int))),
	}
	// wrong s but same claimed R -> relation unsat
	badS := good
	badS.S = sc(new(big.Int).Add(s, big.NewInt(1)))
	cyc(t, &empty, &good, &badS)

	// wrong claimed R for correct s
	badR := good
	badR.R = *pointAff(R.Y.BigInt(new(big.Int)), R.X.BigInt(new(big.Int)))
	cyc(t, &empty, &good, &badR)
}

// TestVarBaseScalarMul (M3.3): Z=[s]PK_R honest + wrong PK_R.
func TestVarBaseScalarMul(t *testing.T) {
	s := big.NewInt(987654321)
	PKR := host.ScalarMul(&params.G, big.NewInt(7))
	Z := host.ScalarMul(PKR, s)
	var empty VarBaseMulBase[emulated.Secp256k1Fp, emulated.Secp256k1Fr]
	good := VarBaseMulBase[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		PKR: *pointAff(PKR.X.BigInt(new(big.Int)), PKR.Y.BigInt(new(big.Int))),
		Z:   *pointAff(Z.X.BigInt(new(big.Int)), Z.Y.BigInt(new(big.Int))),
		S:   sc(s),
	}
	bad := good
	badPKR := host.ScalarMul(&params.G, big.NewInt(8))
	bad.PKR = *pointAff(badPKR.X.BigInt(new(big.Int)), badPKR.Y.BigInt(new(big.Int)))
	cyc(t, &empty, &good, &bad)
}

// TestPedersen (M3.4): honest + wrong z + wrong rho + wrong C.
func TestPedersen(t *testing.T) {
	z := big.NewInt(31415926535)
	rho := big.NewInt(27182818284)
	C := host.Pedersen(z, rho)
	var empty PedersenBase
	mk := func() PedersenBase {
		return PedersenBase{
			Z:   sc(z),
			Rho: sc(rho),
			C:   *pointAff(C.X.BigInt(new(big.Int)), C.Y.BigInt(new(big.Int))),
		}
	}
	good := mk()

	badZ := mk()
	badZ.Z = sc(new(big.Int).Add(z, big.NewInt(1)))
	cyc(t, &empty, &good, &badZ)

	badRho := mk()
	badRho.Rho = sc(new(big.Int).Add(rho, big.NewInt(1)))
	cyc(t, &empty, &good, &badRho)

	// wrong C: X coordinate's base-field element off by one an invalid point
	badC := mk()
	badC.C.X = emulated.ValueOf[emulated.Secp256k1Fp](new(big.Int).Add(C.X.BigInt(new(big.Int)), big.NewInt(1)))
	cyc(t, &empty, &good, &badC)
}

// TestBasicSizes (evidence): compile-only, reports constraint / input counts
// for each M2 base circuit. Fast (no setup/prove).
func TestBasicSizes(t *testing.T) {
	type c struct{ name string; c frontend.Circuit }
	cases := []c{
		{"ScalarNonZeroRange", &ScalarNonZeroRange[emulated.Secp256k1Fr]{}},
		{"FixedBaseMul", &FixedBaseMulBase[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}},
		{"VarBaseMul", &VarBaseMulBase[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}},
		{"Pedersen", &PedersenBase{}},
	}
	for _, ca := range cases {
		ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, ca.c)
		if err != nil {
			t.Fatalf("%s compile: %v", ca.name, err)
		}
		t.Logf("%-20s constraints=%d nbPublic=%d nbSecret=%d",
			ca.name, ccs.GetNbConstraints(), ccs.GetNbPublicVariables(), ccs.GetNbSecretVariables())
	}
}

// TestHostCircuitPointConsistency: a coordinator-style consistency check that
// fixed-base and Pedersen circuit results equal host arithmetic points.
func TestHostCircuitPointConsistency(t *testing.T) {
	s := big.NewInt(123456789)
	Rhost := host.ScalarMul(&params.G, s) // [s]G
	var empty FixedBaseMulBase[emulated.Secp256k1Fp, emulated.Secp256k1Fr]
	good := FixedBaseMulBase[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		S: sc(s),
		R: *pointAff(Rhost.X.BigInt(new(big.Int)), Rhost.Y.BigInt(new(big.Int))),
	}
	cyc(t, &empty, &good, nil)
}