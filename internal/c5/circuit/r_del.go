// Package circuit implements the M4/M5 full R_del inner circuit in Compiled-C
// mode. It assembles the production relations R1-R5 over emulated secp256k1
// arithmetic (base/scalar field over the BLS12-381 scalar circuit field):
//	R1  s != 0,  R = [s]G,                Z = [s]PK_R
//	R2  C = EvalCom(A, xi)                (OUTER deterministic compiler, not the prover)
//	R3  C_j = [z_j]G + [rho_j]H           (Pedersen opening, per output j)
//	R4  k_j = DeriveMask(Z, MaskCtx, j)   (XMD/SHA-256 -> OS2IP mod q, per j)
//	R5  c_j = z_j + k_j (mod q)           (ciphertext field equation, per j)
// Only the inner circuit lives here; R2 is preserved by host.CompiledStatement
// (the outer compiler) which feeds the authoritative C_i in as a public point.
// The prover therefore cannot inject an unbound C_i. Context / receiver /
// profile binding is carried in MaskCtx (a public input hashed into every k_j)
// and in the compiled statement produced by the outer compiler.
package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"

	"c5full/internal/c5/basic"
	"c5full/internal/c5/derive"
)

// RdEl is the full R_del inner circuit (Compiled-C). It is generic in L only
// through the compile-time slice lengths / c.L scalar; the code is L-agnostic.
// Public inputs (verifier / receiver can read them):
//   - PKR   receiver public key point [xR]G
//   - R     sender ephemeral point [s]G
//   - C     per-output Pedersen commitments, length L (from outer compiler: R2)
//   - Cpt   per-output ciphertext scalars c_j, length L (R5)
//   - MaskCtx  public context bytes hashed into every k_j (context binding)
// Secret witnesses (prover):
//   - S     sender scalar s (R1: s != 0)
//   - Zs    per-output opening scalar z_j
//   - Rhos  per-output opening randomness rho_j
// Z itself is re-derived in-circuit as [s]PK_R (so no unconstrained witness),
// then fed into DeriveMask exactly as the host sender/receiver hashes it.
type RdEl struct {
	L int

	PKR sw_emulated.AffinePoint[emulated.Secp256k1Fp] `gnark:",public"`
	R   sw_emulated.AffinePoint[emulated.Secp256k1Fp] `gnark:",public"`
	C   []sw_emulated.AffinePoint[emulated.Secp256k1Fp] `gnark:",public"`
	Cpt []emulated.Element[emulated.Secp256k1Fr]        `gnark:",public"`

	MaskCtx []uints.U8 `gnark:",public"`

	S    emulated.Element[emulated.Secp256k1Fr]
	Zs   []emulated.Element[emulated.Secp256k1Fr]
	Rhos []emulated.Element[emulated.Secp256k1Fr]
}

// Define enforces R1, R3, R4, R5 in-circuit (R2 is outer). Returns an error if
// any sub-relation (including the reusable DeriveMask) fails to mount.
func (c *RdEl) Define(api frontend.API) error {
	if c.L <= 0 || c.L != len(c.C) || c.L != len(c.Cpt) ||
		c.L != len(c.Zs) || c.L != len(c.Rhos) {
		return &lengthMismatchErr{got: c.L}
	}
	curve, err := sw_emulated.New[emulated.Secp256k1Fp, emulated.Secp256k1Fr](
		api, sw_emulated.GetCurveParams[emulated.Secp256k1Fp]())
	if err != nil {
		return err
	}
	field, err := emulated.NewField[emulated.Secp256k1Fr](api)
	if err != nil {
		return err
	}

	// ---- R1: s != 0, R=[s]G, Z=[s]PK_R -------------------------------
	field.AssertIsInRange(&c.S)
	field.AssertIsDifferent(&c.S, field.NewElement(0))
	curve.AssertIsOnCurve(&c.PKR)
	curve.AssertIsOnCurve(&c.R)
	R := curve.ScalarMulBase(&c.S)        // [s]G
	curve.AssertIsEqual(R, &c.R)
	Z := curve.ScalarMul(&c.PKR, &c.S)    // [s]PK_R  (Z re-derived; no witness)
	curve.AssertIsOnCurve(Z)

	// ---- per output j ------------------------------------------------
	for j := 0; j < c.L; j++ {
		// R3: C_j = [z_j]G + [rho_j]H
		field.AssertIsInRange(&c.Zs[j])
		field.AssertIsInRange(&c.Rhos[j])
		curve.AssertIsOnCurve(&c.C[j])
		t1 := curve.ScalarMulBase(&c.Zs[j])        // [z_j]G
		t2 := curve.ScalarMul(&basic.Hpoint, &c.Rhos[j]) // [rho_j]H
		summed := curve.AddUnified(t1, t2)          // [z_j]G + [rho_j]H
		curve.AssertIsEqual(summed, &c.C[j])

		// R4: k_j = DeriveMask(Z, MaskCtx, j+1)  (1-based, matches host)
		kV, err := derive.ComputeMask(api, *Z, c.MaskCtx, j+1) // deref; int -> constant Variable
		if err != nil {
			return err
		}

		// R5: c_j = z_j + k_j (mod q)
		want := field.Add(&c.Zs[j], kV)
		field.AssertIsEqual(want, &c.Cpt[j])
	}
	return nil
}

type lengthMismatchErr struct{ got int }

func (e *lengthMismatchErr) Error() string {
	return "RdEl slice length mismatch (L != slice lengths)"
}

// compile-time assertion that RdEl satisfies the frontend.Circuit interface.
var _ frontend.Circuit = (*RdEl)(nil)