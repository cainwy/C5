// Package basic implements M3 (plan) / M2 (execution) base proof circuits:
// scalar representation & non-zero & range, fixed-base scalar mult R=[s]G,
// variable-base scalar mult Z=[s]PK_R, and Pedersen opening C=[z]G+[rho]H
// using gnark emulated secp256k1 arithmetic over the BLS12-381 scalar field.
// These are small isolation circuits for correctness debugging; they do NOT
// replace the full R_del circuit.
package basic

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// ---------------------------------------------------------------------------
// M3.1 scalar representation, non-zero and range
// ---------------------------------------------------------------------------

// ScalarNonZeroRange asserts a secret secp256k1 scalar s is canonical (reduced
// mod q, i.e. strictly less than q with no overflow) and s != 0. This is the
// scalar-side of "s_i != 0" and canonical z/rho range checks.
type ScalarNonZeroRange[S emulated.FieldParams] struct {
	S emulated.Element[S] // secret scalar (witness)
}

// Define constrains s into range and s != 0.
func (c *ScalarNonZeroRange[S]) Define(api frontend.API) error {
	field, err := emulated.NewField[S](api)
	if err != nil {
		return err
	}
	// Assert canonicality: value must be in [0, q). emulated.Element already
	// limits to the native-circuit bit width, but we additionally bound to the
	// logical secp256k1 scalar modulus q to forbid non-canonical encodings.
	field.AssertIsInRange(&c.S)
	// Assert s != 0.
	field.AssertIsDifferent(&c.S, field.NewElement(0))
	return nil
}

// ---------------------------------------------------------------------------
// M3.2 fixed-base scalar multiplication  R = [s]G
// ---------------------------------------------------------------------------

// FixedBaseMulBase proves R = [s]G. s is secret; R is public.
type FixedBaseMulBase[Base, Scalar emulated.FieldParams] struct {
	S emulated.Element[Scalar]      // secret scalar (witness)
	R sw_emulated.AffinePoint[Base] `gnark:",public"` // public result point
}

// Define constrains R == [s]G and s != 0.
func (c *FixedBaseMulBase[B, Sc]) Define(api frontend.API) error {
	curve, err := sw_emulated.New[B, Sc](api, sw_emulated.GetCurveParams[emulated.Secp256k1Fp]())
	if err != nil {
		return err
	}
	field, err := emulated.NewField[Sc](api)
	if err != nil {
		return err
	}
	field.AssertIsInRange(&c.S)
	field.AssertIsDifferent(&c.S, field.NewElement(0))
	computed := curve.ScalarMulBase(&c.S) // [s]G
	curve.AssertIsEqual(computed, &c.R)
	curve.AssertIsOnCurve(&c.R)
	return nil
}

// ---------------------------------------------------------------------------
// M3.3 variable-base scalar multiplication  Z = [s]PK_R
// ---------------------------------------------------------------------------

// VarBaseMulBase proves Z = [s]PK_R. PK_R is public (receiver key), s is
// secret, Z is public.
type VarBaseMulBase[Base, Scalar emulated.FieldParams] struct {
	PKR sw_emulated.AffinePoint[Base] `gnark:",public"` // variable base (public)
	Z   sw_emulated.AffinePoint[Base] `gnark:",public"` // public result
	S   emulated.Element[Scalar]                        // secret scalar (witness)
}

// Define constrains Z == [s]PK_R and s != 0.
func (c *VarBaseMulBase[B, Sc]) Define(api frontend.API) error {
	curve, err := sw_emulated.New[B, Sc](api, sw_emulated.GetCurveParams[emulated.Secp256k1Fp]())
	if err != nil {
		return err
	}
	field, err := emulated.NewField[Sc](api)
	if err != nil {
		return err
	}
	field.AssertIsInRange(&c.S)
	field.AssertIsDifferent(&c.S, field.NewElement(0))
	curve.AssertIsOnCurve(&c.PKR)
	computed := curve.ScalarMul(&c.PKR, &c.S) // [s]PK_R
	curve.AssertIsEqual(computed, &c.Z)
	curve.AssertIsOnCurve(&c.Z)
	return nil
}

// ---------------------------------------------------------------------------
// M3.4 Pedersen opening  C = [z]G + [rho]H
// ---------------------------------------------------------------------------

// PedersenBase proves C = [z]G + [rho]H over the production Pedersen group
// (G generator, H the frozen derived second generator). H is injected as a
// circuit constant at compile time so prover cannot choose its own H.
// It is concrete on secp256k1 base/scalar fields because H is itself a
// secp256k1 point (not a type parameter).
type PedersenBase struct {
	Z   emulated.Element[emulated.Secp256k1Fr]      // secret z (witness)
	Rho emulated.Element[emulated.Secp256k1Fr]      // secret rho (witness)
	C   sw_emulated.AffinePoint[emulated.Secp256k1Fp] `gnark:",public"` // public opening point
}

// Define constrains C == [z]G + [rho]H.
func (c *PedersenBase) Define(api frontend.API) error {
	curve, err := sw_emulated.New[emulated.Secp256k1Fp, emulated.Secp256k1Fr](api, sw_emulated.GetCurveParams[emulated.Secp256k1Fp]())
	if err != nil {
		return err
	}
	field, err := emulated.NewField[emulated.Secp256k1Fr](api)
	if err != nil {
		return err
	}
	// Both z and rho are field elements; canonical range check.
	field.AssertIsInRange(&c.Z)
	field.AssertIsInRange(&c.Rho)
	term1 := curve.ScalarMulBase(&c.Z)        // [z]G
	term2 := curve.ScalarMul(&Hpoint, &c.Rho) // [rho]H
	summed := curve.AddUnified(term1, term2)  // [z]G + [rho]H
	curve.AssertIsEqual(summed, &c.C)
	curve.AssertIsOnCurve(&c.C)
	return nil
}