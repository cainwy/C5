package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"

	"c5full/internal/c5/basic"
	"c5full/internal/c5/derive"
)

// RdElDirect is the full R_del circuit in Direct-Aout mode: it receives the
// AUTHORITATIVE A_out coefficients (each row = f+1 public points) and xi, and
// computes C_{i,j} = EvalCom(Aout[j], xi) IN-CIRCUIT (R2 moved from the outer
// compiler into the circuit). It then enforces R3/R4/R5 exactly as Compiled-C.
// This is the ablation variant: same logical relation, different physical
// interface. Because each EvalCom multiplies a variable public point by a
// power of xi (variable-base scalar mult), the constraint cost is much higher
type RdElDirect struct {
	F int    // degree = number of A_out coefficient points minus 1 (compile-time)

	// public / authoritative
	Aout [][]sw_emulated.AffinePoint[emulated.Secp256k1Fp] `gnark:",public"` // L rows x (f+1)
	Xi   emulated.Element[emulated.Secp256k1Fr]            `gnark:",public"`
	PKR  sw_emulated.AffinePoint[emulated.Secp256k1Fp]     `gnark:",public"`
	R    sw_emulated.AffinePoint[emulated.Secp256k1Fp]     `gnark:",public"`
	Cpt  []emulated.Element[emulated.Secp256k1Fr]          `gnark:",public"` // c_j
	MaskCtx []uints.U8                                    `gnark:",public"`

	// secret witnesses
	S    emulated.Element[emulated.Secp256k1Fr]
	Zs   []emulated.Element[emulated.Secp256k1Fr]
	Rhos []emulated.Element[emulated.Secp256k1Fr]
}

func (c *RdElDirect) Define(api frontend.API) error {
	L := len(c.Aout)
	if L == 0 || c.F < 0 || len(c.Aout[0]) != c.F+1 {
		return &directLenErr{}
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

	// R1
	field.AssertIsInRange(&c.S)
	field.AssertIsDifferent(&c.S, field.NewElement(0))
	curve.AssertIsOnCurve(&c.PKR)
	curve.AssertIsOnCurve(&c.R)
	R := curve.ScalarMulBase(&c.S)
	curve.AssertIsEqual(R, &c.R)
	Z := curve.ScalarMul(&c.PKR, &c.S)
	curve.AssertIsOnCurve(Z)

	for j := 0; j < L; j++ {
		// R2 in-circuit: C_j = EvalCom(Aout[j], xi) = sum_k xi^k * Aout[j][k]
		field.AssertIsInRange(&c.Zs[j])
		field.AssertIsInRange(&c.Rhos[j])
		var Cj *sw_emulated.AffinePoint[emulated.Secp256k1Fp]
		pw := field.NewElement(1)
		for k := 0; k <= c.F; k++ {
			curve.AssertIsOnCurve(&c.Aout[j][k])
			if k == 0 {
				Cj = curve.ScalarMul(&c.Aout[j][k], pw)
			} else {
				term := curve.ScalarMul(&c.Aout[j][k], pw)
				Cj = curve.AddUnified(Cj, term)
			}
			pw = field.Mul(pw, &c.Xi)
		}
		// R3: C_j = [z_j]G + [rho_j]H
		t1 := curve.ScalarMulBase(&c.Zs[j])
		t2 := curve.ScalarMul(&basic.Hpoint, &c.Rhos[j])
		ped := curve.AddUnified(t1, t2)
		curve.AssertIsEqual(Cj, ped)

		// R4 + R5
		kV, err := derive.ComputeMask(api, *Z, c.MaskCtx, j+1)
		if err != nil {
			return err
		}
		want := field.Add(&c.Zs[j], kV)
		field.AssertIsEqual(want, &c.Cpt[j])
	}
	return nil
}

type directLenErr struct{}

func (e *directLenErr) Error() string { return "RdElDirect bad Aout/F shape" }

var _ frontend.Circuit = (*RdElDirect)(nil)