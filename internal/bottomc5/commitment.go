package bottomc5

import (
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"

	"c5full/internal/c5/host"
	"c5full/internal/c5/params"
)

func commitMakes(z, rho *big.Int) *secp256k1.G1Affine {
	return host.Pedersen(z, rho)
}

func NewWireR(f int, value *big.Int, rng io.Reader) *Wire {
	zc := make([]*big.Int, f+1)
	rc := make([]*big.Int, f+1)
	ac := make([]*secp256k1.G1Affine, f+1)
	zc[0] = modQ(value)
	for k := 0; k <= f; k++ {
		if k > 0 {
			zc[k] = randScalarR(rng, false)
		}
		rc[k] = randScalarR(rng, false)
		ac[k] = commitMakes(zc[k], rc[k])
	}
	return &Wire{Degree: f, ValCoeff: zc, BlindCoeff: rc, Commit: ac}
}

func addCommits(pts ...*secp256k1.G1Affine) *secp256k1.G1Affine {
	return host.AddPoints(pts...)
}

func EvalCom(A []*secp256k1.G1Affine, x *big.Int) *secp256k1.G1Affine {
	acc := new(secp256k1.G1Affine)
	pw := big.NewInt(1)
	for _, a := range A {
		term := host.ScalarMul(a, pw)
		acc = host.AddPoints(acc, term)
		pw.Mul(pw, x).Mod(pw, params.Q)
	}
	return acc
}

func CheckOpening(A []*secp256k1.G1Affine, xi, w, rho *big.Int) bool {
	left := EvalCom(A, xi)
	right := commitMakes(w, rho)
	return host.PointEqual(left, right)
}

func WireShareOf(w *Wire, xi *big.Int) (wVal, rhoVal *big.Int) {
	return polyEval(w.ValCoeff, xi), polyEval(w.BlindCoeff, xi)
}