package m1

// Shamir/Pedersen output-state scaffolding (AP3 M3-2). This builds a synthetic
// but valid committed-output state: for each output coordinate j a degree-f
// polynomial F_j over F_q (F_j(0)=z_j is the output value) plus a degree-f
// blinding polynomial B_j (B_j(0)=rho_j), with Pedersen coefficient commitments
// A_{j,k}=Pedersen(a_{j,k}, b_{j,k}). Evaluation at server point xi_i yields the
// server share [z_j]_i = (z_{i,j}, rho_{i,j}).
// All arithmetic is mod q (secp256k1 scalar field), reusing host Pedersen for
// commitments so the commitments are exactly the AP2-frozen group objects.

import (
	"crypto/rand"
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"

	"c5full/internal/c5/host"
	"c5full/internal/c5/params"
)

// randScalarM1R samples a uniform scalar in [0,q) from rng; nonzero selects F_q*.
func randScalarM1R(rng io.Reader, nonzero bool) *big.Int {
	for {
		b := make([]byte, 32)
		if _, err := io.ReadFull(rng, b); err != nil {
			panic(err)
		}
		x := new(big.Int).SetBytes(b)
		x.Mod(x, params.Q)
		if !nonzero || x.Sign() != 0 {
			return x
		}
	}
}

// randScalarM1 is the production default path: crypto/rand (LA-03 requirement:
// deterministic RNG is never the default).
func randScalarM1(nonzero bool) *big.Int {
	return randScalarM1R(rand.Reader, nonzero)
}

// polyEvalM1 evaluates coeffs (low-to-high) at x mod q (Horner).
func polyEvalM1(coeffs []*big.Int, x *big.Int) *big.Int {
	acc := new(big.Int)
	for i := len(coeffs) - 1; i >= 0; i-- {
		acc.Mul(acc, x)
		acc.Add(acc, coeffs[i])
		acc.Mod(acc, params.Q)
	}
	return acc
}

// shamirShare evaluates a degree-f polynomial at x mod q.
func shamirShare(coeffs []*big.Int, x *big.Int) *big.Int { return polyEvalM1(coeffs, x) }

// lagrangeCoeff computes the Lagrange basis lambda_i for interpolation at 0 over
// the distinct points xs (all in F_q*). lambda_i = prod_{l != i} (-x_l)/(x_i-x_l).
func lagrangeCoeff(xs []*big.Int, i int) *big.Int {
	acc := big.NewInt(1)
	q := params.Q
	for l, xl := range xs {
		if l == i {
			continue
		}
		// numerator: -x_l
		num := new(big.Int).Neg(xl)
		num.Mod(num, q)
		// denominator: x_i - x_l
		den := new(big.Int).Sub(xs[i], xl)
		den.Mod(den, q)
		inv := new(big.Int).ModInverse(den, q)
		if inv == nil {
			panic("m1: non-invertible Lagrange denominator (duplicate eval point?)")
		}
		acc.Mul(acc, num)
		acc.Mul(acc, inv)
		acc.Mod(acc, q)
	}
	return acc
}

// interpolate0 reconstructs the constant term F(0) from f+1 points (xs[i], ys[i]).
func interpolate0(xs []*big.Int, ys []*big.Int) *big.Int {
	sum := big.NewInt(0)
	for i := range xs {
		lambda := lagrangeCoeff(xs, i)
		term := new(big.Int).Mul(lambda, ys[i])
		sum.Add(sum, term)
		sum.Mod(sum, params.Q)
	}
	return sum
}

// OutputPoly is one output coordinate's degree-f value + blinding polynomial.
type OutputPoly struct {
	ZCoeff  []*big.Int                // a_{j,0..f}; a_{j,0} = z_j (output value)
	RhoCoeff []*big.Int               // b_{j,0..f}; b_{j,0} = rho_j
	Acoeff  []*secp256k1.G1Affine     // A_{j,k} = Pedersen(a_{j,k}, b_{j,k})
}

// NewOutputPoly builds a degree-f output polynomial with a random constant term
// (the output value) and random blinding, committing each coefficient.
func NewOutputPoly(f int) *OutputPoly {
	return NewOutputPolyR(f, rand.Reader)
}

// NewOutputPolyR is the RNG-injected variant for deterministic experiment
// fixtures. Using a reproducible rng makes A_j/joint-output commitments
func NewOutputPolyR(f int, rng io.Reader) *OutputPoly {
	zc := make([]*big.Int, f+1)
	rc := make([]*big.Int, f+1)
	ac := make([]*secp256k1.G1Affine, f+1)
	for k := 0; k <= f; k++ {
		zc[k] = randScalarM1R(rng, false)
		rc[k] = randScalarM1R(rng, false)
		ac[k] = host.Pedersen(zc[k], rc[k])
	}
	return &OutputPoly{ZCoeff: zc, RhoCoeff: rc, Acoeff: ac}
}

func NewOutputPolyFromCoeffs(zc, rc []*big.Int, ac []*secp256k1.G1Affine) *OutputPoly {
	if ac == nil {
		ac = make([]*secp256k1.G1Affine, len(zc))
		for k := range zc {
			ac[k] = host.Pedersen(zc[k], rc[k])
		}
	}
	return &OutputPoly{ZCoeff: zc, RhoCoeff: rc, Acoeff: ac}
}

// Value returns the output value z_j = F_j(0).
func (p *OutputPoly) Value() *big.Int { return new(big.Int).Set(p.ZCoeff[0]) }

// ShareAt returns (z_{i,j}, rho_{i,j}) = (F_j(xi), B_j(xi)) at evaluation point xi.
func (p *OutputPoly) ShareAt(xi *big.Int) (z, rho *big.Int) {
	return shamirShare(p.ZCoeff, xi), shamirShare(p.RhoCoeff, xi)
}

// ExpectedCommitment returns EvalCom(A_j, xi) = sum_k xi^k A_{j,k} = Pedersen(z,rho).
func (p *OutputPoly) ExpectedCommitment(xi *big.Int) *secp256k1.G1Affine {
	return EvalComM1(p.Acoeff, xi)
}

func EvalComM1(A []*secp256k1.G1Affine, x *big.Int) *secp256k1.G1Affine {
	acc := new(secp256k1.G1Affine)
	pw := big.NewInt(1)
	for _, a := range A {
		term := host.ScalarMul(a, pw)
		acc = host.AddPoints(acc, term)
		pw.Mul(pw, x).Mod(pw, params.Q)
	}
	return acc
}

// ReconstructionInput is a share point for reconstruction: (xi_i, z_{i,j}).
type ReconstructionInput struct {
	Xi *big.Int
	Z  *big.Int
}

// Reconstruct returns F(0) from f+1 distinct points (xs[i], zs[i]).
func Reconstruct(xs []*big.Int, zs []*big.Int) *big.Int { return interpolate0(xs, zs) }
