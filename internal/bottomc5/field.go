package bottomc5

import (
	"crypto/rand"
	"io"
	"math/big"

	"c5full/internal/c5/params"
)

var fieldOrder *big.Int = new(big.Int).Set(params.Q)

func modQ(x *big.Int) *big.Int { return new(big.Int).Mod(x, params.Q) }

func addQ(a, b *big.Int) *big.Int { return modQ(new(big.Int).Add(a, b)) }
func subQ(a, b *big.Int) *big.Int { return modQ(new(big.Int).Sub(a, b)) }
func mulQ(a, b *big.Int) *big.Int { return modQ(new(big.Int).Mul(a, b)) }

func randScalarR(rng io.Reader, nonzero bool) *big.Int {
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

func randScalar(nonzero bool) *big.Int { return randScalarR(rand.Reader, nonzero) }

func polyEval(coeffs []*big.Int, x *big.Int) *big.Int {
	acc := new(big.Int)
	for i := len(coeffs) - 1; i >= 0; i-- {
		acc.Mul(acc, x)
		acc.Add(acc, coeffs[i])
		acc.Mod(acc, params.Q)
	}
	return acc
}

func lagrangeCoeff0(xs []*big.Int, i int) *big.Int {
	acc := big.NewInt(1)
	for l, xl := range xs {
		if l == i {
			continue
		}
		num := modQ(new(big.Int).Neg(xl))         // -x_l
		den := subQ(xs[i], xl)                    // x_i - x_l
		term := modQ(new(big.Int).Mul(num, new(big.Int).ModInverse(den, params.Q)))
		acc.Mul(acc, term)
		acc.Mod(acc, params.Q)
	}
	return acc
}

func interpolate0(xs, ys []*big.Int) *big.Int {
	acc := new(big.Int)
	for i := range ys {
		term := mulQ(ys[i], lagrangeCoeff0(xs, i))
		acc.Add(acc, term)
		acc.Mod(acc, params.Q)
	}
	return acc
}

func aggregateMul0(xs, ys []*big.Int) *big.Int { return interpolate0(xs, ys) }

func xiPoints(n int) []*big.Int {
	xs := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		xs[i] = big.NewInt(int64(i + 1))
	}
	return xs
}