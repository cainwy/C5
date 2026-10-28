package host

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"

	"c5full/internal/c5/params"
)

// EncodePoint returns the SEC1 compressed encoding of an ordinary affine point.
// If allowIdentity and p is infinity, returns the single octet 0x00; otherwise
// an identity is a parse error here (callers choose the policy).
func EncodePoint(p *secp256k1.G1Affine, allowIdentity bool) []byte {
	if p.IsInfinity() {
		if allowIdentity {
			return []byte{0x00}
		}
		panic(ErrParse)
	}
	return compressPoint(p)
}

func EncodePointAllowInf(p *secp256k1.G1Affine) []byte {
	return EncodePoint(p, true)
}

func compressPoint(p *secp256k1.G1Affine) []byte {
	buf := make([]byte, 33)
	if p.Y.BigInt(new(big.Int)).Bit(0) == 1 {
		buf[0] = 0x03
	} else {
		buf[0] = 0x02
	}
	p.X.BigInt(new(big.Int)).FillBytes(buf[1:])
	return buf
}

// DecodePoint parses a SEC1 compressed point. If nonidentity and the octet is
// the identity marker 0x00, it errors.
func DecodePoint(b []byte, nonidentity bool) (*secp256k1.G1Affine, error) {
	if len(b) == 1 && b[0] == 0x00 {
		if nonidentity {
			return nil, ErrParse
		}
		return new(secp256k1.G1Affine), nil // identity
	}
	if len(b) != 33 || (b[0] != 0x02 && b[0] != 0x03) {
		return nil, ErrParse
	}
	x := new(big.Int).SetBytes(b[1:])
	if x.Cmp(params.P) >= 0 {
		return nil, ErrParse
	}
	var pt secp256k1.G1Affine
	pt.X.SetBigInt(x)
	// compute y = sqrt(x^3+7); set parity
	yy := new(big.Int).Exp(x, big.NewInt(3), params.P)
	yy.Add(yy, big.NewInt(7))
	yy.Mod(yy, params.P)
	y := new(big.Int).ModSqrt(yy, params.P)
	if y == nil {
		return nil, ErrParse
	}
	if (y.Bit(0) == 1) != (b[0]&1 == 1) {
		y.Sub(params.P, y)
	}
	pt.Y.SetBigInt(y)
	if !pt.IsOnCurve() || pt.IsInfinity() {
		return nil, ErrParse
	}
	return &pt, nil
}

// ScalarMulBase computes s*G (fixed-base scalar multiplication).
func ScalarMulBase(s *big.Int) *secp256k1.G1Affine {
	var out secp256k1.G1Affine
	out.ScalarMultiplication(&params.G, s)
	return &out
}

// ScalarMul computes s*A for a variable affine base A.
func ScalarMul(A *secp256k1.G1Affine, s *big.Int) *secp256k1.G1Affine {
	var out secp256k1.G1Affine
	out.ScalarMultiplication(A, s)
	return &out
}

// ScalarMulAffineBase computes s*Base where Base is a constant (J/G/H) base
// using the Jacobian Base operations (faster, constant point).
func ScalarMulAffineBase(s *big.Int, base *secp256k1.G1Affine) *secp256k1.G1Affine {
	return ScalarMul(base, s)
}

// AddPoints sums a list of affine points (any may be infinity).
func AddPoints(pts ...*secp256k1.G1Affine) *secp256k1.G1Affine {
	var accJ secp256k1.G1Jac
	// convert first non-infinity
	started := false
	for _, p := range pts {
		if p == nil || p.IsInfinity() {
			continue
		}
		if !started {
			accJ.FromAffine(p)
			started = true
		} else {
			var pj secp256k1.G1Jac
			pj.FromAffine(p)
			accJ.AddAssign(&pj)
		}
	}
	if !started {
		return new(secp256k1.G1Affine) // identity
	}
	var out secp256k1.G1Affine
	out.FromJacobian(&accJ)
	return &out
}

// Pedersen computes z*G + rho*H.
func Pedersen(z, rho *big.Int) *secp256k1.G1Affine {
	term1 := ScalarMul(&params.G, z)
	term2 := ScalarMul(&params.H, rho)
	return AddPoints(term1, term2)
}

// PointEqual reports whether two affine points encode the same group element.
func PointEqual(a, b *secp256k1.G1Affine) bool {
	if a.IsInfinity() || b.IsInfinity() {
		return a.IsInfinity() && b.IsInfinity()
	}
	return a.X.Equal(&b.X) && a.Y.Equal(&b.Y)
}