package host

import (
	"math/big"

	"c5full/internal/c5/params"
)

// EncodeScalar encodes a field element in F_q as 32-byte big-endian.
func EncodeScalar(x *big.Int) ([]byte, error) {
	if x.Sign() < 0 || x.Cmp(params.Q) >= 0 {
		return nil, ErrParse
	}
	b := x.Bytes()
	if len(b) > 32 {
		return nil, ErrParse
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out, nil
}

// DecodeScalar parses a 32-byte big-endian field element; rejects non-canonical.
func DecodeScalar(b []byte) (*big.Int, error) {
	if len(b) != 32 {
		return nil, ErrParse
	}
	x := new(big.Int).SetBytes(b)
	if x.Cmp(params.Q) >= 0 {
		return nil, ErrParse
	}
	return x, nil
}