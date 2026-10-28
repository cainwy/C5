package params

import (
	"encoding/hex"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// compress returns the SEC1 compressed encoding of an ordinary affine point
// (0x02/0x03 prefix + 32-byte big-endian x). The point must not be infinity.
func compress(pt *secp256k1.G1Affine) []byte {
	if pt.IsInfinity() {
		panic("compress: infinity not encodable for H")
	}
	buf := make([]byte, 33)
	if pt.Y.BigInt(new(big.Int)).Bit(0) == 1 {
		buf[0] = 0x03
	} else {
		buf[0] = 0x02
	}
	pt.X.BigInt(new(big.Int)).FillBytes(buf[1:])
	return buf
}