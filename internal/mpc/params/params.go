// Package params pins the scalar arithmetic domain and the Lifted-ElGamal /
// Pedersen group for the complete-MPC implementation (faithful to Scheme A,
// Gai et al. TDSC 2025, with the multiplication-triple production/dispatch
// contradiction repaired).
// Number-theoretic layout (as in the paper):
//   - GMOD : a 256-bit prime scalar domain used for VSS shares, Beaver-triple
//            arithmetic and output shares. All "secret values" live in Z_GMOD.
//   - Lifted ElGamal / Pedersen group: schemea sets up Z_P^* with generators
//            (P,g,h). Commitments are C(m,r)=g^m·h^r mod P over the group; the
//            scalar domain GMOD is far smaller than the group, so exponents
//            never overflow the group order.
package params

import "math/big"

// GMOD is a 256-bit prime scalar domain (F_GMOD) for shares/triples. It is also
// the *order* of the underlying commitment group: the group modulus used by
// schemea is P = 2·GMOD+1 (a safe prime), and the working subgroup has order
// GMOD, so every scalar exponent reduces mod GMOD and the commitment algebra is
// self-consistent with the share arithmetic.
var GMOD = new(big.Int).SetBytes(mustHex(
	"a0513c0b45c8d552cbcd92085a2f580e887a227e878e4c2fa18f826e99a36523"))

// Default bit widths (paper example: k=256-bit output share split into p=32-bit
// chunks with Lifted ElGamal bounded-DLOG recovery).
const (
	ShareBits    = 256 // k : output-share bit width
	ChunkBits    = 32  // p : partition width
	DefaultThresh = 2  // t : number of shares needed to reconstruct (f+1)
)

func mustHex(s string) []byte {
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		out[i] = hexNibble(s[2*i])<<4 | hexNibble(s[2*i+1])
	}
	return out
}

func hexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

func Mod(x *big.Int) *big.Int { return new(big.Int).Mod(x, GMOD) }