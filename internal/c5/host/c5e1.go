package host

// C5E1 canonical-encoding exports. These expose the AP2-frozen typed/ordered/
// length-delimited C5E1 tuple encoder and the frozen mask-context construction
// so the AP3 M1 layer reuses the *same* canonical byte representation instead of
// defining a second encoding (AP3-REVISE R2). The underlying helpers remain
// private; only the frozen entry points are widened.

import "github.com/consensys/gnark-crypto/ecc/secp256k1"

// EncodeC5E1 serializes a typed/ordered field list into the C5E1 tuple format
// (magic "C5E1", u16 field count, per-field: u8 tag length + tag + u32 value
// length + value). Duplicate tags, empty tags and over-long tags panic (parse
// contract violation).
func EncodeC5E1(fields [][2]string) []byte { return encTuple(fields) }

// U32Bytes encodes x as 4-byte big-endian (the C5E1 integer representation).
func U32Bytes(x int) []byte { return u32Bytes(x) }

// BuildMaskCtx constructs the canonical mask context (AP1 §9.3) with the frozen
// C5E1 encoding, byte-identical to SynthInstance's internal makeMaskCtx.
func BuildMaskCtx(taskCtx, alpha []byte, pkR *secp256k1.G1Affine, i, L int, relationID string) []byte {
	return makeMaskCtx(taskCtx, alpha, pkR, i, L, relationID)
}
