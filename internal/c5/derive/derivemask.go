// Package derive closes the M3/M4 DeriveMask three-end consistency: it
// inside a gnark circuit, so the value enforced by the proof is byte-for-byte
// identical to the host (sender/receiver) computation in internal/host.
// The host hashes the SEC1 *compressed* encoding of Z (33 bytes: a 0x02/0x03
// prefix followed by the 32-byte big-endian x-coordinate). gnark's
// reconstructs the compressed prefix from the y parity bit itself to stay
// wire-compatible with the host.
package derive

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/expand"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"

	"c5full/internal/c5/params"
)

// Derivemask enforces K == DeriveMask(Z, MaskCtx, J) over the frozen profile.
//   - Z       : witness, the shared point on secp256k1 (emulated).
//   - MaskCtx : witness bytes, fixed compile-time length = c.MaskCtxLen.
//   - J       : witness, the 1-based output index j (0<j<=2^32-1). It is
//     serialized as I2OSP(J,4) big-endian, matching host.DeriveMask.
//   - K       : public, the claimed mask reduced mod q.
// MaskCtxLen is a compile-time constant (number of mask bytes); it is ignored
// by the witness schema (plain int field).
type Derivemask struct {
	MaskCtxLen int
	Z          sw_emulated.AffinePoint[emulated.Secp256k1Fp]
	MaskCtx    []uints.U8
	J          frontend.Variable
	K          emulated.Element[emulated.Secp256k1Fr] `gnark:",public"`
}

// Define assembles the XMD(SHA-256) message and enforces K.
func (c *Derivemask) Define(api frontend.API) error {
	k, err := ComputeMask(api, c.Z, c.MaskCtx, c.J)
	if err != nil {
		return err
	}
	field, err := emulated.NewField[emulated.Secp256k1Fr](api)
	if err != nil {
		return err
	}
	field.AssertIsEqual(k, &c.K)
	return nil
}

// as an emulated secp256k1 scalar element. It is the reusable core shared by
// the DeriveMask isolation circuit and the full R_del inner circuit, so both
// enforce the exact same F_q element as the host (sender/receiver).
func ComputeMask(api frontend.API, Z sw_emulated.AffinePoint[emulated.Secp256k1Fp], maskCtx []uints.U8, j frontend.Variable) (*emulated.Element[emulated.Secp256k1Fr], error) {
	field, err := emulated.NewField[emulated.Secp256k1Fr](api)
	if err != nil {
		return nil, err
	}
	// fresh byte API for building U8 values from bits
	uapi, err := uints.NewBytes(api)
	if err != nil {
		return nil, err
	}
	// curve API over BLS12-381 native field for secp256k1 emulation
	curve, err := sw_emulated.New[emulated.Secp256k1Fp, emulated.Secp256k1Fr](api,
		sw_emulated.GetCurveParams[emulated.Secp256k1Fp]())
	if err != nil {
		return nil, err
	}
	curve.AssertIsOnCurve(&Z)

	// --- canonical compressed Z (33 bytes) -------------------------------
	// MarshalG1 gives uncompressed x (bits 0..255) then y (bits 256..511),
	// each big-endian (MSB first).
	m := curve.MarshalG1(Z)
	const xNB = 256    // secp256k1 coordinate bit width
	bytes := make([]uints.U8, 64)
	for k := 0; k < 64; k++ {
		// group m[8k..8k+7] is big-endian within the byte, so reverse to
		// little-endian before FromBinary.
		le := []frontend.Variable{
			m[8*k+7], m[8*k+6], m[8*k+5], m[8*k+4],
			m[8*k+3], m[8*k+2], m[8*k+1], m[8*k],
		}
		bv := bits.FromBinary(api, le)
		bytes[k] = uapi.ValueOf(bv)
	}
	// y parity: bit 511 is the LSB of y in the big-endian concatenation.
	yParity := m[511]
	// SEC1 compressed prefix = 0x02 + parity (2 for even y, 3 for odd y).
	prefix := uapi.ValueOf(api.Add(2, yParity))

	// --- I2OSP(J,4) big-endian bytes ------------------------------------
	jbits := bits.ToBinary(api, j, bits.WithNbDigits(32)) // little-endian
	j0 := uapi.ValueOf(bits.FromBinary(api, jbits[24:32]))  // MSB byte
	j1 := uapi.ValueOf(bits.FromBinary(api, jbits[16:24]))
	j2 := uapi.ValueOf(bits.FromBinary(api, jbits[8:16]))
	j3 := uapi.ValueOf(bits.FromBinary(api, jbits[0:8]))    // LSB byte

	msg := make([]uints.U8, 0, 1+xNB/8+len(maskCtx)+4)
	msg = append(msg, prefix)
	msg = append(msg, bytes[:xNB/8]...)
	msg = append(msg, maskCtx...)
	msg = append(msg, j0, j1, j2, j3)

	// --- XMD(SHA-256, msg, DSTDeliveryMask, 48) -------------------------
	out, err := expand.ExpandMsgXmd(api, msg, []byte(params.DSTDeliveryMask), 48)
	if err != nil {
		return nil, err
	}

	// --- OS2IP(48 bytes) mod q by Horner evaluation ----------------------
	acc := field.NewElement(0)
	const256 := field.NewElement(256)
	for i := 0; i < 48; i++ {
		// bring the tiny (<256) output byte into the emulated field through
		// its 8 little-endian bits (ValueOf only accepts constants/witness).
		byteBits := bits.ToBinary(api, out[i].Val, bits.WithNbDigits(8))
		fe := field.FromBits(byteBits...)
		acc = field.Mul(acc, const256)
		acc = field.Add(acc, fe)
	}
	return acc, nil
}