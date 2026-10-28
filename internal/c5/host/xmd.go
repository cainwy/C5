// Package host implements the C5 R_del semantic (host) layer in pure Go over
// secp256k1, mirroring the authoritative Python semantic M0 (ap2_m0/src/
// semantic_m0.py). It is used for:
//   - sender / receiver host computation (three-end DeriveMask consistency),
//   - canonical encoding + parsing tests,
//   - deterministic A_out -> C_i compiled statement,
//   - R1-R5 relation checks and proof-level negative test harness.
// Host arithmetic uses gnark-crypto secp256k1; it shares constants with
// internal/params and never mixes the BLS12-381 circuit field.
package host

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"

	"c5full/internal/c5/params"
)

// Errors represent distinct failure classes for the parser / verifier boundary.
var (
	ErrParse       = errors.New("parse error")
	ErrProfile     = errors.New("proof profile mismatch")
	ErrParamUnavail = errors.New("proof parameters unavailable")
)

func expand_message_xmd_sha256(msg, dst []byte, lenInBytes int) ([]byte, error) {
	if len(dst) > 255 {
		return nil, fmt.Errorf("%w: DST too long", ErrParse)
	}
	const bIn = 32
	const rIn = 64
	ell := (lenInBytes + bIn - 1) / bIn
	if ell > 255 || lenInBytes > 65535 {
		return nil, fmt.Errorf("%w: invalid expand length", ErrParse)
	}
	dstp := append(append([]byte{}, dst...), byte(len(dst)))
	linb := make([]byte, 2)
	binary.BigEndian.PutUint16(linb, uint16(lenInBytes))
	pad := make([]byte, rIn)
	// b0 = H(pad(64) || msg || I2OSP(len,2) || 0x00 || dstp)
	b0input := append(append(append(pad, msg...), linb...), 0x00)
	b0input = append(b0input, dstp...)
	b0 := sha256.Sum256(b0input)
	// b1 = H(b0 || 0x01 || dstp)
	b1input := append(append(b0[:], 0x01), dstp...)
	b1 := sha256.Sum256(b1input)
	out := make([]byte, 0, lenInBytes)
	out = append(out, b1[:]...)
	bi := b1
	for i := 2; i <= ell; i++ {
		xi := make([]byte, 0, 32)
		for j := 0; j < 32; j++ {
			xi = append(xi, b0[j]^bi[j])
		}
		xi = append(xi, byte(i))
		xi = append(xi, dstp...)
		bi = sha256.Sum256(xi)
		out = append(out, bi[:]...)
	}
	return out[:lenInBytes], nil
}

// DeriveMask computes k = OS2IP(XMD(SHA-256,Z||maskCtx||I2OSP(j,4),48)) mod Q.
func DeriveMask(Z *secp256k1.G1Affine, maskCtx []byte, j int) (*big.Int, error) {
	zb := EncodePoint(Z, false) // canonical SEC1; identity forbidden
	jidx := make([]byte, 4)
	binary.BigEndian.PutUint32(jidx, uint32(j))
	msg := append(append(append([]byte{}, zb...), maskCtx...), jidx...)
	tv, err := expand_message_xmd_sha256(msg, []byte(params.DSTDeliveryMask), 48)
	if err != nil {
		return nil, err
	}
	return new(big.Int).Mod(new(big.Int).SetBytes(tv), params.Q), nil
}