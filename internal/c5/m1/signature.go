package m1

// Signature scaffolding (AP3 M3-2): server endorsement/delivery signatures use
// Ed25519 (frozen in the AP2 profile as "outside R_del M0 circuit", EUF-CMA per
// CR3); the receiver proof-of-possession uses Schnorr over secp256k1 (frozen in
// C5_Paper_v2_2 eq. zkp-of-xr), both with domain-separated transcripts.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"

	"c5full/internal/c5/host"
	"c5full/internal/c5/params"
)

// ---- Ed25519 server signatures -------------------------------------------

// NewServerKey generates an Ed25519 keypair for a server (crypto/rand default).
func NewServerKey() (priv ed25519.PrivateKey, pub ed25519.PublicKey, err error) {
	return NewServerKeyWithRNG(rand.Reader)
}

// NewServerKeyWithRNG is the deterministic-fixture variant (LA-03).
func NewServerKeyWithRNG(rng io.Reader) (priv ed25519.PrivateKey, pub ed25519.PublicKey, err error) {
	pub, priv, err = ed25519.GenerateKey(rng)
	return priv, pub, err
}

// signTranscript signs the canonical transcript with the given DST prefix.
func signTranscript(priv ed25519.PrivateKey, dst string, parts ...[]byte) []byte {
	msg := make([]byte, 0, 64+len(dst))
	msg = append(msg, dst...)
	msg = append(msg, 0x00)
	for _, p := range parts {
		msg = append(msg, u32LE(len(p))...)
		msg = append(msg, p...)
	}
	return ed25519.Sign(priv, msg)
}

// verifyTranscript verifies a server signature over the canonical transcript.
func verifyTranscript(pub ed25519.PublicKey, dst string, sig []byte, parts ...[]byte) bool {
	msg := make([]byte, 0, 64+len(dst))
	msg = append(msg, dst...)
	msg = append(msg, 0x00)
	for _, p := range parts {
		msg = append(msg, u32LE(len(p))...)
		msg = append(msg, p...)
	}
	return ed25519.Verify(pub, msg, sig)
}

// u32LE writes a little-endian u32 length prefix (deterministic framing).
func u32LE(n int) []byte {
	b := make([]byte, 4)
	b[0] = byte(n)
	b[1] = byte(n >> 8)
	b[2] = byte(n >> 16)
	b[3] = byte(n >> 24)
	return b
}

// ---- Receiver Schnorr proof-of-possession (PoP) ---------------------------

// PoP is the receiver proof of possession pi_R^key = (T_R, u_R).
type PoP struct {
	T *secp256k1.G1Affine // a_R G
	U *big.Int            // a_R + e_R x_R mod q
}

// PopChallenge computes e_R = H(DST || tau || PK_R || T_R) mod q (Fiat-Shamir).
func PopChallenge(tau []byte, pkR *secp256k1.G1Affine, tR *secp256k1.G1Affine) *big.Int {
	h := sha256.New()
	h.Write([]byte(params.DSTReceiverPOP))
	h.Write([]byte{0x00})
	h.Write(u32LE(len(tau)))
	h.Write(tau)
	pk := host.EncodePoint(pkR, false)
	h.Write(u32LE(len(pk)))
	h.Write(pk)
	tt := host.EncodePoint(tR, false)
	h.Write(u32LE(len(tt)))
	h.Write(tt)
	return new(big.Int).Mod(new(big.Int).SetBytes(h.Sum(nil)), params.Q)
}

// MakePoP builds a Schnorr PoP for private key xR and task transcript tau
// (crypto/rand default).
func MakePoP(xR *big.Int, tau []byte) (*PoP, *secp256k1.G1Affine) {
	return MakePoPWithRNG(xR, tau, rand.Reader)
}

// MakePoPWithRNG is the deterministic-fixture variant (LA-03).
func MakePoPWithRNG(xR *big.Int, tau []byte, rng io.Reader) (*PoP, *secp256k1.G1Affine) {
	a := randScalarM1R(rng, true)
	tR := host.ScalarMulBase(a)
	pkR := host.ScalarMulBase(xR)
	e := PopChallenge(tau, pkR, tR)
	u := new(big.Int).Mul(e, xR)
	u.Add(u, a)
	u.Mod(u, params.Q)
	return &PoP{T: tR, U: u}, pkR
}

// VerifyPoP verifies u_R G == T_R + e_R PK_R.
func VerifyPoP(tau []byte, pkR *secp256k1.G1Affine, pop *PoP) bool {
	if pop == nil || pop.T == nil || pop.T.IsInfinity() {
		return false
	}
	e := PopChallenge(tau, pkR, pop.T)
	// left = u_R G
	left := host.ScalarMulBase(pop.U)
	// right = T_R + e_R PK_R
	right := host.AddPoints(pop.T, host.ScalarMul(pkR, e))
	return host.PointEqual(left, right)
}
