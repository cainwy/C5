// Package params pins the C5-AP2 concrete cryptographic profile: logical
// field, delivery/Pedersen group, generators, domain-separation tags and the
// production second generator H derivation.
// Host-side arithmetic reuses gnark-crypto secp256k1 (native, well-tested).
// The circuit field is BLS12-381 scalar; the C5 logical field stays secp256k1
// scalar field F_q and is emulated inside circuits (no native-field coercion).
package params

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
)

// Logical field / group modulus.
var (
	// P: secp256k1 base field modulus (y^2 = x^3 + 7 over Fp).
	P = new(big.Int).SetBytes(mustHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"))
	// Q: secp256k1 scalar field modulus = prime-order of the group.
	Q = new(big.Int).SetBytes(mustHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"))
)

const (
	DSTStateID       = "C5/STATE-ID/v1"
	DSTReceiverPOP   = "C5/RECEIVER-POP/v1"
	DSTOutEndorse    = "C5/OUT-ENDORSE/v1"
	DSTDeliveryMask  = "C5-DEL-MASK-v1"
	DSTDeliveryProof = "C5/DEL-PROOF/v1"
	DSTDeliverySig   = "C5/DEL-SIG/v1"
	DSTCertEnc       = "C5/CERT-ENC/v1"
	DSTFinalityRef   = "C5/FINALITY-REF/v1"
)

// H derivation profile. protocol-specific, deterministic, RFC-9380-compatible
// hash-to-curve using gnark-crypto's secp256k1.HashToG1.
const (
	G2Label = "C5/PEDERSEN-H/v1" // free-form message fed into hash-to-curve
	HDST   = "C5-PEDERSEN-H-DST-v1"
)

var (
	// G is the standard secp256k1 generator.
	G secp256k1.G1Affine
	// GJac is the Jacobian form of G (used for repeated scalar mults).
	GJac secp256k1.G1Jac
	// H is the production Pedersen second generator.
	H secp256k1.G1Affine
	// Hbytes is the SEC1-compressed encoding of H (33 bytes).
	Hbytes []byte
	// Hdigest is SHA-256 over the H derivation transcript (for provenance).
	Hdigest [32]byte
)

func init() {
	GJac, G = secp256k1.Generators()
	H = deriveH()
	Hbytes = compress(&H)
	h := sha256.New()
	h.Write([]byte(G2Label))
	h.Write([]byte{0x00})
	h.Write([]byte(HDST))
	h.Write(Hbytes)
	copy(Hdigest[:], h.Sum(nil))
}

// deriveH deterministically maps a fixed protocol label to a secp256k1 point
// using RFC-9380-compatible hash-to-curve. It is NOT the identity and its
// discrete log w.r.t. G is not chosen by us.
func deriveH() secp256k1.G1Affine {
	pt, err := secp256k1.HashToG1([]byte(G2Label), []byte(HDST))
	if err != nil {
		panic(fmt.Sprintf("derive H: %v", err))
	}
	if pt.IsInfinity() || !pt.IsOnCurve() {
		panic("derived H is invalid")
	}
	return pt
}

// Scalar helpers.
func ScalarMod(x *big.Int) *big.Int { return new(big.Int).Mod(x, Q) }

// ProfileJSON is written to profile/crypto_profile.json after H is fixed.
func ProfileJSON() ([]byte, error) {
	src := srcProfile{}
	return json.MarshalIndent(src, "", "  ")
}

type srcProfile struct {
	ProfileID             string `json:"profile_id"`
	Status                string `json:"status"`
	ProtocolSemanticVer   int    `json:"protocol_semantic_version"`
	LogicalField          string `json:"logical_field"`
	QHex                  string `json:"q_hex"`
	Group                 string `json:"delivery_and_pedersen_group"`
	GEncoding             string `json:"G_encoding"`
	HLabel                string `json:"H_label"`
	HDST                  string `json:"H_dst"`
	HCompressedHex        string `json:"H_compressed_point_hex"`
	HDigestHex            string `json:"H_derivation_digest_hex"`
	ProofCandidateMain    string `json:"proof_candidate_main"`
	ProofCandidateBackup  string `json:"proof_candidate_backup"`
	CircuitFieldModulus   string `json:"circuit_field_modulus_hex"`
	GoRequired           string `json:"go_required"`
	GnarkVersion          string `json:"proof_library_tag"`
	GnarkCommit           string `json:"proof_library_commit"`
	GnarkCrypto           string `json:"gnark_crypto"`
}

// BuildProfile assembles the machine-readable profile (H frozen).
func BuildProfile(circuitFieldModulus *big.Int) (*srcProfile, error) {
	return &srcProfile{
		ProfileID:            "C5-AP2-M0-secp256k1-xmdsha256-gnark-g16-bls381-v1.1",
		Status:               "circuit_frozen_pending_evidence",
		ProtocolSemanticVer:  1,
		LogicalField:         "secp256k1 scalar field F_q",
		QHex:                 fmt.Sprintf("%x", Q),
		Group:                "secp256k1 prime-order group, cofactor 1",
		GEncoding:            "SEC1 compressed; ordinary point 33 bytes",
		HLabel:               G2Label,
		HDST:                 HDST,
		HCompressedHex:       fmt.Sprintf("%x", Hbytes),
		HDigestHex:           fmt.Sprintf("%x", Hdigest),
		ProofCandidateMain:   "gnark v0.15.0 / Groth16 / BLS12-381",
		ProofCandidateBackup: "gnark v0.15.0 / PLONK-KZG / BLS12-381",
		CircuitFieldModulus:  fmt.Sprintf("%x", circuitFieldModulus),
		GoRequired:           "1.25.7",
		GnarkVersion:         "v0.15.0",
		GnarkCommit:          "18368a5619e783f349b4aabb8277064495b6a473",
		GnarkCrypto:          "v0.20.1",
	}, nil
}

// fr modulus helper
func _frMod() *big.Int { return fr.Modulus() }

var _ = _frMod