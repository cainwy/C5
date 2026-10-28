package host

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"

	"c5full/internal/c5/params"
)

func mustInstance(t *testing.T, L, f, seed, i, n int) *Instance {
	t.Helper()
	inst, err := SynthInstance(L, f, seed, i, n)
	if err != nil {
		t.Fatalf("SynthInstance: %v", err)
	}
	return inst
}

func TestSemanticBaseline(t *testing.T) {
	base := mustInstance(t, 3, 2, 20260822, 1, 0)

	// honest
	if ok, err := base.RelationCheck("", true); err != nil || !ok {
		t.Fatalf("honest relation failed: ok=%v err=%v", ok, err)
	}
	if !base.ReceiverCheck() {
		t.Fatalf("receiver shared-secret check failed")
	}

	// wrong s
	bad := base.Clone()
	bad.S = new(big.Int).Add(bad.S, big.NewInt(1)).Mod(new(big.Int), params.Q)
	if ok, _ := bad.RelationCheck("", true); ok {
		t.Fatalf("wrong s accepted")
	}
	// wrong R
	bad = base.Clone()
	bad.R = &params.G
	if ok, _ := bad.RelationCheck("", true); ok {
		t.Fatalf("wrong R accepted")
	}
	// wrong z[0]
	bad = base.Clone()
	bad.Zlist = append([]*big.Int{}, bad.Zlist...)
	bad.Zlist[0] = new(big.Int).Add(bad.Zlist[0], big.NewInt(1)).Mod(new(big.Int), params.Q)
	if ok, _ := bad.RelationCheck("", true); ok {
		t.Fatalf("wrong z accepted")
	}
	// wrong rho[0]
	bad = base.Clone()
	bad.Rholist = append([]*big.Int{}, bad.Rholist...)
	bad.Rholist[0] = new(big.Int).Add(bad.Rholist[0], big.NewInt(1)).Mod(new(big.Int), params.Q)
	if ok, _ := bad.RelationCheck("", true); ok {
		t.Fatalf("wrong rho accepted")
	}
	// wrong ciphertext c[0]
	bad = base.Clone()
	bad.Clist = append([]*big.Int{}, bad.Clist...)
	bad.Clist[0] = new(big.Int).Add(bad.Clist[0], big.NewInt(1)).Mod(new(big.Int), params.Q)
	if ok, _ := bad.RelationCheck("", true); ok {
		t.Fatalf("wrong ciphertext accepted")
	}
	// wrong authoritative commitment A_out[0][0]
	bad = base.Clone()
	row := append([]*secp256k1.G1Affine{}, bad.Aout[0]...)
	row[0] = AddPoints(row[0], &params.G)
	bad.Aout = [][]*secp256k1.G1Affine{bad.Aout[0], bad.Aout[1], bad.Aout[2]}
	bad.Aout[0] = row
	if ok, _ := bad.RelationCheck("", true); ok {
		t.Fatalf("wrong A_out accepted")
	}
	// wrong receiver key (mask/ciphertext derived under original key)
	bad = base.Clone()
	bad.PKR = ScalarMul(&params.G, big.NewInt(2))
	if ok, _ := bad.RelationCheck("", true); ok {
		t.Fatalf("wrong receiver key accepted")
	}
	// wrong server index / xi
	bad = base.Clone()
	bad.I = 2
	bad.Xi = big.NewInt(2)
	if ok, _ := bad.RelationCheck("", true); ok {
		t.Fatalf("wrong server index accepted")
	}
	// profile mismatch -> distinct error class
	if _, err := base.RelationCheck("other-profile", true); err != ErrProfile {
		t.Fatalf("profile mismatch not classified: %v", err)
	}
	// params unavailable -> distinct error class
	if _, err := base.RelationCheck("", false); err != ErrParamUnavail {
		t.Fatalf("params unavailable not classified: %v", err)
	}
}

func TestParserValidation(t *testing.T) {
	// 32-byte value >= Q rejected
	qb := params.Q.Bytes()
	if _, err := DecodeScalar(append(make([]byte, 32-len(qb)), qb...)); err != ErrParse {
		t.Fatalf("out-of-range field element not rejected: %v", err)
	}
	// invalid compressed prefix rejected
	if _, err := DecodePoint(make([]byte, 33), true); err != ErrParse {
		t.Fatalf("invalid prefix not rejected: %v", err)
	}
	// identity R forbidden
	if func() (err error) {
		defer func() { if r := recover(); r != nil { err = ErrParse } }()
		EncodePoint(new(secp256k1.G1Affine), false) // identity, nonidentity policy
		return nil
	}() != ErrParse {
		t.Fatalf("identity R not forbidden")
	}
	// identity commitment allowed in A_out
	if got := EncodePoint(new(secp256k1.G1Affine), true); len(got) != 1 || got[0] != 0x00 {
		t.Fatalf("identity A_out encoding wrong")
	}
	if _, err := DecodePoint([]byte{0x00}, false); err != nil {
		t.Fatalf("identity A_out decode failed: %v", err)
	}
	// on-curve roundtrip of a real point
	pt := ScalarMul(&params.G, big.NewInt(12345))
	d, err := DecodePoint(EncodePoint(pt, false), true)
	if err != nil {
		t.Fatalf("point roundtrip failed: %v", err)
	}
	if !PointEqual(d, pt) {
		t.Fatalf("point roundtrip mismatch")
	}
}

func TestRFC9380XMDVector(t *testing.T) {
	// RFC 9380 Appendix K.1 expand_message_xmd(SHA-256), msg="abc", 128 bytes.
	want := "abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a647e6c3163d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40"
	out, err := expand_message_xmd_sha256([]byte("abc"), []byte("QUUX-V01-CS02-with-expander-SHA256-128"), 128)
	if err != nil {
		t.Fatalf("xmd: %v", err)
	}
	if hex.EncodeToString(out) != want {
		t.Fatalf("XMD vector mismatch")
	}
}

func TestCompiledDeterminism(t *testing.T) {
	inst := mustInstance(t, 2, 1, 7, 1, 0)
	a := inst.CompiledStatement()
	b := mustInstance(t, 2, 1, 7, 1, 0)
	c := b.CompiledStatement()
	// same seed => identical authoritative state => identical compiled statement
	ka, _ := hex.DecodeString(a["alpha"].(string))
	kc, _ := hex.DecodeString(c["alpha"].(string))
	if string(ka) != string(kc) {
		t.Fatalf("compiled statement not deterministic")
	}
	// compiled determinism within same instance run
	if len(a["C"].([]string)) != inst.L {
		t.Fatalf("C length mismatch")
	}
}