package schemea

import (
	"bytes"
	"crypto/sha256"
	"io"
	"math/big"
	"testing"

	"c5full/internal/mpc/params"
)

type hashReader struct {
	seed  []byte
	block uint64
	buf   []byte
	off   int
}

func newHashReader(seed string) io.Reader { return &hashReader{seed: []byte(seed)} }

func (r *hashReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if r.off >= len(r.buf) {
			h := sha256.New()
			h.Write(r.seed)
			h.Write([]byte{byte(r.block >> 56), byte(r.block >> 48), byte(r.block >> 40), byte(r.block >> 32), byte(r.block >> 24), byte(r.block >> 16), byte(r.block >> 8), byte(r.block)})
			r.buf = h.Sum(nil)
			r.off = 0
			r.block++
		}
		c := copy(p[n:], r.buf[r.off:])
		r.off += c
		n += c
	}
	return n, nil
}

func diagGroup(t *testing.T) *Params {
	t.Helper()
	eg := NewEx(params.GMOD, 256, 32, 42)
	return eg
}

func TestZKPoCHonestProveVerify(t *testing.T) {
	p := diagGroup(t)
	order := new(big.Int).Sub(p.P, big.NewInt(1))
	v := big.NewInt(1234567)
	l := big.NewInt(987654321)
	ct := p.Encrypt(v, l)
	pf := p.MakeZKPoC(ct.C0, ct.C1, v, l, order, newHashReader("zkp-seed-1"))
	if !p.VerifyZKPoC(pf, order) {
		t.Fatal("honest ZKPoC must verify")
	}
}

func TestZKPoCRejectsWrongCommitment(t *testing.T) {
	p := diagGroup(t)
	order := new(big.Int).Sub(p.P, big.NewInt(1))
	v := big.NewInt(77)
	l := big.NewInt(88)
	ct := p.Encrypt(v, l)
	pf := p.MakeZKPoC(ct.C0, ct.C1, v, new(big.Int).Add(l, big.NewInt(1)), order, newHashReader("zkp-seed-2"))
	if p.VerifyZKPoC(pf, order) {
		t.Fatal("wrong blinding must be rejected")
	}
	pf2 := p.MakeZKPoC(ct.C0, ct.C1, v, l, order, newHashReader("zkp-seed-3"))
	pf2.C1 = new(big.Int).Add(pf2.C1, big.NewInt(1))
	if p.VerifyZKPoC(pf2, order) {
		t.Fatal("tampered transcript must be rejected")
	}
}

func TestZKPoCRandomnessNotFixed(t *testing.T) {
	p := diagGroup(t)
	order := new(big.Int).Sub(p.P, big.NewInt(1))
	v, l := big.NewInt(5), big.NewInt(9)
	ct := p.Encrypt(v, l)
	a1 := p.MakeZKPoC(ct.C0, ct.C1, v, l, order, newHashReader("seed-a"))
	a2 := p.MakeZKPoC(ct.C0, ct.C1, v, l, order, newHashReader("seed-b"))
	if a1.D.Cmp(a2.D) == 0 && a1.F.Cmp(a2.F) == 0 {
		t.Fatal("ZKPoC randomness appears fixed (deterministic nonce re-use)")
	}
}

func TestThresholdDecryptionTopology(t *testing.T) {
	p := diagGroup(t)
	set, err := p.NewDecryptionShareSet(2, 3, newHashReader("thr-seed"))
	if err != nil {
		t.Fatalf("share set: %v", err)
	}
	v := big.NewInt(20260917)
	l := big.NewInt(314159265)
	ct := p.Encrypt(v, l)
	partials := []*big.Int{p.PartialDecrypt(ct, set, 0), p.PartialDecrypt(ct, set, 1)}
	tj, err := CombineDecrypt(partials, []int{0, 1}, set)
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	// g^v = C1 / tj
	inv := new(big.Int).ModInverse(tj, p.P)
	gv := new(big.Int).Mul(ct.C1, inv)
	gv.Mod(gv, p.P)
	if new(big.Int).Exp(p.G, v, p.P).Cmp(gv) != 0 {
		t.Fatal("threshold decryption did not recover g^v")
	}
	msg := p.RevealDecrypt(ct, set, 0)
	if len(msg) == 0 {
		t.Fatal("reveal message empty")
	}
}

func TestSerializationExactBytes(t *testing.T) {
	p := diagGroup(t)
	ct := p.Encrypt(big.NewInt(7), big.NewInt(11))
	ctBytes := p.CiphertextBytes(ct)
	order := new(big.Int).Sub(p.P, big.NewInt(1))
	pf := p.MakeZKPoC(ct.C0, ct.C1, big.NewInt(7), big.NewInt(11), order, newHashReader("ser-seed"))
	pfBytes := p.ZKPoCBytes(pf)
	if len(ctBytes) == 0 || len(pfBytes) == 0 {
		t.Fatalf("serialization empty: ct=%d pf=%d", len(ctBytes), len(pfBytes))
	}
	if ctBytes[0] == 0 || pfBytes[0] == 0 {
		t.Fatalf("length prefix zero (empty field)")
	}
	partial := SerializePartial(new(big.Int).Exp(ct.C0, big.NewInt(5), p.P), p.P)
	if len(partial) == 0 {
		t.Fatal("partial serialize empty")
	}
	if !bytes.Equal(ctBytes, p.CiphertextBytes(ct)) {
		t.Fatal("ciphertext serialization not deterministic")
	}
}

func TestProfilesValidate(t *testing.T) {
	p128, err := NewProfile(PUB128)
	if err != nil {
		t.Fatalf("P-SA-128 group: %v", err)
	}
	if p128.PrimeBits < 3000 || !p128.P.ProbablyPrime(20) {
		t.Fatalf("P-SA-128 prime invalid: bits=%d", p128.PrimeBits)
	}
	p112, err := NewProfile(PUB112)
	if err != nil {
		t.Fatalf("P-SA-112 group: %v", err)
	}
	if p112.PrimeBits < 2000 {
		t.Fatalf("P-SA-112 prime invalid")
	}
	_ = p112
}

func TestAggregateShortcutIsolatedDiag(t *testing.T) {
	p := diagGroup(t)
	cts, _ := p.EncryptShare(big.NewInt(123456), big.NewInt(654321))
	gv := p.DecryptShareAggregateDiag(cts)
	if len(gv) != p.NumChunks {
		t.Fatal("aggregate diag decrypt wrong length")
	}
}