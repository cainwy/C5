package m1

// LA-03 determinism tests: same seed → identical public fixture hash;
// different seed → different hash; default API remains cryptographic (its
// fixture hash is practically never colliding across runs and differs from the
// seeded ones).

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"

	"c5full/internal/c5/host"
)

// hostEncode encodes a G1 point with the host's canonical (uncompressed) format.
func hostEncode(p *secp256k1.G1Affine) []byte { return host.EncodePoint(p, false) }

// hashSeedHex folds domain + byte slices into a hex digest (deterministic).
func hashSeedHex(seed []byte, domain string, parts ...[]byte) string {
	h := sha256.New()
	h.Write(seed)
	h.Write([]byte(domain))
	h.Write([]byte{0x00})
	for _, p := range parts {
		h.Write(p)
		h.Write([]byte{0x01})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// fixtureHash derives a public, nondeterministic-independent fingerprint of the
// task's public material (receiver PK, alpha, context, server pubs). It never
// includes private material, but it is representative of the fixture output.
func fixtureHash(t *Task, seedB []byte) string {
	return hashSeedHex(seedB, "m1-fixture", t.Alpha, t.TaskCtx,
		hostEncode(t.ReceiverPK), t.ServerPub[0], t.ServerPub[1])
}

func TestSameSeedSameFixture(t *testing.T) {
	seed := []byte("la03-seed-001")
	r1 := NewHashSeedReader(seed)
	r2 := NewHashSeedReader(seed)
	tk1, err := NewTaskWithRNG(3, 1, 2, "tau-la03", r1)
	if err != nil {
		t.Fatalf("task1: %v", err)
	}
	tk2, err := NewTaskWithRNG(3, 1, 2, "tau-la03", r2)
	if err != nil {
		t.Fatalf("task2: %v", err)
	}
	h1, h2 := fixtureHash(tk1, seed), fixtureHash(tk2, seed)
	if h1 != h2 {
		t.Fatalf("same seed produced different fixtures:\n%s\n%s", h1, h2)
	}
	d1 := tk1.MakeDeliveryWithRNG(0, NewHashSeedReader(seed))
	d2 := tk2.MakeDeliveryWithRNG(0, NewHashSeedReader(seed))
	if !d1.R.Equal(d2.R) || d1.S.Cmp(d2.S) != 0 || !bytes.Equal(d1.Sig, d2.Sig) {
		t.Fatalf("same-seed deliveries differ")
	}
}

func TestDifferentSeedDifferentFixture(t *testing.T) {
	tkA, _ := NewTaskWithRNG(3, 1, 2, "tau-la03", NewHashSeedReader([]byte("seed-A")))
	tkB, _ := NewTaskWithRNG(3, 1, 2, "tau-la03", NewHashSeedReader([]byte("seed-B")))
	if fixtureHash(tkA, []byte("seed-A")) == fixtureHash(tkB, []byte("seed-B")) {
		t.Fatalf("different seeds must produce different public fixtures")
	}
}

func TestDefaultAPIIsCryptoRand(t *testing.T) {
	tk1, _ := NewTask(3, 1, 2, "tau-la03")
	tk2, _ := NewTask(3, 1, 2, "tau-la03")
	if fixtureHash(tk1, []byte("x")) == fixtureHash(tk2, []byte("x")) {
		t.Fatalf("default NewTask appears deterministic — production default must be crypto/rand")
	}
	tkD, _ := NewTaskWithRNG(3, 1, 2, "tau-la03", NewHashSeedReader([]byte("seed-recover")))
	tkD.EndorseAll()
	ds := map[int]*Delivery{0: tkD.MakeDeliveryWithRNG(0, NewHashSeedReader([]byte("del0"))), 1: tkD.MakeDeliveryWithRNG(1, NewHashSeedReader([]byte("del1")))}
	r := tkD.Recover(ds)
	if !r.IsOK() {
		t.Fatalf("deterministic task recovery failed: %+v", r)
	}
	if _, err := json.Marshal(tkD); err != nil {
		t.Fatalf("marshal deterministic task: %v", err)
	}
}