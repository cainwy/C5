package paperdecrypt

import (
	"encoding/json"
	"math/big"
	"strconv"
	"strings"
	"testing"

	schemeacore "c5full/internal/mpc/schemea"

	"c5full/blockchain/tests/harness"
)

func testGroup(t *testing.T, seed int64, h *big.Int) *schemeacore.Params {
	t.Helper()
	base := schemeacore.NewParams(256, 128, 16, seed)
	return &schemeacore.Params{
		P: base.P, G: base.G, H: h,
		S:         nil,
		K:         128,
		ChunkBits: 16,
		NumChunks: 8,
		PrimeBits: base.PrimeBits,
	}
}

func encryptWith(t *testing.T, p *schemeacore.Params, z *big.Int, seed string) []Ciphertext {
	t.Helper()
	rng := harness.NewHashSeedReader(seed)
	order := new(big.Int).Sub(p.P, big.NewInt(1))
	cts, _ := p.EncryptShareR(z, randInRange(order, rng), rng)
	out := make([]Ciphertext, len(cts))
	for i, c := range cts {
		out[i] = Ciphertext{C0: c.C0, C1: c.C1}
	}
	return out
}

func roundTrip(t *testing.T, ring *KeyRing, p *schemeacore.Params, cts []Ciphertext) *DecryptResult {
	t.Helper()
	res, err := ring.DecryptPartitions(cts, p.ChunkBits, 16)
	if err != nil {
		t.Fatalf("DecryptPartitions: %v", err)
	}
	return res
}

func TestEq20CorrectnessM2M3M5(t *testing.T) {
	for _, m := range []int{2, 3, 5} {
		m := m
		t.Run("m="+strconv.Itoa(m), func(t *testing.T) {
			seed := "paperdecrypt::correct::" + strconv.Itoa(m)
			probe := schemeacore.NewParams(256, 128, 16, int64(m))
			ring, err := NewKeyRing(probe.P, probe.G, m, harness.NewHashSeedReader(seed))
			if err != nil {
				t.Fatalf("NewKeyRing: %v", err)
			}
			p := testGroup(t, int64(m), ring.H)

			acc := big.NewInt(1)
			for _, k := range ring.PublicShares() {
				acc.Mul(acc, k)
				acc.Mod(acc, p.P)
			}
			if acc.Cmp(ring.H) != 0 {
				t.Fatalf("h != ∏ k_i")
			}

			z := big.NewInt(0x1234_5678_9abc)
			cts := encryptWith(t, p, z, seed+"::enc")
			res := roundTrip(t, ring, p, cts)
			if res.Z.Cmp(z) != 0 {
				t.Fatalf("recovered z=%s want %s", res.Z, z)
			}
			if res.PartialsPerProduct != m {
				t.Fatalf("number_of_decrypt_partials=%d want m_clients=%d", res.PartialsPerProduct, m)
			}
			if res.TotalPartials != m*res.Partitions {
				t.Fatalf("total_client_partials=%d want m×w=%d×%d", res.TotalPartials, m, res.Partitions)
			}
			if err := res.AssertEq20Participants(m); err != nil {
				t.Fatalf("AssertEq20Participants: %v", err)
			}
			ac := ActorCounts{NServers: 3, TSecretSharing: 2, MClients: m, DecryptPartials: res.PartialsPerProduct}
			if err := ac.Check(); err != nil {
				t.Fatalf("ActorCounts.Check: %v", err)
			}
		})
	}
}

func TestEq20MissingPartialIsRejected(t *testing.T) {
	probe := schemeacore.NewParams(256, 128, 16, 11)
	ring, err := NewKeyRing(probe.P, probe.G, 3, harness.NewHashSeedReader("paperdecrypt::missing"))
	if err != nil {
		t.Fatalf("NewKeyRing: %v", err)
	}
	ct0 := big.NewInt(2)
	_, parts, err := ring.ClientPartials(ct0)
	if err != nil {
		t.Fatalf("ClientPartials: %v", err)
	}
	if len(parts) != 3 {
		t.Fatalf("expected 3 partials, got %d", len(parts))
	}
	if _, err := Eq20Product(probe.P, parts[:2], 3); err == nil {
		t.Fatal("Eq.(20) must reject fewer than m partials")
	}
	extra := append([]*big.Int{}, parts...)
	extra = append(extra, parts[0])
	if _, err := Eq20Product(probe.P, extra, 3); err == nil {
		t.Fatal("Eq.(20) must reject more than m partials")
	}
	if _, err := Eq20Product(probe.P, parts, 3); err != nil {
		t.Fatalf("Eq.(20) must accept exactly m partials: %v", err)
	}
	bad := ActorCounts{NServers: 3, TSecretSharing: 2, MClients: 3, DecryptPartials: 2}
	if err := bad.Check(); err == nil {
		t.Fatal("ActorCounts must reject number_of_decrypt_partials != m_clients")
	}
}

func TestEq20TamperedPartialFailsRecovery(t *testing.T) {
	probe := schemeacore.NewParams(256, 128, 16, 13)
	ring, err := NewKeyRing(probe.P, probe.G, 3, harness.NewHashSeedReader("paperdecrypt::tamper"))
	if err != nil {
		t.Fatalf("NewKeyRing: %v", err)
	}
	p := testGroup(t, 13, ring.H)
	z := big.NewInt(0x0fed_cba9_8765)
	cts := encryptWith(t, p, z, "paperdecrypt::tamper::enc")

	want := roundTrip(t, ring, p, cts)
	wantV := want.V[0]

	_, parts, _ := ring.ClientPartials(cts[0].C0)
	tampered := append([]*big.Int{}, parts...)
	tampered[1] = new(big.Int).Mul(tampered[1], big.NewInt(2))
	tampered[1].Mod(tampered[1], p.P)
	tj, err := Eq20Product(p.P, tampered, 3)
	if err != nil {
		t.Fatalf("Eq20Product: %v", err)
	}
	gv, err := RecoverGv(p.P, cts[0].C1, tj)
	if err != nil {
		t.Fatalf("RecoverGv: %v", err)
	}
	v, ok := BSGSBounded(p.P, p.G, gv, 16)
	if ok && v.Cmp(wantV) == 0 {
		t.Fatalf("tampered partial must not recover the correct value; got same v=%s", v)
	}
	if !ok {
		t.Logf("tampered partial → bounded DLOG found no solution（fail-closed）")
	} else {
		t.Logf("tampered partial → DLOG returned a different value (%s vs %s)", v, wantV)
	}
}

func TestEq20WrongClientKeyFails(t *testing.T) {
	probe := schemeacore.NewParams(256, 128, 16, 17)
	ring1, err := NewKeyRing(probe.P, probe.G, 3, harness.NewHashSeedReader("paperdecrypt::rk1"))
	if err != nil {
		t.Fatalf("NewKeyRing: %v", err)
	}
	ring2, err := NewKeyRing(probe.P, probe.G, 3, harness.NewHashSeedReader("paperdecrypt::rk2"))
	if err != nil {
		t.Fatalf("NewKeyRing: %v", err)
	}
	if ring1.H.Cmp(ring2.H) == 0 {
		t.Fatal("two independent keyrings must have different h")
	}
	p := testGroup(t, 17, ring1.H)
	z := big.NewInt(0x00ab_cdef_1234)
	cts := encryptWith(t, p, z, "paperdecrypt::rk::enc")

	if got := roundTrip(t, ring1, p, cts); got.Z.Cmp(z) != 0 {
		t.Fatalf("ring1 must recover z; got %s", got.Z)
	}
	res2, err := ring2.DecryptPartitions(cts, p.ChunkBits, 16)
	if err == nil && res2.Z.Cmp(z) == 0 {
		t.Fatal("wrong client key must NOT recover the correct z")
	}
	if err != nil {
		t.Logf("wrong client key → %v（fail-closed）", err)
	} else {
		t.Logf("wrong client key → wrong z=%s（≠ %s）", res2.Z, z)
	}
}

func TestEq20PartialOrderIrrelevant(t *testing.T) {
	probe := schemeacore.NewParams(256, 128, 16, 19)
	ring, err := NewKeyRing(probe.P, probe.G, 5, harness.NewHashSeedReader("paperdecrypt::order"))
	if err != nil {
		t.Fatalf("NewKeyRing: %v", err)
	}
	ct0 := big.NewInt(3)
	_, parts, err := ring.ClientPartials(ct0)
	if err != nil {
		t.Fatalf("ClientPartials: %v", err)
	}
	base, err := Eq20Product(probe.P, parts, 5)
	if err != nil {
		t.Fatalf("Eq20Product: %v", err)
	}
	rev := make([]*big.Int, len(parts))
	for i := range parts {
		rev[i] = parts[len(parts)-1-i]
	}
	got, err := Eq20Product(probe.P, rev, 5)
	if err != nil {
		t.Fatalf("Eq20Product(rev): %v", err)
	}
	if got.Cmp(base) != 0 {
		t.Fatal("Eq.(20) product must be independent of partial order")
	}
	sum := big.NewInt(0)
	for _, c := range ring.Clients {
		sum.Add(sum, c.s)
	}
	okv, err := VerifyProductIndependent(probe.P, ct0, parts, sum, 5)
	if err != nil {
		t.Fatalf("VerifyProductIndependent: %v", err)
	}
	if !okv {
		t.Fatal("Eq.(20) product must equal C0^{Σ s_i}")
	}
}

func TestNoPlaintextLeakage(t *testing.T) {
	probe := schemeacore.NewParams(256, 128, 16, 23)
	ring, err := NewKeyRing(probe.P, probe.G, 3, harness.NewHashSeedReader("paperdecrypt::leak"))
	if err != nil {
		t.Fatalf("NewKeyRing: %v", err)
	}
	type publicView struct {
		P      string   `json:"p"`
		G      string   `json:"g"`
		H      string   `json:"h"`
		Ki     []string `json:"k_i"`
		Digest string   `json:"digest"`
		M      int      `json:"m_clients"`
	}
	pv := publicView{P: probe.P.Text(16), G: probe.G.Text(16), H: ring.H.Text(16), M: ring.M}
	for _, k := range ring.PublicShares() {
		pv.Ki = append(pv.Ki, k.Text(16))
	}
	pv.Digest = ring.PublicDigest()
	b, err := json.Marshal(pv)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := strings.ToLower(string(b))
	for i, c := range ring.Clients {
		if c.s == nil {
			t.Fatalf("client %d lost its private share", i)
		}
		if strings.Contains(s, strings.ToLower(c.s.Text(16))) {
			t.Fatalf("private share s_%d leaked into serializable public material", i+1)
		}
	}
	rb, err := json.Marshal(ring)
	if err != nil {
		t.Fatalf("marshal ring: %v", err)
	}
	rs := strings.ToLower(string(rb))
	for i, c := range ring.Clients {
		if strings.Contains(rs, strings.ToLower(c.s.Text(16))) {
			t.Fatalf("private share s_%d leaked from KeyRing marshal", i+1)
		}
	}
}

func TestNoAggregateSecretPath(t *testing.T) {
	probe := schemeacore.NewParams(256, 128, 16, 29)
	ring, err := NewKeyRing(probe.P, probe.G, 3, harness.NewHashSeedReader("paperdecrypt::noagg"))
	if err != nil {
		t.Fatalf("NewKeyRing: %v", err)
	}
	p := testGroup(t, 29, ring.H)
	if p.S != nil {
		t.Fatal("test group must have nil aggregate secret")
	}
	z := big.NewInt(0x0000_0000_00ff)
	cts := encryptWith(t, p, z, "paperdecrypt::noagg::enc")
	if got := roundTrip(t, ring, p, cts); got.Z.Cmp(z) != 0 {
		t.Fatalf("decryption must not depend on an aggregate secret; got %s", got.Z)
	}
}
