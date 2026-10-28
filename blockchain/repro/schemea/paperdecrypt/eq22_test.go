package paperdecrypt

import (
	"crypto/sha256"
	"math/big"
	"testing"

	schemeacore "c5full/internal/mpc/schemea"

	"c5full/blockchain/tests/harness"
)

func newParams256(seed int64) *schemeacore.Params {
	return schemeacore.NewParams(256, 128, 16, seed)
}

func shareModulus256() *big.Int {
	p, _ := new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)
	return p
}

func TestShamirShareReconstructEq22(t *testing.T) {
	mod := shareModulus256()
	secret := new(big.Int).SetBytes(mustHash("sa::secret"))
	secret.Mod(secret, mod)

	for _, n := range []int{3, 5, 9} {
		for _, th := range []int{1, 2, 3} {
			if th > n {
				continue
			}
			seed := "paperdecrypt::eq22::" + string(rune('0'+n)) + "::" + string(rune('0'+th))
			shares, err := ShamirShare(secret, th, n, mod, harness.NewHashSeedReader(seed))
			if err != nil {
				t.Fatalf("ShamirShare n=%d t=%d: %v", n, th, err)
			}
			if len(shares) != n {
				t.Fatalf("expected %d shares, got %d", n, len(shares))
			}
			idx := make([]int, th)
			sub := make([]*big.Int, th)
			for i := 0; i < th; i++ {
				idx[i] = i + 1
				sub[i] = shares[i]
			}
			got, err := LagrangeReconstruct(sub, idx, th, mod)
			if err != nil {
				t.Fatalf("LagrangeReconstruct n=%d t=%d: %v", n, th, err)
			}
			if got.Cmp(secret) != 0 {
				t.Fatalf("n=%d t=%d: Eq.(22) reconstruct got %s want %s", n, th, got, secret)
			}
			if th > 1 {
				if _, err := LagrangeReconstruct(sub[:th-1], idx[:th-1], th, mod); err == nil {
					t.Fatalf("n=%d t=%d: must reject fewer than t shares", n, th)
				}
			}
			if n > th {
				idx2 := make([]int, th)
				sub2 := make([]*big.Int, th)
				for i := 0; i < th; i++ {
					idx2[i] = n - i
					sub2[i] = shares[n-1-i]
				}
				got2, err := LagrangeReconstruct(sub2, idx2, th, mod)
				if err != nil {
					t.Fatalf("LagrangeReconstruct(alt) n=%d t=%d: %v", n, th, err)
				}
				if got2.Cmp(secret) != 0 {
					t.Fatalf("n=%d t=%d: alternative share subset reconstructed %s != %s", n, th, got2, secret)
				}
			}
		}
	}
}

func TestEq22IsNotUsedForDecryption(t *testing.T) {
	mod := shareModulus256()
	base := newParams256(31)
	ring, err := NewKeyRing(base.P, base.G, 4, harness.NewHashSeedReader("paperdecrypt::roles"))
	if err != nil {
		t.Fatalf("NewKeyRing: %v", err)
	}
	ct0 := big.NewInt(5)
	_, parts, err := ring.ClientPartials(ct0)
	if err != nil {
		t.Fatalf("ClientPartials: %v", err)
	}
	for _, k := range []int{1, 2, 3} {
		if _, err := Eq20Product(base.P, parts[:k], 4); err == nil {
			t.Fatalf("Eq.(20) must not accept %d partials when m=4", k)
		}
	}
	if _, err := Eq20Product(base.P, parts, 4); err != nil {
		t.Fatalf("Eq.(20) must accept all m=4 partials: %v", err)
	}
	shares, err := ShamirShare(big.NewInt(1234567), 2, 4, mod, harness.NewHashSeedReader("paperdecrypt::roles::sh"))
	if err != nil {
		t.Fatalf("ShamirShare: %v", err)
	}
	got, err := LagrangeReconstruct(shares[:2], []int{1, 2}, 2, mod)
	if err != nil {
		t.Fatalf("LagrangeReconstruct: %v", err)
	}
	if got.Cmp(big.NewInt(1234567)) != 0 {
		t.Fatalf("Eq.(22) got %s want 1234567", got)
	}
}

func mustHash(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}
