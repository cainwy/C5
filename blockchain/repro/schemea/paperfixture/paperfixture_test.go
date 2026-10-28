package paperfixture

import (
	"math/big"
	"testing"

	schemeacore "c5full/internal/mpc/schemea"

	"c5full/blockchain/bridge"
	"c5full/blockchain/fabric/chaincode/model"
	"c5full/blockchain/repro/schemea/paperdecrypt"
)

func mustDecodeC0(t *testing.T, pf *PaperSAFixture, sub *model.SchemeAOutputSubmission) *big.Int {
	t.Helper()
	cts, _, err := bridge.DecodeSchemeAOutput(sub, pf.Fixture.Width())
	if err != nil {
		t.Fatalf("DecodeSchemeAOutput: %v", err)
	}
	if len(cts) == 0 {
		t.Fatal("no ciphertexts in submission")
	}
	return cts[0].C0
}

func TestPaperFixtureFullChain(t *testing.T) {
	cases := []struct {
		name    string
		n, m, t int
	}{
		{"n3_t2_m2", 3, 2, 2},
		{"n3_t3_m3", 3, 3, 3},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			x := big.NewInt(0x12345)
			y := big.NewInt(0x6789a)
			pf, err := Build(schemeacore.PUB128, c.n, c.m, c.t, x, y, "off", "test::"+c.name)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			if pf.Params.S != nil {
				t.Fatal("paper-faithful params must not carry an aggregate secret")
			}
			acc := big.NewInt(1)
			for _, k := range pf.Ring.PublicShares() {
				acc.Mul(acc, k)
				acc.Mod(acc, pf.Params.P)
			}
			if acc.Cmp(pf.Ring.H) != 0 {
				t.Fatal("h != ∏ g^{s_i}")
			}
			if pf.Counts.MClients != c.m || pf.Counts.DecryptPartials != c.m {
				t.Fatalf("actor counts wrong: %+v", pf.Counts)
			}
			if err := pf.Counts.Check(); err != nil {
				t.Fatalf("ActorCounts.Check: %v", err)
			}

			dsum, err := pf.DecryptServerShares(32)
			if err != nil {
				t.Fatalf("DecryptServerShares: %v", err)
			}
			zs := dsum.Zs
			if dsum.PartialsPerProduct != c.m {
				t.Fatalf("number_of_decrypt_partials=%d want m_clients=%d", dsum.PartialsPerProduct, c.m)
			}
			if len(zs) != c.n {
				t.Fatalf("expected %d recovered server shares, got %d", c.n, len(zs))
			}
			if dsum.TotalPartials != c.m*c.n*dsum.PartitionsPerServer {
				t.Fatalf("total client partials=%d want m×n×w=%d", dsum.TotalPartials, c.m*c.n*dsum.PartitionsPerServer)
			}
			t.Logf("n=%d m=%d t=%d partitions=%d total_partials=%d dlog_ns=%d eq20_ns=%d",
				c.n, c.m, c.t, dsum.PartitionsPerServer, dsum.TotalPartials, dsum.DLOGNS, dsum.Eq20NS)
			for i, z := range zs {
				if z.Cmp(pf.Shares[i]) != 0 {
					t.Fatalf("server %d share mismatch: got %s want %s", i+1, z, pf.Shares[i])
				}
			}
			got, err := pf.Reconstruct(zs, c.t, c.t)
			if err != nil {
				t.Fatalf("Reconstruct: %v", err)
			}
			want := new(big.Int).Mul(x, y)
			want.Mod(want, ShareMod)
			if got.Cmp(want) != 0 {
				t.Fatalf("Eq.(22) reconstructed %s want x·y=%s", got, want)
			}
		})
	}
}

func TestPaperFixtureEq20RejectsPartialSubset(t *testing.T) {
	pf, err := Build(schemeacore.PUB128, 3, 3, 2, big.NewInt(3), big.NewInt(5), "off", "test::sub")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	sub, err := pf.Fixture.Submission(0)
	if err != nil {
		t.Fatalf("Submission: %v", err)
	}
	ct0 := mustDecodeC0(t, pf, sub)
	_, parts, err := pf.Ring.ClientPartials(ct0)
	if err != nil {
		t.Fatalf("ClientPartials: %v", err)
	}
	for k := 1; k < 3; k++ {
		if _, err := paperdecrypt.Eq20Product(pf.Params.P, parts[:k], 3); err == nil {
			t.Fatalf("Eq.(20) must reject %d partials when m=3", k)
		}
	}
	if _, err := paperdecrypt.Eq20Product(pf.Params.P, parts, 3); err != nil {
		t.Fatalf("Eq.(20) must accept all m=3 partials: %v", err)
	}
}
