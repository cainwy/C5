package bottomc5

import (
	"math/big"
	"testing"

	"c5full/internal/c5/params"
)

func TestFaithfulBeaverNonDegenerateAndCorrect(t *testing.T) {
	for _, nf := range [][2]int{{3, 1}, {5, 2}, {9, 4}} {
		p := Params{N: nf[0], F: nf[1], L: 1}
		x, y := big.NewInt(0x1234567), big.NewInt(0x89abcde)
		d := NewDealer(p, x, y, nil)
		b, _, tm, err := d.RunWithTimings()
		if err != nil {
			t.Fatalf("n=%d f=%d run: %v", nf[0], nf[1], err)
		}
		if bad := VerifyInvariant(b); bad != -1 {
			t.Fatalf("n=%d f=%d invariant violated at %d", nf[0], nf[1], bad)
		}
		want := new(big.Int).Mul(x, y)
		want.Mod(want, params.Q)
		if b.Output[0].Cmp(want) != 0 {
			t.Fatalf("n=%d f=%d output %s != x*y %s", nf[0], nf[1], b.Output[0], want)
		}
		if !d.TripleNonDegenerate() {
			t.Fatalf("n=%d f=%d triple is degenerate (FID-01 regression)", nf[0], nf[1])
		}
		if d.WireA.Value().Sign() == 0 || d.WireB.Value().Sign() == 0 ||
			d.WireC.Value().Sign() == 0 {
			t.Fatalf("n=%d f=%d triple constant terms not all non-zero", nf[0], nf[1])
		}
		if tm.InputShareNS <= 0 || tm.TriplePrepNS <= 0 || tm.OnlineMulNS() <= 0 {
			t.Fatalf("n=%d f=%d zero stage timing: %+v", nf[0], nf[1], tm)
		}
	}
}

func TestDefaultDealerIsFaithful(t *testing.T) {
	p := Params{N: 3, F: 1, L: 1}
	x, y := big.NewInt(12345), big.NewInt(6789)
	d := NewDealer(p, x, y, nil)
	b, _, err := d.Run()
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	want := new(big.Int).Mul(x, y)
	want.Mod(want, params.Q)
	if b.Output[0].Cmp(want) != 0 {
		t.Fatalf("output %s != x*y %s", b.Output[0], want)
	}
	if !d.TripleNonDegenerate() {
		t.Fatal("default dealer produced degenerate triple (FID-01 regression)")
	}
}
