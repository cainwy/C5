package bottomc5

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"

	"c5full/internal/c5/host"
	"c5full/internal/c5/params"
)

func g1Eq(a, b *secp256k1.G1Affine) bool { return host.PointEqual(a, b) }

func TestBeaverPrimaryInvariant(t *testing.T) {
	p := Params{N: 3, F: 1, L: 1}
	d := NewDealer(p, big.NewInt(123456789), big.NewInt(987654321), nil)
	b, tr, err := d.Run()
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if tr == nil || b == nil {
		t.Fatal("nil result")
	}
	if bad := VerifyInvariant(b); bad != -1 {
		t.Fatalf("invariant violated at server %d", bad)
	}
	want := new(big.Int).Mul(big.NewInt(123456789), big.NewInt(987654321))
	want.Mod(want, params.Q)
	if b.Output[0].Cmp(want) != 0 {
		t.Fatalf("output %s != x*y %s", b.Output[0], want)
	}
	if len(b.Openings) != p.N {
		t.Fatalf("openings = %d, want %d", len(b.Openings), p.N)
	}
	if tr.Accepted != p.N || tr.Rejected != 0 {
		t.Fatalf("accept/reject wrong: %d/%d", tr.Accepted, tr.Rejected)
	}
}

func TestBeaverDifferentSeedsDiffer(t *testing.T) {
	p := Params{N: 3, F: 1, L: 1}
	d1 := NewDealer(p, big.NewInt(5), big.NewInt(7), nil)
	b1, _, err := d1.Run()
	if err != nil {
		t.Fatalf("run1: %v", err)
	}
	d2 := NewDealer(p, big.NewInt(5), big.NewInt(7), nil)
	b2, _, err := d2.Run()
	if err != nil {
		t.Fatalf("run2: %v", err)
	}
	if b1.Output[0].Cmp(b2.Output[0]) != 0 {
		t.Fatalf("output must be same x*y")
	}
	same := true
	for i := 0; i < p.N; i++ {
		if !g1Eq(b1.Aout[0][0], b2.Aout[0][0]) {
			same = false
			break
		}
	}
	if same {
		t.Fatalf("commitments identical across random runs (expected randomness)")
	}
}

func TestBeaverTamperDiffShareRejected(t *testing.T) {
	p := Params{N: 3, F: 1, L: 1}
	d := NewDealer(p, big.NewInt(10), big.NewInt(20), nil)
	if err := d.manualSetup(); err != nil {
		t.Fatalf("manual setup: %v", err)
	}
	honest := d.DiffShareOf(0)
	bad := honest
	bad.D = modQ(new(big.Int).Add(bad.D, big.NewInt(1)))
	if d.checkDiffCom(bad) {
		t.Fatalf("tampered diff share passed commitment check")
	}
	if !d.checkDiffCom(honest) {
		t.Fatalf("honest diff share must pass commitment check")
	}
	d.DiffTries = []DiffShare{bad, d.DiffShareOf(1), d.DiffShareOf(2)}
	b, tr := d.runBeaver()
	if b == nil || tr == nil {
		t.Fatal("nil result")
	}
	want := modQ(new(big.Int).Mul(big.NewInt(10), big.NewInt(20)))
	if b.Output[0].Cmp(want) != 0 {
		t.Fatalf("reconstruction polluted by tampered share: %s != %s", b.Output[0], want)
	}
	if _, ok := b.OpeningAt(0); ok {
		t.Fatalf("rejected server 0 opening should be absent")
	}
	if tr == nil || tr.Accepted != 2 {
		t.Fatalf("trace accepted = %v, want 2", tr)
	}
}

func (d *Dealer) manualSetup() error {
	d.WireX = NewWireR(d.P.F, d.X, d.RNG)
	d.WireA = NewWireR(d.P.F, new(big.Int), d.RNG)
	d.WireY = NewWireR(d.P.F, d.Y, d.RNG)
	d.WireB = NewWireR(d.P.F, new(big.Int), d.RNG)
	d.WireC = NewWireR(d.P.F, mulQ(d.WireA.Value(), d.WireB.Value()), d.RNG)
	return nil
}

func TestBeaverInsufficientShares(t *testing.T) {
	p := Params{N: 3, F: 1, L: 1}
	d := NewDealer(p, big.NewInt(1), big.NewInt(1), nil)
	if err := d.manualSetup(); err != nil {
		t.Fatalf("manual setup: %v", err)
	}
	honest := d.DiffShareOf(0)
	bad1 := d.DiffShareOf(1)
	bad1.D = modQ(new(big.Int).Add(bad1.D, big.NewInt(1)))
	bad2 := d.DiffShareOf(2)
	bad2.D = modQ(new(big.Int).Add(bad2.D, big.NewInt(1)))
	if !d.checkDiffCom(honest) {
		t.Fatalf("honest share must pass")
	}
	if d.checkDiffCom(bad1) {
		t.Fatalf("tampered share must fail")
	}
	d.DiffTries = []DiffShare{honest, bad1, bad2}
	if _, _, err := d.Run(); err == nil {
		t.Fatalf("expected insufficient-shares error")
	}
}