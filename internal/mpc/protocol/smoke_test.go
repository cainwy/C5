package protocol

import (
	"math/big"
	"testing"

	"c5full/internal/mpc/mpccore"
	"c5full/internal/mpc/params"
	"c5full/internal/mpc/schemea"
	"c5full/internal/mpc/vss"
)

// TestEndToEnd runs the repaired Scheme-A pipeline for z = x·y over n=3,t=2
// servers and asserts (a) the public multiplication verification passes and
// (b) the client recovers z = x·y.
func TestEndToEnd(t *testing.T) {
	eg := schemea.NewEx(params.GMOD, 256, 32, 42)
	grp := mpccore.NewParams(eg.P, eg.G, eg.H, 2, 3)

	x := big.NewInt(6)
	y := big.NewInt(9)
	want := new(big.Int).Mul(x, y)

	cli := grp.NewClient(x, y, 20260908)
	tr := cli.MakeTriple(20260908)

	// VSS share verification: every server's value+blinding share must match
	// its committed share.
	for _, s := range []struct{ set *vss.ShareSet }{{cli.XSet}, {cli.YSet}, {tr.A}, {tr.B}, {tr.C}} {
		for i := 0; i < 3; i++ {
			if !verifyShareOpen(eg, s.set, i) {
				t.Fatalf("VSS share verification failed at index %d", i)
			}
		}
	}

	res, err := Run(grp, cli, tr, 2, eg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !res.Valid {
		t.Fatalf("public multiplication verification (eq 16/17) failed")
	}
	if res.Z.Cmp(want) != 0 {
		t.Fatalf("recovered z=%v want %v (x·y)", res.Z, want)
	}
	t.Logf("OK: z=%v verified=%v ClientRecover=%.4fs RevealBytes=%d ClientRecoverBytes=%d",
		res.Z, res.Valid, res.Stats.ClientRecoverS, res.Stats.RevealBytes, res.Stats.ClientRecoverBytes)
}

// verifyShareOpen checks g^{v_i}h^{R(i)} == product A_alpha^{i^alpha} (VSS open).
func verifyShareOpen(eg *schemea.Params, s *vss.ShareSet, i int) bool {
	val, blind, idx := s.ServerShare(i)
	lhs := new(big.Int).Exp(eg.G, val, eg.P)
	hr := new(big.Int).Exp(eg.H, blind, eg.P)
	lhs.Mul(lhs, hr).Mod(lhs, eg.P)
	// product over alpha of A_alpha^{idx^alpha} (exponents live in Z_GMOD)
	acc := big.NewInt(1)
	pw := big.NewInt(1)
	for _, a := range s.Acoeff {
		term := new(big.Int).Exp(a, pw, eg.P)
		acc.Mul(acc, term).Mod(acc, eg.P)
		pw.Mul(pw, idx).Mod(pw, params.GMOD)
	}
	return lhs.Cmp(acc) == 0
}