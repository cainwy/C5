package schemea

//   invalid share / wrong multiplication intermediate / wrong client blinding factor /
//   wrong Eq17 commitment / wrong Eq16 derivation / wrong server index /

import (
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"c5full/internal/mpc/schemea"
)

func testParams(t *testing.T) *schemea.Params {
	t.Helper()
	p := schemea.NewParams(256, 8, 4, 42)
	if p == nil || p.P == nil || p.G == nil || p.H == nil {
		t.Fatal("NewParams returned nil fields")
	}
	return p
}

func encHex(v *big.Int) string { return hex.EncodeToString(v.Bytes()) }

//	z_i = c_i + e_i·a_i + d_i·b_i + d_i·e_i
//	                     ⇒  cz_i = cc_i · ca_i^{e_i} · cb_i^{d_i} · c(de)_i   (Eq.16)
type mulFixture struct {
	P   *schemea.Params
	M   *MulIntermediate
	St  *MulState
	CzI *big.Int
}

func newMulFixture(t *testing.T, dVal, eVal int64) *mulFixture {
	t.Helper()
	p := testParams(t)

	rx := big.NewInt(101)
	ra := big.NewInt(202)
	ry := big.NewInt(303)
	rb := big.NewInt(404)
	rc := big.NewInt(505)
	rde := big.NewInt(606)

	rd := new(big.Int).Sub(rx, ra)
	re := new(big.Int).Sub(ry, rb)
	d := big.NewInt(dVal)
	e := big.NewInt(eVal)

	a := big.NewInt(1000)
	b := big.NewInt(2000)
	x := new(big.Int).Add(a, d)
	y := new(big.Int).Add(b, e)
	c := big.NewInt(777)

	cx, err := PedersenCommit(p, x, rx)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := PedersenCommit(p, a, ra)
	if err != nil {
		t.Fatal(err)
	}
	cd, err := PedersenCommit(p, d, rd)
	if err != nil {
		t.Fatal(err)
	}
	cy, err := PedersenCommit(p, y, ry)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := PedersenCommit(p, b, rb)
	if err != nil {
		t.Fatal(err)
	}
	ce, err := PedersenCommit(p, e, re)
	if err != nil {
		t.Fatal(err)
	}
	cc, err := PedersenCommit(p, c, rc)
	if err != nil {
		t.Fatal(err)
	}
	// c(de)_i = g^{d·e} h^{r_de}
	de := new(big.Int).Mul(d, e)
	cde, err := PedersenCommit(p, de, rde)
	if err != nil {
		t.Fatal(err)
	}

	m := &MulIntermediate{
		Schema: "sa-mul-intermediate-v1", TaskID: "t1", ServerIndex: 1,
		DHex: encHex(d), EHex: encHex(e),
		CxHex: encHex(cx), CaHex: encHex(ca), CdHex: encHex(cd),
		CyHex: encHex(cy), CbHex: encHex(cb), CeHex: encHex(ce),
	}
	st := &MulState{
		Params: p,
		CC:     map[int]*big.Int{1: cc},
		CDe:    map[int]*big.Int{1: cde},
	}

	cea := new(big.Int).Exp(ca, e, p.P)
	cdb := new(big.Int).Exp(cb, d, p.P)
	want := MulMod(p, cc, cea)
	want = MulMod(p, want, cdb)
	want = MulMod(p, want, cde)

	return &mulFixture{P: p, M: m, St: st, CzI: want}
}

func TestVerifyEq17AcceptsValid(t *testing.T) {
	fx := newMulFixture(t, 7, 9)
	ok, err := VerifyEq17(fx.P, fx.M)
	if err != nil {
		t.Fatalf("Eq17 error: %v", err)
	}
	if !ok {
		t.Fatal("valid Eq17 relation must pass")
	}
}

func TestVerifyEq16DerivesExpected(t *testing.T) {
	fx := newMulFixture(t, 7, 9)
	cz, err := VerifyEq16(fx.P, fx.M, fx.St)
	if err != nil {
		t.Fatalf("Eq16 error: %v", err)
	}
	if cz.Cmp(fx.CzI) != 0 {
		t.Fatalf("Eq16 derived wrong commitment:\n got %s\nwant %s", cz, fx.CzI)
	}
}

func TestDeriveOutputCommitmentChainHappyPath(t *testing.T) {
	fx := newMulFixture(t, 11, 13)
	cz, err := DeriveOutputCommitmentChain(fx.P, fx.M, fx.St)
	if err != nil {
		t.Fatalf("chain error: %v", err)
	}
	if cz.Cmp(fx.CzI) != 0 {
		t.Fatal("chain derived wrong commitment")
	}
}

func TestVerifyAdditionEq15(t *testing.T) {
	p := testParams(t)
	cx, err := PedersenCommit(p, big.NewInt(5), big.NewInt(11))
	if err != nil {
		t.Fatal(err)
	}
	cy, err := PedersenCommit(p, big.NewInt(6), big.NewInt(22))
	if err != nil {
		t.Fatal(err)
	}
	cz, err := VerifyAdditionEq15(p, encHex(cx), encHex(cy))
	if err != nil {
		t.Fatalf("Eq15 error: %v", err)
	}
	want := MulMod(p, cx, cy)
	if cz.Cmp(want) != 0 {
		t.Fatal("Eq15 result mismatch")
	}
	direct, err := PedersenCommit(p, big.NewInt(11), big.NewInt(33))
	if err != nil {
		t.Fatal(err)
	}
	if cz.Cmp(direct) != 0 {
		t.Fatal("Eq15 must equal direct Pedersen of summed values")
	}
}

func TestVerifyEq17RejectsWrongBlindingFactor(t *testing.T) {
	fx := newMulFixture(t, 7, 9)
	p := fx.P
	badCd, err := PedersenCommit(p, big.NewInt(7), big.NewInt(999))
	if err != nil {
		t.Fatal(err)
	}
	fx.M.CdHex = encHex(badCd)
	ok, err := VerifyEq17(p, fx.M)
	if err == nil || ok {
		t.Fatalf("wrong blinding factor must fail Eq17 with an error (ok=%v err=%v)", ok, err)
	}
	if !errors.Is(err, ErrMulEq17Commit) {
		t.Fatalf("expected ErrMulEq17Commit, got %v", err)
	}
}

func TestVerifyEq17RejectsWrongCommitment(t *testing.T) {
	fx := newMulFixture(t, 7, 9)
	p := fx.P
	badCx, err := PedersenCommit(p, big.NewInt(123456), big.NewInt(101))
	if err != nil {
		t.Fatal(err)
	}
	fx.M.CxHex = encHex(badCx)
	ok, err := VerifyEq17(p, fx.M)
	if err == nil || ok {
		t.Fatalf("wrong cx must fail Eq17 (ok=%v err=%v)", ok, err)
	}
	if !errors.Is(err, ErrMulEq17Commit) {
		t.Fatalf("expected ErrMulEq17Commit, got %v", err)
	}
	fx2 := newMulFixture(t, 7, 9)
	badCy, err := PedersenCommit(p, big.NewInt(654321), big.NewInt(303))
	if err != nil {
		t.Fatal(err)
	}
	fx2.M.CyHex = encHex(badCy)
	ok, err = VerifyEq17(p, fx2.M)
	if err == nil || ok {
		t.Fatalf("wrong cy must fail Eq17 (ok=%v err=%v)", ok, err)
	}
	if !errors.Is(err, ErrMulEq17Commit) {
		t.Fatalf("expected ErrMulEq17Commit, got %v", err)
	}
}

func TestWrongMultiplicationIntermediateChangesOutput(t *testing.T) {
	fx := newMulFixture(t, 7, 9)
	fx.M.DHex = encHex(big.NewInt(999))
	ok, err := VerifyEq17(fx.P, fx.M)
	if err != nil || !ok {
		t.Fatalf("Eq17 should pass with tampered d (D not in Eq17), got ok=%v err=%v", ok, err)
	}
	cz, err := VerifyEq16(fx.P, fx.M, fx.St)
	if err != nil {
		t.Fatal(err)
	}
	if cz.Cmp(fx.CzI) == 0 {
		t.Fatal("tampered d must change the Eq16-derived commitment (else Eq18 can't catch it)")
	}

	fx2 := newMulFixture(t, 7, 9)
	fx2.M.EHex = encHex(big.NewInt(555))
	cz2, err := VerifyEq16(fx2.P, fx2.M, fx2.St)
	if err != nil {
		t.Fatal(err)
	}
	if cz2.Cmp(fx2.CzI) == 0 {
		t.Fatal("tampered e must change the Eq16-derived commitment")
	}
}

func TestVerifyEq16RejectsMissingState(t *testing.T) {
	fx := newMulFixture(t, 7, 9)
	st := &MulState{Params: fx.P, CC: map[int]*big.Int{}, CDe: fx.St.CDe}
	if _, err := VerifyEq16(fx.P, fx.M, st); !errors.Is(err, ErrMulMissingState) {
		t.Fatalf("missing cc: expected ErrMulMissingState, got %v", err)
	}
	st2 := &MulState{Params: fx.P, CC: fx.St.CC, CDe: map[int]*big.Int{}}
	if _, err := VerifyEq16(fx.P, fx.M, st2); !errors.Is(err, ErrMulMissingState) {
		t.Fatalf("missing cde: expected ErrMulMissingState, got %v", err)
	}
	// nil state
	if _, err := VerifyEq16(fx.P, fx.M, nil); !errors.Is(err, ErrMulMissingState) {
		t.Fatalf("nil state: expected ErrMulMissingState, got %v", err)
	}
}

func TestVerifyEq16RejectsWrongCC(t *testing.T) {
	fx := newMulFixture(t, 7, 9)
	badCC, err := PedersenCommit(fx.P, big.NewInt(1), big.NewInt(2))
	if err != nil {
		t.Fatal(err)
	}
	st := &MulState{Params: fx.P, CC: map[int]*big.Int{1: badCC}, CDe: fx.St.CDe}
	cz, err := VerifyEq16(fx.P, fx.M, st)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cz.Cmp(fx.CzI) == 0 {
		t.Fatal("tampered cc must change derived commitment")
	}
}

func TestDeriveChainDetectsTamperedCCAgainstEq18(t *testing.T) {
	fx := newMulFixture(t, 7, 9)
	badCC, err := PedersenCommit(fx.P, big.NewInt(4242), big.NewInt(24))
	if err != nil {
		t.Fatal(err)
	}
	st := &MulState{Params: fx.P, CC: map[int]*big.Int{1: badCC}, CDe: fx.St.CDe}
	cz, err := DeriveOutputCommitmentChain(fx.P, fx.M, st)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cz.Cmp(fx.CzI) == 0 {
		t.Fatal("derived commitment must differ when registered state is tampered")
	}
}

func TestDeriveOutputCommitmentChainRejectsBadEq17(t *testing.T) {
	fx := newMulFixture(t, 7, 9)
	fx.M.CxHex = encHex(big.NewInt(3))
	_, err := DeriveOutputCommitmentChain(fx.P, fx.M, fx.St)
	if err == nil {
		t.Fatal("chain must reject when Eq17 fails")
	}
}

func TestMulShapeAndIndexErrors(t *testing.T) {
	p := testParams(t)
	base := newMulFixture(t, 7, 9).M

	// nil params
	if _, err := VerifyEq17(nil, base); !errors.Is(err, ErrMulShape) {
		t.Fatalf("nil params: expected ErrMulShape, got %v", err)
	}
	// nil intermediate
	if _, err := VerifyEq17(p, nil); !errors.Is(err, ErrMulShape) {
		t.Fatalf("nil m: expected ErrMulShape, got %v", err)
	}
	bad := *base
	bad.ServerIndex = 0
	if _, err := VerifyEq17(p, &bad); !errors.Is(err, ErrMulBadIndex) {
		t.Fatalf("index 0: expected ErrMulBadIndex, got %v", err)
	}
	bad2 := *base
	bad2.ServerIndex = -3
	if _, err := VerifyEq17(p, &bad2); !errors.Is(err, ErrMulBadIndex) {
		t.Fatalf("negative index: expected ErrMulBadIndex, got %v", err)
	}
	for _, field := range []string{"DHex", "EHex", "CxHex", "CaHex", "CdHex", "CyHex", "CbHex", "CeHex"} {
		b := *base
		switch field {
		case "DHex":
			b.DHex = ""
		case "EHex":
			b.EHex = ""
		case "CxHex":
			b.CxHex = ""
		case "CaHex":
			b.CaHex = ""
		case "CdHex":
			b.CdHex = ""
		case "CyHex":
			b.CyHex = ""
		case "CbHex":
			b.CbHex = ""
		case "CeHex":
			b.CeHex = ""
		}
		if _, err := VerifyEq17(p, &b); !errors.Is(err, ErrMulShape) {
			t.Fatalf("empty %s: expected ErrMulShape, got %v", field, err)
		}
	}
}

func TestMulMalformedHexAndRange(t *testing.T) {
	p := testParams(t)
	base := newMulFixture(t, 7, 9).M

	bad := *base
	bad.CxHex = "zz"
	if _, err := VerifyEq17(p, &bad); !errors.Is(err, ErrMulShape) {
		t.Fatalf("bad hex: expected ErrMulShape, got %v", err)
	}
	_ = base
	over := *base
	over.CxHex = hex.EncodeToString(new(big.Int).Add(p.P, big.NewInt(1)).Bytes())
	if _, err := VerifyEq17(p, &over); !errors.Is(err, ErrMulShape) {
		t.Fatalf("out of range: expected ErrMulShape, got %v", err)
	}
	zer := *base
	zer.CxHex = "00"
	if _, err := VerifyEq17(p, &zer); !errors.Is(err, ErrMulShape) {
		t.Fatalf("zero element: expected ErrMulShape, got %v", err)
	}
}

func TestPedersenCommitShapeErrors(t *testing.T) {
	p := testParams(t)
	if _, err := PedersenCommit(nil, big.NewInt(1), big.NewInt(1)); !errors.Is(err, ErrMulShape) {
		t.Fatalf("nil params: expected ErrMulShape, got %v", err)
	}
	if _, err := PedersenCommit(p, nil, big.NewInt(1)); !errors.Is(err, ErrMulShape) {
		t.Fatalf("nil v: expected ErrMulShape, got %v", err)
	}
	if _, err := PedersenCommit(p, big.NewInt(1), nil); !errors.Is(err, ErrMulShape) {
		t.Fatalf("nil r: expected ErrMulShape, got %v", err)
	}
}

func TestVerifyAdditionEq15Errors(t *testing.T) {
	p := testParams(t)
	if _, err := VerifyAdditionEq15(nil, "01", "01"); !errors.Is(err, ErrMulShape) {
		t.Fatalf("nil params: expected ErrMulShape, got %v", err)
	}
	if _, err := VerifyAdditionEq15(p, "zz", "01"); !errors.Is(err, ErrMulShape) {
		t.Fatalf("bad hex: expected ErrMulShape, got %v", err)
	}
	if _, err := VerifyAdditionEq15(p, "00", "01"); !errors.Is(err, ErrMulShape) {
		t.Fatalf("zero element: expected ErrMulShape, got %v", err)
	}
}

func TestVerifyShareAgainstPolyCommitments(t *testing.T) {
	p := testParams(t)
	s0, s1 := big.NewInt(111), big.NewInt(222)
	t0, t1 := big.NewInt(333), big.NewInt(444)
	e0, err := PedersenCommit(p, s0, t0)
	if err != nil {
		t.Fatal(err)
	}
	e1, err := PedersenCommit(p, s1, t1)
	if err != nil {
		t.Fatal(err)
	}
	poly := []*big.Int{e0, e1}

	j := 3
	sj := new(big.Int).Add(s0, new(big.Int).Mul(big.NewInt(3), s1))
	tj := new(big.Int).Add(t0, new(big.Int).Mul(big.NewInt(3), t1))

	ok, err := VerifyShareAgainstPolyCommitments(p, poly, j, encHex(sj), encHex(tj))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("honest share must pass poly-commitment check")
	}

	badS := new(big.Int).Add(sj, big.NewInt(1))
	ok, err = VerifyShareAgainstPolyCommitments(p, poly, j, encHex(badS), encHex(tj))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatal("tampered s share must fail")
	}
	badT := new(big.Int).Add(tj, big.NewInt(1))
	ok, err = VerifyShareAgainstPolyCommitments(p, poly, j, encHex(sj), encHex(badT))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatal("tampered t share must fail")
	}
	s4 := new(big.Int).Add(s0, new(big.Int).Mul(big.NewInt(4), s1))
	t4 := new(big.Int).Add(t0, new(big.Int).Mul(big.NewInt(4), t1))
	ok, err = VerifyShareAgainstPolyCommitments(p, poly, j, encHex(s4), encHex(t4))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatal("wrong server index share must fail")
	}
}

func TestVerifyShareAgainstPolyCommitmentsErrors(t *testing.T) {
	p := testParams(t)
	e0, _ := PedersenCommit(p, big.NewInt(1), big.NewInt(1))
	poly := []*big.Int{e0}

	if _, err := VerifyShareAgainstPolyCommitments(nil, poly, 1, "01", "01"); !errors.Is(err, ErrMulShape) {
		t.Fatalf("nil params: expected ErrMulShape, got %v", err)
	}
	if _, err := VerifyShareAgainstPolyCommitments(p, nil, 1, "01", "01"); !errors.Is(err, ErrMulShape) {
		t.Fatalf("empty poly: expected ErrMulShape, got %v", err)
	}
	if _, err := VerifyShareAgainstPolyCommitments(p, poly, 0, "01", "01"); !errors.Is(err, ErrMulBadIndex) {
		t.Fatalf("j=0: expected ErrMulBadIndex, got %v", err)
	}
	if _, err := VerifyShareAgainstPolyCommitments(p, poly, 1, "zz", "01"); !errors.Is(err, ErrMulShape) {
		t.Fatalf("bad hex: expected ErrMulShape, got %v", err)
	}
	// nil poly element
	if _, err := VerifyShareAgainstPolyCommitments(p, []*big.Int{nil}, 1, "01", "01"); !errors.Is(err, ErrMulShape) {
		t.Fatalf("nil element: expected ErrMulShape, got %v", err)
	}
}

func TestDedupeServers(t *testing.T) {
	uniq, dups := DedupeServers([]int{1, 2, 2, 3, 1, 1})
	if len(uniq) != 3 {
		t.Fatalf("want 3 unique, got %d (%v)", len(uniq), uniq)
	}
	if len(dups) != 3 {
		t.Fatalf("want 3 duplicates, got %d (%v)", len(dups), dups)
	}
	if uniq[0] != 1 || uniq[1] != 2 || uniq[2] != 3 {
		t.Fatalf("unique order not preserved: %v", uniq)
	}
	uniq2, dups2 := DedupeServers([]int{5, 6})
	if len(uniq2) != 2 || len(dups2) != 0 {
		t.Fatalf("no-dup case wrong: uniq=%v dups=%v", uniq2, dups2)
	}
	uniq3, dups3 := DedupeServers(nil)
	if len(uniq3) != 0 || len(dups3) != 0 {
		t.Fatal("empty input should give empty output")
	}
}
