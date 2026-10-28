package c5

//   invalid input share / invalid d/e opening / invalid intermediate signature /
//   duplicate intermediate server / insufficient f+1 / wrong candidate alpha /
//   server opening mismatch but attempts Auth / duplicate cert signer /

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"

	"c5full/internal/bottomc5"
	"c5full/internal/c5/host"
	"c5full/internal/c5/params"
)

// ---- helpers ---------------------------------------------------------------

func mustRng(t *testing.T, seed string) *deterministicRng {
	t.Helper()
	h := sha256.Sum256([]byte(seed))
	return &deterministicRng{seed: h[:], ctr: 0}
}

type deterministicRng struct {
	seed []byte
	ctr  uint64
}

func (r *deterministicRng) Read(p []byte) (int, error) {
	for i := 0; i < len(p); {
		h := sha256.New()
		h.Write(r.seed)
		var c [8]byte
		for j := 0; j < 8; j++ {
			c[j] = byte(r.ctr >> (8 * j))
		}
		h.Write(c[:])
		sum := h.Sum(nil)
		r.ctr++
		i += copy(p[i:], sum)
	}
	return len(p), nil
}

func testRegistry(n int, t *testing.T) (map[int]ed25519.PublicKey, map[int]ed25519.PrivateKey) {
	t.Helper()
	pubs := map[int]ed25519.PublicKey{}
	privs := map[int]ed25519.PrivateKey{}
	for i := 0; i < n; i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519 keygen: %v", err)
		}
		pubs[i], privs[i] = pub, priv
	}
	return pubs, privs
}

func TestFaithfulBeaverTripleNonDegenerate(t *testing.T) {
	rng := mustRng(t, "beaver-1")
	for trial := 0; trial < 20; trial++ {
		tp, err := NewFaithfulBeaverTriple(1, rng)
		if err != nil {
			t.Fatalf("trial %d: NewFaithfulBeaverTriple: %v", trial, err)
		}
		if err := tp.Check(); err != nil {
			t.Fatalf("trial %d: Check: %v", trial, err)
		}
		if tp.A.Sign() == 0 || tp.B.Sign() == 0 {
			t.Fatalf("trial %d: degenerate triple a=%s b=%s", trial, tp.A, tp.B)
		}
		// c == a*b mod q
		want := new(big.Int).Mul(tp.A, tp.B)
		want.Mod(want, params.Q)
		if tp.C.Cmp(want) != 0 {
			t.Fatalf("trial %d: c != a*b", trial)
		}
		if !tp.NonDegenerate() {
			t.Fatalf("trial %d: NonDegenerate() = false", trial)
		}
	}
}

func TestUpstreamTripleIsDegenerateEvidence(t *testing.T) {
	aWire := bottomc5.NewWireR(1, new(big.Int), mustRng(t, "up-a"))
	bWire := bottomc5.NewWireR(1, new(big.Int), mustRng(t, "up-b"))
	if aWire.Value().Sign() != 0 || bWire.Value().Sign() != 0 {
		t.Fatal("expected upstream-style triple to be degenerate (a=b=0)")
	}
	tp, err := NewFaithfulBeaverTriple(1, mustRng(t, "fixed"))
	if err != nil {
		t.Fatal(err)
	}
	if tp.A.Sign() == 0 || tp.B.Sign() == 0 {
		t.Fatal("faithful triple must not be degenerate")
	}
}

func TestFaithfulBeaverTripleNilRng(t *testing.T) {
	if _, err := NewFaithfulBeaverTriple(1, nil); err == nil {
		t.Fatal("expected error on nil rng")
	}
}

func TestFaithfulBeaverTripleCheckRejectsBad(t *testing.T) {
	// nil wire
	var nilTp *FaithfulBeaverTriple
	if err := nilTp.Check(); err == nil {
		t.Fatal("expected error for nil triple")
	}
	// c != a*b
	tp, err := NewFaithfulBeaverTriple(1, mustRng(t, "bad-c"))
	if err != nil {
		t.Fatal(err)
	}
	bad := &FaithfulBeaverTriple{WireA: tp.WireA, WireB: tp.WireB,
		WireC: bottomc5.NewWireR(1, big.NewInt(7), mustRng(t, "other"))}
	if err := bad.Check(); err == nil {
		t.Fatal("expected c != a*b to be rejected")
	}
}

func TestCheckInputShareAcceptsValid(t *testing.T) {
	w := bottomc5.NewWireR(1, big.NewInt(12345), mustRng(t, "wire-x"))
	for i := 0; i < 3; i++ {
		xi := big.NewInt(int64(i + 1))
		wi, rhoi := bottomc5.WireShareOf(w, xi)
		if err := CheckInputShare(w.Commit, xi, wi, rhoi); err != nil {
			t.Fatalf("server %d: valid share rejected: %v", i, err)
		}
	}
}

func TestCheckInputShareRejectsTampered(t *testing.T) {
	w := bottomc5.NewWireR(1, big.NewInt(999), mustRng(t, "wire-y"))
	xi := big.NewInt(1)
	wi, rhoi := bottomc5.WireShareOf(w, xi)

	cases := []struct {
		name   string
		w, rho *big.Int
	}{
		{"tampered value", new(big.Int).Add(wi, big.NewInt(1)), rhoi},
		{"tampered blinding", wi, new(big.Int).Add(rhoi, big.NewInt(1))},
		{"both tampered", new(big.Int).Add(wi, big.NewInt(2)), new(big.Int).Add(rhoi, big.NewInt(3))},
	}
	for _, c := range cases {
		if err := CheckInputShare(w.Commit, xi, c.w, c.rho); !errors.Is(err, ErrInputShareCheck) {
			t.Fatalf("%s: expected ErrInputShareCheck, got %v", c.name, err)
		}
	}
	if err := CheckInputShare(nil, xi, wi, rhoi); err == nil {
		t.Fatal("expected error on empty commitment")
	}
	if err := CheckInputShare(w.Commit, nil, wi, rhoi); err == nil {
		t.Fatal("expected error on nil xi")
	}
	if err := CheckInputShare(w.Commit, xi, nil, rhoi); err == nil {
		t.Fatal("expected error on nil w")
	}
	if err := CheckInputShare(w.Commit, xi, wi, nil); err == nil {
		t.Fatal("expected error on nil rho")
	}
}

func TestCheckWireSharesReport(t *testing.T) {
	w := bottomc5.NewWireR(1, big.NewInt(42), mustRng(t, "wire-z"))
	xi := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)}
	reps := CheckWireShares([]byte("tau"), "x", w, xi)
	if len(reps) != 3 {
		t.Fatalf("want 3 reports, got %d", len(reps))
	}
	if !AllPassed(reps) {
		t.Fatal("all reports should pass for an honest wire")
	}
	for i, r := range reps {
		if !r.Checked || !r.Passed {
			t.Fatalf("report %d not checked/passed: %+v", i, r)
		}
		if r.WireLabel != "x" || r.Index1Based != i+1 {
			t.Fatalf("report %d has wrong label/index: %+v", i, r)
		}
	}
	if AllPassed(nil) {
		t.Fatal("AllPassed(nil) must be false")
	}
	reps[1].Passed = false
	if AllPassed(reps) {
		t.Fatal("AllPassed must be false when one report failed")
	}
	reps[1].Passed = true
	reps[2].Checked = false
	if AllPassed(reps) {
		t.Fatal("AllPassed must be false when a check was not performed")
	}
}

// ---- C5-M1: signed DiffShareEnvelope ---------------------------------------

func TestDiffShareEnvelopeRoundTrip(t *testing.T) {
	pubs, privs := testRegistry(3, t)
	taskCtx := []byte("task-ctx-abc")
	s := bottomc5.DiffShare{Index: 1, D: big.NewInt(11), Delta: big.NewInt(22),
		E: big.NewInt(33), Eps: big.NewInt(44)}

	env := SignDiffShare(privs[1], taskCtx, 1, s)
	got, err := VerifyDiffShareEnvelope(env, taskCtx, pubs)
	if err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}
	if got.Index != 1 || got.D.Cmp(s.D) != 0 || got.Delta.Cmp(s.Delta) != 0 ||
		got.E.Cmp(s.E) != 0 || got.Eps.Cmp(s.Eps) != 0 {
		t.Fatalf("round-trip mismatch: got %+v want %+v", got, s)
	}
	if env.Index1Based != 2 {
		t.Fatalf("index_1based = %d, want 2", env.Index1Based)
	}
}

func TestDiffShareEnvelopeRejectsTamperedD(t *testing.T) {
	pubs, privs := testRegistry(3, t)
	taskCtx := []byte("tau")
	env := SignDiffShare(privs[0], taskCtx, 0,
		bottomc5.DiffShare{Index: 0, D: big.NewInt(5), Delta: big.NewInt(6), E: big.NewInt(7), Eps: big.NewInt(8)})

	orig := env.DHex
	env.DHex = "0000000000000000000000000000000000000000000000000000000000000009"
	if _, err := VerifyDiffShareEnvelope(env, taskCtx, pubs); !errors.Is(err, ErrEnvelopeBadSignature) {
		t.Fatalf("tampered d: expected ErrEnvelopeBadSignature, got %v", err)
	}
	env.DHex = orig

	env.EHex = "000000000000000000000000000000000000000000000000000000000000001f"
	if _, err := VerifyDiffShareEnvelope(env, taskCtx, pubs); !errors.Is(err, ErrEnvelopeBadSignature) {
		t.Fatalf("tampered e: expected ErrEnvelopeBadSignature, got %v", err)
	}
	env.EHex = "0000000000000000000000000000000000000000000000000000000000000007"

	env.SigHex = "00" + env.SigHex[2:]
	if _, err := VerifyDiffShareEnvelope(env, taskCtx, pubs); !errors.Is(err, ErrEnvelopeBadSignature) {
		t.Fatalf("tampered sig: expected ErrEnvelopeBadSignature, got %v", err)
	}
}

func TestDiffShareEnvelopeRejectsWrongServer(t *testing.T) {
	pubs, privs := testRegistry(3, t)
	taskCtx := []byte("tau")
	s := bottomc5.DiffShare{Index: 0, D: big.NewInt(1), Delta: big.NewInt(2), E: big.NewInt(3), Eps: big.NewInt(4)}

	env := SignDiffShare(privs[0], taskCtx, 0, s)
	env.ServerIndex = 2
	env.Index1Based = 3
	if _, err := VerifyDiffShareEnvelope(env, taskCtx, pubs); !errors.Is(err, ErrEnvelopeBadSignature) {
		t.Fatalf("impersonation: expected ErrEnvelopeBadSignature, got %v", err)
	}

	env2 := SignDiffShare(privs[0], taskCtx, 0, s)
	env2.ServerIndex = 99
	env2.Index1Based = 100
	if _, err := VerifyDiffShareEnvelope(env2, taskCtx, pubs); !errors.Is(err, ErrEnvelopeUnknownServer) {
		t.Fatalf("unknown server: expected ErrEnvelopeUnknownServer, got %v", err)
	}
}

func TestDiffShareEnvelopeRejectsTaskMismatch(t *testing.T) {
	pubs, privs := testRegistry(2, t)
	env := SignDiffShare(privs[0], []byte("task-A"), 0,
		bottomc5.DiffShare{Index: 0, D: big.NewInt(1), Delta: big.NewInt(1), E: big.NewInt(1), Eps: big.NewInt(1)})
	if _, err := VerifyDiffShareEnvelope(env, []byte("task-B"), pubs); !errors.Is(err, ErrEnvelopeTaskMismatch) {
		t.Fatalf("task mismatch: expected ErrEnvelopeTaskMismatch, got %v", err)
	}
}

func TestDiffShareEnvelopeShapeErrors(t *testing.T) {
	pubs, privs := testRegistry(2, t)
	taskCtx := []byte("tau")
	base := SignDiffShare(privs[0], taskCtx, 0,
		bottomc5.DiffShare{Index: 0, D: big.NewInt(1), Delta: big.NewInt(1), E: big.NewInt(1), Eps: big.NewInt(1)})

	e1 := base
	e1.Schema = "wrong"
	if _, err := VerifyDiffShareEnvelope(e1, taskCtx, pubs); !errors.Is(err, ErrEnvelopeShape) {
		t.Fatalf("bad schema: expected ErrEnvelopeShape, got %v", err)
	}
	e2 := base
	e2.Index1Based = 7
	if _, err := VerifyDiffShareEnvelope(e2, taskCtx, pubs); !errors.Is(err, ErrEnvelopeShape) {
		t.Fatalf("bad index_1based: expected ErrEnvelopeShape, got %v", err)
	}
	e3 := base
	e3.TaskCtxHex = "zz"
	if _, err := VerifyDiffShareEnvelope(e3, taskCtx, pubs); !errors.Is(err, ErrEnvelopeShape) {
		t.Fatalf("bad task hex: expected ErrEnvelopeShape, got %v", err)
	}
	e4 := base
	e4.DHex = "zz"
	if _, err := VerifyDiffShareEnvelope(e4, taskCtx, pubs); !errors.Is(err, ErrEnvelopeShape) {
		t.Fatalf("bad d hex: expected ErrEnvelopeShape, got %v", err)
	}
	e5 := base
	e5.DeltaHex = "zz"
	if _, err := VerifyDiffShareEnvelope(e5, taskCtx, pubs); !errors.Is(err, ErrEnvelopeShape) {
		t.Fatalf("bad delta hex: expected ErrEnvelopeShape, got %v", err)
	}
	e6 := base
	e6.EHex = "zz"
	if _, err := VerifyDiffShareEnvelope(e6, taskCtx, pubs); !errors.Is(err, ErrEnvelopeShape) {
		t.Fatalf("bad e hex: expected ErrEnvelopeShape, got %v", err)
	}
	e7 := base
	e7.EpsHex = "zz"
	if _, err := VerifyDiffShareEnvelope(e7, taskCtx, pubs); !errors.Is(err, ErrEnvelopeShape) {
		t.Fatalf("bad eps hex: expected ErrEnvelopeShape, got %v", err)
	}
	e8 := base
	e8.SigHex = "00"
	if _, err := VerifyDiffShareEnvelope(e8, taskCtx, pubs); !errors.Is(err, ErrEnvelopeBadSignature) {
		t.Fatalf("short sig: expected ErrEnvelopeBadSignature, got %v", err)
	}
	e9 := base
	e9.DHex = "00" + e9.DHex
	if _, err := VerifyDiffShareEnvelope(e9, taskCtx, pubs); !errors.Is(err, ErrEnvelopeShape) {
		t.Fatalf("long scalar: expected ErrEnvelopeShape, got %v", err)
	}
}

func TestCollectDistinctValid(t *testing.T) {
	const n, f = 3, 1
	pubs, privs := testRegistry(n, t)
	taskCtx := []byte("collect-tau")
	rng := mustRng(t, "collect")

	wx := bottomc5.NewWireR(f, big.NewInt(1000), rng)
	wa := bottomc5.NewWireR(f, big.NewInt(7), rng)
	wy := bottomc5.NewWireR(f, big.NewInt(2000), rng)
	wb := bottomc5.NewWireR(f, big.NewInt(9), rng)

	axMinusAa := diffCommit(wx.Commit, wa.Commit)
	ayMinusAb := diffCommit(wy.Commit, wb.Commit)
	xiOf := func(i int) *big.Int { return big.NewInt(int64(i + 1)) }

	envs := make([]DiffShareEnvelope, 0, n)
	for i := 0; i < n; i++ {
		xi := xiOf(i)
		xv, xr := bottomc5.WireShareOf(wx, xi)
		av, ar := bottomc5.WireShareOf(wa, xi)
		yv, yr := bottomc5.WireShareOf(wy, xi)
		bv, br := bottomc5.WireShareOf(wb, xi)
		s := bottomc5.DiffShare{
			Index: i,
			D:     subMod(xv, av), Delta: subMod(xr, ar),
			E: subMod(yv, bv), Eps: subMod(yr, br),
		}
		envs = append(envs, SignDiffShare(privs[i], taskCtx, i, s))
	}

	valid, rejected := CollectDistinctValid(envs, taskCtx, pubs, xiOf, axMinusAa, ayMinusAb)
	if len(valid) != n {
		t.Fatalf("want %d valid, got %d (rejected=%v)", n, len(valid), rejected)
	}
	if len(rejected) != 0 {
		t.Fatalf("no rejections expected, got %v", rejected)
	}
	if err := RequireThreshold(valid, f); err != nil {
		t.Fatalf("threshold should be met: %v", err)
	}
}

func TestCollectDistinctValidDuplicateIndex(t *testing.T) {
	const n, f = 3, 1
	pubs, privs := testRegistry(n, t)
	taskCtx := []byte("dup-tau")
	rng := mustRng(t, "dup")

	wx := bottomc5.NewWireR(f, big.NewInt(1000), rng)
	wa := bottomc5.NewWireR(f, big.NewInt(7), rng)
	wy := bottomc5.NewWireR(f, big.NewInt(2000), rng)
	wb := bottomc5.NewWireR(f, big.NewInt(9), rng)
	axMinusAa := diffCommit(wx.Commit, wa.Commit)
	ayMinusAb := diffCommit(wy.Commit, wb.Commit)
	xiOf := func(i int) *big.Int { return big.NewInt(int64(i + 1)) }

	xi := xiOf(0)
	xv, xr := bottomc5.WireShareOf(wx, xi)
	av, ar := bottomc5.WireShareOf(wa, xi)
	yv, yr := bottomc5.WireShareOf(wy, xi)
	bv, br := bottomc5.WireShareOf(wb, xi)
	s := bottomc5.DiffShare{Index: 0,
		D: subMod(xv, av), Delta: subMod(xr, ar), E: subMod(yv, bv), Eps: subMod(yr, br)}
	env := SignDiffShare(privs[0], taskCtx, 0, s)

	valid, rejected := CollectDistinctValid([]DiffShareEnvelope{env, env, env},
		taskCtx, pubs, xiOf, axMinusAa, ayMinusAb)
	if len(valid) != 1 {
		t.Fatalf("duplicates must collapse to 1 distinct, got %d", len(valid))
	}
	if _, ok := rejected[0]; !ok {
		t.Fatalf("duplicate should be recorded as rejected: %v", rejected)
	}
	if err := RequireThreshold(valid, f); !errors.Is(err, ErrEnvelopeInsufficient) {
		t.Fatalf("expected ErrEnvelopeInsufficient, got %v", err)
	}
}

func TestCollectDistinctValidOpeningMismatch(t *testing.T) {
	const n, f = 2, 1
	pubs, privs := testRegistry(n, t)
	taskCtx := []byte("open-tau")
	rng := mustRng(t, "open")

	wx := bottomc5.NewWireR(f, big.NewInt(1000), rng)
	wa := bottomc5.NewWireR(f, big.NewInt(7), rng)
	wy := bottomc5.NewWireR(f, big.NewInt(2000), rng)
	wb := bottomc5.NewWireR(f, big.NewInt(9), rng)
	axMinusAa := diffCommit(wx.Commit, wa.Commit)
	ayMinusAb := diffCommit(wy.Commit, wb.Commit)
	xiOf := func(i int) *big.Int { return big.NewInt(int64(i + 1)) }

	xi0 := xiOf(0)
	xv, xr := bottomc5.WireShareOf(wx, xi0)
	av, ar := bottomc5.WireShareOf(wa, xi0)
	yv, yr := bottomc5.WireShareOf(wy, xi0)
	bv, br := bottomc5.WireShareOf(wb, xi0)
	good := SignDiffShare(privs[0], taskCtx, 0, bottomc5.DiffShare{Index: 0,
		D: subMod(xv, av), Delta: subMod(xr, ar), E: subMod(yv, bv), Eps: subMod(yr, br)})

	bad := SignDiffShare(privs[1], taskCtx, 1, bottomc5.DiffShare{Index: 1,
		D: big.NewInt(424242), Delta: big.NewInt(1), E: big.NewInt(2), Eps: big.NewInt(3)})

	valid, rejected := CollectDistinctValid([]DiffShareEnvelope{good, bad},
		taskCtx, pubs, xiOf, axMinusAa, ayMinusAb)
	if len(valid) != 1 {
		t.Fatalf("only server 0 should be valid, got %d", len(valid))
	}
	if !errors.Is(rejected[1], ErrEnvelopeOpening) {
		t.Fatalf("server 1 should be rejected for opening failure, got %v", rejected[1])
	}
}

func TestCollectDistinctValidBadSignatureRejected(t *testing.T) {
	const n, f = 2, 1
	pubs, privs := testRegistry(n, t)
	taskCtx := []byte("badsig-tau")
	rng := mustRng(t, "badsig")
	wx := bottomc5.NewWireR(f, big.NewInt(1), rng)
	wa := bottomc5.NewWireR(f, big.NewInt(1), rng)
	wy := bottomc5.NewWireR(f, big.NewInt(1), rng)
	wb := bottomc5.NewWireR(f, big.NewInt(1), rng)
	axMinusAa := diffCommit(wx.Commit, wa.Commit)
	ayMinusAb := diffCommit(wy.Commit, wb.Commit)
	xiOf := func(i int) *big.Int { return big.NewInt(int64(i + 1)) }

	env := SignDiffShare(privs[0], taskCtx, 0,
		bottomc5.DiffShare{Index: 0, D: big.NewInt(1), Delta: big.NewInt(1), E: big.NewInt(1), Eps: big.NewInt(1)})
	env.SigHex = "aa" + env.SigHex[2:]

	valid, rejected := CollectDistinctValid([]DiffShareEnvelope{env},
		taskCtx, pubs, xiOf, axMinusAa, ayMinusAb)
	if len(valid) != 0 {
		t.Fatalf("bad signature must not be accepted, got %d valid", len(valid))
	}
	if !errors.Is(rejected[0], ErrEnvelopeBadSignature) {
		t.Fatalf("expected ErrEnvelopeBadSignature, got %v", rejected[0])
	}
}

func TestRequireThreshold(t *testing.T) {
	if err := RequireThreshold(nil, 1); !errors.Is(err, ErrEnvelopeInsufficient) {
		t.Fatalf("empty should fail threshold, got %v", err)
	}
	one := []bottomc5.DiffShare{{Index: 0}}
	if err := RequireThreshold(one, 1); !errors.Is(err, ErrEnvelopeInsufficient) {
		t.Fatalf("1 < f+1=2 must fail, got %v", err)
	}
	two := []bottomc5.DiffShare{{Index: 0}, {Index: 1}}
	if err := RequireThreshold(two, 1); err != nil {
		t.Fatalf("2 >= f+1=2 should pass, got %v", err)
	}
	if err := RequireThreshold(one, 0); err != nil {
		t.Fatalf("1 >= f+1=1 should pass, got %v", err)
	}
}

func TestVerifyDiffShareOpeningDirect(t *testing.T) {
	const f = 1
	rng := mustRng(t, "direct")
	wx := bottomc5.NewWireR(f, big.NewInt(11), rng)
	wa := bottomc5.NewWireR(f, big.NewInt(3), rng)
	wy := bottomc5.NewWireR(f, big.NewInt(13), rng)
	wb := bottomc5.NewWireR(f, big.NewInt(5), rng)
	axMinusAa := diffCommit(wx.Commit, wa.Commit)
	ayMinusAb := diffCommit(wy.Commit, wb.Commit)
	xi := big.NewInt(1)
	xv, xr := bottomc5.WireShareOf(wx, xi)
	av, ar := bottomc5.WireShareOf(wa, xi)
	yv, yr := bottomc5.WireShareOf(wy, xi)
	bv, br := bottomc5.WireShareOf(wb, xi)
	ok := bottomc5.DiffShare{Index: 0, D: subMod(xv, av), Delta: subMod(xr, ar), E: subMod(yv, bv), Eps: subMod(yr, br)}
	if !VerifyDiffShareOpening(ok, xi, axMinusAa, ayMinusAb) {
		t.Fatal("honest diff share must pass opening check")
	}
	bad := ok
	bad.D = new(big.Int).Add(ok.D, big.NewInt(1))
	if VerifyDiffShareOpening(bad, xi, axMinusAa, ayMinusAb) {
		t.Fatal("tampered d must fail opening check")
	}
	bad2 := ok
	bad2.E = new(big.Int).Add(ok.E, big.NewInt(1))
	if VerifyDiffShareOpening(bad2, xi, axMinusAa, ayMinusAb) {
		t.Fatal("tampered e must fail opening check")
	}
}

// ---- C5-M6: receiver PoP ---------------------------------------------------

func TestReceiverPoPRoundTrip(t *testing.T) {
	rng := mustRng(t, "pop-1")
	kp, err := NewReceiverKeyPair(rng)
	if err != nil {
		t.Fatal(err)
	}
	taskCtx := []byte("pop-task-ctx")
	reg, err := NewReceiverRegistration(taskCtx, "R1", kp.XR, rng)
	if err != nil {
		t.Fatalf("generate PoP: %v", err)
	}
	if err := VerifyReceiverPoP(reg, taskCtx, "R1"); err != nil {
		t.Fatalf("valid PoP rejected: %v", err)
	}
}

func TestReceiverPoPRejectsWrongU(t *testing.T) {
	rng := mustRng(t, "pop-2")
	kp, _ := NewReceiverKeyPair(rng)
	taskCtx := []byte("tau")
	reg, err := NewReceiverRegistration(taskCtx, "R1", kp.XR, rng)
	if err != nil {
		t.Fatal(err)
	}
	reg.URHex = "0000000000000000000000000000000000000000000000000000000000000001"
	if err := VerifyReceiverPoP(reg, taskCtx, "R1"); !errors.Is(err, ErrPoPVerify) {
		t.Fatalf("wrong u: expected ErrPoPVerify, got %v", err)
	}
}

func TestReceiverPoPRejectsWrongTaskBinding(t *testing.T) {
	rng := mustRng(t, "pop-3")
	kp, _ := NewReceiverKeyPair(rng)
	reg, err := NewReceiverRegistration([]byte("task-A"), "R1", kp.XR, rng)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReceiverPoP(reg, []byte("task-B"), "R1"); !errors.Is(err, ErrRegistrationBind) {
		t.Fatalf("task swap: expected ErrRegistrationBind, got %v", err)
	}
	if err := VerifyReceiverPoP(reg, []byte("task-A"), "R2"); !errors.Is(err, ErrRegistrationBind) {
		t.Fatalf("receiver swap: expected ErrRegistrationBind, got %v", err)
	}
}

func TestReceiverPoPShapeErrors(t *testing.T) {
	rng := mustRng(t, "pop-4")
	kp, _ := NewReceiverKeyPair(rng)
	taskCtx := []byte("tau")
	good, err := NewReceiverRegistration(taskCtx, "R1", kp.XR, rng)
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyReceiverPoP(nil, taskCtx, "R1"); !errors.Is(err, ErrPoPShape) {
		t.Fatalf("nil reg: expected ErrPoPShape, got %v", err)
	}
	badSchema := *good
	badSchema.Schema = "x"
	if err := VerifyReceiverPoP(&badSchema, taskCtx, "R1"); !errors.Is(err, ErrPoPShape) {
		t.Fatalf("bad schema: expected ErrPoPShape, got %v", err)
	}
	badCtx := *good
	badCtx.TaskCtxHex = "zz"
	if err := VerifyReceiverPoP(&badCtx, taskCtx, "R1"); !errors.Is(err, ErrPoPShape) {
		t.Fatalf("bad ctx hex: expected ErrPoPShape, got %v", err)
	}
	badPK := *good
	badPK.PKRHex = "zz"
	if err := VerifyReceiverPoP(&badPK, taskCtx, "R1"); !errors.Is(err, ErrPoPShape) {
		t.Fatalf("bad pk hex: expected ErrPoPShape, got %v", err)
	}
	badT := *good
	badT.TRHex = "zz"
	if err := VerifyReceiverPoP(&badT, taskCtx, "R1"); !errors.Is(err, ErrPoPShape) {
		t.Fatalf("bad T hex: expected ErrPoPShape, got %v", err)
	}
	badU := *good
	badU.URHex = "zz"
	if err := VerifyReceiverPoP(&badU, taskCtx, "R1"); !errors.Is(err, ErrPoPShape) {
		t.Fatalf("bad u hex: expected ErrPoPShape, got %v", err)
	}
	big2 := *good
	big2.URHex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if err := VerifyReceiverPoP(&big2, taskCtx, "R1"); !errors.Is(err, ErrPoPShape) {
		t.Fatalf("u out of range: expected ErrPoPShape, got %v", err)
	}
	inf := *good
	inf.PKRHex = "00"
	if err := VerifyReceiverPoP(&inf, taskCtx, "R1"); !errors.Is(err, ErrPoPShape) {
		t.Fatalf("infinity pk: expected ErrPoPShape, got %v", err)
	}
	if _, err := NewReceiverRegistration(nil, "R1", kp.XR, rng); !errors.Is(err, ErrPoPShape) {
		t.Fatalf("nil ctx: expected ErrPoPShape, got %v", err)
	}
	if _, err := NewReceiverRegistration(taskCtx, "", kp.XR, rng); !errors.Is(err, ErrPoPShape) {
		t.Fatalf("empty id: expected ErrPoPShape, got %v", err)
	}
	if _, err := NewReceiverRegistration(taskCtx, "R1", nil, rng); !errors.Is(err, ErrPoPShape) {
		t.Fatalf("nil xR: expected ErrPoPShape, got %v", err)
	}
	if _, err := NewReceiverRegistration(taskCtx, "R1", big.NewInt(0), rng); !errors.Is(err, ErrPoPShape) {
		t.Fatalf("zero xR: expected ErrPoPShape, got %v", err)
	}
	if _, err := NewReceiverRegistration(taskCtx, "R1", kp.XR, nil); !errors.Is(err, ErrPoPShape) {
		t.Fatalf("nil rng: expected ErrPoPShape, got %v", err)
	}
	if _, err := NewReceiverKeyPair(nil); !errors.Is(err, ErrPoPShape) {
		t.Fatalf("nil rng keypair: expected ErrPoPShape, got %v", err)
	}
}

func TestVerifyRegistrationSeparatesPoPAndAuth(t *testing.T) {
	rng := mustRng(t, "reg-1")
	kp, _ := NewReceiverKeyPair(rng)
	taskCtx := []byte("tau")
	reg, err := NewReceiverRegistration(taskCtx, "R1", kp.XR, rng)
	if err != nil {
		t.Fatal(err)
	}
	authOK := &ReceiverAuthorization{ReceiverID: "R1", TaskCtxHex: hexEncode(taskCtx), Authorized: true}
	if err := VerifyRegistration(reg, authOK, taskCtx, "R1"); err != nil {
		t.Fatalf("valid registration rejected: %v", err)
	}
	authNo := &ReceiverAuthorization{ReceiverID: "R1", TaskCtxHex: hexEncode(taskCtx), Authorized: false}
	if err := VerifyRegistration(reg, authNo, taskCtx, "R1"); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("unauthorized: expected ErrNotAuthorized, got %v", err)
	}
	// nil auth
	if err := VerifyRegistration(reg, nil, taskCtx, "R1"); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("nil auth: expected ErrNotAuthorized, got %v", err)
	}
	authWrong := &ReceiverAuthorization{ReceiverID: "R2", TaskCtxHex: hexEncode(taskCtx), Authorized: true}
	if err := VerifyRegistration(reg, authWrong, taskCtx, "R1"); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("wrong subject: expected ErrNotAuthorized, got %v", err)
	}
	authTask := &ReceiverAuthorization{ReceiverID: "R1", TaskCtxHex: hexEncode([]byte("other")), Authorized: true}
	if err := VerifyRegistration(reg, authTask, taskCtx, "R1"); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("wrong task: expected ErrNotAuthorized, got %v", err)
	}
	authBadHex := &ReceiverAuthorization{ReceiverID: "R1", TaskCtxHex: "zz", Authorized: true}
	if err := VerifyRegistration(reg, authBadHex, taskCtx, "R1"); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("bad auth hex: expected ErrNotAuthorized, got %v", err)
	}
	badReg := *reg
	badReg.URHex = "0000000000000000000000000000000000000000000000000000000000000001"
	if err := VerifyRegistration(&badReg, authOK, taskCtx, "R1"); !errors.Is(err, ErrPoPVerify) {
		t.Fatalf("bad pop: expected ErrPoPVerify, got %v", err)
	}
}

// ---- C5-M4: server actors + C5-M5: VerifyCertFaithful ----------------------

func setupActors(t *testing.T, n, f, L int, seed string) ([]*ServerActor, *CertFaithful, []*big.Int) {
	t.Helper()
	rng := mustRng(t, seed)
	taskCtx := []byte("actor-tau")

	outs := make([]*bottomc5.Wire, L)
	for j := 0; j < L; j++ {
		outs[j] = bottomc5.NewWireR(f, big.NewInt(int64(500+j*13)), rng)
	}
	aout := make([][]*secp256k1.G1Affine, L)
	for j := 0; j < L; j++ {
		aout[j] = outs[j].Commit
	}

	xi := make([]*big.Int, n)
	for i := range xi {
		xi[i] = big.NewInt(int64(i + 1))
	}

	pubs, privs := testRegistry(n, t)
	alpha := host.HashState(taskCtx, aout)
	kp, err := NewReceiverKeyPair(rng)
	if err != nil {
		t.Fatal(err)
	}

	actors := make([]*ServerActor, 0, n)
	for i := 0; i < n; i++ {
		shares := make([]SharePair, L)
		for j := 0; j < L; j++ {
			z, r := bottomc5.WireShareOf(outs[j], xi[i])
			shares[j] = SharePair{Z: z, Rho: r}
		}
		a, err := NewServerActor(i, privs[i], taskCtx, alpha, aout, xi[i], shares)
		if err != nil {
			t.Fatalf("NewServerActor %d: %v", i, err)
		}
		actors = append(actors, a)
	}
	cert := &CertFaithful{
		TaskCtx: taskCtx, PKR: kp.PKR, Aout: aout, Alpha: alpha,
		Registry: pubs, NF: n - f,
	}
	return actors, cert, xi
}

func TestServerActorsEndorseAndVerifyCert(t *testing.T) {
	const n, f, L = 3, 1, 1
	actors, cert, _ := setupActors(t, n, f, L, "actors-1")

	if err := AssertKeyIsolation(actors); err != nil {
		t.Fatalf("key isolation: %v", err)
	}

	for _, a := range actors {
		auth, err := a.Endorse()
		if err != nil {
			t.Fatalf("server %d Endorse: %v", a.Index, err)
		}
		sig, err := hexDecode(auth.SigHex)
		if err != nil {
			t.Fatal(err)
		}
		cert.Q = append(cert.Q, auth.ServerIndex)
		cert.Sigs = append(cert.Sigs, sig)
	}

	valid, err := VerifyCertFaithful(cert)
	if err != nil {
		t.Fatalf("VerifyCertFaithful: %v", err)
	}
	if valid != n {
		t.Fatalf("want %d valid signers, got %d", n, valid)
	}
}

func TestServerActorRefusesToSignOnOpeningMismatch(t *testing.T) {
	const n, f, L = 3, 1, 1
	actors, _, _ := setupActors(t, n, f, L, "actors-2")

	bad := actors[0]
	bad.shares[0] = SharePair{Z: big.NewInt(999999), Rho: big.NewInt(1)}
	if _, err := bad.Endorse(); !errors.Is(err, ErrActorOpeningMismatch) {
		t.Fatalf("expected ErrActorOpeningMismatch, got %v", err)
	}
}

func TestVerifyCertFaithfulRejectsWrongAlpha(t *testing.T) {
	const n, f, L = 3, 1, 1
	actors, cert, _ := setupActors(t, n, f, L, "actors-3")
	for _, a := range actors {
		auth, _ := a.Endorse()
		sig, _ := hexDecode(auth.SigHex)
		cert.Q = append(cert.Q, auth.ServerIndex)
		cert.Sigs = append(cert.Sigs, sig)
	}
	bad := *cert
	bad.Alpha = bytes.Repeat([]byte{0xAA}, len(cert.Alpha))
	if _, err := VerifyCertFaithful(&bad); !errors.Is(err, ErrCertAlphaMismatch) {
		t.Fatalf("wrong alpha: expected ErrCertAlphaMismatch, got %v", err)
	}
}

func TestVerifyCertFaithfulRejectsNonRegistryServer(t *testing.T) {
	const n, f, L = 3, 1, 1
	actors, cert, _ := setupActors(t, n, f, L, "actors-4")
	for _, a := range actors {
		auth, _ := a.Endorse()
		sig, _ := hexDecode(auth.SigHex)
		cert.Q = append(cert.Q, auth.ServerIndex)
		cert.Sigs = append(cert.Sigs, sig)
	}
	bad := *cert
	bad.Q = append([]int(nil), cert.Q...)
	bad.Q[0] = 99
	if _, err := VerifyCertFaithful(&bad); !errors.Is(err, ErrActorNotInRegistry) {
		t.Fatalf("non-registry: expected ErrActorNotInRegistry, got %v", err)
	}
}

func TestVerifyCertFaithfulRejectsDuplicateSigner(t *testing.T) {
	const n, f, L = 3, 1, 1
	actors, cert, _ := setupActors(t, n, f, L, "actors-5")
	auth0, _ := actors[0].Endorse()
	sig0, _ := hexDecode(auth0.SigHex)
	cert.Q = []int{0, 0}
	cert.Sigs = [][]byte{sig0, sig0}
	if _, err := VerifyCertFaithful(cert); !errors.Is(err, ErrCertDuplicateSigner) {
		t.Fatalf("duplicate: expected ErrCertDuplicateSigner, got %v", err)
	}
}

func TestVerifyCertFaithfulRejectsBadSignature(t *testing.T) {
	const n, f, L = 3, 1, 1
	actors, cert, _ := setupActors(t, n, f, L, "actors-6")
	for _, a := range actors {
		auth, _ := a.Endorse()
		sig, _ := hexDecode(auth.SigHex)
		cert.Q = append(cert.Q, auth.ServerIndex)
		cert.Sigs = append(cert.Sigs, sig)
	}
	bad := *cert
	bad.Sigs = append([][]byte(nil), cert.Sigs...)
	bad.Sigs[0] = bytes.Repeat([]byte{0x00}, ed25519.SignatureSize)
	if _, err := VerifyCertFaithful(&bad); !errors.Is(err, ErrCertBadSignature) {
		t.Fatalf("bad sig: expected ErrCertBadSignature, got %v", err)
	}
}

func TestVerifyCertFaithfulRejectsInsufficientThreshold(t *testing.T) {
	const n, f, L = 5, 2, 1 // n-f = 3
	actors, cert, _ := setupActors(t, n, f, L, "actors-7")
	for i := 0; i < 2; i++ {
		auth, _ := actors[i].Endorse()
		sig, _ := hexDecode(auth.SigHex)
		cert.Q = append(cert.Q, auth.ServerIndex)
		cert.Sigs = append(cert.Sigs, sig)
	}
	if _, err := VerifyCertFaithful(cert); !errors.Is(err, ErrCertInsufficient) {
		t.Fatalf("insufficient: expected ErrCertInsufficient, got %v", err)
	}
}

func TestVerifyCertFaithfulShapeErrors(t *testing.T) {
	if _, err := VerifyCertFaithful(nil); !errors.Is(err, ErrCertShape) {
		t.Fatalf("nil: expected ErrCertShape, got %v", err)
	}
	const n, f, L = 3, 1, 1
	actors, cert, _ := setupActors(t, n, f, L, "actors-8")
	auth, _ := actors[0].Endorse()
	sig, _ := hexDecode(auth.SigHex)

	c1 := *cert
	c1.Q, c1.Sigs = []int{0, 1}, [][]byte{sig}
	if _, err := VerifyCertFaithful(&c1); !errors.Is(err, ErrCertShape) {
		t.Fatalf("len mismatch: expected ErrCertShape, got %v", err)
	}
	c2 := *cert
	c2.Q, c2.Sigs = nil, nil
	if _, err := VerifyCertFaithful(&c2); !errors.Is(err, ErrCertShape) {
		t.Fatalf("empty Q: expected ErrCertShape, got %v", err)
	}
	// nil TaskCtx
	c3 := *cert
	c3.TaskCtx = nil
	if _, err := VerifyCertFaithful(&c3); !errors.Is(err, ErrCertShape) {
		t.Fatalf("nil ctx: expected ErrCertShape, got %v", err)
	}
	// nil PKR
	c4 := *cert
	c4.PKR = nil
	if _, err := VerifyCertFaithful(&c4); !errors.Is(err, ErrCertShape) {
		t.Fatalf("nil pkR: expected ErrCertShape, got %v", err)
	}
	// nil Alpha
	c5 := *cert
	c5.Alpha = nil
	if _, err := VerifyCertFaithful(&c5); !errors.Is(err, ErrCertShape) {
		t.Fatalf("nil alpha: expected ErrCertShape, got %v", err)
	}
	c6 := *cert
	c6.NF = -1
	if _, err := VerifyCertFaithful(&c6); !errors.Is(err, ErrCertShape) {
		t.Fatalf("negative nf: expected ErrCertShape, got %v", err)
	}
	c7 := *cert
	c7.Aout = nil
	if _, err := VerifyCertFaithful(&c7); !errors.Is(err, ErrCertShape) {
		t.Fatalf("empty aout: expected ErrCertShape, got %v", err)
	}
}

func TestNewServerActorShapeErrors(t *testing.T) {
	_, privs := testRegistry(1, t)
	xi := big.NewInt(1)
	aout := [][]*secp256k1.G1Affine{{{}}}
	shares := []SharePair{{Z: big.NewInt(1), Rho: big.NewInt(1)}}

	if _, err := NewServerActor(0, []byte{1, 2, 3}, []byte("t"), []byte("a"), aout, xi, shares); !errors.Is(err, ErrActorShape) {
		t.Fatalf("bad key: expected ErrActorShape, got %v", err)
	}
	// nil xi
	if _, err := NewServerActor(0, privs[0], []byte("t"), []byte("a"), aout, nil, shares); !errors.Is(err, ErrActorShape) {
		t.Fatalf("nil xi: expected ErrActorShape, got %v", err)
	}
	if _, err := NewServerActor(0, privs[0], []byte("t"), []byte("a"), aout, xi, nil); !errors.Is(err, ErrActorShape) {
		t.Fatalf("share count: expected ErrActorShape, got %v", err)
	}
}

func TestServerActorPublicKey(t *testing.T) {
	const n, f, L = 3, 1, 1
	actors, _, _ := setupActors(t, n, f, L, "pubkey")
	pub := actors[0].PublicKey()
	if pub == nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("PublicKey should return a valid %d-byte key, got len=%d", ed25519.PublicKeySize, len(pub))
	}
}

func TestAssertKeyIsolationRejectsDuplicate(t *testing.T) {
	_, privs := testRegistry(2, t)
	xi := big.NewInt(1)
	aout := [][]*secp256k1.G1Affine{{{}}}
	shares := []SharePair{{Z: big.NewInt(1), Rho: big.NewInt(1)}}
	a0, err := NewServerActor(0, privs[0], []byte("t"), []byte("a"), aout, xi, shares)
	if err != nil {
		t.Fatal(err)
	}
	a1, err := NewServerActor(1, privs[0], []byte("t"), []byte("a"), aout, xi, shares)
	if err != nil {
		t.Fatal(err)
	}
	if err := AssertKeyIsolation([]*ServerActor{a0, a1}); !errors.Is(err, ErrActorShape) {
		t.Fatalf("duplicate keys: expected ErrActorShape, got %v", err)
	}
	a2, _ := NewServerActor(1, privs[1], []byte("t"), []byte("a"), aout, xi, shares)
	if err := AssertKeyIsolation([]*ServerActor{a0, a2}); err != nil {
		t.Fatalf("distinct keys should pass: %v", err)
	}
}

func TestLocalOpeningCheckMultiCoord(t *testing.T) {
	const n, f, L = 3, 1, 2
	actors, _, _ := setupActors(t, n, f, L, "multi-coord")
	for _, a := range actors {
		if err := a.LocalOpeningCheck(); err != nil {
			t.Fatalf("server %d opening check: %v", a.Index, err)
		}
	}
	bad := actors[1]
	bad.shares[1] = SharePair{Z: big.NewInt(7), Rho: big.NewInt(7)}
	if err := bad.LocalOpeningCheck(); !errors.Is(err, ErrActorOpeningMismatch) {
		t.Fatalf("coord 1 tamper: expected ErrActorOpeningMismatch, got %v", err)
	}
}

func diffCommit(a, b []*secp256k1.G1Affine) []*secp256k1.G1Affine {
	out := make([]*secp256k1.G1Affine, len(a))
	for k := range a {
		neg := host.ScalarMul(b[k], big.NewInt(-1))
		out[k] = host.AddPoints(a[k], neg)
	}
	return out
}

func subMod(a, b *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Sub(a, b), params.Q)
}
