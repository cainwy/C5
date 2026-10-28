package m1

// State / finality scaffolding (AP3 M3-2). A Task holds a synthetic committed
// output state (Shamir output polynomials + Pedersen coefficient commitments),
// the receiver key, per-server Ed25519 keys, endorsement signatures, and a
// FinalityRecord (F_Record mock). It keeps certificate validity (CertValid) and
// authoritative finality (Finalized) as separate logical responsibilities, even

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"

	"c5full/internal/c5/host"
	"c5full/internal/c5/params"
)

// ---- canonical context encoding (reuse AP2 C5E1 via host, no second encoding) --

// fieldBytes canonicalizes a big.Int into fixed 32-byte big-endian (F_q).
func fieldBytes(x *big.Int) []byte {
	b := make([]byte, 32)
	x.Mod(new(big.Int).Set(x), params.Q).FillBytes(b)
	return b
}

// ---- FinalityRecord: F_Record mock (single-valued finalization) ------------

// FinalityRecord emulates FR1/FR2/FR3: at most one authoritative state id per
// task version, persistent, publicly readable.
type FinalityRecord struct {
	taskVersion int
	finalized   string // hex state id; empty = none finalized yet
}

func NewFinalityRecord(taskVersion int) *FinalityRecord {
	return &FinalityRecord{taskVersion: taskVersion}
}

// Finalize marks stateID authoritative. Returns true on first finalization (or
// same-state idempotent re-mark), false if a different state is already fixed.
func (r *FinalityRecord) Finalize(stateID string) bool {
	if r.finalized == "" {
		r.finalized = stateID
		return true
	}
	return r.finalized == stateID
}

// IsFinalized reports whether stateID is the authoritative one.
func (r *FinalityRecord) IsFinalized(stateID string) bool {
	return r.finalized != "" && r.finalized == stateID
}

// FinalizedID returns the current authoritative state id ("" if none).
func (r *FinalityRecord) FinalizedID() string { return r.finalized }

// ---- Task ------------------------------------------------------------------

// Task is a full synthetic delivery task (n servers, f threshold, L outputs).
type Task struct {
	N, F, L int
	Seed    string

	Xi []*big.Int // evaluation points xi_i = i (distinct, nonzero), i=1..n

	ReceiverX  *big.Int
	ReceiverPK *secp256k1.G1Affine

	ReceiverAuthorized bool  // AU1 task authorization policy
	ReceiverPoP        *PoP  // Schnorr proof of possession (verified at registration)
	BottomAborted      bool  // BM5 bottom-MPC abort flag (no candidate if true)

	Outputs []*OutputPoly              // L output polynomials (value + blinding)
	Aout    [][]*secp256k1.G1Affine    // L x (f+1) coefficient commitments

	TaskCtx  []byte // canonical task context (C5E1)
	Alpha    []byte // state id = H(DST || TaskCtx || Aout) via host.HashState
	TaskVer  int    // integer task version (matches AP2 u32 encoding)

	ServerPriv []ed25519.PrivateKey
	ServerPub  []ed25519.PublicKey

	Endorsements [][]byte // per-server endorsement signature over (tau, alpha)

	Finality *FinalityRecord
}

// NewTask builds a valid synthetic task. n must be >= 2f+1. Server i uses
// evaluation point xi_i = i. The receiver key is sampled fresh; servers get
// fresh Ed25519 keys. Production default random source: crypto/rand (LA-03).
func NewTask(n, f, L int, seed string) (*Task, error) {
	return NewTaskWithRNG(n, f, L, seed, rand.Reader)
}

func NewTaskWithRNG(n, f, L int, seed string, rng io.Reader) (*Task, error) {
	if n < 2*f+1 || f < 0 || L < 1 {
		return nil, errBadParams
	}
	t := &Task{N: n, F: f, L: L, Seed: seed, TaskVer: 1, ReceiverAuthorized: true}

	// evaluation points xi_i = i (1..n), distinct nonzero
	t.Xi = make([]*big.Int, n)
	for i := 0; i < n; i++ {
		t.Xi[i] = big.NewInt(int64(i + 1))
	}

	// receiver key
	t.ReceiverX = randScalarM1R(rng, true)
	t.ReceiverPK = host.ScalarMulBase(t.ReceiverX)

	// output polynomials + coefficient commitments
	t.Outputs = make([]*OutputPoly, L)
	t.Aout = make([][]*secp256k1.G1Affine, L)
	for j := 0; j < L; j++ {
		t.Outputs[j] = NewOutputPolyR(f, rng)
		t.Aout[j] = t.Outputs[j].Acoeff
	}

	// task context + state id (alpha = H(DST || TaskCtx || Aout))
	t.TaskCtx = t.buildTaskCtx()
	t.Alpha = t.buildAlpha()

	// receiver proof of possession (bound to the task context transcript)
	t.ReceiverPoP, _ = MakePoPWithRNG(t.ReceiverX, t.TaskCtx, rng)

	// server keys
	t.ServerPriv = make([]ed25519.PrivateKey, n)
	t.ServerPub = make([]ed25519.PublicKey, n)
	t.Endorsements = make([][]byte, n)
	for i := 0; i < n; i++ {
		priv, pub, err := NewServerKeyWithRNG(rng)
		if err != nil {
			return nil, err
		}
		t.ServerPriv[i], t.ServerPub[i] = priv, pub
	}

	t.Finality = NewFinalityRecord(t.TaskVer)
	return t, nil
}

var errBadParams = &m1Error{"bad n/f/L parameters"}

type m1Error struct{ msg string }

func (e *m1Error) Error() string { return "m1: " + e.msg }

// the AP2 C5E1 encoding (byte-identical to host.SynthInstance).
func (t *Task) buildTaskCtx() []byte {
	pk := host.EncodePoint(t.ReceiverPK, false)
	return host.EncodeC5E1([][2]string{
		{"pid", "C5"}, {"ver", "\x00\x01"}, {"domainId", "post-mpc-delivery"},
		{"tau", t.Seed}, {"taskVersion", string(host.U32Bytes(t.TaskVer))}, {"serverSetId", "srvset"},
		{"receiverId", "rcvr"}, {"PK_R", string(pk)},
		{"n", string(host.U32Bytes(t.N))}, {"f", string(host.U32Bytes(t.F))}, {"L", string(host.U32Bytes(t.L))},
		{"paramSetId", "secp256k1-rfc9380xmd-v1"},
		{"deliveryProfileId", "gnark-v0.15.0-groth16-bls12-381-v1"},
	})
}

// buildAlpha computes alpha = H(DST || TaskCtx || Aout) via the AP2 host.HashState.
func (t *Task) buildAlpha() []byte {
	return host.HashState(t.TaskCtx, t.Aout)
}

// MaskCtxFor builds the canonical mask context for server index i (1-based),
// using the AP2 frozen C5E1 mask-context construction (byte-identical to
// host.SynthInstance's internal makeMaskCtx).
func (t *Task) MaskCtxFor(i int) []byte {
	return host.BuildMaskCtx(t.TaskCtx, t.Alpha, t.ReceiverPK, i, t.L, "RDEL-v2")
}

// ShareAt returns server i's share (z_{i,j}, rho_{i,j}) for output j.
func (t *Task) ShareAt(i, j int) (z, rho *big.Int) {
	return t.Outputs[j].ShareAt(t.Xi[i])
}

func (t *Task) ExpectedCommitment(i, j int) *secp256k1.G1Affine {
	return EvalComM1(t.Aout[j], t.Xi[i])
}

// ExpectedCommitments returns the per-output expected commitments for server i.
func (t *Task) ExpectedCommitments(i int) []*secp256k1.G1Affine {
	c := make([]*secp256k1.G1Affine, t.L)
	for j := 0; j < t.L; j++ {
		c[j] = t.ExpectedCommitment(i, j)
	}
	return c
}

// OutputValues returns the authoritative output vector (z_1..z_L).
func (t *Task) OutputValues() []*big.Int {
	v := make([]*big.Int, t.L)
	for j := 0; j < t.L; j++ {
		v[j] = t.Outputs[j].Value()
	}
	return v
}

// ---- endorsement + certificate -------------------------------------------

// Endorse produces server i's endorsement signature over m_out = (tau, alpha),
// after locally checking its openings (AP1 alg C). Returns nil if a local
// opening mismatches.
func (t *Task) Endorse(i int) []byte {
	for j := 0; j < t.L; j++ {
		z, rho := t.ShareAt(i, j)
		if !host.PointEqual(t.ExpectedCommitment(i, j), host.Pedersen(z, rho)) {
			return nil // local opening mismatch -> no endorsement
		}
	}
	return signTranscript(t.ServerPriv[i], params.DSTOutEndorse, t.TaskCtx, t.Alpha)
}

// EndorseAll builds all servers' endorsements.
func (t *Task) EndorseAll() {
	for i := 0; i < t.N; i++ {
		t.Endorsements[i] = t.Endorse(i)
	}
}

// VerifyCert checks certificate validity: at least n-f distinct servers with
// valid endorsement signatures over (tau, alpha). It does NOT check finality.
// Malformed inputs (nil slices, length mismatch, out-of-range / duplicate
func (t *Task) VerifyCert(certIndices []int, certSigs [][]byte) Result {
	if certIndices == nil || certSigs == nil {
		return Reject(RejectInvalidCert)
	}
	if len(certIndices) != len(certSigs) {
		return Reject(RejectInvalidCert)
	}
	seen := map[int]bool{}
	valid := 0
	for idx, i := range certIndices {
		if i < 0 || i >= t.N || seen[i] {
			continue // duplicate / out of range excluded (AP1 alg D)
		}
		seen[i] = true
		if verifyTranscript(t.ServerPub[i], params.DSTOutEndorse, certSigs[idx], t.TaskCtx, t.Alpha) {
			valid++
		}
	}
	if valid < t.N-t.F {
		return Reject(RejectInvalidCert)
	}
	return Ok(valid)
}

// VerifyFinalized checks the authoritative finality (F_Record), distinct from
// certificate validity.
func (t *Task) VerifyFinalized() Result {
	if t.Finality.IsFinalized(hexOf(t.Alpha)) {
		return Ok(t.Alpha)
	}
	return FinalityPending(hexOf(t.Alpha))
}

func hexOf(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexdigits[c>>4], hexdigits[c&0xf])
	}
	return string(out)
}
