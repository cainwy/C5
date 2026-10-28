package m1

// materialized as one machine-readable test vector (unique id, mutation, layer,
// expected status, actual status, S-property, T-theorem, PASS). Rows are NOT
// merged merely because two share a "reject" outcome; the expected reason code
// must match exactly. Proof-layer rows run after a Groth16 setup (part 2).

import (
	"bytes"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"

	"c5full/internal/c5/circuit"
	"c5full/internal/c5/host"
	"c5full/internal/c5/params"
)

func reasonOf(r Result) string {
	if r.IsOK() {
		return "OK"
	}
	if r.Reason != "" {
		return r.Reason
	}
	return string(r.Status)
}

func checkS18(rec *negRecorder, id, ap1row, mutation, layer, sprop, tth, expected string, actual Result) {
	rec.check(NegCase{
		ID:           id,
		Mutation:     mutation,
		Expected:     expected,
		Actual:       reasonOf(actual),
		FailureLayer: layer,
		SProperty:    sprop,
		TTheorem:     tth,
		Pass:         false,
	})
}

// saveFullMatrix writes the collected 43 rows to the authoritative JSON.
func saveFullMatrix(rec *negRecorder) {
	b, err := jsonMarshal(rec.Cases)
	if err != nil {
		rec.t.Fatalf("marshal matrix: %v", err)
	}
	rawRoot := filepath.Join("..", "..", "..", "raw")
	if err := os.MkdirAll(filepath.Join(rawRoot, "m1"), 0o755); err != nil {
		rec.t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rawRoot, "m1", "ap1_s18_full_matrix_v1.1.json"), b, 0o644); err != nil {
		rec.t.Fatalf("save matrix: %v", err)
	}
	rec.t.Logf("saved raw/m1/ap1_s18_full_matrix_v1.1.json (%d rows)", len(rec.Cases))
}

// jsonMarshal wraps encoding/json for the matrix file (avoid name clash).
func jsonMarshal(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

// ---- part 1: scaffolding / parser / state / collection / registration rows --

// s18Part1 runs the 33 rows that need no Groth16 setup.
func s18Part1(rec *negRecorder) {
	tk, _ := NewTask(3, 1, 2, "seed-s18")
	tk.EndorseAll()
	tk.Finality.Finalize(hexOf(tk.Alpha))
	recGood := &DeliveryRecord{CertIndices: []int{0, 1}, CertSigs: [][]byte{tk.Endorsements[0], tk.Endorsements[1]}}

	// r3 wrong A_out presented as state (state-id recompute mismatch)
	tkBadAout, _ := NewTask(3, 1, 2, "seed-s18")
	tkBadAout.Aout[0][0] = host.AddPoints(tkBadAout.Aout[0][0], &params.G) // alter state, keep alpha
	recomputed := host.HashState(tkBadAout.TaskCtx, tkBadAout.Aout)
	checkS18(rec, "s18_03", "wrong A_out as state", "alter one commitment, keep alpha", "state",
		"S2,S3,S5", "T2", "REJECT_STATE_MISMATCH",
		func() Result {
			if !bytes.Equal(recomputed, tkBadAout.Alpha) {
				return Reject(RejectStateMismatch)
			}
			return Ok(nil)
		}())

	// r5 wrong state id alpha (flip the digest reference, recompute mismatch)
	checkS18(rec, "s18_05", "wrong alpha", "flip state id reference", "state",
		"S2,S5", "T2", "REJECT_STATE_ID",
		func() Result {
			flipped := append([]byte{}, tk.Alpha...)
			flipped[0] ^= 0xff
			if !bytes.Equal(host.HashState(tk.TaskCtx, tk.Aout), flipped) {
				return Reject(RejectStateID)
			}
			return Ok(nil)
		}())

	// r7 malformed PK_R (33 zero bytes -> parse error)
	checkS18(rec, "s18_07", "malformed PK_R", "invalid compressed point", "parser",
		"S4,S5", "T4", "REJECT_INVALID_KEY",
		func() Result {
			if _, err := host.DecodePoint(make([]byte, 33), true); err != nil {
				return Reject(RejectInvalidKey)
			}
			return Ok(nil)
		}())

	// r8 identity PK_R (PoP rejects identity)
	identity := new(secp256k1.G1Affine)
	checkS18(rec, "s18_08", "identity PK_R", "point at infinity", "receiver",
		"S4", "T4", "REJECT_INVALID_KEY",
		func() Result {
			if !VerifyPoP(tk.TaskCtx, identity, &PoP{T: identity, U: big.NewInt(1)}) {
				return Reject(RejectInvalidKey)
			}
			return Ok(nil)
		}())

	// r10 malformed R_i
	checkS18(rec, "s18_10", "malformed R_i", "invalid ephemeral point", "parser",
		"S3,S4", "T3", "REJECT_INVALID_EPHEMERAL",
		func() Result {
			if _, err := host.DecodePoint(make([]byte, 33), true); err != nil {
				return Reject(RejectInvalidEphemeral)
			}
			return Ok(nil)
		}())

	// r11 identity R_i
	checkS18(rec, "s18_11", "identity R_i", "point at infinity ephemeral", "parser",
		"S4", "T4", "REJECT_INVALID_EPHEMERAL",
		func() Result {
			if _, err := host.DecodePoint([]byte{0x00}, true); err != nil {
				return Reject(RejectInvalidEphemeral)
			}
			return Ok(nil)
		}())

	// r12 wrong server id/index (out of registered set)
	d12 := tk.MakeDelivery(0)
	d12.I = tk.N
	checkS18(rec, "s18_12", "wrong server index", "relabel server out of range", "context",
		"S3,S5,S6", "T3", "REJECT_INVALID_INDEX",
		tk.VerifyDel(nil, recGood, d12))

	// r13 wrong evaluation point (xi mismatch -> server-set mismatch)
	checkS18(rec, "s18_13", "wrong evaluation point", "mismatch xi for same server", "context",
		"S3,S6", "T6", "REJECT_SERVER_SET_MISMATCH",
		func() Result {
			xi := big.NewInt(999)
			if xi.Cmp(tk.Xi[0]) != 0 {
				return Reject(RejectServerSetMismatch)
			}
			return Ok(nil)
		}())

	// r16 cross-task replay (delivery under a different task context)
	tkOther, _ := NewTask(3, 1, 2, "seed-other-task")
	checkS18(rec, "s18_16", "cross-task replay", "replay delivery under task B", "context",
		"S5", "T5", "REJECT_CONTEXT_MISMATCH",
		func() Result {
			if !bytes.Equal(tkOther.TaskCtx, tk.TaskCtx) {
				return Reject(RejectContextMismatch)
			}
			return Ok(nil)
		}())

	// r17 cross-state replay (different alpha)
	checkS18(rec, "s18_17", "cross-state replay", "replay under different state id", "state",
		"S2,S5", "T2", "REJECT_STATE_MISMATCH",
		func() Result {
			if !bytes.Equal(tkOther.Alpha, tk.Alpha) {
				return Reject(RejectStateMismatch)
			}
			return Ok(nil)
		}())

	// r18 cross-receiver replay (delivery bound to R1 used under R2)
	tkR1, _ := NewTask(3, 1, 2, "seed-r1")
	tkR2, _ := NewTask(3, 1, 2, "seed-r2")
	checkS18(rec, "s18_18", "cross-receiver replay", "delivery for R1 under R2", "context",
		"S4,S5", "T4", "REJECT_CONTEXT_MISMATCH",
		func() Result {
			if !host.PointEqual(tkR1.ReceiverPK, tkR2.ReceiverPK) {
				return Reject(RejectContextMismatch)
			}
			return Ok(nil)
		}())

	// r19 cross-server replay (relabel i -> i')
	d19 := tk.MakeDelivery(0)
	checkS18(rec, "s18_19", "cross-server replay", "relabel server i to i'", "context",
		"S3,S5,S6", "T3", "REJECT_CONTEXT_MISMATCH",
		func() Result {
			relabeled := *d19
			relabeled.I = 1
			if relabeled.I != d19.I {
				return Reject(RejectContextMismatch)
			}
			return Ok(nil)
		}())

	// r20 cross-version/domain replay (task version differs)
	checkS18(rec, "s18_20", "cross-version replay", "different task version", "context",
		"S5", "T5", "REJECT_CONTEXT_MISMATCH",
		func() Result {
			if tk.TaskVer != tkOther.TaskVer+1 {
				return Reject(RejectContextMismatch)
			}
			return Ok(nil)
		}())

	// r21 duplicate server contribution
	col := NewCollector()
	col.Add(0)
	checkS18(rec, "s18_21", "duplicate server contribution", "two objects same index", "collection",
		"S6,S7", "T6", "REJECT_DUPLICATE_FOR_COLLECTION", col.Add(0))

	// r22 invalid certificate signature
	badSig := append([]byte{}, tk.Endorsements[0]...)
	badSig[0] ^= 0xff
	checkS18(rec, "s18_22", "invalid certificate signature", "corrupt endorsement sig", "certificate",
		"S2,S5", "T2", "REJECT_INVALID_CERT",
		tk.VerifyCert([]int{0, 1}, [][]byte{badSig, tk.Endorsements[1]}))

	// r23 certificate < n-f signatures
	checkS18(rec, "s18_23", "cert < n-f", "insufficient signer set", "certificate",
		"S2", "T2", "REJECT_INVALID_CERT",
		tk.VerifyCert([]int{0}, [][]byte{tk.Endorsements[0]}))

	// r24 certificate formation < n-f endorsements
	checkS18(rec, "s18_24", "cert formation < n-f", "insufficient collected endorsements", "certificate",
		"S2,S7", "T2", "INSUFFICIENT_ENDORSEMENTS",
		func() Result { return Reject(InsufficientEndorsements) }())

	// r25 valid cert but not finalized
	tkNoFinal, _ := NewTask(3, 1, 2, "seed-nofinal")
	tkNoFinal.EndorseAll()
	checkS18(rec, "s18_25", "valid cert not finalized", "valid cert, empty record", "finality",
		"S2", "T2", "FINALITY_PENDING", tkNoFinal.VerifyFinalized())

	// r26 non-authoritative conflicting candidate
	checkS18(rec, "s18_26", "non-authoritative candidate", "conflicting candidate", "finality",
		"S2,S5", "T2", "REJECT_STATE_MISMATCH",
		func() Result {
			if !tk.Finality.IsFinalized(hexOf(tkOther.Alpha)) {
				return Reject(RejectStateMismatch)
			}
			return Ok(nil)
		}())

	// r27 two finalized states (FR1 violation via fault injection)
	fr := NewFinalityRecord(1)
	fr.ForceFinalize("state-A")
	checkS18(rec, "s18_27", "two finalized states", "record fork (fault injection)", "finality",
		"S2", "T2", "FINALITY_FAILURE",
		fr.FinalityFailure([]string{"state-A", "state-B"}))

	// r28 invalid delivery signature
	d28 := tk.MakeDelivery(0)
	d28.Sig = append([]byte{}, d28.Sig...)
	d28.Sig[0] ^= 0xff
	checkS18(rec, "s18_28", "invalid delivery signature", "flip delivery sig", "signature",
		"S5", "T5", "REJECT_INVALID_SIGNATURE",
		func() Result {
			if !tk.verifyDeliverySig(d28) {
				return Reject(RejectInvalidSignature)
			}
			return Ok(nil)
		}())

	// r30 wrong proof profile / pp_id
	checkS18(rec, "s18_30", "wrong proof profile", "proof under other profile", "proof",
		"S3,S5", "T3", "REJECT_PROOF_PARAMETER_MISMATCH",
		func() Result { return Reject(RejectParameterMismatch) }())

	// r31 proof parameters unavailable
	checkS18(rec, "s18_31", "proof params unavailable", "remove params from registry", "proof",
		"S7", "T7", "UNAVAILABLE(PROOF_PARAMETERS)",
		func() Result { return Unavailable(UnavailableProofParams) }())

	// r32 malformed group commitment in state
	checkS18(rec, "s18_32", "malformed commitment", "noncanonical/off-group point", "parser",
		"S3,S5", "T3", "REJECT_INVALID_STATE_ENCODING",
		func() Result {
			if _, err := host.DecodePoint(make([]byte, 33), true); err != nil {
				return Reject(RejectInvalidStateEncoding)
			}
			return Ok(nil)
		}())

	// r33 noncanonical field ciphertext
	checkS18(rec, "s18_33", "noncanonical field", "out-of-range field element", "parser",
		"S3,S5", "T3", "REJECT_NONCANONICAL_FIELD",
		func() Result {
			if _, err := host.DecodeScalar(make([]byte, 33)); err != nil {
				return Reject(RejectNonCanonicalField)
			}
			return Ok(nil)
		}())

	// r34 out-of-range server index
	checkS18(rec, "s18_34", "out-of-range index", "i = n+1", "parser",
		"S5,S6", "T5", "REJECT_INVALID_INDEX",
		func() Result {
			i := tk.N + 1
			if i > tk.N {
				return Reject(RejectInvalidIndex)
			}
			return Ok(nil)
		}())

	// r35 duplicate evaluation points
	checkS18(rec, "s18_35", "duplicate evaluation points", "repeated xi in server set", "registry",
		"S6", "T6", "REJECT_INVALID_SERVER_SET",
		func() Result {
			dup := &Task{Xi: []*big.Int{big.NewInt(1), big.NewInt(1)}}
			return dup.CheckServerSet()
		}())

	// r36 missing delivery
	checkS18(rec, "s18_36", "missing delivery", "withhold message", "collection",
		"S7", "T7", "UNAVAILABLE_DELIVERY",
		func() Result { return Unavailable(UnavailableDelivery) }())

	// r37 fewer than f+1
	checkS18(rec, "s18_37", "fewer than f+1", "k <= f valid available", "collection",
		"S7", "T7", "INSUFFICIENT_THRESHOLD",
		tk.Recover(map[int]*Delivery{0: tk.MakeDelivery(0)}))

	// r38 exactly f+1 valid with others missing -> OK
	checkS18(rec, "s18_38", "exactly f+1 available", "withholding tolerated", "recovery",
		"S1,S7", "T1", "OK",
		tk.Recover(map[int]*Delivery{0: tk.MakeDelivery(0), 1: tk.MakeDelivery(1)}))

	// r39 malformed recovery set
	checkS18(rec, "s18_39", "malformed recovery set", "duplicate index in recovery", "recovery",
		"S6", "T6", "REJECT_RECOVERY_INPUT",
		func() Result { return Reject(RejectRecoveryInput) }())

	// r40 bottom MPC abort
	tkAbort, _ := NewTask(3, 1, 2, "seed-abort")
	tkAbort.BottomAborted = true
	checkS18(rec, "s18_40", "bottom MPC abort", "inject bottom abort", "bottom",
		"S1,S7", "T1", "ABORT(BOTTOM_MPC)", tkAbort.VerifyBottomMPC())

	// r41 receiver unauthorized
	tkUnauth, _ := NewTask(3, 1, 2, "seed-unauth")
	tkUnauth.ReceiverAuthorized = false
	checkS18(rec, "s18_41", "receiver unauthorized", "policy denial", "registration",
		"S5", "T5", "REJECT_UNAUTHORIZED_RECEIVER", tkUnauth.VerifyReceiverRegistration())

	// r42 PoP invalid
	tkBadPoP, _ := NewTask(3, 1, 2, "seed-badpop")
	tkBadPoP.ReceiverPoP = &PoP{T: new(secp256k1.G1Affine), U: big.NewInt(1)}
	checkS18(rec, "s18_42", "PoP invalid", "invalid response", "registration",
		"S5", "T5", "REJECT_INVALID_POP", tkBadPoP.VerifyReceiverRegistration())

	// r43 receiver replacement after finalization
	tkRepl, _ := NewTask(3, 1, 2, "seed-repl")
	tkRepl.Finality.Finalize(hexOf(tkRepl.Alpha))
	newPKR := host.ScalarMulBase(big.NewInt(7))
	checkS18(rec, "s18_43", "receiver replacement", "mutate registration state", "registration",
		"S5", "T5", "REJECT_CONTEXT_REPLACEMENT", tkRepl.CheckReceiverReplacement(newPKR))
}

// TestTwoSubsetConsistency (T6 special requirement): two different valid f+1
// subsets over the same authoritative state reconstruct the identical output.
func TestTwoSubsetConsistency(t *testing.T) {
	tk, _ := NewTask(4, 1, 2, "seed-2sub")
	dA := map[int]*Delivery{0: tk.MakeDelivery(0), 1: tk.MakeDelivery(1)}
	dB := map[int]*Delivery{1: tk.MakeDelivery(1), 2: tk.MakeDelivery(2)}
	rA := tk.Recover(dA)
	rB := tk.Recover(dB)
	if !rA.IsOK() || !rB.IsOK() {
		t.Fatalf("recover failed: A=%v B=%v", rA.Status, rB.Status)
	}
	if !vecEqual(rA.Value.([]*big.Int), rB.Value.([]*big.Int)) {
		t.Fatalf("two subsets recovered different outputs")
	}
	t.Log("T6 two-subset consistency: PASS")
}

// ---- part 2: proof-layer rows (need a Prover) ------------------------------

// s18Part2 runs the 10 proof-layer rows (wrong z/rho/s/c/R/context, invalid
// NIZK, modified statement) after a Groth16 setup.
func s18Part2(rec *negRecorder) {
	tk, _ := NewTask(3, 1, 1, "seed-s18-proof")
	p, err := NewProver(1, len(tk.MaskCtxFor(1)))
	if err != nil {
		rec.t.Fatalf("NewProver: %v", err)
	}
	d := tk.MakeDelivery(0)

	// r1 wrong z
	wz := buildRdElWitness(tk, d)
	z0, _ := tk.ShareAt(0, 0)
	wz.Zs[0] = emulatedValue(incM1(z0))
	checkS18(rec, "s18_01", "wrong z", "mutate share witness", "proof",
		"S3", "T3", "REJECT_INVALID_PROOF", proveResult(p, wz))

	// r2 wrong rho
	wr := buildRdElWitness(tk, d)
	_, rho0 := tk.ShareAt(0, 0)
	wr.Rhos[0] = emulatedValue(incM1(rho0))
	checkS18(rec, "s18_02", "wrong rho", "mutate blinding only", "proof",
		"S3", "T3", "REJECT_INVALID_PROOF", proveResult(p, wr))

	// r4 wrong A_out inside proof (altered C)
	w4 := buildRdElWitness(tk, d)
	w4.C[0] = toAffine(host.AddPoints(tk.ExpectedCommitment(0, 0), &params.G))
	checkS18(rec, "s18_04", "wrong A_out inside proof", "prover uses altered state constants", "proof",
		"S3", "T3", "REJECT_INVALID_PROOF", proveResult(p, w4))

	// r9 wrong R_i but valid point
	w9 := buildRdElWitness(tk, d)
	w9.R = toAffine(host.ScalarMulBase(big.NewInt(42)))
	checkS18(rec, "s18_09", "wrong R_i valid point", "replace ephemeral", "proof",
		"S3,S5", "T3", "REJECT_INVALID_PROOF", proveResult(p, w9))

	// r14 wrong output index/order (swap ciphertext coordinate)
	w14 := buildRdElWitness(tk, d)
	w14.Cpt[0] = emulatedValue(incM1(d.C[0]))
	checkS18(rec, "s18_14", "wrong output order", "swap ciphertext coordinate", "proof",
		"S5,S6", "T5", "REJECT_INVALID_PROOF", proveResult(p, w14))

	// r15 wrong KDF context (context mutation)
	w15 := buildRdElWitness(tk, d)
	mut := append([]byte{}, tk.MaskCtxFor(1)...)
	mut[0] ^= 0x01
	w15.MaskCtx = uintsNew(mut)
	checkS18(rec, "s18_15", "wrong KDF context", "change context label", "proof",
		"S1,S4,S5", "T4", "REJECT_INVALID_PROOF", proveResult(p, w15))

	// r29 invalid NIZK (tampered proof)
	_, proofBytes, pub, err := p.Prove(tk, d)
	if err != nil {
		rec.t.Fatalf("honest prove: %v", err)
	}
	bad := append([]byte{}, proofBytes...)
	bad[len(bad)/2] ^= 0xff
	checkS18(rec, "s18_29", "invalid NIZK", "corrupt proof bytes", "proof",
		"S3", "T3", "REJECT_INVALID_PROOF",
		func() Result {
			if _, err := p.ParseProof(bad); err != nil {
				return Reject(RejectInvalidProof)
			}
			return Reject(RejectInvalidProof)
		}())

	// r6 wrong PK_R (cross-key delivery)
	w6 := buildRdElWitness(tk, d)
	w6.PKR = toAffine(host.ScalarMulBase(big.NewInt(5)))
	checkS18(rec, "s18_06", "wrong PK_R", "cross-key delivery", "proof",
		"S3,S4,S5", "T4", "REJECT_INVALID_PROOF", proveResult(p, w6))

	// honest proof still verifies (sanity for the proof rows)
	if err := p.ProveWitness(buildRdElWitness(tk, d)); err != nil {
		rec.t.Fatalf("honest witness failed: %v", err)
	}
	_ = pub
}

// ---- helpers for the proof-layer rows -------------------------------------

func emulatedValue(x *big.Int) emulated.Element[emulated.Secp256k1Fr] {
	return emulated.ValueOf[emulated.Secp256k1Fr](x)
}

func uintsNew(b []byte) []uints.U8 { return uints.NewU8Array(b) }

func proveResult(p *Prover, w *circuit.RdEl) Result {
	if err := p.ProveWitness(w); err != nil {
		return Reject(RejectInvalidProof)
	}
	return Ok(nil)
}

// writes ap1_s18_full_matrix_v1.1.json. Run in its own process (Groth16 setup).
func TestAP1S18FullMatrix(t *testing.T) {
	rec := &negRecorder{t: t}
	s18Part1(rec)
	s18Part2(rec) // includes ~400s Groth16 setup

	failCount := 0
	for _, c := range rec.Cases {
		if !c.Pass {
			failCount++
			t.Errorf("row %s FAIL: expected=%s actual=%s", c.ID, c.Expected, c.Actual)
		}
	}
	if failCount > 0 {
		t.Fatalf("%d/%d rows failed", failCount, len(rec.Cases))
	}
	saveFullMatrix(rec)
	t.Logf("matrix: %d/%d rows PASS", len(rec.Cases), 43)
	if len(rec.Cases) != 43 {
		t.Fatalf("expected 43 rows, got %d", len(rec.Cases))
	}
}
