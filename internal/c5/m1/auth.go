package m1

// maps to, kept distinct so failures are not collapsed.

import (
	"github.com/consensys/gnark-crypto/ecc/secp256k1"

	"c5full/internal/c5/host"
)

// VerifyBottomMPC checks the bottom-MPC boundary (BM5). If the bottom MPC
// aborted, no candidate state exists and delivery never starts.
func (t *Task) VerifyBottomMPC() Result {
	if t.BottomAborted {
		return Abort(AbortBottomMPC)
	}
	return Ok(nil)
}

// VerifyReceiverRegistration checks the receiver authorization (AU1) and the
// proof of possession (Schnorr over secp256k1). The two are distinct checks:
// PoP proves key possession, authorization is a task-policy decision.
func (t *Task) VerifyReceiverRegistration() Result {
	if !t.ReceiverAuthorized {
		return Reject(RejectUnauthorizedReceiver)
	}
	if t.ReceiverPoP == nil || !VerifyPoP(t.TaskCtx, t.ReceiverPK, t.ReceiverPoP) {
		return Reject(RejectInvalidPoP)
	}
	return Ok(t.ReceiverPK)
}

// CheckReceiverReplacement rejects replacing the receiver key after the state is
// finalized (AU2 immutability). A new receiver requires a new task context.
func (t *Task) CheckReceiverReplacement(newPKR *secp256k1.G1Affine) Result {
	if !t.Finality.IsFinalized(hexOf(t.Alpha)) {
		return Ok(nil) // not yet finalized, no replacement semantics yet
	}
	if !host.PointEqual(newPKR, t.ReceiverPK) {
		return Reject(RejectContextReplacement)
	}
	return Ok(nil)
}

// CheckServerSet validates the server-set registry: distinct, nonzero, canonical
// evaluation points (REG1 / S6). Reused for wrong-xi and duplicate-xi rows.
func (t *Task) CheckServerSet() Result {
	seen := map[string]bool{}
	for _, xi := range t.Xi {
		if xi == nil || xi.Sign() == 0 {
			return Reject(RejectInvalidServerSet)
		}
		key := xi.String()
		if seen[key] {
			return Reject(RejectInvalidServerSet)
		}
		seen[key] = true
	}
	return Ok(nil)
}

// ForceFinalize injects a conflicting finalized state for fault-injection
// guard, emulating a broken F_Record.
func (r *FinalityRecord) ForceFinalize(stateID string) {
	r.finalized = stateID
}

// FinalityFailure reports whether the record is in a fork state (two distinct
// finalized ids observed). A real single-valued record never does; this models
// an environmental FR1 violation detected by the consistency monitor.
func (r *FinalityRecord) FinalityFailure(observed []string) Result {
	if len(observed) < 2 {
		return Ok(nil)
	}
	seen := map[string]bool{}
	for _, id := range observed {
		if id == "" {
			continue
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		if len(seen) > 1 {
			return Result{Status: StatusFinalityFailure, Reason: "FINALITY_FAILURE"}
		}
	}
	return Ok(nil)
}
