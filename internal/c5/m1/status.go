// Package m1 implements the C5 AP3 M1 minimal end-to-end prototype over the
// AP2 frozen concrete profile: synthetic committed-output state -> certificate/
// finality -> server delivery -> Compiled-C -> Groth16 proof -> public
// verification -> distinct-index collection -> receiver recovery.
// This package reuses the AP2 host layer (SynthInstance/Pedersen/DeriveMask/
// CompiledStatement) and the AP2 circuit (R_del) unchanged, and adds the
// delivery-layer scaffolding that AP2 intentionally left out: signatures,
// certificate/finality, collector, receiver reconstruction, and structured
// failure semantics (AP1 §13).
package m1

// Status is the structured result vocabulary from AP1 §13.2. It keeps the five
// primary classes (Reject / Unavailable / Abort / InsufficientThreshold /
// FinalityPending) distinct from OK, so the test oracle never collapses all
// failures into a single "proof failed".
type Status string

const (
	StatusOK                    Status = "OK"
	StatusReject                Status = "REJECT"                 // received but invalid object
	StatusUnavailable           Status = "UNAVAILABLE"            // missing / not readable
	StatusAbort                 Status = "ABORT"                  // phase cannot proceed
	StatusInsufficientThreshold Status = "INSUFFICIENT_THRESHOLD" // < f+1 valid available
	StatusFinalityPending       Status = "FINALITY_PENDING"       // not yet authoritative
	StatusFinalityFailure       Status = "FINALITY_FAILURE"       // FR1 violation
)

// Reject codes (AP1 §13.4). Each is a distinct, machine-readable reason.
const (
	RejectInvalidProof           = "REJECT_INVALID_PROOF"
	RejectInvalidSignature       = "REJECT_INVALID_SIGNATURE"
	RejectInvalidCert            = "REJECT_INVALID_CERT"
	RejectInvalidKey             = "REJECT_INVALID_KEY"
	RejectInvalidEphemeral       = "REJECT_INVALID_EPHEMERAL"
	RejectContextMismatch        = "REJECT_CONTEXT_MISMATCH"
	RejectStateMismatch          = "REJECT_STATE_MISMATCH"
	RejectStateID                = "REJECT_STATE_ID"
	RejectParameterMismatch      = "REJECT_PROOF_PARAMETER_MISMATCH"
	RejectDuplicateForCollection = "REJECT_DUPLICATE_FOR_COLLECTION"
	RejectInvalidIndex           = "REJECT_INVALID_INDEX"
	RejectServerSetMismatch      = "REJECT_SERVER_SET_MISMATCH"
	RejectInvalidServerSet       = "REJECT_INVALID_SERVER_SET"
	RejectNonCanonicalField      = "REJECT_NONCANONICAL_FIELD"
	RejectInvalidStateEncoding   = "REJECT_INVALID_STATE_ENCODING"
	RejectRecoveryInput          = "REJECT_RECOVERY_INPUT"
	RejectUnauthorizedReceiver   = "REJECT_UNAUTHORIZED_RECEIVER"
	RejectInvalidPoP             = "REJECT_INVALID_POP"
	RejectContextReplacement     = "REJECT_CONTEXT_REPLACEMENT"
	InsufficientEndorsements     = "INSUFFICIENT_ENDORSEMENTS"
	AbortBottomMPC               = "ABORT(BOTTOM_MPC)"
	AbortSetup                   = "ABORT_SETUP"
	UnavailableDelivery          = "UNAVAILABLE_DELIVERY"
	UnavailableProofParams       = "UNAVAILABLE(PROOF_PARAMETERS)"
	UnavailableCandidateMissing  = "UNAVAILABLE/CANDIDATE_MISSING"
)

// Result is a structured outcome carrying a status and an optional reason code
// plus a value (used for OK(output)).
type Result struct {
	Status Status
	Reason string // reject/abort/unavailable code; empty for OK
	Value  any    // OK(output) payload
}

// Ok builds an OK result with an optional value.
func Ok(v any) Result { return Result{Status: StatusOK, Value: v} }

// Reject builds a Reject result with a reason code.
func Reject(reason string) Result { return Result{Status: StatusReject, Reason: reason} }

// Unavailable builds an Unavailable result with a reason code.
func Unavailable(reason string) Result { return Result{Status: StatusUnavailable, Reason: reason} }

// Insufficient builds an InsufficientThreshold result.
func Insufficient(have, need int) Result {
	return Result{Status: StatusInsufficientThreshold, Reason: "INSUFFICIENT_THRESHOLD", Value: [2]int{have, need}}
}

// FinalityPending builds a FinalityPending result.
func FinalityPending(stateID string) Result {
	return Result{Status: StatusFinalityPending, Reason: "FINALITY_PENDING", Value: stateID}
}

// Abort builds an Abort result with a reason code.
func Abort(reason string) Result { return Result{Status: StatusAbort, Reason: reason} }

// IsOK reports whether the result is a successful OK.
func (r Result) IsOK() bool { return r.Status == StatusOK }
