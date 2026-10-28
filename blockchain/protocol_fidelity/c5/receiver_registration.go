//	Pi_R = [ T_R = a_R G ;  e_R = Hash(tau, R, PK_R, T_R) in F_q ;  u_R = a_R + e_R x_R mod q ]
//	pi_R^key = (T_R, u_R)
// `ReceiverConfig{Authorized: true, MakeSyntheticPoP: true}` ——
package c5

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"

	"c5full/internal/c5/host"
	"c5full/internal/c5/params"
)

var (
	ErrPoPVerify        = errors.New("c5-fidelity: receiver PoP verification failed")
	ErrPoPShape         = errors.New("c5-fidelity: receiver PoP shape invalid")
	ErrNotAuthorized    = errors.New("c5-fidelity: receiver not authorized for this task")
	ErrRegistrationBind = errors.New("c5-fidelity: registration not bound to current task")
)

type ReceiverRegistration struct {
	Schema     string `json:"schema"`
	TaskCtxHex string `json:"task_ctx_hex"`
	ReceiverID string `json:"receiver_id"`
	PKRHex     string `json:"pk_r_hex"` // 33B compressed
	TRHex      string `json:"t_r_hex"`  // 33B compressed
	URHex      string `json:"u_r_hex"`  // 32B scalar
}

type ReceiverAuthorization struct {
	ReceiverID string `json:"receiver_id"`
	TaskCtxHex string `json:"task_ctx_hex"`
	Authorized bool   `json:"authorized"`
}

//	T_R = a_R G
//	e_R = Hash(tau, R, PK_R, T_R) mod q
//	u_R = a_R + e_R * x_R mod q
func NewReceiverRegistration(taskCtx []byte, receiverID string, xR *big.Int, rng io.Reader) (*ReceiverRegistration, error) {
	if len(taskCtx) == 0 || receiverID == "" || xR == nil || xR.Sign() == 0 {
		return nil, ErrPoPShape
	}
	if rng == nil {
		return nil, fmt.Errorf("%w: nil rng", ErrPoPShape)
	}
	pkR := host.ScalarMulBase(xR)
	aR := randScalarNonZero(rng)
	tR := host.ScalarMulBase(aR)
	eR := popChallenge(taskCtx, receiverID, pkR, tR)
	uR := new(big.Int).Mul(eR, xR)
	uR.Add(uR, aR)
	uR.Mod(uR, params.Q)

	reg := &ReceiverRegistration{
		Schema:     "c5-receiver-registration-v1",
		TaskCtxHex: hexEncode(taskCtx),
		ReceiverID: receiverID,
		PKRHex:     hexEncode(host.EncodePoint(pkR, false)),
		TRHex:      hexEncode(host.EncodePoint(tR, false)),
		URHex:      hexEncode(scalarBytes(uR)),
	}
	if err := VerifyReceiverPoP(reg, taskCtx, receiverID); err != nil {
		return nil, fmt.Errorf("c5-fidelity: self-check after PoP generation: %w", err)
	}
	return reg, nil
}

func VerifyReceiverPoP(reg *ReceiverRegistration, taskCtx []byte, receiverID string) error {
	if reg == nil || reg.Schema != "c5-receiver-registration-v1" {
		return fmt.Errorf("%w: schema", ErrPoPShape)
	}
	gotCtx, err := hexDecode(reg.TaskCtxHex)
	if err != nil {
		return fmt.Errorf("%w: task ctx hex: %v", ErrPoPShape, err)
	}
	if !bytesEqual(gotCtx, taskCtx) {
		return fmt.Errorf("%w: task ctx mismatch", ErrRegistrationBind)
	}
	if reg.ReceiverID != receiverID {
		return fmt.Errorf("%w: receiver id mismatch", ErrRegistrationBind)
	}
	pkRB, err := hexDecode(reg.PKRHex)
	if err != nil {
		return fmt.Errorf("%w: pk hex: %v", ErrPoPShape, err)
	}
	tRB, err := hexDecode(reg.TRHex)
	if err != nil {
		return fmt.Errorf("%w: T hex: %v", ErrPoPShape, err)
	}
	uR, err := scalarFromHex(reg.URHex)
	if err != nil {
		return fmt.Errorf("%w: u hex: %v", ErrPoPShape, err)
	}
	pkR, err := host.DecodePoint(pkRB, true)
	if err != nil {
		return fmt.Errorf("%w: pk decode: %v", ErrPoPShape, err)
	}
	tR, err := host.DecodePoint(tRB, true)
	if err != nil {
		return fmt.Errorf("%w: T decode: %v", ErrPoPShape, err)
	}
	if uR.Sign() == 0 || uR.Cmp(params.Q) >= 0 {
		return fmt.Errorf("%w: u out of range", ErrPoPShape)
	}
	eR := popChallenge(taskCtx, receiverID, pkR, tR)
	// u_R G ?= T_R + e_R' PK_R
	lhs := host.ScalarMulBase(uR)
	rhs := host.AddPoints(tR, host.ScalarMul(pkR, eR))
	if !host.PointEqual(lhs, rhs) {
		return ErrPoPVerify
	}
	return nil
}

func VerifyRegistration(reg *ReceiverRegistration, auth *ReceiverAuthorization, taskCtx []byte, receiverID string) error {
	if err := VerifyReceiverPoP(reg, taskCtx, receiverID); err != nil {
		return err
	}
	if auth == nil || !auth.Authorized {
		return ErrNotAuthorized
	}
	if auth.ReceiverID != receiverID {
		return fmt.Errorf("%w: authorization subject mismatch", ErrNotAuthorized)
	}
	gotCtx, err := hexDecode(auth.TaskCtxHex)
	if err != nil || !bytesEqual(gotCtx, taskCtx) {
		return fmt.Errorf("%w: authorization task mismatch", ErrNotAuthorized)
	}
	return nil
}

func popChallenge(taskCtx []byte, receiverID string, pkR, tR *secp256k1.G1Affine) *big.Int {
	h := sha256.New()
	h.Write([]byte(params.DSTReceiverPOP))
	h.Write([]byte{0x00})
	h.Write(u32LELen(len(taskCtx)))
	h.Write(taskCtx)
	h.Write(u32LELen(len(receiverID)))
	h.Write([]byte(receiverID))
	pkb := host.EncodePoint(pkR, false)
	h.Write(u32LELen(len(pkb)))
	h.Write(pkb)
	tb := host.EncodePoint(tR, false)
	h.Write(u32LELen(len(tb)))
	h.Write(tb)
	digest := h.Sum(nil)
	return new(big.Int).Mod(new(big.Int).SetBytes(digest), params.Q)
}

type ReceiverKeyPair struct {
	XR  *big.Int
	PKR *secp256k1.G1Affine
}

func NewReceiverKeyPair(rng io.Reader) (*ReceiverKeyPair, error) {
	if rng == nil {
		return nil, fmt.Errorf("%w: nil rng", ErrPoPShape)
	}
	xR := randScalarNonZero(rng)
	return &ReceiverKeyPair{XR: xR, PKR: host.ScalarMulBase(xR)}, nil
}
