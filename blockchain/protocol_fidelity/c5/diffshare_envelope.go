//	                        Eq.(check-de)
package c5


import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"

	"c5full/internal/bottomc5"
	"c5full/internal/c5/params"
)

const DSTDiffShare = "C5/DIFF-SHARE/v1"

var (
	ErrEnvelopeShape         = errors.New("c5-fidelity: diff-share envelope shape invalid")
	ErrEnvelopeUnknownServer = errors.New("c5-fidelity: diff-share server not in registry")
	ErrEnvelopeBadSignature  = errors.New("c5-fidelity: diff-share signature invalid")
	ErrEnvelopeTaskMismatch  = errors.New("c5-fidelity: diff-share task context mismatch")
	ErrEnvelopeDuplicate     = errors.New("c5-fidelity: duplicate diff-share server index")
	ErrEnvelopeOpening       = errors.New("c5-fidelity: diff-share commitment opening failed")
	ErrEnvelopeInsufficient  = errors.New("c5-fidelity: insufficient distinct valid diff-shares")
)

//	D, Delta   ← d_i, delta_i
//	E, Eps     ← e_i, epsilon_i
type DiffShareEnvelope struct {
	Schema      string `json:"schema"`
	TaskCtxHex  string `json:"task_ctx_hex"`
	ServerIndex int    `json:"server_index"`
	Index1Based int    `json:"index_1based"`
	DHex        string `json:"d_hex"`        // d_i
	DeltaHex    string `json:"delta_hex"`    // delta_i
	EHex        string `json:"e_hex"`        // e_i
	EpsHex      string `json:"eps_hex"`      // epsilon_i
	SigHex      string `json:"sig_hex"`      // Ed25519 over DiffShareTranscript
}

func DiffShareTranscript(taskCtx []byte, serverIndex int, d, delta, e, eps *big.Int) []byte {
	msg := make([]byte, 0, 128+len(taskCtx))
	msg = append(msg, DSTDiffShare...)
	msg = append(msg, 0x00)
	msg = appendFrame(msg, taskCtx)
	msg = appendFrame(msg, u32LE(serverIndex))
	msg = appendFrame(msg, scalarBytes(d))
	msg = appendFrame(msg, scalarBytes(delta))
	msg = appendFrame(msg, scalarBytes(e))
	msg = appendFrame(msg, scalarBytes(eps))
	return msg
}

func SignDiffShare(priv ed25519.PrivateKey, taskCtx []byte, serverIndex int, s bottomc5.DiffShare) DiffShareEnvelope {
	sig := ed25519.Sign(priv, DiffShareTranscript(taskCtx, serverIndex, s.D, s.Delta, s.E, s.Eps))
	return DiffShareEnvelope{
		Schema:      "c5-diff-share-envelope-v1",
		TaskCtxHex:  hexEncode(taskCtx),
		ServerIndex: serverIndex,
		Index1Based: serverIndex + 1,
		DHex:        hexEncode(scalarBytes(s.D)),
		DeltaHex:    hexEncode(scalarBytes(s.Delta)),
		EHex:        hexEncode(scalarBytes(s.E)),
		EpsHex:      hexEncode(scalarBytes(s.Eps)),
		SigHex:      hexEncode(sig),
	}
}

func VerifyDiffShareEnvelope(env DiffShareEnvelope, taskCtx []byte, registry map[int]ed25519.PublicKey) (bottomc5.DiffShare, error) {
	if env.Schema != "c5-diff-share-envelope-v1" {
		return bottomc5.DiffShare{}, fmt.Errorf("%w: schema %q", ErrEnvelopeShape, env.Schema)
	}
	pub, ok := registry[env.ServerIndex]
	if !ok {
		return bottomc5.DiffShare{}, fmt.Errorf("%w: index %d", ErrEnvelopeUnknownServer, env.ServerIndex)
	}
	if env.Index1Based != env.ServerIndex+1 {
		return bottomc5.DiffShare{}, fmt.Errorf("%w: index_1based %d != server_index+1", ErrEnvelopeShape, env.Index1Based)
	}
	gotCtx, err := hexDecode(env.TaskCtxHex)
	if err != nil {
		return bottomc5.DiffShare{}, fmt.Errorf("%w: task ctx hex: %v", ErrEnvelopeShape, err)
	}
	if !bytesEqual(gotCtx, taskCtx) {
		return bottomc5.DiffShare{}, ErrEnvelopeTaskMismatch
	}
	d, err := scalarFromHex(env.DHex)
	if err != nil {
		return bottomc5.DiffShare{}, fmt.Errorf("%w: d: %v", ErrEnvelopeShape, err)
	}
	delta, err := scalarFromHex(env.DeltaHex)
	if err != nil {
		return bottomc5.DiffShare{}, fmt.Errorf("%w: delta: %v", ErrEnvelopeShape, err)
	}
	e, err := scalarFromHex(env.EHex)
	if err != nil {
		return bottomc5.DiffShare{}, fmt.Errorf("%w: e: %v", ErrEnvelopeShape, err)
	}
	eps, err := scalarFromHex(env.EpsHex)
	if err != nil {
		return bottomc5.DiffShare{}, fmt.Errorf("%w: eps: %v", ErrEnvelopeShape, err)
	}
	sig, err := hexDecode(env.SigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return bottomc5.DiffShare{}, fmt.Errorf("%w: signature size %d", ErrEnvelopeBadSignature, len(sig))
	}
	msg := DiffShareTranscript(taskCtx, env.ServerIndex, d, delta, e, eps)
	if !ed25519.Verify(pub, msg, sig) {
		return bottomc5.DiffShare{}, ErrEnvelopeBadSignature
	}
	return bottomc5.DiffShare{Index: env.ServerIndex, D: d, Delta: delta, E: e, Eps: eps}, nil
}

//	Com(d_i; delta_i) == EvalCom(A_x - A_a, xi_i)
//	Com(e_i; epsilon_i) == EvalCom(A_y - A_b, xi_i)
func VerifyDiffShareOpening(s bottomc5.DiffShare, xi *big.Int, axMinusAa, ayMinusAb []*secp256k1.G1Affine) bool {
	if !bottomc5.CheckOpening(axMinusAa, xi, s.D, s.Delta) {
		return false
	}
	return bottomc5.CheckOpening(ayMinusAb, xi, s.E, s.Eps)
}

func CollectDistinctValid(envs []DiffShareEnvelope, taskCtx []byte, registry map[int]ed25519.PublicKey,
	xiOf func(int) *big.Int, axMinusAa, ayMinusAb []*secp256k1.G1Affine) ([]bottomc5.DiffShare, map[int]error) {

	rejected := map[int]error{}
	accepted := map[int]bottomc5.DiffShare{}
	for _, env := range envs {
		s, err := VerifyDiffShareEnvelope(env, taskCtx, registry)
		if err != nil {
			rejected[env.ServerIndex] = err
			continue
		}
		if _, dup := accepted[s.Index]; dup {
			rejected[s.Index] = ErrEnvelopeDuplicate
			continue
		}
		if !VerifyDiffShareOpening(s, xiOf(s.Index), axMinusAa, ayMinusAb) {
			rejected[s.Index] = ErrEnvelopeOpening
			continue
		}
		accepted[s.Index] = s
	}
	out := make([]bottomc5.DiffShare, 0, len(accepted))
	for i := 0; i < len(accepted); i++ {
		if s, ok := accepted[i]; ok {
			out = append(out, s)
		}
	}
	return out, rejected
}

func RequireThreshold(valid []bottomc5.DiffShare, f int) error {
	if len(valid) < f+1 {
		return fmt.Errorf("%w: have %d, need %d", ErrEnvelopeInsufficient, len(valid), f+1)
	}
	return nil
}

func init() {
	for _, d := range []string{
		params.DSTStateID, params.DSTReceiverPOP, params.DSTOutEndorse,
		params.DSTDeliveryMask, params.DSTDeliveryProof, params.DSTDeliverySig,
		params.DSTCertEnc, params.DSTFinalityRef,
	} {
		if d == DSTDiffShare {
			panic("c5-fidelity: DSTDiffShare collides with a frozen params DST")
		}
	}
}

func appendFrame(dst, p []byte) []byte {
	dst = append(dst, u32LE(len(p))...)
	return append(dst, p...)
}

func u32LE(n int) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(n))
	return b
}

func scalarBytes(x *big.Int) []byte {
	out := make([]byte, 32)
	if x == nil {
		return out
	}
	b := x.Bytes()
	if len(b) > 32 {
		b = b[len(b)-32:]
	}
	copy(out[32-len(b):], b)
	return out
}

func scalarFromHex(h string) (*big.Int, error) {
	b, err := hexDecode(h)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 || len(b) > 32 {
		return nil, fmt.Errorf("scalar length %d not in 1..32", len(b))
	}
	return new(big.Int).SetBytes(b), nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func hexEncode(b []byte) string          { return hex.EncodeToString(b) }
func hexDecode(s string) ([]byte, error) { return hex.DecodeString(s) }
