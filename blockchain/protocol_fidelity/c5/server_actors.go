package c5

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"

	"c5full/internal/c5/host"
	"c5full/internal/c5/params"
)

const DSTOutEndorse = params.DSTOutEndorse

var (
	ErrActorOpeningMismatch = errors.New("c5-fidelity: server local opening mismatch; refusing to sign")
	ErrActorNotInRegistry   = errors.New("c5-fidelity: server not in registered set")
	ErrCertAlphaMismatch    = errors.New("c5-fidelity: certificate alpha != recomputed alpha")
	ErrCertDuplicateSigner  = errors.New("c5-fidelity: duplicate certificate signer")
	ErrCertBadSignature     = errors.New("c5-fidelity: certificate signature invalid")
	ErrCertInsufficient     = errors.New("c5-fidelity: certificate below n-f threshold")
	ErrCertShape            = errors.New("c5-fidelity: certificate shape invalid")
)

type ServerActor struct {
	Index int
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	taskCtx []byte
	alpha   []byte
	aout    [][]*secp256k1.G1Affine
	xi      *big.Int
	shares []SharePair
}

type SharePair struct {
	Z   *big.Int
	Rho *big.Int
}

func NewServerActor(index int, priv ed25519.PrivateKey, taskCtx, alpha []byte,
	aout [][]*secp256k1.G1Affine, xi *big.Int, shares []SharePair) (*ServerActor, error) {
	if priv == nil || len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: bad private key for server %d", ErrActorShape, index)
	}
	if xi == nil {
		return nil, fmt.Errorf("%w: nil xi for server %d", ErrActorShape, index)
	}
	if len(shares) != len(aout) {
		return nil, fmt.Errorf("%w: server %d has %d shares but %d output coords",
			ErrActorShape, index, len(shares), len(aout))
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: cannot derive public key", ErrActorShape)
	}
	return &ServerActor{
		Index: index, priv: priv, pub: pub,
		taskCtx: taskCtx, alpha: alpha, aout: aout, xi: xi, shares: shares,
	}, nil
}

var ErrActorShape = errors.New("c5-fidelity: server actor shape invalid")

func (a *ServerActor) PublicKey() ed25519.PublicKey { return a.pub }

//	C_{i,j} = EvalCom(A_j, xi_i)  ?=  z_{i,j}G + rho_{i,j}H
func (a *ServerActor) LocalOpeningCheck() error {
	for j := range a.aout {
		expected := evalComLocal(a.aout[j], a.xi)
		actual := host.Pedersen(a.shares[j].Z, a.shares[j].Rho)
		if !host.PointEqual(expected, actual) {
			return fmt.Errorf("%w: server %d coord %d", ErrActorOpeningMismatch, a.Index, j)
		}
	}
	return nil
}

type AuthContribution struct {
	ServerIndex int    `json:"server_index"`
	Index1Based int    `json:"index_1based"`
	AlphaHex    string `json:"alpha_hex"`
	SigHex      string `json:"sig_hex"`
}

func (a *ServerActor) Endorse() (AuthContribution, error) {
	if err := a.LocalOpeningCheck(); err != nil {
		return AuthContribution{}, err
	}
	sig := ed25519.Sign(a.priv, OutEndorseTranscript(a.taskCtx, a.alpha))
	return AuthContribution{
		ServerIndex: a.Index, Index1Based: a.Index + 1,
		AlphaHex: hexEncode(a.alpha), SigHex: hexEncode(sig),
	}, nil
}

func AssertKeyIsolation(actors []*ServerActor) error {
	seen := map[string]int{}
	for _, a := range actors {
		k := string(a.pub)
		if prev, dup := seen[k]; dup {
			return fmt.Errorf("%w: actor %d and %d share the same key", ErrActorShape, prev, a.Index)
		}
		seen[k] = a.Index
	}
	return nil
}

type CertFaithful struct {
	TaskCtx  []byte
	PKR      *secp256k1.G1Affine
	Aout     [][]*secp256k1.G1Affine
	Alpha    []byte
	Q        []int // distinct server indices
	Sigs     [][]byte
	Registry map[int]ed25519.PublicKey
	NF       int
}

//	(3) |Q| >= n-f
func VerifyCertFaithful(c *CertFaithful) (int, error) {
	if c == nil || c.TaskCtx == nil || c.PKR == nil || c.Alpha == nil || c.NF < 0 {
		return 0, ErrCertShape
	}
	if len(c.Q) != len(c.Sigs) || len(c.Q) == 0 {
		return 0, ErrCertShape
	}
	if len(c.Aout) == 0 {
		return 0, ErrCertShape
	}

	recomputed := host.HashState(c.TaskCtx, c.Aout)
	if !bytesEqual(recomputed, c.Alpha) {
		return 0, ErrCertAlphaMismatch
	}

	seen := map[int]bool{}
	valid := 0
	for idx, i := range c.Q {
		if seen[i] {
			return 0, fmt.Errorf("%w: index %d", ErrCertDuplicateSigner, i)
		}
		seen[i] = true
		pub, ok := c.Registry[i]
		if !ok {
			return 0, fmt.Errorf("%w: index %d", ErrActorNotInRegistry, i)
		}
		if !ed25519.Verify(pub, OutEndorseTranscript(c.TaskCtx, c.Alpha), c.Sigs[idx]) {
			return 0, fmt.Errorf("%w: index %d", ErrCertBadSignature, i)
		}
		valid++
	}
	if valid < c.NF {
		return 0, fmt.Errorf("%w: have %d, need %d", ErrCertInsufficient, valid, c.NF)
	}
	return valid, nil
}

func evalComLocal(A []*secp256k1.G1Affine, x *big.Int) *secp256k1.G1Affine {
	acc := new(secp256k1.G1Affine)
	pw := big.NewInt(1)
	for _, a := range A {
		term := host.ScalarMul(a, pw)
		acc = host.AddPoints(acc, term)
		pw = new(big.Int).Mul(pw, x)
		pw.Mod(pw, hostQ())
	}
	return acc
}

func hostQ() *big.Int { return params.Q }

func OutEndorseTranscript(taskCtx, alpha []byte) []byte {
	msg := make([]byte, 0, 64+len(taskCtx)+len(alpha))
	msg = append(msg, DSTOutEndorse...)
	msg = append(msg, 0x00)
	msg = append(msg, u32LELen(len(taskCtx))...)
	msg = append(msg, taskCtx...)
	msg = append(msg, u32LELen(len(alpha))...)
	msg = append(msg, alpha...)
	return msg
}

func u32LELen(n int) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(n))
	return b
}
