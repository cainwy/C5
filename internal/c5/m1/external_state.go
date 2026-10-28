package m1

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"

	"c5full/internal/bottomc5"
	"c5full/internal/c5/host"
	"c5full/internal/c5/params"
)

type CommittedOutputBundle = bottomc5.CommittedOutputBundle

func ComposeBundle(n, f int, x, y *big.Int, rng io.Reader) (*CommittedOutputBundle, error) {
	p := bottomc5.Params{N: n, F: f, L: 1}
	d := bottomc5.NewDealer(p, x, y, rng)
	b, _, err := d.Run()
	return b, err
}

func ComposeBundleTrace(n, f int, x, y *big.Int, rng io.Reader) (*CommittedOutputBundle, *bottomc5.Trace, error) {
	p := bottomc5.Params{N: n, F: f, L: 1}
	d := bottomc5.NewDealer(p, x, y, rng)
	return d.Run()
}

type BottomBundleOpts struct {
	FaithfulBeaver bool
}

func ComposeBundleTimed(n, f int, x, y *big.Int, rng io.Reader, o BottomBundleOpts) (
	*CommittedOutputBundle, *bottomc5.Trace, bottomc5.StageTimings, bool, error) {
	_ = o

	p := bottomc5.Params{N: n, F: f, L: 1}
	d := bottomc5.NewDealer(p, x, y, rng)
	b, tr, tm, err := d.RunWithTimings()
	if err != nil {
		return nil, tr, tm, false, err
	}
	return b, tr, tm, d.TripleNonDegenerate(), nil
}

func VerifyBundleInvariant(b *CommittedOutputBundle) int {
	return bottomc5.VerifyInvariant(b)
}

type ReceiverConfig struct {
	ReceiverX    *big.Int
	ReceiverPK   *secp256k1.G1Affine
	Authorized   bool
	MakeSyntheticPoP bool
}

func NewTaskFromCommittedOutput(b *CommittedOutputBundle, cfg ReceiverConfig, rng io.Reader) (*Task, error) {
	if rng == nil {
		rng = rand.Reader
	}
	if b == nil {
		return nil, &m1Error{"nil committed-output bundle"}
	}
	if b.N < 2*b.F+1 || b.F < 0 || b.L < 1 {
		return nil, &m1Error{"bundle n/f/L invalid"}
	}
	if len(b.Xi) != b.N {
		return nil, &m1Error{"bundle xi length != n"}
	}
	if len(b.Aout) != b.L {
		return nil, &m1Error{"bundle Aout rows != L"}
	}
	if len(b.Openings) == 0 {
		return nil, &m1Error{"bundle openings empty"}
	}
	seen := map[string]bool{}
	for _, xi := range b.Xi {
		if xi == nil || xi.Sign() == 0 || xi.Cmp(params.Q) >= 0 {
			return nil, &m1Error{"bundle xi out of range/zero"}
		}
		k := xi.String()
		if seen[k] {
			return nil, &m1Error{"bundle xi duplicate"}
		}
		seen[k] = true
	}
	for j := 0; j < b.L; j++ {
		if len(b.Aout[j]) != b.F+1 {
			return nil, &m1Error{"bundle Aout column != f+1"}
		}
	}
	openByIndex := map[int]bottomc5.ServerOpening{}
	for _, o := range b.Openings {
		if o.Index < 0 || o.Index >= b.N {
			return nil, &m1Error{"bundle opening index out of range"}
		}
		if _, dup := openByIndex[o.Index]; dup {
			return nil, &m1Error{"bundle duplicate opening index"}
		}
		openByIndex[o.Index] = o
	}
	for i := 0; i < b.N; i++ {
		o, ok := openByIndex[i]
		if !ok {
			return nil, &m1Error{"bundle opening missing for server"}
		}
		for j := 0; j < b.L; j++ {
			if !host.PointEqual(EvalComM1(b.Aout[j], b.Xi[i]), host.Pedersen(o.Z, o.Rho)) {
				return nil, &m1Error{"bundle committed-opening invariant violated"}
			}
		}
	}

	_ = openByIndex
	t := &Task{N: b.N, F: b.F, L: b.L, Seed: anchoredSeed(b), TaskVer: 1}
	t.Xi = make([]*big.Int, b.N)
	copy(t.Xi, b.Xi)

	t.ReceiverAuthorized = cfg.Authorized
	if cfg.ReceiverPK == nil {
		cfg.ReceiverPK = host.ScalarMulBase(cfg.ReceiverX)
	}
	t.ReceiverPK = cfg.ReceiverPK
	t.ReceiverX = new(big.Int).Set(cfg.ReceiverX)

	t.Outputs = make([]*OutputPoly, b.L)
	t.Aout = make([][]*secp256k1.G1Affine, b.L)
	if len(b.ZCoeff) != b.L || len(b.RhoCoeff) != b.L {
		return nil, &m1Error{"bundle z/rho coeff rows != L"}
	}
	for j := 0; j < b.L; j++ {
		if len(b.ZCoeff[j]) != b.F+1 || len(b.RhoCoeff[j]) != b.F+1 {
			return nil, &m1Error{"bundle z/rho coeff columns != f+1"}
		}
		zc := append([]*big.Int(nil), b.ZCoeff[j]...)
		rc := append([]*big.Int(nil), b.RhoCoeff[j]...)
		t.Outputs[j] = NewOutputPolyFromCoeffs(zc, rc, b.Aout[j])
		t.Aout[j] = b.Aout[j]
	}

	t.TaskCtx = t.buildTaskCtx()
	t.Alpha = t.buildAlpha()

	if cfg.MakeSyntheticPoP {
		pop, _ := MakePoPWithRNG(t.ReceiverX, t.TaskCtx, rng)
		t.ReceiverPoP = pop
	}

	t.ServerPriv = make([]ed25519.PrivateKey, b.N)
	t.ServerPub = make([]ed25519.PublicKey, b.N)
	t.Endorsements = make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		priv, pub, err := NewServerKeyWithRNG(rng)
		if err != nil {
			return nil, err
		}
		t.ServerPriv[i], t.ServerPub[i] = priv, pub
	}

	t.Finality = NewFinalityRecord(t.TaskVer)

	if r := t.CheckServerSet(); !r.IsOK() {
		return nil, &m1Error{"adapter server set invalid"}
	}
	if !cfg.MakeSyntheticPoP {
	} else if r := t.VerifyReceiverRegistration(); !r.IsOK() {
		return nil, &m1Error{"adapter receiver registration invalid"}
	}
	for i := 0; i < b.N; i++ {
		for j := 0; j < b.L; j++ {
			if !host.PointEqual(t.ExpectedCommitment(i, j), host.Pedersen(b.Openings[i].Z, b.Openings[i].Rho)) {
				return nil, &m1Error{"adapter re-check invariant failed"}
			}
		}
	}
	return t, nil
}

func anchoredSeed(b *CommittedOutputBundle) string {
	h := host.HashState([]byte("bundle-anchor"), b.Aout)
	return fmt.Sprintf("%x", h[:6])
}

func mulQ(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Mul(a, b), params.Q) }