package schemeafaithful

import (
	crand "crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

type ErrFaithful struct{ Code, Msg string }

func (e *ErrFaithful) Error() string { return "schemeafaithful/" + e.Code + ": " + e.Msg }

func errf(code, format string, a ...any) error {
	return &ErrFaithful{Code: code, Msg: fmt.Sprintf(format, a...)}
}

var (
	ErrBadParams     = "BAD-PARAMS"
	ErrBadGroup      = "BAD-GROUP"
	ErrBadShare      = "BAD-SHARE"
	ErrBadCommit     = "BAD-COMMIT"
	ErrZKPoC         = "ZKPOC-FAIL"
	ErrDecrypt       = "DECRYPT-FAIL"
	ErrReconstruct   = "RECONSTRUCT-FAIL"
	ErrShape         = "SHAPE"
	ErrChannel       = "CHANNEL"
	errUnexpectedNil = errors.New("unexpected nil")
)

type Group struct {
	P      *big.Int
	G      *big.Int
	ExpMod *big.Int
	Bits   int
}

func NewGroupRFC3526(bits int) (*Group, error) {
	s, ok := rfc3526[bits]
	if !ok {
		return nil, errf(ErrBadParams, "no embedded RFC3526 prime for %d bits", bits)
	}
	P, ok2 := new(big.Int).SetString(s, 0)
	if !ok2 {
		return nil, errf(ErrBadParams, "prime parse failed")
	}
	return newGroupFromPrime(P, big.NewInt(2))
}

func NewGroupGeneral(P, Q, G *big.Int) (*Group, error) {
	if P == nil || Q == nil {
		return nil, errf(ErrBadParams, "nil P/Q")
	}
	if !P.ProbablyPrime(32) {
		return nil, errf(ErrBadGroup, "P is not prime")
	}
	if !Q.ProbablyPrime(32) {
		return nil, errf(ErrBadGroup, "Q is not prime (subgroup order must be prime)")
	}
	pm1 := new(big.Int).Sub(P, big.NewInt(1))
	if new(big.Int).Mod(pm1, Q).Sign() != 0 {
		return nil, errf(ErrBadGroup, "Q does not divide P-1")
	}
	if G == nil || G.Sign() == 0 {
		rng := randReaderFromSeed(int64(P.BitLen())*1_000_003 + int64(Q.BitLen()))
		for tries := 0; tries < 1_000_000; tries++ {
			cand := randIntFrom(rng, pm1)
			cand.Add(cand, big.NewInt(2))
			cand.Mod(cand, P)
			if cand.Cmp(big.NewInt(1)) == 0 {
				continue
			}
			if new(big.Int).Exp(cand, Q, P).Cmp(big.NewInt(1)) == 0 {
				return &Group{P: P, G: cand, ExpMod: new(big.Int).Set(Q), Bits: P.BitLen()}, nil
			}
		}
		return nil, errf(ErrBadGroup, "no order-Q generator found within tries")
	}
	if G.Cmp(big.NewInt(1)) == 0 || G.Cmp(P) >= 0 {
		return nil, errf(ErrBadGroup, "G must satisfy 1 < G < P")
	}
	if new(big.Int).Exp(G, Q, P).Cmp(big.NewInt(1)) != 0 {
		return nil, errf(ErrBadGroup, "G^Q != 1 mod P (G not in order-Q subgroup)")
	}
	return &Group{P: new(big.Int).Set(P), G: new(big.Int).Set(G), ExpMod: new(big.Int).Set(Q), Bits: P.BitLen()}, nil
}

func NewGroupRandom(bits int, seed int64) (*Group, error) {
	if bits < 16 || bits > 8192 {
		return nil, errf(ErrBadParams, "bits %d out of range", bits)
	}
	P := safePrime(bits, seed)
	return newGroupFromPrime(P, nil)
}

func newGroupFromPrime(P, g *big.Int) (*Group, error) {
	if P == nil || !P.ProbablyPrime(32) {
		return nil, errf(ErrBadGroup, "P is not prime")
	}
	pm1 := new(big.Int).Sub(P, big.NewInt(1))
	q := new(big.Int).Rsh(pm1, 1)
	if !q.ProbablyPrime(32) {
		return nil, errf(ErrBadGroup, "P is not a safe prime (P-1)/2 composite")
	}
	if g == nil {
		g = qrGenerator(P, q)
	} else {
		if new(big.Int).Exp(g, q, P).Cmp(big.NewInt(1)) != 0 {
			return nil, errf(ErrBadGroup, "g not in order-q subgroup")
		}
		if g.Cmp(big.NewInt(1)) == 0 {
			return nil, errf(ErrBadGroup, "degenerate g=1")
		}
	}
	return &Group{P: P, G: g, ExpMod: q, Bits: P.BitLen()}, nil
}

func qrGenerator(P, q *big.Int) *big.Int {
	for g := big.NewInt(2); ; g.Add(g, big.NewInt(1)) {
		if new(big.Int).Exp(g, q, P).Cmp(big.NewInt(1)) == 0 {
			return new(big.Int).Set(g)
		}
	}
}

func safePrime(bits int, seed int64) *big.Int {
	rng := randReaderFromSeed(seed)
	for {
		q, err := crand.Int(rng, new(big.Int).Lsh(big.NewInt(1), uint(bits-1)))
		if err != nil {
			continue
		}
		q.SetBit(q, bits-2, 1)
		q.SetBit(q, 0, 1)
		if !q.ProbablyPrime(24) {
			continue
		}
		P := new(big.Int).Lsh(q, 1)
		P.Add(P, big.NewInt(1))
		if P.ProbablyPrime(24) {
			return P
		}
	}
}

type KeyPair struct {
	S *big.Int
	H *big.Int // h = g^s mod P
}

func (g *Group) NewKeyPair(rng crandReader) (*KeyPair, error) {
	s, err := crand.Int(rng, g.ExpMod)
	if err != nil {
		return nil, err
	}
	if s.Sign() == 0 {
		s.Set(big.NewInt(1))
	}
	h := new(big.Int).Exp(g.G, s, g.P)
	return &KeyPair{S: s, H: h}, nil
}

func (g *Group) Commit(h, m, r *big.Int) *big.Int {
	gm := new(big.Int).Exp(g.G, m, g.P)
	hr := new(big.Int).Exp(h, r, g.P)
	gm.Mul(gm, hr)
	return gm.Mod(gm, g.P)
}

func (g *Group) Pow(b, e *big.Int) *big.Int { return new(big.Int).Exp(b, e, g.P) }

func (g *Group) Mul(a, b *big.Int) *big.Int {
	out := new(big.Int).Mul(a, b)
	return out.Mod(out, g.P)
}

type crandReader = interface {
	Read(p []byte) (int, error)
}
