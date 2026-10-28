// Package vss implements Pedersen's verifiable threshold secret sharing
// (Preliminaries III-B, Scheme A / Gai et al. TDSC 2025): a dealer splits a
// secret into t-1-degree polynomial shares and broadcasts coefficient
// commitments so every participant can verify its share without a trusted
// channel, and any t valid shares reconstruct the secret.
//   - Secret/randomness/blinding scalars live in Z_GMOD (params.GMOD).
//   - Commitments C(m,r)=g^m·h^r live in the Lifted-ElGamal/Pedersen group
//     Z_P^* supplied by schemea.
package vss

import (
	"math/big"
	"math/rand"

	"c5full/internal/mpc/params"
)

// Group is the Pedersen commitment/Lifted-ElGamal group parameters.
type Group struct {
	P, G, H *big.Int
}

// ShareSet is one dealer's share bundle over n servers (threshold t).
type ShareSet struct {
	T       int        // threshold (number of points needed to reconstruct)
	Fcoeff  []*big.Int // F coefficients (F(0)=secret), length t
	Gcoeff  []*big.Int // G coefficients (G(0)=blinding), length t
	Acoeff  []*big.Int // A_α = C(F_α, G_α) coefficient commitments, length t
	servers [][]*big.Int // not exported; share points (Fi,Gi) per server
}

// randZ picks a uniform element of Z_{GMOD}\{0} as specified (redeclared below
// with a *rand.Rand source).

// Share splits (secret, rho) into n shares with threshold t, returns a ShareSet.
func (grp *Group) Share(secret, rho *big.Int, t, n int, seed int64) *ShareSet {
	rng := rand.New(rand.NewSource(seed ^ 0x5eed_f00d))
	f := make([]*big.Int, t)
	g := make([]*big.Int, t)
	f[0] = new(big.Int).Mod(secret, params.GMOD)
	g[0] = new(big.Int).Mod(rho, params.GMOD)
	for k := 1; k < t; k++ {
		f[k] = randZ(rng, big.NewInt(0))
		g[k] = randZ(rng, big.NewInt(0))
	}
	a := make([]*big.Int, t)
	for k := 0; k < t; k++ {
		a[k] = grp.Commit(f[k], g[k])
	}
	servers := make([][]*big.Int, n)
	for i := 0; i < n; i++ {
		xx := big.NewInt(int64(i + 1))
		servers[i] = []*big.Int{polyEval(f, xx), polyEval(g, xx)}
	}
	return &ShareSet{T: t, Fcoeff: f, Gcoeff: g, Acoeff: a, servers: servers}
}

// ServerShare returns server i's (value-share, blinding-share, index).
func (s *ShareSet) ServerShare(i int) (val, blind *big.Int, idx *big.Int) {
	idx = big.NewInt(int64(i + 1))
	return s.servers[i][0], s.servers[i][1], idx
}

// Commit computes C(m,r)=g^m·h^r mod P.
func (grp *Group) Commit(m, r *big.Int) *big.Int {
	gm := new(big.Int).Exp(grp.G, m, grp.P)
	hr := new(big.Int).Exp(grp.H, r, grp.P)
	gm.Mul(gm, hr).Mod(gm, grp.P)
	return gm
}

// VerifyShare checks g^{F(i)}·h^{G(i)} == ∏_α A_α^{i^α}.
func (grp *Group) VerifyShare(s *ShareSet, i int) bool {
	val, blind, idx := s.ServerShare(i)
	lhs := grp.Commit(val, blind)
	if lhs.Cmp(evalCommit(grp, s.Acoeff, idx)) != 0 {
		return false
	}
	_ = s
	return true
}

func evalCommit(grp *Group, A []*big.Int, x *big.Int) *big.Int {
	acc := big.NewInt(1)
	pw := big.NewInt(1)
	for _, a := range A {
		t := new(big.Int).Exp(a, pw, grp.P)
		acc.Mul(acc, t).Mod(acc, grp.P)
		pw.Mul(pw, x).Mod(pw, params.GMOD)
	}
	return acc
}

func polyEval(coeff []*big.Int, x *big.Int) *big.Int {
	acc := big.NewInt(0)
	for i := len(coeff) - 1; i >= 0; i-- {
		acc.Mul(acc, x)
		acc.Add(acc, coeff[i])
		acc.Mod(acc, params.GMOD)
	}
	return acc
}

// Reconstruct returns F(0) from t distinct shares (indices 1..n, values in Z_GMOD).
func Reconstruct(idxs, vals []*big.Int) *big.Int {
	sum := big.NewInt(0)
	for i := range idxs {
		lam := lagrange(idxs, i)
		term := new(big.Int).Mul(lam, vals[i])
		sum.Add(sum, term).Mod(sum, params.GMOD)
	}
	return sum
}

// lagrange returns the i-th Lagrange basis at x=0 over the given points.
func lagrange(xs []*big.Int, i int) *big.Int {
	acc := big.NewInt(1)
	for l, xl := range xs {
		if l == i {
			continue
		}
		num := new(big.Int).Neg(xl)
		num.Mod(num, params.GMOD)
		den := new(big.Int).Sub(xs[i], xl)
		den.Mod(den, params.GMOD)
		inv := new(big.Int).ModInverse(den, params.GMOD)
		if inv == nil {
			panic("vss: non-invertible Lagrange denominator")
		}
		acc.Mul(acc, num).Mul(acc, inv).Mod(acc, params.GMOD)
	}
	return acc
}

// randZ draws a uniform nonzero scalar from Z_GMOD using a seeded deterministic
// stream (Reproducible; params.GMOD is < 2^256 so fits math/rand byte output).
func randZ(r *rand.Rand, exclude ...*big.Int) *big.Int {
	for {
		x := new(big.Int).Rand(r, params.GMOD)
		bad := false
		for _, e := range exclude {
			if x.Cmp(e) == 0 {
				bad = true
				break
			}
		}
		if !bad {
			return x
		}
	}
}

// NewBlinder returns a random t-1-degree blinding polynomial R with R(0)=r0,
// used as the *shared* blinding polynomial for all value shares so that
// linear share combinations have an exact, controllable blinding (this is the
// engineering completeness fix for Scheme A's under-specified blinding
// structure that is needed for eq. (17)/(16) to hold verbatim).
func (grp *Group) NewBlinder(r0 *big.Int, t int, seed int64) []*big.Int {
	rng := rand.New(rand.NewSource(seed ^ 0xabcdef01))
	b := make([]*big.Int, t)
	b[0] = new(big.Int).Mod(r0, params.GMOD)
	for k := 1; k < t; k++ {
		b[k] = randZ(rng, big.NewInt(0))
	}
	return b
}

// ShareWithBlind splits a secret under a caller-supplied blinding polynomial
// (blind[0] is the constant blinding random r; share i keeps value F(i) with
// blinding R(i)); coefficient commitments are C(F_α, Blind_α).
func (grp *Group) ShareWithBlind(secret *big.Int, blind []*big.Int, n int, seed int64) *ShareSet {
	t := len(blind)
	rng := rand.New(rand.NewSource(seed ^ 0x1234abcd))
	f := make([]*big.Int, t)
	f[0] = new(big.Int).Mod(secret, params.GMOD)
	for k := 1; k < t; k++ {
		f[k] = randZ(rng, big.NewInt(0))
	}
	a := make([]*big.Int, t)
	for k := 0; k < t; k++ {
		a[k] = grp.Commit(f[k], blind[k])
	}
	servers := make([][]*big.Int, n)
	for i := 0; i < n; i++ {
		xx := big.NewInt(int64(i + 1))
		servers[i] = []*big.Int{polyEval(f, xx), polyEval(blind, xx)}
	}
	return &ShareSet{T: t, Fcoeff: f, Gcoeff: blind, Acoeff: a, servers: servers}
}