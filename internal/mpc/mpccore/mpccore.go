// Package mpccore implements the repaired multiplication-triple pipeline of
// Scheme A (Gai et al., TDSC 2025): client-generated Beaver triples whose
// shares are dispatched to servers, plus the verifiable (P,VSS) multiplication
// that computes z_i = c_i + e·a_i + d·b_i + (d·e)_i.
// Repairs applied (documented for the paper's internal contradiction):
//  1. Triple generator unified to "client" (§IV-D-2), removing the
//     "trusted third party" wording of §IV-D-3.
//  2. A single shared blinding polynomial R is used for every value share
//     (inputs x,y and triple components a,b,c). This makes intermediate
//     commitments of differences carry zero blinding, so eq. (17)
//     (c_xi = c_ai·c_di etc.) holds verbatim.
//  3. The missing c_(d·e)_i term in eq. (16) is supplied by a client-committed
//     public t-1-degree re-sharing polynomial P with P(0)=1, so that
//     (d·e)_i := d·e·P(i) and Σ λ_i·(d·e)_i = d·e; its commitment is
//     c_(de)_i = g^{d·e·P(i)} (public scalar, zero blinding).
// All value arithmetic is in Z_GMOD; commitments live in the Z_P^* group.
package mpccore

import (
	"math/big"

	"c5full/internal/mpc/params"
	"c5full/internal/mpc/vss"
)

// Params carries the group + threshold + server count.
type Params struct {
	Grp *vss.Group
	T   int // threshold (eq. F(0) reconstruction needs t shares)
	N   int // number of servers
}

// Triple is a Beaver triple ⟨a,b,c⟩ with c = a·b mod GMOD. Each component is
// VSS-shared under the SAME blinding polynomial R (repair #2).
type Triple struct {
	A, B, C *vss.ShareSet
	CA, CB, CC []*big.Int // per-server commitments c_ai, c_bi, c_ci
}

// Client holds the private inputs and the shared blinding / re-share polys.
type Client struct {
	P    *Params
	R    []*big.Int  // shared blinding polynomial R (repair #2)
	Pdel []*big.Int  // public re-share polynomial P, P(0)=1 (repair #3)
	// input secrets for the demo function (x·y via one multiplication)
	x, y *big.Int
	XSet *vss.ShareSet
	YSet *vss.ShareSet
	XComm, YComm []*big.Int // per-server commitments c_xi, c_yi
}

// NewParams builds a Params over a schemea-supplied group.
func NewParams(P, G, H *big.Int, t, n int) *Params {
	return &Params{Grp: &vss.Group{P: P, G: G, H: H}, T: t, N: n}
}

// NewClient prepares inputs x,y and one Beaver triple for the servers, plus
// the shared re-share polynomial P(0)=1.
func (p *Params) NewClient(x, y *big.Int, seed int64) *Client {
	r0 := big.NewInt(0xfeed)
	R := p.Grp.NewBlinder(r0, p.T, seed)
	pdel := make([]*big.Int, p.T)
	pdel[0] = big.NewInt(1)
	{
		rng := rnd(seed ^ 0x33331337)
		for k := 1; k < p.T; k++ {
			pdel[k] = randZ(rng, big.NewInt(0))
		}
	}
	c := &Client{P: p, R: R, Pdel: pdel, x: x, y: y}
	c.XSet = p.Grp.ShareWithBlind(x, R, p.N, seed)
	c.YSet = p.Grp.ShareWithBlind(y, R, p.N, seed)
	c.XComm = perServerComm(p.Grp, c.XSet, R, p.N)
	c.YComm = perServerComm(p.Grp, c.YSet, R, p.N)
	return c
}

// MakeTriple generates a fresh Beaver triple ⟨a,b,c⟩ (c=a·b) VSS-shared under R.
func (c *Client) MakeTriple(seed int64) *Triple {
	a := new(big.Int).Set(big.NewInt(int64(7 + seed%89)))
	b := new(big.Int).Set(big.NewInt(int64(3 + (seed*13)%97)))
	ab := new(big.Int).Mul(a, b)
	ab.Mod(ab, params.GMOD)
	as := c.P.Grp.ShareWithBlind(a, c.R, c.P.N, seed)
	bs := c.P.Grp.ShareWithBlind(b, c.R, c.P.N, seed)
	cs := c.P.Grp.ShareWithBlind(ab, c.R, c.P.N, seed^0x55)
	t := &Triple{A: as, B: bs, C: cs}
	t.CA = perServerComm(c.P.Grp, as, c.R, c.P.N)
	t.CB = perServerComm(c.P.Grp, bs, c.R, c.P.N)
	t.CC = perServerComm(c.P.Grp, cs, c.R, c.P.N)
	return t
}

// perServerComm returns C(shareVal_i, R(i)) for every server (needed for (16)/(17)).
func perServerComm(g *vss.Group, s *vss.ShareSet, R []*big.Int, n int) []*big.Int {
	out := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		val, _, idx := s.ServerShare(i)
		ri := polyAt(R, idx)
		out[i] = g.Commit(val, ri)
	}
	return out
}

func polyAt(coeff []*big.Int, x *big.Int) *big.Int {
	acc := big.NewInt(0)
	for i := len(coeff) - 1; i >= 0; i-- {
		acc.Mul(acc, x).Add(acc, coeff[i]).Mod(acc, params.GMOD)
	}
	return acc
}

func rnd(seed int64) *rngS { return &rngS{seed: seed} }

type rngS struct{ seed int64 }

// randZ returns a nonzero random scalar for a seeded stream (helper kept local).
func randZ(r *rngS, _ *big.Int) *big.Int {
	r.seed = r.seed*6364136223846793005 + 1442695040888963407
	// take low 52 bits scaled to GMOD via big.Int set
	v := new(big.Int).SetUint64(uint64(r.seed))
	return new(big.Int).Mod(v, params.GMOD)
}

// ServerNode is server i's view of the inputs + a triple.
type ServerNode struct {
	Idx      int
	Xi, Yi   *big.Int
	Ri       *big.Int // R(i) blinding share
	ai, bi, ci *big.Int
}

// BuildServer materializes server i's shares for computation.
func (c *Client) BuildServer(i int, tr *Triple) *ServerNode {
	xi, _, _ := c.XSet.ServerShare(i)
	yi, _, _ := c.YSet.ServerShare(i)
	ai, _, _ := tr.A.ServerShare(i)
	bi, _, _ := tr.B.ServerShare(i)
	ci, _, _ := tr.C.ServerShare(i)
	ri := polyAt(c.R, big.NewInt(int64(i+1)))
	return &ServerNode{Idx: i, Xi: xi, Yi: yi, Ri: ri,
		ai: ai, bi: bi, ci: ci}
}

// Reveal returns the (d_i,e_i) share this server broadcasts for the multiplication.
func (s *ServerNode) Reveal() *Broadcast {
	d := new(big.Int).Sub(s.Xi, s.ai)
	d.Mod(d, params.GMOD)
	e := new(big.Int).Sub(s.Yi, s.bi)
	e.Mod(e, params.GMOD)
	return &Broadcast{Idx: s.Idx, Di: d, Ei: e}
}

// CorruptB tampers this server's b-share (malicious behavior) so that the
// public verification (eq. 17 commitment-mismatch) must fail.
func (s *ServerNode) CorruptB() {
	s.bi = new(big.Int).Add(s.bi, big.NewInt(1))
	s.bi.Mod(s.bi, params.GMOD)
}

// Broadcast is the intermediate (d_i, e_i) a server reveals for the multiplication.
type Broadcast struct {
	Idx  int
	Di   *big.Int
	Ei   *big.Int
}

// MulResult is one server's multiplication output share + its Pedersen blinding.
type MulResult struct {
	Idx     int
	Zi      *big.Int // z_i = c_i + e·a_i + d·b_i + (d·e)_i
	ZBlind  *big.Int // R(i)·(1 + e + d)  mod GMOD
	CDEi    *big.Int // commitment c_(de)_i = g^{d·e·P(i)} (repair #3)
}

// localMul computes zi and its blinding for the given revealed d,e (constants).
func (s *ServerNode) localMul(tr *Triple, pcoeff []*big.Int, d, e *big.Int) *MulResult {
	cm := params.GMOD
	de := new(big.Int).Mul(d, e)
	de.Mod(de, cm)
	dei := new(big.Int).Mul(de, polyAt(pcoeff, big.NewInt(int64(s.Idx+1))))
	dei.Mod(dei, cm)
	z := new(big.Int).Set(s.ci)
	z.Add(z, new(big.Int).Mul(e, s.ai))
	z.Add(z, new(big.Int).Mul(d, s.bi))
	z.Add(z, dei)
	z.Mod(z, cm)
	// blinding R(i)·(1+e+d) mod GMOD
	one := big.NewInt(1)
	zbl := new(big.Int).Add(one, e)
	zbl.Add(zbl, d).Mod(zbl, cm)
	zbl.Mul(zbl, s.Ri).Mod(zbl, cm)
	return &MulResult{Idx: s.Idx, Zi: z, ZBlind: zbl, CDEi: dei}
}

// LocalMulPublic exposes localMul for the orchestrator.
func (s *ServerNode) LocalMulPublic(tr *Triple, pcoeff []*big.Int, d, e *big.Int) *MulResult {
	return s.localMul(tr, pcoeff, d, e)
}

// GetPdel returns the public re-share polynomial P.
func (c *Client) GetPdel() []*big.Int { return c.Pdel }

func gmul(grp *vss.Group, a, b *big.Int) *big.Int {
	r := new(big.Int).Mul(a, b)
	return r.Mod(r, grp.P)
}

func gpown(grp *vss.Group, a, e *big.Int) *big.Int {
	return new(big.Int).Exp(a, e, grp.P)
}

// VerifyMul checks eq. (17) (revealed d_i,e_i are consistent with the
// commitments) and eq. (16) (the output-share commitment c_zi is the
// homomorphic combination c_ci·c_ai^e·c_bi^d·c_(de)_i) for every server. This
// is exactly the step that Scheme A's literal instantiation cannot complete
// without the (d·e) re-sharing commitment supplied by repair #3.
// Returns (ok, first-failing-server-index).
func (c *Client) VerifyMul(tr *Triple, srvs []*ServerNode, d, e *big.Int) (bool, int) {
	grp := c.P.Grp
	for i := 0; i < len(srvs); i++ {
		s := srvs[i]
		di := new(big.Int).Sub(s.Xi, s.ai)
		di.Mod(di, params.GMOD)
		ei := new(big.Int).Sub(s.Yi, s.bi)
		ei.Mod(ei, params.GMOD)
		// eq. (17): c_xi == c_ai · g^{d_i},   c_yi == c_bi · g^{e_i}
		if gmul(grp, tr.CA[i], grp.Commit(di, big.NewInt(0))).Cmp(c.XComm[i]) != 0 {
			return false, i
		}
		if gmul(grp, tr.CB[i], grp.Commit(ei, big.NewInt(0))).Cmp(c.YComm[i]) != 0 {
			return false, i
		}
		// eq. (16): c_zi == c_ci · c_ai^e · c_bi^d · g^{(d·e)_i}
		mr := s.localMul(tr, c.Pdel, d, e)
		cand := tr.CC[i]
		cand = gmul(grp, cand, gpown(grp, tr.CA[i], e))
		cand = gmul(grp, cand, gpown(grp, tr.CB[i], d))
		cand = gmul(grp, cand, grp.Commit(mr.CDEi, big.NewInt(0)))
		if cand.Cmp(grp.Commit(mr.Zi, mr.ZBlind)) != 0 {
			return false, i
		}
	}
	return true, -1
}