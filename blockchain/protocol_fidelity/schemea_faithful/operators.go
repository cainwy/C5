package schemeafaithful


import (
	"io"
	"math/big"
)

type TripleMode int

const (
	TripleModeClient TripleMode = iota
	TripleModeServer
)

type ResharePoly struct {
	Fc []*big.Int
	Gc []*big.Int
	E  []*big.Int
}

func (g *Group) NewResharePoly(t int, hPub *big.Int, r io.Reader) (*ResharePoly, error) {
	return newResharePoly(g, hPub, t, r)
}

func newResharePoly(g *Group, hPub *big.Int, t int, r io.Reader) (*ResharePoly, error) {
	mod := g.ScalarMod()
	Fc := make([]*big.Int, t)
	Gc := make([]*big.Int, t)
	Fc[0] = big.NewInt(1)
	Gc[0] = big.NewInt(0)
	for k := 1; k < t; k++ {
		f, err := RandScalar(mod, r)
		if err != nil {
			return nil, err
		}
		bb, err := RandScalar(mod, r)
		if err != nil {
			return nil, err
		}
		Fc[k] = f
		Gc[k] = bb
	}
	E := make([]*big.Int, t)
	for k := 0; k < t; k++ {
		E[k] = g.Commit(hPub, Fc[k], Gc[k])
	}
	return &ResharePoly{Fc: Fc, Gc: Gc, E: E}, nil
}

func (g *Group) DeShare(rp *ResharePoly, de *big.Int, j int) (val, blind *big.Int) {
	x := big.NewInt(int64(j))
	return new(big.Int).Mod(new(big.Int).Mul(de, polyEval(rp.Fc, x, g.ExpMod)), g.ExpMod),
		new(big.Int).Mod(new(big.Int).Mul(de, polyEval(rp.Gc, x, g.ExpMod)), g.ExpMod)
}

func (g *Group) DeCommit(rp *ResharePoly, de *big.Int, j int) *big.Int {
	x := big.NewInt(int64(j))
	ej := big.NewInt(1)
	for alpha, Ea := range rp.E {
		exp := new(big.Int).Exp(x, big.NewInt(int64(alpha)), nil)
		ej = g.Mul(ej, g.Pow(Ea, exp))
	}
	return g.Pow(ej, de)
}

type BeaverTriple struct {
	A, B, C *ShareSet
	CA, CB, CC []*big.Int
	RA, RB, RC []*big.Int
}

func (g *Group) MakeTriple(t, n int, mode TripleMode, hPub *big.Int, r io.Reader) (*BeaverTriple, error) {
	if t < 1 || n < t {
		return nil, errf(ErrBadShare, "bad t/n")
	}
	_ = mode
	mod := g.ScalarMod()
	a, err := RandScalar(mod, r)
	if err != nil {
		return nil, err
	}
	b, err2 := RandScalar(mod, r)
	if err2 != nil {
		return nil, err2
	}
	c := new(big.Int).Mul(a, b)
	c.Mod(c, mod)
	_ = mode
	ra, err3 := RandScalar(mod, r)
	if err3 != nil {
		return nil, err3
	}
	rb, err4 := RandScalar(mod, r)
	if err4 != nil {
		return nil, err4
	}
	rc, err5 := RandScalar(mod, r)
	if err5 != nil {
		return nil, err5
	}
	as, err := g.VSSShare(a, ra, hPub, t, n, r)
	if err != nil {
		return nil, err
	}
	bs, err := g.VSSShare(b, rb, hPub, t, n, r)
	if err != nil {
		return nil, err
	}
	cs, err := g.VSSShare(c, rc, hPub, t, n, r)
	if err != nil {
		return nil, err
	}
	ca := make([]*big.Int, n)
	cbn := make([]*big.Int, n)
	cc := make([]*big.Int, n)
	raL := make([]*big.Int, n)
	rbL := make([]*big.Int, n)
	rcL := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		raL[i] = polyEval(as.Gc, big.NewInt(int64(i+1)), g.ScalarMod())
		rbL[i] = polyEval(bs.Gc, big.NewInt(int64(i+1)), g.ScalarMod())
		rcL[i] = polyEval(cs.Gc, big.NewInt(int64(i+1)), g.ScalarMod())
		ca[i] = g.Commit(hPub, as.Shares[i].S, raL[i])
		cbn[i] = g.Commit(hPub, bs.Shares[i].S, rbL[i])
		cc[i] = g.Commit(hPub, cs.Shares[i].S, rcL[i])
	}
	return &BeaverTriple{A: as, B: bs, C: cs, CA: ca, CB: cbn, CC: cc, RA: raL, RB: rbL, RC: rcL}, nil
}

func MulReveal(sAlpha, sBeta, aI, bI *big.Int, mod *big.Int) (dI, eI *big.Int) {
	dI = new(big.Int).Sub(sAlpha, aI)
	dI.Mod(dI, mod)
	eI = new(big.Int).Sub(sBeta, bI)
	eI.Mod(eI, mod)
	return dI, eI
}

func (g *Group) MulLocal(ci, aI, bI, d, e, dei *big.Int, raI, rbI, rcI, rdeI *big.Int) (z, zr *big.Int) {
	mod := g.ScalarMod()
	z = new(big.Int).Mul(e, aI)
	z.Add(z, new(big.Int).Mul(d, bI))
	z.Add(z, ci)
	z.Add(z, dei)
	z.Mod(z, mod)
	zr = new(big.Int).Mul(e, raI)
	zr.Add(zr, new(big.Int).Mul(d, rbI))
	zr.Add(zr, rcI)
	zr.Add(zr, rdeI)
	zr.Mod(zr, mod)
	return z, zr
}

func AddOp(x, y *big.Int, mod *big.Int) *big.Int {
	z := new(big.Int).Add(x, y)
	return z.Mod(z, mod)
}

func ConstMulOp(c, x *big.Int, mod *big.Int) *big.Int {
	z := new(big.Int).Mul(c, x)
	return z.Mod(z, mod)
}

func ConstAddOp(c, x *big.Int, mod *big.Int) *big.Int {
	z := new(big.Int).Add(c, x)
	return z.Mod(z, mod)
}
