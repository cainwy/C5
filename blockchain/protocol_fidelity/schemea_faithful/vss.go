package schemeafaithful


import (
	"crypto/rand"
	"math/big"
)

type ShareSet struct {
	T, N  int
	F     []*big.Int
	Gc    []*big.Int
	E     []*big.Int
	Shares []*Share
}

type Share struct {
	J  int
	S  *big.Int // s_{i,j} = F(j)
	Tb *big.Int // t_{i,j} = G(j)
}

func (g *Group) ScalarMod() *big.Int { return new(big.Int).Set(g.ExpMod) }

func RandScalar(mod *big.Int, r crandReader) (*big.Int, error) {
	for {
		x, err := rand.Int(r, mod)
		if err != nil {
			return nil, err
		}
		if x.Sign() != 0 {
			return x, nil
		}
	}
}

func (g *Group) VSSShare(secret, rho, hPub *big.Int, t, n int, r crandReader) (*ShareSet, error) {
	if t < 1 || n < t {
		return nil, errf(ErrBadShare, "bad threshold t=%d n=%d", t, n)
	}
	if secret == nil || rho == nil {
		return nil, errf(ErrBadShare, "nil secret/rho")
	}
	mod := g.ScalarMod()
	F := make([]*big.Int, t)
	Gc := make([]*big.Int, t)
	F[0] = new(big.Int).Mod(secret, mod)
	Gc[0] = new(big.Int).Mod(rho, mod)
	for k := 1; k < t; k++ {
		f, err := RandScalar(mod, r)
		if err != nil {
			return nil, err
		}
		bb, err := RandScalar(mod, r)
		if err != nil {
			return nil, err
		}
		F[k] = f
		Gc[k] = bb
	}
	E := make([]*big.Int, t)
	for k := 0; k < t; k++ {
		E[k] = g.Commit(hPub, F[k], Gc[k])
	}
	shares := make([]*Share, n)
	for j := 1; j <= n; j++ {
		x := big.NewInt(int64(j))
		shares[j-1] = &Share{J: j, S: polyEval(F, x, mod), Tb: polyEval(Gc, x, mod)}
	}
	return &ShareSet{T: t, N: n, F: F, Gc: Gc, E: E, Shares: shares}, nil
}

func polyEval(coeff []*big.Int, x, m *big.Int) *big.Int {
	acc := big.NewInt(0)
	for i := len(coeff) - 1; i >= 0; i-- {
		acc.Mul(acc, x)
		acc.Add(acc, coeff[i])
		acc.Mod(acc, m)
	}
	return acc
}

func (g *Group) VerifyShare(hPub *big.Int, E []*big.Int, sh *Share) (bool, error) {
	if sh == nil || sh.J < 1 || len(E) == 0 {
		return false, errf(ErrBadShare, "bad share/commitments")
	}
	for i, Ea := range E {
		if Ea == nil {
			return false, errf(ErrBadShare, "nil E_%d", i)
		}
	}
	lhs := g.Commit(hPub, sh.S, sh.Tb)
	rhs := big.NewInt(1)
	jx := big.NewInt(int64(sh.J))
	for alpha, Ea := range E {
		exp := new(big.Int).Exp(jx, big.NewInt(int64(alpha)), nil)
		term := g.Pow(Ea, exp)
		rhs = g.Mul(rhs, term)
	}
	return lhs.Cmp(rhs) == 0, nil
}

func Reconstruct(shares []*Share, mod *big.Int) (*big.Int, error) {
	if len(shares) == 0 {
		return nil, errf(ErrReconstruct, "no shares")
	}
	seen := map[int]bool{}
	for _, sh := range shares {
		if sh == nil || sh.J < 1 || seen[sh.J] {
			return nil, errf(ErrReconstruct, "nil/duplicate share index")
		}
		seen[sh.J] = true
	}
	sum := big.NewInt(0)
	for i, si := range shares {
		lam := lagrangeAt0(shares, i, mod)
		term := new(big.Int).Mul(lam, si.S)
		term.Mod(term, mod)
		sum.Add(sum, term)
		sum.Mod(sum, mod)
	}
	return sum, nil
}

func lagrangeAt0(shares []*Share, i int, mod *big.Int) *big.Int {
	acc := big.NewInt(1)
	for j, sj := range shares {
		if j == i {
			continue
		}
		num := new(big.Int).Neg(big.NewInt(int64(sj.J)))
		num.Mod(num, mod)
		den := new(big.Int).Sub(big.NewInt(int64(shares[i].J)), big.NewInt(int64(sj.J)))
		den.Mod(den, mod)
		inv := new(big.Int).ModInverse(den, mod)
		if inv == nil {
			return big.NewInt(0)
		}
		acc.Mul(acc, num)
		acc.Mul(acc, inv)
		acc.Mod(acc, mod)
	}
	return acc
}
