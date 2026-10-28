package schemeafaithful

//	        H_j = Hash(C^0_j, C^1_j, A^0_j, A^1_j, g, h)
//	        d_j = a_j + H_j·v_j ; f_j = b_j + H_j·l_j
//	        g^{d_j} h^{f_j} ?= A^1_j · (C^1_j)^{H_j}

import (
	"crypto/sha256"
	"io"
	"math/big"
)

type ZKPoCConfig struct {
	SubgroupOrder bool
}

var DefaultZKPoC = ZKPoCConfig{SubgroupOrder: true}

type ZKProof struct {
	A0, A1 *big.Int
	D, F   *big.Int
}

func (g *Group) challenge(hPub, c0, c1, a0, a1, order *big.Int) *big.Int {
	hsh := sha256.New()
	hsh.Write([]byte("sa-zkpoc-v1"))
	for _, x := range []*big.Int{c0, c1, a0, a1, g.G, hPub} {
		b := x.Bytes()
		hsh.Write([]byte{byte(len(b) >> 8), byte(len(b))})
		hsh.Write(b)
	}
	return new(big.Int).Mod(new(big.Int).SetBytes(hsh.Sum(nil)), order)
}

func (g *Group) MakeZKPoC(hPub *big.Int, c *CipherText, v, l *big.Int, cfg ZKPoCConfig, rng io.Reader) (*ZKProof, error) {
	order := g.ExpMod
	if !cfg.SubgroupOrder {
		order = new(big.Int).Sub(g.P, big.NewInt(1))
	}
	a, err := RandScalar(order, rng)
	if err != nil {
		return nil, err
	}
	b, err := RandScalar(order, rng)
	if err != nil {
		return nil, err
	}
	a0 := g.Pow(g.G, b)
	a1 := g.Commit(hPub, a, b)
	H := g.challenge(hPub, c.C0, c.C1, a0, a1, order)
	d := new(big.Int).Mul(H, v)
	d.Add(d, a)
	d.Mod(d, order)
	f := new(big.Int).Mul(H, l)
	f.Add(f, b)
	f.Mod(f, order)
	return &ZKProof{A0: a0, A1: a1, D: d, F: f}, nil
}

func (g *Group) VerifyZKPoC(hPub *big.Int, c *CipherText, pf *ZKProof, cfg ZKPoCConfig) (bool, error) {
	if pf == nil || pf.A0 == nil || pf.A1 == nil || pf.D == nil || pf.F == nil {
		return false, errf(ErrZKPoC, "nil proof fields")
	}
	order := g.ExpMod
	if !cfg.SubgroupOrder {
		order = new(big.Int).Sub(g.P, big.NewInt(1))
	}
	H := g.challenge(hPub, c.C0, c.C1, pf.A0, pf.A1, order)
	// g^f ?= A0 · C0^H
	lhs := g.Pow(g.G, pf.F)
	rhs := g.Mul(pf.A0, g.Pow(c.C0, H))
	if lhs.Cmp(rhs) != 0 {
		return false, nil
	}
	// g^d h^f ?= A1 · C1^H
	lh2 := g.Commit(hPub, pf.D, pf.F)
	rh2 := g.Mul(pf.A1, g.Pow(c.C1, H))
	return lh2.Cmp(rh2) == 0, nil
}
