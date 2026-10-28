package schemeafaithful


import (
	"io"
	"math/big"
)

type ElGamalConfig struct {
	K         int
	ChunkBits int
}

func (c ElGamalConfig) W() int { return c.K / c.ChunkBits }

var DefaultElGamal = ElGamalConfig{K: 256, ChunkBits: 32}

var PatentElGamal = ElGamalConfig{K: 128, ChunkBits: 16}

func (g *Group) Split(z *big.Int, cfg ElGamalConfig) []*big.Int {
	w := cfg.W()
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(cfg.ChunkBits)), big.NewInt(1))
	vs := make([]*big.Int, w)
	for j := 0; j < w; j++ {
		vj := new(big.Int).And(new(big.Int).Rsh(z, uint(j*cfg.ChunkBits)), mask)
		vs[j] = vj
	}
	return vs
}

func (g *Group) Recombine(vs []*big.Int, cfg ElGamalConfig) *big.Int {
	z := big.NewInt(0)
	for j := 0; j < len(vs); j++ {
		z.Add(z, new(big.Int).Lsh(vs[j], uint(j*cfg.ChunkBits)))
	}
	return z
}

type CipherText struct {
	C0, C1 *big.Int
}

func (g *Group) EncryptPartition(h, v, l *big.Int) *CipherText {
	c0 := g.Pow(g.G, l)
	c1 := g.Commit(h, v, l)
	return &CipherText{C0: c0, C1: c1}
}

type EncryptedShare struct {
	Cts []*CipherText
	ls  []*big.Int
	Vs  []*big.Int
}

func (g *Group) EncryptShare(h, z, r *big.Int, cfg ElGamalConfig, rng io.Reader) (*EncryptedShare, error) {
	if z == nil || r == nil {
		return nil, errf(ErrBadParams, "nil z/r")
	}
	if z.BitLen() > cfg.K {
		return nil, errf(ErrBadParams, "z.BitLen()=%d exceeds k=%d (share must fit k bits)", z.BitLen(), cfg.K)
	}
	vs := g.Split(z, cfg)
	w := len(vs)
	ls := make([]*big.Int, w)
	for j := 1; j < w; j++ {
		l, err := RandScalar(g.ExpMod, rng)
		if err != nil {
			return nil, err
		}
		ls[j] = l
	}
	// l_0 = r − Σ l_j·2^{jp} mod ExpMod
	acc := big.NewInt(0)
	for j := 1; j < w; j++ {
		term := new(big.Int).Lsh(ls[j], uint(j*cfg.ChunkBits))
		acc.Add(acc, term)
	}
	l0 := new(big.Int).Sub(r, acc)
	l0.Mod(l0, g.ExpMod)
	ls[0] = l0
	cts := make([]*CipherText, w)
	for j := 0; j < w; j++ {
		cts[j] = g.EncryptPartition(h, vs[j], ls[j])
	}
	return &EncryptedShare{Cts: cts, ls: ls, Vs: vs}, nil
}

func (e *EncryptedShare) Ls() []*big.Int { return e.ls }

func (g *Group) HomomorphicProduct(cts []*CipherText, cfg ElGamalConfig) *big.Int {
	prod := big.NewInt(1)
	for j, ct := range cts {
		exp := new(big.Int).Lsh(big.NewInt(1), uint(j*cfg.ChunkBits))
		term := g.Pow(ct.C1, exp)
		prod = g.Mul(prod, term)
	}
	return prod
}
