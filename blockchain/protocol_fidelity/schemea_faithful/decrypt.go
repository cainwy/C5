package schemeafaithful


import (
	"math/big"
)

type KeyShare struct {
	Client int      // 1..m
	S      *big.Int
}

type DecryptKeySet struct {
	Shares []*KeyShare
}

func NewDecryptKeySet(s *big.Int, m int, g *Group, r crandReader) (*DecryptKeySet, error) {
	if m < 1 {
		return nil, errf(ErrDecrypt, "m<1")
	}
	shares := make([]*KeyShare, m)
	sum := big.NewInt(0)
	for i := 0; i < m-1; i++ {
		si, err := RandScalar(g.ExpMod, r)
		if err != nil {
			return nil, err
		}
		shares[i] = &KeyShare{Client: i + 1, S: si}
		sum.Add(sum, si)
	}
	last := new(big.Int).Sub(s, sum)
	last.Mod(last, g.ExpMod)
	shares[m-1] = &KeyShare{Client: m, S: last}
	return &DecryptKeySet{Shares: shares}, nil
}

func (g *Group) ProductDecrypt(ct *CipherText, partials []*big.Int) (*big.Int, error) {
	if len(partials) == 0 {
		return nil, errf(ErrDecrypt, "no partials")
	}
	t := big.NewInt(1)
	for _, p := range partials {
		if p == nil {
			return nil, errf(ErrDecrypt, "nil partial")
		}
		t = g.Mul(t, p)
	}
	inv := new(big.Int).ModInverse(t, g.P)
	if inv == nil {
		return nil, errf(ErrDecrypt, "non-invertible t_j")
	}
	return g.Mul(ct.C1, inv), nil
}

func (g *Group) PartialDecrypt(ct *CipherText, ks *KeyShare) *big.Int {
	return g.Pow(ct.C0, ks.S)
}
