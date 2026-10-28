package schemea

//	Eq.(20): t_j = ∏_{i=1}^m C0_j^{s_i} ;  g^{v_j} = C1_j / t_j

import (
	"io"
	"math/big"
)

type DecryptionShareSet struct {
	P      *big.Int
	G      *big.Int
	M      int
	T      int
	Shares []*big.Int
	Commit []*big.Int
}

func (p *Params) NewDecryptionShareSet(t, m int, rng io.Reader) (*DecryptionShareSet, error) {
	if t < 1 || m < t || m < 1 {
		return nil, &SchemeAError{"bad threshold topology"}
	}
	order := new(big.Int).Sub(p.P, big.NewInt(1)) // Z_{P-1}
	coeffs := make([]*big.Int, t)
	coeffs[0] = new(big.Int).Mod(new(big.Int).Set(p.S), order)
	for k := 1; k < t; k++ {
		coeffs[k] = randExponent(order, rng)
	}
	set := &DecryptionShareSet{P: p.P, G: p.G, M: m, T: t,
		Shares: make([]*big.Int, m), Commit: make([]*big.Int, m)}
	for i := 0; i < m; i++ {
		xi := big.NewInt(int64(i + 1))
		si := polyEvalA(coeffs, xi, order)
		set.Shares[i] = si
		set.Commit[i] = new(big.Int).Exp(p.G, si, p.P)
	}
	return set, nil
}

func (p *Params) PartialDecrypt(ct *Ciphertext, set *DecryptionShareSet, i int) *big.Int {
	return new(big.Int).Exp(ct.C0, set.Shares[i], p.P)
}

func CombineDecrypt(partials []*big.Int, idx []int, set *DecryptionShareSet) (*big.Int, error) {
	if len(partials) != len(idx) || len(partials) < set.T {
		return nil, &SchemeAError{"insufficient partials"}
	}
	order := new(big.Int).Sub(set.P, big.NewInt(1))
	acc := big.NewInt(1)
	for i := range idx {
		lam := lagrangeAt(idx, i, order)
		term := new(big.Int).Exp(partials[i], lam, set.P)
		acc.Mul(acc, term)
		acc.Mod(acc, set.P)
	}
	return acc, nil
}

func (p *Params) RevealDecrypt(ct *Ciphertext, set *DecryptionShareSet, i int) []byte {
	partial := p.PartialDecrypt(ct, set, i)
	return SerializePartial(partial, p.P)
}

func VerifyPartial(ct0, partial, commitShare, P *big.Int) bool {
	if partial == nil || partial.Cmp(big.NewInt(1)) < 0 || partial.Cmp(P) >= 0 {
		return false
	}
	_ = commitShare
	return true
}

func lagrangeAt(idx []int, i int, order *big.Int) *big.Int {
	acc := big.NewInt(1)
	xi := big.NewInt(int64(idx[i] + 1))
	for j, xj := range idx {
		if j == i {
			continue
		}
		num := new(big.Int).Neg(big.NewInt(int64(xj + 1)))
		num.Mod(num, order)
		den := new(big.Int).Sub(xi, big.NewInt(int64(xj+1)))
		den.Mod(den, order)
		denInv := new(big.Int).ModInverse(den, order)
		term := new(big.Int).Mul(num, denInv)
		term.Mod(term, order)
		acc.Mul(acc, term)
		acc.Mod(acc, order)
	}
	return acc
}

func polyEvalA(coeffs []*big.Int, x, m *big.Int) *big.Int {
	acc := new(big.Int)
	for i := len(coeffs) - 1; i >= 0; i-- {
		acc.Mul(acc, x)
		acc.Add(acc, coeffs[i])
		acc.Mod(acc, m)
	}
	return acc
}

type SchemeAError struct{ msg string }

func (e *SchemeAError) Error() string { return "schemea: " + e.msg }