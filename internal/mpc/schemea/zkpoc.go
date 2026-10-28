package schemea

//	Eq.(13): A0_j = g^{b_j}      A1_j = g^{a_j} h^{b_j}
//	         H_j  = Hash(desc || C0_j, C1_j, A0_j, A1_j, g, h, P) mod q
//	      g^{d_j} h^{f_j} ?= A1_j · C1_j^{H_j}

import (
	"crypto/sha256"
	"io"
	"math/big"
)

type ZKPoC struct {
	C0 *big.Int
	C1 *big.Int
	A0 *big.Int // g^b
	A1 *big.Int // g^a h^b
	H  *big.Int // Fiat-Shamir challenge
	D  *big.Int // d = a + H·v mod q
	F  *big.Int // f = b + H·l mod q
}

func ZKPoCChallenge(P, g, h, c0, c1, a0, a1, groupOrder *big.Int) *big.Int {
	hsh := sha256.New()
	hsh.Write([]byte("zkpoc-v1"))
	for _, x := range []*big.Int{P, g, h, c0, c1, a0, a1} {
		b := x.Bytes()
		hsh.Write([]byte{byte(len(b) >> 8), byte(len(b))})
		hsh.Write(b)
	}
	return new(big.Int).Mod(new(big.Int).SetBytes(hsh.Sum(nil)), groupOrder)
}

func (p *Params) MakeZKPoC(c0, c1, v, l, groupOrder *big.Int, rng io.Reader) *ZKPoC {
	a := randExponent(groupOrder, rng)
	b := randExponent(groupOrder, rng)
	A0 := new(big.Int).Exp(p.G, b, p.P)
	A1 := new(big.Int).Exp(p.G, a, p.P)
	A1.Mul(A1, new(big.Int).Exp(p.H, b, p.P))
	A1.Mod(A1, p.P)
	H := ZKPoCChallenge(p.P, p.G, p.H, c0, c1, A0, A1, groupOrder)
	D := new(big.Int).Mul(H, v)
	D.Add(D, a)
	D.Mod(D, groupOrder)
	F := new(big.Int).Mul(H, l)
	F.Add(F, b)
	F.Mod(F, groupOrder)
	return &ZKPoC{C0: new(big.Int).Set(c0), C1: new(big.Int).Set(c1), A0: A0, A1: A1, H: H, D: D, F: F}
}

func (p *Params) VerifyZKPoC(pf *ZKPoC, groupOrder *big.Int) bool {
	if pf == nil || pf.C0 == nil || pf.C1 == nil || pf.A0 == nil || pf.A1 == nil || pf.H == nil {
		return false
	}
	wantH := ZKPoCChallenge(p.P, p.G, p.H, pf.C0, pf.C1, pf.A0, pf.A1, groupOrder)
	if wantH.Cmp(pf.H) != 0 {
		return false
	}
	lf := new(big.Int).Exp(p.G, pf.F, p.P)
	rh1 := new(big.Int).Exp(pf.C0, pf.H, p.P)
	rh1.Mul(rh1, pf.A0)
	rh1.Mod(rh1, p.P)
	if lf.Cmp(rh1) != 0 {
		return false
	}
	ld := new(big.Int).Exp(p.G, pf.D, p.P)
	ld.Mul(ld, new(big.Int).Exp(p.H, pf.F, p.P))
	ld.Mod(ld, p.P)
	rh2 := new(big.Int).Exp(pf.C1, pf.H, p.P)
	rh2.Mul(rh2, pf.A1)
	rh2.Mod(rh2, p.P)
	return ld.Cmp(rh2) == 0
}

func randExponent(m *big.Int, rng io.Reader) *big.Int {
	for {
		b := make([]byte, (m.BitLen()+7)/8)
		if _, err := io.ReadFull(rng, b); err != nil {
			continue
		}
		x := new(big.Int).SetBytes(b)
		if x.Sign() > 0 && x.Cmp(m) < 0 {
			return x
		}
	}
}