package schemea

import (
	"crypto/rand"
	"io"
	"math/big"
)

type PaperPublicKey struct {
	P      *big.Int
	G      *big.Int
	H      *big.Int   // h = ∏_{i=1}^m g^{s_i} = g^{Σ s_i}
	Shares []*big.Int
	Count  int
}

type PaperClientKeys struct {
	P      *big.Int        `json:"p"`
	G      *big.Int        `json:"g"`
	S      []*big.Int      `json:"-"`
	Public *PaperPublicKey `json:"public"`
}

func NewPaperClientKeys(P, G *big.Int, m int, rng io.Reader) (*PaperClientKeys, error) {
	if P == nil || G == nil {
		return nil, &PaperErr{"nil group parameter"}
	}
	if m < 1 {
		return nil, &PaperErr{"m must be >= 1"}
	}
	if rng == nil {
		rng = rand.Reader
	}
	order := new(big.Int).Sub(P, big.NewInt(1))
	s := make([]*big.Int, m)
	pubShares := make([]*big.Int, m)
	h := big.NewInt(1)
	for i := 0; i < m; i++ {
		s[i] = randExponentIn(order, rng) // s_i ∈ [1, P-2]
		pubShares[i] = new(big.Int).Exp(G, s[i], P)
		h.Mul(h, pubShares[i])
		h.Mod(h, P)
	}
	return &PaperClientKeys{
		P: P, G: G, S: s,
		Public: &PaperPublicKey{
			P: P, G: G, H: h, Shares: pubShares, Count: m,
		},
	}, nil
}

func (k *PaperClientKeys) PaperPartialDecrypt(ct0 *big.Int, i int) *big.Int {
	return new(big.Int).Exp(ct0, k.S[i], k.P)
}

//	t_j = ∏_{i=1}^{m} (C_j^0)^{s_i}
func (k *PaperClientKeys) PaperCombine(ct0 *big.Int) *big.Int {
	t := big.NewInt(1)
	for i := 0; i < k.Public.Count; i++ {
		ti := k.PaperPartialDecrypt(ct0, i)
		t.Mul(t, ti)
		t.Mod(t, k.P)
	}
	return t
}

func (k *PaperClientKeys) PaperRecoverGv(ct0, ct1 *big.Int) *big.Int {
	t := k.PaperCombine(ct0)
	inv := new(big.Int).ModInverse(t, k.P)
	out := new(big.Int).Mul(ct1, inv)
	return out.Mod(out, k.P)
}

type PublicBytes struct {
	P   string
	G   string
	H   string
	Ki  []string
	Sum string
}

type PaperErr struct{ msg string }

func (e *PaperErr) Error() string { return "repro/schemea: " + e.msg }

func randExponentIn(mod *big.Int, rng io.Reader) *big.Int {
	w := (mod.BitLen() + 7) / 8
	buf := make([]byte, w)
	for {
		if _, err := io.ReadFull(rng, buf); err != nil {
			panic("repro/schemea: rng read failed: " + err.Error())
		}
		x := new(big.Int).SetBytes(buf)
		x.Mod(x, new(big.Int).Sub(mod, big.NewInt(1)))
		x.Add(x, big.NewInt(1)) // [1, mod-1]
		if x.Cmp(mod) < 0 {
			return x
		}
	}
}
