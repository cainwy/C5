package schemea

import (
	"math/big"
	"testing"

	root "c5full/internal/mpc/schemea"
)

func TestPaperClientKeySetTopology(t *testing.T) {
	base := root.NewParams(256, 8, 4, 7)
	P, G := base.P, base.G

	keys, err := NewPaperClientKeys(P, G, 3, nil)
	if err != nil {
		t.Fatalf("NewPaperClientKeys: %v", err)
	}
	wantH := big.NewInt(1)
	for i := 0; i < 3; i++ {
		ki := new(big.Int).Exp(G, keys.S[i], P)
		if ki.Cmp(keys.Public.Shares[i]) != 0 {
			t.Fatalf("public share k_%d mismatch", i)
		}
		wantH.Mul(wantH, ki)
		wantH.Mod(wantH, P)
	}
	if wantH.Cmp(keys.Public.H) != 0 {
		t.Fatalf("h mismatch")
	}

	v := big.NewInt(12345)
	l := big.NewInt(678)
	ct0 := new(big.Int).Exp(G, l, P)
	ct1 := new(big.Int).Mul(new(big.Int).Exp(G, v, P), new(big.Int).Exp(keys.Public.H, l, P))
	ct1.Mod(ct1, P)

	gv := keys.PaperRecoverGv(ct0, ct1)
	wantGv := new(big.Int).Exp(G, v, P)
	if gv.Cmp(wantGv) != 0 {
		t.Fatalf("Eq.(20) recovered wrong g^v: got %s want %s", gv, wantGv)
	}
}

func TestPaperClientKeySetIncorrectPartial(t *testing.T) {
	base := root.NewParams(256, 8, 4, 7)
	P, G := base.P, base.G
	keys, _ := NewPaperClientKeys(P, G, 2, nil)

	v := big.NewInt(99)
	l := big.NewInt(5)
	ct0 := new(big.Int).Exp(G, l, P)
	ct1 := new(big.Int).Mul(new(big.Int).Exp(G, v, P), new(big.Int).Exp(keys.Public.H, l, P))
	ct1.Mod(ct1, P)

	bad := &PaperClientKeys{P: P, G: G, S: []*big.Int{big.NewInt(1), big.NewInt(7)},
		Public: keys.Public}
	gv := bad.PaperRecoverGv(ct0, ct1)
	if gv.Cmp(new(big.Int).Exp(G, v, P)) == 0 {
		t.Fatal("incorrect private shares must NOT recover the correct output")
	}
}

func TestPaperClientKeySetErrors(t *testing.T) {
	if _, err := NewPaperClientKeys(nil, big.NewInt(2), 1, nil); err == nil {
		t.Fatal("expected error on nil P")
	}
	if _, err := NewPaperClientKeys(big.NewInt(23), nil, 1, nil); err == nil {
		t.Fatal("expected error on nil G")
	}
	if _, err := NewPaperClientKeys(big.NewInt(23), big.NewInt(2), 0, nil); err == nil {
		t.Fatal("expected error on m=0")
	}
}
