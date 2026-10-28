//	d.WireC = NewWireR(f, mulQ(a, b), d.RNG)     // ⇒ c = 0
//	d_i = x_i - a_i = x_i - 0 = x_i
//	e_i = y_i - b_i = y_i - 0 = y_i
package c5

import (
	"errors"
	"fmt"
	"io"
	"math/big"

	"c5full/internal/bottomc5"
	"c5full/internal/c5/params"
)

var ErrDegenerateTriple = errors.New("c5-fidelity: degenerate Beaver triple (a or b is zero)")

type FaithfulBeaverTriple struct {
	WireA *bottomc5.Wire
	WireB *bottomc5.Wire
	WireC *bottomc5.Wire
	A *big.Int `json:"-"`
	B *big.Int `json:"-"`
	C *big.Int `json:"-"`
}

func NewFaithfulBeaverTriple(f int, rng io.Reader) (*FaithfulBeaverTriple, error) {
	if rng == nil {
		return nil, fmt.Errorf("c5-fidelity: nil rng")
	}
	a := randScalarNonZero(rng)
	b := randScalarNonZero(rng)
	c := new(big.Int).Mul(a, b)
	c.Mod(c, params.Q)

	t := &FaithfulBeaverTriple{
		WireA: bottomc5.NewWireR(f, a, rng),
		WireB: bottomc5.NewWireR(f, b, rng),
		WireC: bottomc5.NewWireR(f, c, rng),
		A:     a, B: b, C: c,
	}
	if err := t.Check(); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *FaithfulBeaverTriple) Check() error {
	if t == nil || t.WireA == nil || t.WireB == nil || t.WireC == nil {
		return fmt.Errorf("%w: nil wire", ErrDegenerateTriple)
	}
	av := t.WireA.Value()
	bv := t.WireB.Value()
	cv := t.WireC.Value()
	if av.Sign() == 0 || bv.Sign() == 0 {
		return fmt.Errorf("%w: a=%s b=%s", ErrDegenerateTriple, av.String(), bv.String())
	}
	want := new(big.Int).Mul(av, bv)
	want.Mod(want, params.Q)
	if cv.Cmp(want) != 0 {
		return fmt.Errorf("%w: c != a*b", ErrDegenerateTriple)
	}
	return nil
}

func (t *FaithfulBeaverTriple) NonDegenerate() bool { return t.Check() == nil }

func randScalarNonZero(rng io.Reader) *big.Int {
	buf := make([]byte, 40)
	for {
		if _, err := io.ReadFull(rng, buf); err != nil {
			panic("c5-fidelity: rng read failed: " + err.Error())
		}
		x := new(big.Int).SetBytes(buf)
		x.Mod(x, params.Q)
		if x.Sign() != 0 {
			return x
		}
	}
}
