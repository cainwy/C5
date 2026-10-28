package bottomc5


import (
	"crypto/rand"
	"io"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"

	"c5full/internal/c5/host"
)

type StageTimings struct {
	InputShareNS    int64 `json:"input_share_ns"`
	TriplePrepNS    int64 `json:"triple_prep_ns"`
	DiffShareNS     int64 `json:"diff_share_ns"`
	OutputCombineNS int64 `json:"output_combine_ns"`
	BundleNS        int64 `json:"bundle_ns"`
}

func (s StageTimings) OnlineMulNS() int64 { return s.DiffShareNS + s.OutputCombineNS }

type DiffShare struct {
	Index int      // 0-based
	D     *big.Int
	Delta *big.Int
	E     *big.Int
	Eps   *big.Int
}

type Dealer struct {
	P     Params
	X     *big.Int
	Y     *big.Int
	RNG   io.Reader
	WireX *Wire
	WireY *Wire
	WireA *Wire
	WireB *Wire
	WireC *Wire
	WireZ *Wire
	DiffTries []DiffShare
	Accepted  []DiffShare

	FaithfulDeprecated bool

	Timings StageTimings
}

func NewDealer(p Params, x, y *big.Int, rng io.Reader) *Dealer {
	if rng == nil {
		rng = rand.Reader
	}
	return &Dealer{P: p, X: x, Y: y, RNG: rng}
}

func (d *Dealer) DiffShareOf(i int) DiffShare {
	xi := d.Xi()[i]
	xv, xr := WireShareOf(d.WireX, xi)
	av, ar := WireShareOf(d.WireA, xi)
	yv, yr := WireShareOf(d.WireY, xi)
	bv, br := WireShareOf(d.WireB, xi)
	return DiffShare{
		Index: i,
		D:     subQ(xv, av), Delta: subQ(xr, ar),
		E: subQ(yv, bv), Eps: subQ(yr, br),
	}
}

func (d *Dealer) Xi() []*big.Int { return xiPoints(d.P.N) }

// checkDiffCom validates a difference share against the wire-commitment
func (d *Dealer) checkDiffCom(s DiffShare) bool {
	if s.Index < 0 || s.Index >= d.P.N {
		return false
	}
	xi := d.Xi()[s.Index]
	diffA := make([]*secp256k1.G1Affine, d.P.F+1)
	for k := 0; k <= d.P.F; k++ {
		neg := host.ScalarMul(d.WireA.Commit[k], big.NewInt(-1))
		diffA[k] = host.AddPoints(d.WireX.Commit[k], neg)
	}
	if !CheckOpening(diffA, xi, s.D, s.Delta) {
		return false
	}
	diffB := make([]*secp256k1.G1Affine, d.P.F+1)
	for k := 0; k <= d.P.F; k++ {
		neg := host.ScalarMul(d.WireB.Commit[k], big.NewInt(-1))
		diffB[k] = host.AddPoints(d.WireY.Commit[k], neg)
	}
	return CheckOpening(diffB, xi, s.E, s.Eps)
}

func (d *Dealer) gatherValid() []DiffShare {
	seen := map[int]bool{}
	valid := []DiffShare{}
	for _, s := range d.DiffTries {
		if seen[s.Index] {
			continue
		}
		seen[s.Index] = true
		if d.checkDiffCom(s) {
			valid = append(valid, s)
			d.Accepted = append(d.Accepted, s)
		}
	}
	return valid
}

func reconstructD(valid []DiffShare, choose func([]DiffShare) []DiffShare) (*big.Int, *big.Int) {
	sel := choose(valid)
	xs := make([]*big.Int, len(sel))
	ds := make([]*big.Int, len(sel))
	es := make([]*big.Int, len(sel))
	for i, s := range sel {
		xs[i] = big.NewInt(int64(s.Index + 1)) // xi_i = i+1
		ds[i] = s.D
		es[i] = s.E
	}
	return interpolate0(xs, ds), interpolate0(xs, es)
}

func firstK(valid []DiffShare, k int) []DiffShare {
	sel := append([]DiffShare{}, valid...)
	for a := 1; a < len(sel); a++ {
		for b := a; b > 0 && sel[b].Index < sel[b-1].Index; b-- {
			sel[b], sel[b-1] = sel[b-1], sel[b]
		}
	}
	if len(sel) > k {
		sel = sel[:k]
	}
	return sel
}

func (d *Dealer) runBeaver() (*CommittedOutputBundle, *Trace) {
	p := d.P
	f := p.F
	hasWires := d.WireX != nil && d.WireA != nil && d.WireY != nil && d.WireB != nil && d.WireC != nil
	if hasWires {
		if d.WireZ != nil {
			return d.buildBundle(f)
		}
	}

	if !hasWires {
		tIS := time.Now()
		d.WireX = NewWireR(f, d.X, d.RNG)
		d.WireY = NewWireR(f, d.Y, d.RNG)
		d.Timings.InputShareNS = time.Since(tIS).Nanoseconds()

		tTP := time.Now()
		a := randScalarR(d.RNG, true)
		b := randScalarR(d.RNG, true)
		d.WireA = NewWireR(f, a, d.RNG)
		d.WireB = NewWireR(f, b, d.RNG)
		d.WireC = NewWireR(f, mulQ(a, b), d.RNG)
		d.Timings.TriplePrepNS = time.Since(tTP).Nanoseconds()
	}

	tDiff := time.Now()
	d.Accepted = nil
	if len(d.DiffTries) == 0 {
		d.DiffTries = make([]DiffShare, p.N)
		for i := 0; i < p.N; i++ {
			d.DiffTries[i] = d.DiffShareOf(i)
		}
	}
	valid := d.gatherValid()
	if len(valid) < p.Threshold() {
		return nil, nil
	}
	dVal, eVal := reconstructD(valid, func(v []DiffShare) []DiffShare { return firstK(v, p.Threshold()) })
	d.Timings.DiffShareNS = time.Since(tDiff).Nanoseconds()

	tOC := time.Now()
	zed := mulQ(dVal, eVal)
	zedG := host.ScalarMulBase(zed)
	zc := make([]*big.Int, f+1)
	rc := make([]*big.Int, f+1)
	ac := make([][]*secp256k1.G1Affine, 1) // L=1 primary
	ac[0] = make([]*secp256k1.G1Affine, f+1)
	for k := 0; k <= f; k++ {
		zk := addQ(addQ(d.WireC.ValCoeff[k], mulQ(eVal, d.WireA.ValCoeff[k])), mulQ(dVal, d.WireB.ValCoeff[k]))
		rk := addQ(addQ(d.WireC.BlindCoeff[k], mulQ(eVal, d.WireA.BlindCoeff[k])), mulQ(dVal, d.WireB.BlindCoeff[k]))
		if k == 0 {
			zk = addQ(zk, zed)
		}
		zc[k], rc[k] = zk, rk
		com := host.AddPoints(
			d.WireC.Commit[k],
			host.ScalarMul(d.WireA.Commit[k], eVal),
			host.ScalarMul(d.WireB.Commit[k], dVal),
		)
		if k == 0 {
			com = host.AddPoints(com, zedG)
		}
		ac[0][k] = com
	}
	d.WireZ = &Wire{Degree: f, ValCoeff: zc, BlindCoeff: rc, Commit: ac[0]}
	d.Timings.OutputCombineNS = time.Since(tOC).Nanoseconds()
	return d.buildBundle(f)
}

func (d *Dealer) buildBundle(f int) (*CommittedOutputBundle, *Trace) {
	tB := time.Now()
	defer func() { d.Timings.BundleNS = time.Since(tB).Nanoseconds() }()
	xi := d.Xi()
	out := &CommittedOutputBundle{
		N:      d.P.N, F: d.P.F, L: 1,
		Xi:     xi,
		Aout:   [][]*secp256k1.G1Affine{d.WireZ.Commit},
		ZCoeff: [][]*big.Int{append([]*big.Int(nil), d.WireZ.ValCoeff...)},
		RhoCoeff: [][]*big.Int{append([]*big.Int(nil), d.WireZ.BlindCoeff...)},
	}
	out.Output = []*big.Int{modQ(d.WireZ.Value())}
	acceptedIdx := map[int]bool{}
	for _, s := range d.Accepted {
		acceptedIdx[s.Index] = true
	}
	out.Openings = make([]ServerOpening, 0, len(d.Accepted))
	for i := 0; i < d.P.N; i++ {
		if !acceptedIdx[i] {
			continue
		}
		zvi, rvi := WireShareOf(d.WireZ, xi[i])
		out.Openings = append(out.Openings, ServerOpening{Index: i, Z: zvi, Rho: rvi})
	}
	tr := NewTrace(d)
	out.BottomTraceHash = tr.Hash()
	return out, tr
}

func (d *Dealer) Run() (*CommittedOutputBundle, *Trace, error) {
	if !d.P.Check() {
		return nil, nil, &BottomError{"bad params"}
	}
	if d.X == nil || d.Y == nil {
		return nil, nil, &BottomError{"nil input"}
	}
	b, tr := d.runBeaver()
	if b == nil {
		return nil, tr, &BottomError{"insufficient valid diff shares"}
	}
	return b, tr, nil
}

func (d *Dealer) RunWithTimings() (*CommittedOutputBundle, *Trace, StageTimings, error) {
	b, tr, err := d.Run()
	return b, tr, d.Timings, err
}

func (d *Dealer) TripleNonDegenerate() bool {
	if d.WireA == nil || d.WireB == nil || d.WireC == nil {
		return false
	}
	a, b, c := d.WireA.Value(), d.WireB.Value(), d.WireC.Value()
	return a.Sign() != 0 && b.Sign() != 0 && c.Sign() != 0 && mulQ(a, b).Cmp(c) == 0
}

func VerifyInvariant(b *CommittedOutputBundle) int {
	for j := 0; j < b.L; j++ {
		for i := 0; i < b.N; i++ {
			xi := b.Xi[i]
			o, ok := b.OpeningAt(i)
			if !ok {
				return i
			}
			if !CheckOpening(b.OutputAout(j), xi, o.Z, o.Rho) {
				return i
			}
		}
	}
	return -1
}

type BottomError struct{ msg string }

func (e *BottomError) Error() string { return "bottomc5: " + e.msg }