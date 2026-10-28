package bottomc5

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"
)

type Params struct {
	N, F, L int
}

func (p Params) Check() bool {
	return p.N >= 2*p.F+1 && p.F >= 0 && p.L >= 1
}

func (p Params) Threshold() int { return p.F + 1 }

type ServerOpening struct {
	Index int      `json:"index"`
	Z     *big.Int `json:"z"`
	Rho   *big.Int `json:"rho"`
}

type CommittedOutputBundle struct {
	N             int                        `json:"n"`
	F             int                        `json:"f"`
	L             int                        `json:"l"`
	Xi            []*big.Int                 `json:"xi"`
	Aout          [][]*secp256k1.G1Affine    `json:"aout"`          // L x (f+1)
	Openings      []ServerOpening            `json:"openings"`
	Output        []*big.Int                 `json:"output"`
	ZCoeff        [][]*big.Int               `json:"z_coeff"`
	RhoCoeff      [][]*big.Int               `json:"rho_coeff"`
	BottomTraceHash [32]byte                 `json:"bottom_trace_hash"`
}

func (b *CommittedOutputBundle) OutputAout(j int) []*secp256k1.G1Affine {
	if j < 0 || j >= b.L || j >= len(b.Aout) {
		return nil
	}
	return b.Aout[j]
}

func (b *CommittedOutputBundle) OpeningAt(i int) (ServerOpening, bool) {
	for _, o := range b.Openings {
		if o.Index == i {
			return o, true
		}
	}
	return ServerOpening{}, false
}

type Wire struct {
	Degree     int                      // f
	ValCoeff   []*big.Int
	BlindCoeff []*big.Int               // b_{0..f}
	Commit     []*secp256k1.G1Affine    // A_w,k
}

func (w *Wire) Value() *big.Int { return new(big.Int).Set(w.ValCoeff[0]) }