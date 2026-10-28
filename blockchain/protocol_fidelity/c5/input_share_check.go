//	  Com(w_i; rho_{w,i}) ?= EvalCom(A_w, xi_i) = sum_{k=0}^{f} xi_i^k A_{w,k}
package c5

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"

	"c5full/internal/bottomc5"
)

var ErrInputShareCheck = errors.New("c5-fidelity: input share inconsistent with coefficient commitment")

func CheckInputShare(Aw []*secp256k1.G1Affine, xi, wi, rhoi *big.Int) error {
	if len(Aw) == 0 {
		return fmt.Errorf("%w: empty coefficient commitment", ErrInputShareCheck)
	}
	if xi == nil || wi == nil || rhoi == nil {
		return fmt.Errorf("%w: nil input", ErrInputShareCheck)
	}
	if !bottomc5.CheckOpening(Aw, xi, wi, rhoi) {
		return ErrInputShareCheck
	}
	return nil
}

type InputShareReport struct {
	Schema      string `json:"schema"`
	TaskCtxHex  string `json:"task_ctx_hex"`
	ServerIndex int    `json:"server_index"`
	Index1Based int    `json:"index_1based"`
	WireLabel   string `json:"wire_label"` // "x" | "y" | "a" | "b" | "c"
	Checked     bool   `json:"checked"`
	Passed      bool   `json:"passed"`
	Failure     string `json:"failure,omitempty"`
}

func CheckWireShares(taskCtx []byte, label string, w *bottomc5.Wire, xi []*big.Int) []InputShareReport {
	reports := make([]InputShareReport, 0, len(xi))
	for i, x := range xi {
		wi, rhoi := bottomc5.WireShareOf(w, x)
		rep := InputShareReport{
			Schema: "c5-input-share-check-v1", TaskCtxHex: hexEncode(taskCtx),
			ServerIndex: i, Index1Based: i + 1, WireLabel: label, Checked: true,
		}
		if err := CheckInputShare(w.Commit, x, wi, rhoi); err != nil {
			rep.Passed = false
			rep.Failure = err.Error()
		} else {
			rep.Passed = true
		}
		reports = append(reports, rep)
	}
	return reports
}

func AllPassed(reports []InputShareReport) bool {
	if len(reports) == 0 {
		return false
	}
	for _, r := range reports {
		if !r.Checked || !r.Passed {
			return false
		}
	}
	return true
}
