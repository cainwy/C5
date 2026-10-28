package verify

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"c5full/internal/c5/params"

	"c5full/blockchain/bridge"
	"c5full/blockchain/fabric/chaincode/model"
)

func schemeaGroupOrder(P *big.Int) *big.Int {
	return new(big.Int).Sub(P, big.NewInt(1))
}

func hexC(c []*big.Int) []string {
	out := make([]string, len(c))
	for i, x := range c {
		b := make([]byte, 32)
		new(big.Int).Mod(x, params.Q).FillBytes(b)
		out[i] = hex.EncodeToString(b)
	}
	return out
}

type RangeLedger interface {
	KeysWithPrefix(prefix string) ([]string, error)
}

func rangeKeys(l Ledger, prefix string) ([]string, error) {
	rl, ok := l.(RangeLedger)
	if !ok {
		return nil, model.Reject(model.CodeMalformedRecord, "ledger does not support prefix range scan")
	}
	return rl.KeysWithPrefix(prefix)
}

func schemeAOutputSizes(sub *model.SchemeAOutputSubmission) (string, error) {
	if len(sub.Cts) == 0 {
		return "", model.Reject(model.CodeShapeMismatch, "empty submission")
	}
	return fmt.Sprintf("cts=%d zkpocs=%d", len(sub.Cts), len(sub.ZKPoCs)), nil
}

func CanonicalVerdictJSON(v *Verdict) ([]byte, error) {
	if v == nil {
		return nil, model.Reject(model.CodeMalformedRecord, "nil verdict")
	}
	return model.MarshalJSONCanonical(v)
}

func CanonicalConstraints(L, constraints int) bool {
	return bridge.CanonicalConstraints(L, constraints)
}