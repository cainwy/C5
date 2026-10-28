package contracts

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"

	"c5full/blockchain/fabric/chaincode/verify"
)

type StubAPI interface {
	GetState(key string) ([]byte, error)
	PutState(key string, value []byte) error
	GetStateByRange(startKey, endKey string) (shim.StateQueryIteratorInterface, error)
	GetTxID() string
}

type stubLedger struct {
	stub StubAPI
}

func (l stubLedger) GetState(key string) ([]byte, error) { return l.stub.GetState(key) }

func (l stubLedger) PutState(key string, value []byte) error {
	return l.stub.PutState(key, value)
}

func (l stubLedger) KeysWithPrefix(prefix string) ([]string, error) {
	end := prefix + string(rune(0xFF))
	it, err := l.stub.GetStateByRange(prefix, end)
	if err != nil {
		return nil, err
	}
	defer it.Close()
	out := []string{}
	for it.HasNext() {
		kv, err := it.Next()
		if err != nil {
			return nil, err
		}
		if kv == nil {
			break
		}
		out = append(out, kv.Key)
	}
	return out, nil
}

func ledgerOf(ctx contractapi.TransactionContextInterface) (verify.Ledger, error) {
	adapter, err := stubOf(ctx)
	if err != nil {
		return nil, err
	}
	return stubLedger{stub: adapter}, nil
}

func stubOf(ctx contractapi.TransactionContextInterface) (StubAPI, error) {
	if ctx == nil {
		return nil, fmt.Errorf("contracts: nil transaction context")
	}
	st := ctx.GetStub()
	if st == nil {
		return nil, fmt.Errorf("contracts: nil stub")
	}
	adapter, ok := st.(StubAPI)
	if !ok {
		return nil, fmt.Errorf("contracts: stub does not satisfy StubAPI")
	}
	return adapter, nil
}

func logTiming(txID, contract, fn, scheme string, v *verify.Verdict) {
	if v == nil {
		return
	}
	line := map[string]any{
		"tag":                    "cc_core_timing",
		"tx_id":                  txID,
		"contract":               contract,
		"function":               fn,
		"scheme":                 scheme,
		"result":                 verdictResult(v),
		"certificate_verify_ns":  v.Timing.CertVerifyNS,
		"signature_verify_ns":    v.Timing.SignatureVerifyNS,
		"proof_verify_ns":        v.Timing.ProofVerifyNS,
		"zkpoc_verify_ns":        v.Timing.ZKPoCVerifyNS,
		"commitment_verify_ns":   v.Timing.CommitmentVerifyNS,
		"group_check_ns":         v.Timing.GroupCheckNS,
		"state_read_ns":          v.Timing.StateReadNS,
		"state_write_prepare_ns": v.Timing.StateWritePrepareNS,
		"verify_core_ns":         v.Timing.VerifyCoreNS,
	}
	b, _ := json.Marshal(line)
	fmt.Println(string(b))
}

func stripTiming(v *verify.Verdict) *verify.Verdict {
	if v == nil {
		return nil
	}
	out := *v
	out.Timing = verify.Timing{}
	return &out
}

func verdictResult(v *verify.Verdict) string {
	if v == nil {
		return "reject"
	}
	if v.OK {
		return "pass"
	}
	return "reject"
}

func txID(ctx contractapi.TransactionContextInterface) string {
	st, err := stubOf(ctx)
	if err != nil {
		return ""
	}
	return st.GetTxID()
}