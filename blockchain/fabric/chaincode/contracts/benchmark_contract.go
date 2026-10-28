package contracts


import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"

	"c5full/blockchain/bridge"
	"c5full/blockchain/fabric/chaincode/model"
	"c5full/blockchain/fabric/chaincode/verify"
)

type BenchmarkContract struct {
	contractapi.Contract

	Res *Resources
}

func (b *BenchmarkContract) resources() (*Resources, error) {
	if b.Res != nil {
		return b.Res, nil
	}
	return MustInitResources("")
}

func benchKey(taskID, requestID string) string {
	return fmt.Sprintf("%s%s:%s", verify.KeyBenchPrefix, taskID, requestID)
}

type benchRecord struct {
	Schema    string `json:"schema"`
	TaskID    string `json:"task_id"`
	Scheme    string `json:"scheme"`
	RequestID string `json:"request_id"`
	DigestHex string `json:"digest_hex"`
	Index     int    `json:"index"`
	Result    string `json:"result"`
}

func (b *BenchmarkContract) BenchmarkVerifyC5(ctx contractapi.TransactionContextInterface, taskID string, deliveryPayloadHex string, benchRequestID string) (*verify.Verdict, error) {
	l, err := ledgerOf(ctx)
	if err != nil {
		return nil, err
	}
	if benchRequestID == "" {
		return nil, model.Reject(model.CodeMalformedRecord, "bench_request_id required")
	}
	res, err := b.resources()
	if err != nil {
		return nil, err
	}
	idx, rHex, cHex, sigHex, proofHex, err := decodePayloadHex(deliveryPayloadHex)
	if err != nil {
		return nil, err
	}
	taskN, taskL, err := taskShape(l, taskID)
	if err != nil {
		return nil, err
	}
	d, err := bridge.DecodeDelivery(idx, rHex, cHex, sigHex, proofHex, taskN, taskL)
	if err != nil {
		return nil, err
	}
	v, _, _, _, err := verify.VerifyC5DeliveryCore(l, taskID, d, res.Verifier)
	if err != nil {
		return nil, err
	}
	if err := b.putBench(l, taskID, benchRequestID, "C5", d.I+1, v.AcceptedDigest); err != nil {
		return nil, err
	}
	logTiming(txID(ctx), "BenchmarkContract", "BenchmarkVerifyC5", "C5", v)
	return stripTiming(v), nil
}

func (b *BenchmarkContract) BenchmarkVerifySchemeA(ctx contractapi.TransactionContextInterface, taskID string, submissionJSON string, benchRequestID string) (*verify.Verdict, error) {
	l, err := ledgerOf(ctx)
	if err != nil {
		return nil, err
	}
	if benchRequestID == "" {
		return nil, model.Reject(model.CodeMalformedRecord, "bench_request_id required")
	}
	var sub model.SchemeAOutputSubmission
	if err := json.Unmarshal([]byte(submissionJSON), &sub); err != nil {
		return nil, model.Reject(model.CodeMalformedRecord, "submission is not valid JSON")
	}
	sub.TaskID = taskID
	v, _, err := verify.VerifySchemeAOutputCore(l, taskID, &sub)
	if err != nil {
		return nil, err
	}
	if err := b.putBench(l, taskID, benchRequestID, "SchemeA", sub.ServerIndex, v.AcceptedDigest); err != nil {
		return nil, err
	}
	logTiming(txID(ctx), "BenchmarkContract", "BenchmarkVerifySchemeA", "SchemeA", v)
	return stripTiming(v), nil
}

func (b *BenchmarkContract) putBench(l verify.Ledger, taskID, requestID, scheme string, index int, digest string) error {
	rec := &benchRecord{
		Schema: model.SchemaID, TaskID: taskID, Scheme: scheme,
		RequestID: requestID, DigestHex: digest, Index: index, Result: "pass",
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return l.PutState(benchKey(taskID, requestID), raw)
}

func (b *BenchmarkContract) BenchmarkProfile(ctx contractapi.TransactionContextInterface) (string, error) {
	out := map[string]any{
		"schema":          model.SchemaID,
		"contract":        "BenchmarkContract",
		"is_protocol_endpoint": false,
		"disclosure":      "benchmark-only endpoint; reuses the production verification core unchanged",
		"repeats_allowed": true,
		"state_prefix":    verify.KeyBenchPrefix,
		"generated_by":    "contracts.BenchmarkProfile",
	}
	b2, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	return string(b2), nil
}