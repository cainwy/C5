package contracts


import (
	"encoding/json"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"

	"c5full/blockchain/fabric/chaincode/model"
	"c5full/blockchain/fabric/chaincode/verify"
)

type SchemeAContract struct {
	contractapi.Contract
}

func (s *SchemeAContract) RegisterSchemeATask(ctx contractapi.TransactionContextInterface, payloadJSON string) (*verify.Verdict, error) {
	l, err := ledgerOf(ctx)
	if err != nil {
		return nil, err
	}
	var rec model.SchemeATaskRecord
	if err := json.Unmarshal([]byte(payloadJSON), &rec); err != nil {
		return nil, model.Reject(model.CodeMalformedRecord, "scheme A task payload is not valid JSON")
	}
	v, err := verify.RegisterSchemeATask(l, &rec)
	if err != nil {
		return nil, err
	}
	logTiming(txID(ctx), "SchemeAContract", "RegisterSchemeATask", "SchemeA", v)
	return stripTiming(v), nil
}

func (s *SchemeAContract) VerifySchemeAOutput(ctx contractapi.TransactionContextInterface, taskID string, submissionJSON string) (*verify.Verdict, error) {
	l, err := ledgerOf(ctx)
	if err != nil {
		return nil, err
	}
	var sub model.SchemeAOutputSubmission
	if err := json.Unmarshal([]byte(submissionJSON), &sub); err != nil {
		return nil, model.Reject(model.CodeMalformedRecord, "scheme A submission is not valid JSON")
	}
	sub.TaskID = taskID
	v, err := verify.AcceptSchemeAOutput(l, taskID, &sub)
	if err != nil {
		return nil, err
	}
	logTiming(txID(ctx), "SchemeAContract", "VerifySchemeAOutput", "SchemeA", v)
	return stripTiming(v), nil
}

func (s *SchemeAContract) QuerySchemeAAcceptedOutputs(ctx contractapi.TransactionContextInterface, taskID string) (string, error) {
	l, err := ledgerOf(ctx)
	if err != nil {
		return "", err
	}
	n, idx, err := verify.CountAcceptedSAOutputs(l, taskID)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(map[string]any{"count": n, "indices": idx})
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (s *SchemeAContract) SchemeAChaincodeProfile(ctx contractapi.TransactionContextInterface) (string, error) {
	out := map[string]any{
		"schema":             model.SchemaID,
		"contract":           "SchemeAContract",
		"main_profile":       "P-SA-128 (3072-bit, k=256, p=32, w=8)",
		"supporting_profile": "P-SA-112 (2048-bit)",
		"diagnostic_only":    "P-SA-256-DIAG (256-bit; excluded from main results)",
		"plaintext_inputs":   false,
		"dlog_on_chain":      false,
		"verify_steps": []string{
			"decode", "optional-subgroup", "zkpoc",
			"eq17-intermediate-verification", "eq16-output-commitment-derivation",
			"homomorphic-vs-derived-commitment",
		},
		"protocol_fidelity": map[string]any{
			"paper":                     "Gai et al., IEEE TDSC 2025",
			"eq15_addition":             true,
			"eq16_multiplication":       true,
			"eq17_blinding_factors":     true,
			"input_commitments_onchain": true,
			"mul_intermediates_onchain": true,
			"derived_not_injected":      true,
		},
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	return string(b), nil
}


func (s *SchemeAContract) RegisterSchemeAInputCommitments(ctx contractapi.TransactionContextInterface, payloadJSON string) (*verify.Verdict, error) {
	l, err := ledgerOf(ctx)
	if err != nil {
		return nil, err
	}
	var rec model.SchemeAInputCommitmentRecord
	if err := json.Unmarshal([]byte(payloadJSON), &rec); err != nil {
		return nil, model.Reject(model.CodeMalformedRecord, "input commitment payload is not valid JSON")
	}
	v, err := verify.RegisterSchemeAInputCommitments(l, &rec)
	if err != nil {
		return nil, err
	}
	logTiming(txID(ctx), "SchemeAContract", "RegisterSchemeAInputCommitments", "SchemeA", v)
	return stripTiming(v), nil
}

func (s *SchemeAContract) SubmitSchemeAMultiplicationIntermediate(ctx contractapi.TransactionContextInterface, payloadJSON string) (*verify.Verdict, error) {
	l, err := ledgerOf(ctx)
	if err != nil {
		return nil, err
	}
	var rec model.SchemeAMulIntermediateRecord
	if err := json.Unmarshal([]byte(payloadJSON), &rec); err != nil {
		return nil, model.Reject(model.CodeMalformedRecord, "intermediate payload is not valid JSON")
	}
	v, err := verify.SubmitSchemeAMultiplicationIntermediate(l, &rec)
	if err != nil {
		return nil, err
	}
	logTiming(txID(ctx), "SchemeAContract", "SubmitSchemeAMultiplicationIntermediate", "SchemeA", v)
	return stripTiming(v), nil
}

func (s *SchemeAContract) DeriveSchemeAOutputCommitment(ctx contractapi.TransactionContextInterface, taskID string, serverIndex1Based int) (*verify.Verdict, error) {
	l, err := ledgerOf(ctx)
	if err != nil {
		return nil, err
	}
	cz, err := verify.DeriveSchemeAOutputCommitment(l, taskID, serverIndex1Based)
	if err != nil {
		return nil, err
	}
	raw, err := l.GetState(verify.KeySATask + taskID)
	if err != nil {
		return nil, err
	}
	var task model.SchemeATaskRecord
	if err := json.Unmarshal(raw, &task); err != nil {
		return nil, model.Reject(model.CodeMalformedRecord, "corrupt scheme A task")
	}
	width := (task.PrimeBits + 7) / 8
	if err := verify.StoreDerivedCz(l, taskID, serverIndex1Based, cz, width); err != nil {
		return nil, err
	}
	v := &verify.Verdict{OK: true, TaskID: taskID, Index: serverIndex1Based,
		Notes: []string{"output commitment derived on-chain from registered state (Eq.16)"}}
	logTiming(txID(ctx), "SchemeAContract", "DeriveSchemeAOutputCommitment", "SchemeA", v)
	return stripTiming(v), nil
}
