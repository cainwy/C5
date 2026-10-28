package contracts


import (
	"encoding/json"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"

	"c5full/blockchain/bridge"
	"c5full/blockchain/fabric/chaincode/model"
	"c5full/blockchain/fabric/chaincode/verify"
)

type C5Contract struct {
	contractapi.Contract

	Res *Resources
}

func (c *C5Contract) resources() (*Resources, error) {
	if c.Res != nil {
		return c.Res, nil
	}
	return MustInitResources("")
}

func (c *C5Contract) RegisterC5Task(ctx contractapi.TransactionContextInterface, payloadJSON string) (*verify.Verdict, error) {
	l, err := ledgerOf(ctx)
	if err != nil {
		return nil, err
	}
	var rec model.PublicTaskRecord
	if err := json.Unmarshal([]byte(payloadJSON), &rec); err != nil {
		return nil, model.Reject(model.CodeMalformedRecord, "task payload is not valid JSON")
	}
	res, err := c.resources()
	if err != nil {
		return nil, err
	}
	if res.Manifest != nil {
		if rec.VKHash != res.VKHash {
			return nil, model.Reject(model.CodeVKMismatch, "task vk_hash != chaincode vk hash")
		}
		if rec.Constraints != res.Manifest.Constraints || rec.MaskCtxLen != res.Manifest.MaskCtxLen {
			return nil, model.Reject(model.CodeProfileMismatch, "task profile != chaincode profile")
		}
	}
	v, err := verify.RegisterC5Task(l, &rec)
	if err != nil {
		return nil, err
	}
	logTiming(txID(ctx), "C5Contract", "RegisterC5Task", "C5", v)
	return stripTiming(v), nil
}

func (c *C5Contract) FinalizeC5State(ctx contractapi.TransactionContextInterface, taskID string, certJSON string) (*verify.Verdict, error) {
	l, err := ledgerOf(ctx)
	if err != nil {
		return nil, err
	}
	var cert model.CertificateRecord
	if err := json.Unmarshal([]byte(certJSON), &cert); err != nil {
		return nil, model.Reject(model.CodeMalformedRecord, "certificate payload is not valid JSON")
	}
	v, _, err := verify.FinalizeC5State(l, taskID, &cert)
	if err != nil {
		return nil, err
	}
	logTiming(txID(ctx), "C5Contract", "FinalizeC5State", "C5", v)
	return stripTiming(v), nil
}

func (c *C5Contract) VerifyC5Delivery(ctx contractapi.TransactionContextInterface, taskID string, deliveryPayloadHex string) (*verify.Verdict, error) {
	l, err := ledgerOf(ctx)
	if err != nil {
		return nil, err
	}
	res, err := c.resources()
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
	v, err := verify.AcceptC5Delivery(l, taskID, d, res.Verifier)
	if err != nil {
		return nil, err
	}
	logTiming(txID(ctx), "C5Contract", "VerifyC5Delivery", "C5", v)
	return stripTiming(v), nil
}

func (c *C5Contract) QueryC5FinalizedState(ctx contractapi.TransactionContextInterface, taskID string) (*model.FinalizedStateRecord, error) {
	l, err := ledgerOf(ctx)
	if err != nil {
		return nil, err
	}
	return verify.QueryC5FinalizedState(l, taskID)
}

func (c *C5Contract) QueryC5AcceptedDeliveries(ctx contractapi.TransactionContextInterface, taskID string) (string, error) {
	l, err := ledgerOf(ctx)
	if err != nil {
		return "", err
	}
	n, idx, err := verify.CountAcceptedDeliveries(l, taskID)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(map[string]any{"count": n, "indices": idx})
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (c *C5Contract) C5ChaincodeProfile(ctx contractapi.TransactionContextInterface) (string, error) {
	res, err := c.resources()
	if err != nil {
		return "", err
	}
	out := map[string]any{
		"schema":        model.SchemaID,
		"contract":      "C5Contract",
		"profile_id":    res.Manifest.ProfileID,
		"L":             res.Manifest.L,
		"maskctx_len":   res.Manifest.MaskCtxLen,
		"constraints":   res.Manifest.Constraints,
		"vk_hash":       res.VKHash,
		"vk_size":       res.Manifest.SizeVK,
		"pk_in_chaincode": false,
		"verify_order":  []string{"certificate", "finality", "index", "signature", "groth16-proof"},
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	return string(b), nil
}