package contracts

import (
	"encoding/hex"
	"encoding/json"

	"c5full/blockchain/fabric/chaincode/model"
	"c5full/blockchain/fabric/chaincode/verify"
)

func decodePayloadHex(h string) (index int, rHex string, cHex []string, sigHex, proofHex string, err error) {
	raw, derr := hex.DecodeString(h)
	if derr != nil {
		return 0, "", nil, "", "", model.Reject(model.CodeMalformedRecord, "payload is not valid hex")
	}
	return model.ParseCanonicalDeliveryBytes(raw)
}

func taskShape(l verify.Ledger, taskID string) (int, int, error) {
	b, err := l.GetState(verify.KeyC5Task + taskID)
	if err != nil {
		return 0, 0, err
	}
	if len(b) == 0 {
		return 0, 0, model.Reject(model.CodeTaskNotFound, "task not registered")
	}
	var rec model.PublicTaskRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return 0, 0, model.Reject(model.CodeMalformedRecord, "corrupt stored task")
	}
	return rec.N, rec.L, nil
}