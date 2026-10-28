package verify

//	IV-D-3  "server S_i need to submit d_i and e_i to the blockchain"
//	        Eq.(16) cz_i = cc_i · cea_i · cdb_i · c(de)_i

import (
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"c5full/internal/mpc/schemea"

	"c5full/blockchain/bridge"
	"c5full/blockchain/fabric/chaincode/model"
	sapf "c5full/blockchain/protocol_fidelity/schemea"
)

func RegisterSchemeAInputCommitments(l Ledger, rec *model.SchemeAInputCommitmentRecord) (*Verdict, error) {
	t0 := time.Now()
	if err := rec.Validate(); err != nil {
		return nil, err
	}
	taskRaw, err := l.GetState(KeySATask + rec.TaskID)
	if err != nil {
		return nil, err
	}
	if len(taskRaw) == 0 {
		return nil, model.Reject(model.CodeTaskNotFound, "scheme A task not registered")
	}
	var task model.SchemeATaskRecord
	if err := json.Unmarshal(taskRaw, &task); err != nil {
		return nil, model.Reject(model.CodeMalformedRecord, "corrupt scheme A task")
	}
	width := bridge.WidthForPrimeBits(task.PrimeBits)

	for ci, row := range rec.PolyCommitmentsHex {
		if len(row) == 0 {
			return nil, model.Reject(model.CodeShapeMismatch, fmt.Sprintf("client %d has no commitments", ci))
		}
		for ai, h := range row {
			v, err := bridge.DecodeSchemeAElement(h, width)
			if err != nil {
				return nil, err
			}
			if v.Sign() <= 0 || v.Cmp(new(big.Int).SetBytes(mustBigHex(task.PHex))) >= 0 {
				return nil, model.Reject(model.CodeMalformedGroup,
					fmt.Sprintf("poly commitment [%d][%d] out of range", ci, ai))
			}
		}
	}
	for k := range rec.BeaverCommitmentsHex {
		idx, err := parseServerKey(k, task.Servers)
		if err != nil {
			return nil, err
		}
		_ = idx
	}
	for k := range rec.MulDiffCommitmentsHex {
		if _, err := parseServerKey(k, task.Servers); err != nil {
			return nil, err
		}
	}
	for k, set := range rec.BeaverCommitmentsHex {
		for _, h := range []string{set.CAHex, set.CBHex, set.CCHex} {
			v, err := bridge.DecodeSchemeAElement(h, width)
			if err != nil {
				return nil, err
			}
			if v.Sign() <= 0 {
				return nil, model.Reject(model.CodeMalformedGroup, "zero Beaver commitment for server "+k)
			}
		}
	}
	for k, h := range rec.MulDiffCommitmentsHex {
		v, err := bridge.DecodeSchemeAElement(h, width)
		if err != nil {
			return nil, err
		}
		if v.Sign() <= 0 {
			return nil, model.Reject(model.CodeMalformedGroup, "zero c(de) commitment for server "+k)
		}
	}

	key := model.KeySAInputCommPrefix + rec.TaskID
	if b, err := l.GetState(key); err != nil {
		return nil, err
	} else if len(b) != 0 {
		var prev model.SchemeAInputCommitmentRecord
		if err := json.Unmarshal(b, &prev); err != nil {
			return nil, model.Reject(model.CodeMalformedRecord, "corrupt input commitment record")
		}
		if jsonEqual(&prev, rec) {
			return &Verdict{OK: true, TaskID: rec.TaskID,
				Notes: []string{"idempotent input-commitment re-registration"}}, nil
		}
		return nil, model.Reject(model.CodeTaskExists, "input commitments already registered with different content")
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	if err := l.PutState(key, raw); err != nil {
		return nil, err
	}
	return &Verdict{OK: true, TaskID: rec.TaskID, Notes: []string{"input commitments registered"},
		Timing: Timing{StateWritePrepareNS: time.Since(t0).Nanoseconds()}}, nil
}

func SubmitSchemeAMultiplicationIntermediate(l Ledger, rec *model.SchemeAMulIntermediateRecord) (*Verdict, error) {
	t0 := time.Now()
	if err := rec.Validate(); err != nil {
		return nil, err
	}
	taskRaw, err := l.GetState(KeySATask + rec.TaskID)
	if err != nil {
		return nil, err
	}
	if len(taskRaw) == 0 {
		return nil, model.Reject(model.CodeTaskNotFound, "scheme A task not registered")
	}
	var task model.SchemeATaskRecord
	if err := json.Unmarshal(taskRaw, &task); err != nil {
		return nil, model.Reject(model.CodeMalformedRecord, "corrupt scheme A task")
	}
	if rec.ServerIndex < 1 || rec.ServerIndex > task.Servers {
		return nil, model.Reject(model.CodeInvalidIndex, "server index out of range")
	}
	sp, err := bridge.SAParamsFromRecord(&task)
	if err != nil {
		return nil, err
	}

	inRaw, err := l.GetState(model.KeySAInputCommPrefix + rec.TaskID)
	if err != nil {
		return nil, err
	}
	if len(inRaw) == 0 {
		return nil, model.Reject(model.CodeTaskNotFound, "input commitments not registered for this task")
	}

	tv := time.Now()
	m := &sapf.MulIntermediate{
		Schema: "sa-mul-intermediate-v1", TaskID: rec.TaskID, ServerIndex: rec.ServerIndex,
		DHex: rec.DHex, EHex: rec.EHex,
		CxHex: rec.CxHex, CaHex: rec.CaHex, CdHex: rec.CdHex,
		CyHex: rec.CyHex, CbHex: rec.CbHex, CeHex: rec.CeHex,
	}
	if _, err := sapf.VerifyEq17(sp.Params, m); err != nil {
		return nil, model.Reject(model.CodeCommitmentMismatch, "Eq.(17) intermediate verification failed: "+err.Error())
	}
	eq17NS := time.Since(tv).Nanoseconds()

	key := model.KeySAMulIntermPrefix + rec.TaskID + ":" + fmt.Sprint(rec.ServerIndex)
	if b, err := l.GetState(key); err != nil {
		return nil, err
	} else if len(b) != 0 {
		var prev model.SchemeAMulIntermediateRecord
		if err := json.Unmarshal(b, &prev); err != nil {
			return nil, model.Reject(model.CodeMalformedRecord, "corrupt intermediate record")
		}
		if jsonEqual(&prev, rec) {
			return &Verdict{OK: true, TaskID: rec.TaskID, Index: rec.ServerIndex,
				Notes:  []string{"idempotent intermediate re-submission"},
				Timing: Timing{CertVerifyNS: eq17NS, StateReadNS: time.Since(t0).Nanoseconds()}}, nil
		}
		return nil, model.Reject(model.CodeDuplicateDelivery,
			"multiplication intermediate already submitted with different content")
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	if err := l.PutState(key, raw); err != nil {
		return nil, err
	}
	return &Verdict{OK: true, TaskID: rec.TaskID, Index: rec.ServerIndex,
		Notes: []string{"multiplication intermediate accepted (Eq.17 verified)"},
		Timing: Timing{CertVerifyNS: eq17NS, StateWritePrepareNS: time.Since(t0).Nanoseconds(),
			VerifyCoreNS: time.Since(t0).Nanoseconds()}}, nil
}

func DeriveSchemeAOutputCommitment(l Ledger, taskID string, serverIndex1Based int) (*big.Int, error) {
	taskRaw, err := l.GetState(KeySATask + taskID)
	if err != nil {
		return nil, err
	}
	if len(taskRaw) == 0 {
		return nil, model.Reject(model.CodeTaskNotFound, "scheme A task not registered")
	}
	var task model.SchemeATaskRecord
	if err := json.Unmarshal(taskRaw, &task); err != nil {
		return nil, model.Reject(model.CodeMalformedRecord, "corrupt scheme A task")
	}
	if serverIndex1Based < 1 || serverIndex1Based > task.Servers {
		return nil, model.Reject(model.CodeInvalidIndex, "server index out of range")
	}
	sp, err := bridge.SAParamsFromRecord(&task)
	if err != nil {
		return nil, err
	}
	width := bridge.WidthForPrimeBits(task.PrimeBits)

	inRaw, err := l.GetState(model.KeySAInputCommPrefix + taskID)
	if err != nil {
		return nil, err
	}
	if len(inRaw) == 0 {
		return nil, model.Reject(model.CodeTaskNotFound, "input commitments not registered")
	}
	var in model.SchemeAInputCommitmentRecord
	if err := json.Unmarshal(inRaw, &in); err != nil {
		return nil, model.Reject(model.CodeMalformedRecord, "corrupt input commitments")
	}
	key := fmt.Sprint(serverIndex1Based)
	set, ok := in.BeaverCommitmentsHex[key]
	if !ok {
		return nil, model.Reject(model.CodeShapeMismatch, "no Beaver commitment for server "+key)
	}
	cdeHex, ok := in.MulDiffCommitmentsHex[key]
	if !ok {
		return nil, model.Reject(model.CodeShapeMismatch, "no c(de) commitment for server "+key)
	}

	midRaw, err := l.GetState(model.KeySAMulIntermPrefix + taskID + ":" + key)
	if err != nil {
		return nil, err
	}
	if len(midRaw) == 0 {
		return nil, model.Reject(model.CodeTaskNotFound,
			"multiplication intermediate not submitted for server "+key)
	}
	var mid model.SchemeAMulIntermediateRecord
	if err := json.Unmarshal(midRaw, &mid); err != nil {
		return nil, model.Reject(model.CodeMalformedRecord, "corrupt multiplication intermediate")
	}

	cc, err := bridge.DecodeSchemeAElement(set.CCHex, width)
	if err != nil {
		return nil, err
	}
	cde, err := bridge.DecodeSchemeAElement(cdeHex, width)
	if err != nil {
		return nil, err
	}
	st := &sapf.MulState{
		Params: sp.Params,
		CC:     map[int]*big.Int{serverIndex1Based: cc},
		CDe:    map[int]*big.Int{serverIndex1Based: cde},
	}
	m := &sapf.MulIntermediate{
		Schema: "sa-mul-intermediate-v1", TaskID: taskID, ServerIndex: serverIndex1Based,
		DHex: mid.DHex, EHex: mid.EHex,
		CxHex: mid.CxHex, CaHex: mid.CaHex, CdHex: mid.CdHex,
		CyHex: mid.CyHex, CbHex: mid.CbHex, CeHex: mid.CeHex,
	}
	return sapf.DeriveOutputCommitmentChain(sp.Params, m, st)
}

func StoreDerivedCz(l Ledger, taskID string, serverIndex1Based int, cz *big.Int, width int) error {
	if cz == nil {
		return model.Reject(model.CodeCommitmentMismatch, "nil derived commitment")
	}
	key := model.KeySADerivedCzPrefix + taskID + ":" + fmt.Sprint(serverIndex1Based)
	return l.PutState(key, []byte(bridge.EncodeSchemeAElement(cz, width)))
}

func LoadDerivedCz(l Ledger, taskID string, serverIndex1Based int, width int) (*big.Int, error) {
	key := model.KeySADerivedCzPrefix + taskID + ":" + fmt.Sprint(serverIndex1Based)
	b, err := l.GetState(key)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, model.Reject(model.CodeTaskNotFound, "derived commitment not stored")
	}
	return bridge.DecodeSchemeAElement(string(b), width)
}

// ---- helpers ---------------------------------------------------------------

func parseServerKey(k string, servers int) (int, error) {
	var idx int
	if _, err := fmt.Sscanf(k, "%d", &idx); err != nil {
		return 0, model.Reject(model.CodeMalformedRecord, "bad server key "+k)
	}
	if idx < 1 || idx > servers {
		return 0, model.Reject(model.CodeInvalidIndex, "server key out of range: "+k)
	}
	return idx, nil
}

func jsonEqual(a, b any) bool {
	ab, err1 := json.Marshal(a)
	bb, err2 := json.Marshal(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return string(ab) == string(bb)
}

func mustBigHex(h string) []byte {
	v, err := bridge.DecodeSchemeAElement(h, len(h)/2)
	if err != nil {
		return []byte{0}
	}
	return v.Bytes()
}

var _ = (*schemea.Params)(nil)
