package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"c5full/internal/c5/host"
	"c5full/internal/c5/m1"

	"c5full/blockchain/bridge"
	"c5full/blockchain/fabric/chaincode/model"
)

type Ledger interface {
	GetState(key string) ([]byte, error)
	PutState(key string, value []byte) error
}

const (
	// KeyC5Task / KeyC5Cert / KeyC5Fin / KeyC5DelPrefix / KeyC5DelIndex
	KeyC5Task      = "c5task:"  // + taskID
	KeyC5Cert      = "c5cert:"  // + taskID
	KeyC5Fin       = "c5fin:"   // + taskID
	KeyC5DelPrefix = "c5del:"   // + taskID + ":" + index
	KeySATask      = "satask:"  // + taskID
	KeySAOutPrefix = "saout:"   // + taskID + ":" + serverIndex
	KeySAParamsHash = "saparams:" // + taskID
	KeyBenchPrefix  = "bench:"

	PrefixC5Del = "c5del:"
	PrefixSAOut = "saout:"
)

func keyC5Del(taskID string, index1Based int) string {
	return fmt.Sprintf("%s%s:%d", KeyC5DelPrefix, taskID, index1Based)
}
func keySAOut(taskID string, serverIdx1Based int) string {
	return fmt.Sprintf("%s%s:%d", KeySAOutPrefix, taskID, serverIdx1Based)
}

type Timing struct {
	CertVerifyNS        int64 `json:"certificate_verify_ns"`
	FinalityCheckNS     int64 `json:"finality_check_ns"`
	ServerIndexNS       int64 `json:"server_index_ns"`
	SignatureVerifyNS   int64 `json:"signature_verify_ns"`
	ProofVerifyNS       int64 `json:"proof_verify_ns"`
	StateReadNS         int64 `json:"state_read_ns"`
	StateWritePrepareNS int64 `json:"state_write_prepare_ns"`
	VerifyCoreNS        int64 `json:"verify_core_ns"`
	ZKPoCVerifyNS       int64 `json:"zkpoc_verify_ns"`
	CommitmentVerifyNS  int64 `json:"commitment_verify_ns"`
	GroupCheckNS        int64 `json:"group_check_ns"`
	StaticGroupValidationNS int64 `json:"static_group_validation_ns"`
	RecordDecodeNS          int64 `json:"record_decode_ns"`
	LedgerLogicNS           int64 `json:"ledger_logic_ns"`
}

//   chaincode response 500, Error handling success response. Value did not match schema:
//   1. return: code is required  2. return: detail is required ...
type Verdict struct {
	OK             bool     `json:"ok"`
	Code           string   `json:"code,omitempty" metadata:",optional"`
	Detail         string   `json:"detail,omitempty" metadata:",optional"`
	TaskID         string   `json:"task_id,omitempty" metadata:",optional"`
	Index          int      `json:"index,omitempty" metadata:",optional"`
	CertValid      int      `json:"cert_valid_endorsements,omitempty" metadata:",optional"`
	CertThreshold  int      `json:"cert_threshold,omitempty" metadata:",optional"`
	AcceptedDigest string   `json:"accepted_digest,omitempty" metadata:",optional"`
	Timing         Timing   `json:"timing_ns,omitempty"`
	Notes          []string `json:"notes,omitempty" metadata:",optional"`
}

func RegisterC5Task(l Ledger, rec *model.PublicTaskRecord) (*Verdict, error) {
	t0 := time.Now()
	if err := rec.Validate(); err != nil {
		return nil, err
	}
	if b, err := l.GetState(KeyC5Task + rec.TaskID); err != nil {
		return nil, err
	} else if len(b) != 0 {
		var prev model.PublicTaskRecord
		if err := json.Unmarshal(b, &prev); err != nil {
			return nil, model.Reject(model.CodeMalformedRecord, "corrupt stored task")
		}
		if prev.AlphaHex == rec.AlphaHex && prev.TaskCtxHex == rec.TaskCtxHex {
			return &Verdict{OK: true, TaskID: rec.TaskID, Notes: []string{"idempotent re-registration"}, Timing: Timing{StateReadNS: time.Since(t0).Nanoseconds()}}, nil
		}
		return nil, model.Reject(model.CodeTaskExists, "task already registered with different content")
	}
	if err := bridge.VerifyRegisteredCtx(rec); err != nil {
		return nil, err
	}
	if rec.ProfileID != "gnark-v0.15.0-groth16-bls12-381-v1" {
		return nil, model.Reject(model.CodeProfileMismatch, "unexpected delivery profile")
	}
	if !CanonicalConstraints(rec.L, rec.Constraints) {
		return nil, model.Reject(model.CodeProfileMismatch, "constraints != canonical profile for L")
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	if err := l.PutState(KeyC5Task+rec.TaskID, raw); err != nil {
		return nil, err
	}
	return &Verdict{OK: true, TaskID: rec.TaskID, Notes: []string{"registered"}, Timing: Timing{
		StateReadNS:         time.Since(t0).Nanoseconds(),
		StateWritePrepareNS: time.Since(t0).Nanoseconds(),
	}}, nil
}

// ---- finality -------------------------------------------------------------

func FinalizeC5State(l Ledger, taskID string, cert *model.CertificateRecord) (*Verdict, *model.FinalizedStateRecord, error) {
	tr0 := time.Now()
	taskRaw, err := l.GetState(KeyC5Task + taskID)
	if err != nil {
		return nil, nil, err
	}
	readNS := time.Since(tr0).Nanoseconds()
	if len(taskRaw) == 0 {
		return nil, nil, model.Reject(model.CodeTaskNotFound, "task not registered")
	}
	var rec model.PublicTaskRecord
	if err := json.Unmarshal(taskRaw, &rec); err != nil {
		return nil, nil, model.Reject(model.CodeMalformedRecord, "corrupt stored task")
	}
	if cert == nil {
		return nil, nil, model.Reject(model.CodeInvalidCert, "nil certificate")
	}
	cert.TaskID = taskID
	if err := cert.ValidateCertShape(rec.N); err != nil {
		return nil, nil, err
	}

	t, err := bridge.RebuildPublicTask(&rec, nil)
	if err != nil {
		return nil, nil, err
	}

	t1 := time.Now()
	indices := make([]int, len(cert.Indices))
	copy(indices, cert.Indices)
	sigs := make([][]byte, len(cert.SigsHex))
	for i, h := range cert.SigsHex {
		b, err := hex.DecodeString(h)
		if err != nil {
			return nil, nil, model.Reject(model.CodeInvalidCert, "bad sig hex")
		}
		sigs[i] = b
	}
	certRes := t.VerifyCert(indices, sigs)
	certNS := time.Since(t1).Nanoseconds()
	if !certRes.IsOK() {
		return nil, nil, model.Reject(model.CodeInvalidCert, "certificate validity failed: "+certRes.Reason)
	}
	validCount, _ := certRes.Value.(int)

	if cert.AlphaHex != rec.AlphaHex {
		return nil, nil, model.Reject(model.CodeAlphaMismatch, "certificate alpha != registered alpha")
	}
	cert.CertHash = bridge.CertHash(cert)

	fin := &model.FinalizedStateRecord{
		Schema:        model.SchemaID,
		TaskID:        taskID,
		TaskVer:       rec.TaskVer,
		AlphaHex:      rec.AlphaHex,
		Finalized:     true,
		CertHash:      cert.CertHash,
		CertSigsValid: validCount,
		CertThreshold: rec.N - rec.F,
	}

	if prevRaw, err := l.GetState(KeyC5Fin + taskID); err != nil {
		return nil, nil, err
	} else if len(prevRaw) != 0 {
		var prev model.FinalizedStateRecord
		if err := json.Unmarshal(prevRaw, &prev); err != nil {
			return nil, nil, model.Reject(model.CodeMalformedRecord, "corrupt finality record")
		}
		if prev.AlphaHex == rec.AlphaHex {
			v := &Verdict{OK: true, TaskID: taskID, CertValid: validCount, CertThreshold: fin.CertThreshold,
				Notes:  []string{"idempotent finalize (same alpha)"},
				Timing: Timing{StateReadNS: readNS, CertVerifyNS: certNS, VerifyCoreNS: time.Since(tr0).Nanoseconds()}}
			return v, &prev, nil
		}
		return nil, nil, model.Reject(model.CodeFinalityConflict, "task already finalized with different alpha")
	}

	certRaw, err := json.Marshal(cert)
	if err != nil {
		return nil, nil, err
	}
	finRaw, err := json.Marshal(fin)
	if err != nil {
		return nil, nil, err
	}
	tw := time.Now()
	if err := l.PutState(KeyC5Cert+taskID, certRaw); err != nil {
		return nil, nil, err
	}
	if err := l.PutState(KeyC5Fin+taskID, finRaw); err != nil {
		return nil, nil, err
	}
	writeNS := time.Since(tw).Nanoseconds()

	v := &Verdict{OK: true, TaskID: taskID, CertValid: validCount, CertThreshold: fin.CertThreshold,
		Notes: []string{"finalized"},
		Timing: Timing{StateReadNS: readNS, CertVerifyNS: certNS, StateWritePrepareNS: writeNS,
			VerifyCoreNS: time.Since(tr0).Nanoseconds()}}
	return v, fin, nil
}

func QueryC5FinalizedState(l Ledger, taskID string) (*model.FinalizedStateRecord, error) {
	raw, err := l.GetState(KeyC5Fin + taskID)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, model.Reject(model.CodeFinalityPending, "no finalized state")
	}
	var fin model.FinalizedStateRecord
	if err := json.Unmarshal(raw, &fin); err != nil {
		return nil, model.Reject(model.CodeMalformedRecord, "corrupt finality record")
	}
	if !fin.Finalized {
		return nil, model.Reject(model.CodeFinalityPending, "state not finalized")
	}
	return &fin, nil
}

func VerifyC5DeliveryCore(l Ledger, taskID string, d *m1.Delivery, prover *m1.Prover) (*Verdict, *model.PublicTaskRecord, *model.CertificateRecord, *model.FinalizedStateRecord, error) {
	return verifyC5DeliveryCore(l, taskID, d, prover, false)
}

func VerifyC5DeliveryCoreStrictParity(l Ledger, taskID string, d *m1.Delivery, prover *m1.Prover) (*Verdict, *model.PublicTaskRecord, *model.CertificateRecord, *model.FinalizedStateRecord, error) {
	return verifyC5DeliveryCore(l, taskID, d, prover, true)
}

func verifyC5DeliveryCore(l Ledger, taskID string, d *m1.Delivery, prover *m1.Prover, strictParity bool) (*Verdict, *model.PublicTaskRecord, *model.CertificateRecord, *model.FinalizedStateRecord, error) {
	coreStart := time.Now()
	taskRaw, err := l.GetState(KeyC5Task + taskID)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if len(taskRaw) == 0 {
		return nil, nil, nil, nil, model.Reject(model.CodeTaskNotFound, "task not registered")
	}
	var rec model.PublicTaskRecord
	if err := json.Unmarshal(taskRaw, &rec); err != nil {
		return nil, nil, nil, nil, model.Reject(model.CodeMalformedRecord, "corrupt stored task")
	}
	certRaw, err := l.GetState(KeyC5Cert + taskID)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if len(certRaw) == 0 {
		return nil, nil, nil, nil, model.Reject(model.CodeInvalidCert, "no certificate on ledger")
	}
	var cert model.CertificateRecord
	if err := json.Unmarshal(certRaw, &cert); err != nil {
		return nil, nil, nil, nil, model.Reject(model.CodeMalformedRecord, "corrupt certificate record")
	}
	finRaw, err := l.GetState(KeyC5Fin + taskID)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if len(finRaw) == 0 {
		return nil, nil, nil, nil, model.Reject(model.CodeFinalityPending, "no finalized state")
	}
	var fin model.FinalizedStateRecord
	if err := json.Unmarshal(finRaw, &fin); err != nil {
		return nil, nil, nil, nil, model.Reject(model.CodeMalformedRecord, "corrupt finality record")
	}
	stateReadNS := time.Since(coreStart).Nanoseconds()
	if !fin.Finalized || fin.AlphaHex != rec.AlphaHex {
		return nil, nil, nil, nil, model.Reject(model.CodeFinalityPending, "ledger finality != registered alpha")
	}
	if cert.AlphaHex != rec.AlphaHex || cert.CertHash != bridge.CertHash(&cert) {
		return nil, nil, nil, nil, model.Reject(model.CodeCertMismatch, "ledger certificate does not match registered alpha")
	}

	finAlpha := fin.AlphaHex
	t, err := bridge.RebuildPublicTask(&rec, &finAlpha)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	indices := append([]int(nil), cert.Indices...)
	sigs := make([][]byte, len(cert.SigsHex))
	for i, h := range cert.SigsHex {
		b, err := hex.DecodeString(h)
		if err != nil {
			return nil, nil, nil, nil, model.Reject(model.CodeInvalidCert, "bad sig hex")
		}
		sigs[i] = b
	}
	delRec := &m1.DeliveryRecord{CertIndices: indices, CertSigs: sigs}

	t1 := time.Now()
	certRes := t.VerifyCert(indices, sigs)
	certNS := time.Since(t1).Nanoseconds()
	if !certRes.IsOK() {
		return nil, nil, nil, nil, model.Reject(model.CodeInvalidCert, certRes.Reason)
	}
	if r := t.VerifyFinalized(); !r.IsOK() {
		return nil, nil, nil, nil, model.Reject(model.CodeFinalityPending, r.Reason)
	}
	finNS := time.Since(t1).Nanoseconds()
	if d == nil {
		return nil, nil, nil, nil, model.Reject(model.CodeMalformedRecord, "nil delivery")
	}
	idxNS := time.Now()
	if d.I < 0 || d.I >= t.N {
		return nil, nil, nil, nil, model.Reject(model.CodeInvalidIndex, "index out of range")
	}
	finProbeNS := time.Since(idxNS).Nanoseconds()
	t2 := time.Now()
	if !m1.VerifyDeliverySignature(t, d) {
		return nil, nil, nil, nil, model.Reject(model.CodeInvalidSignature, "delivery signature invalid")
	}
	sigNS := time.Since(t2).Nanoseconds()
	t3 := time.Now()
	if prover == nil {
		return nil, nil, nil, nil, model.Reject(m1.UnavailableProofParams, "proof parameters unavailable")
	}
	pf, err := prover.ParseProof(d.Proof)
	if err != nil {
		return nil, nil, nil, nil, model.Reject(model.CodeInvalidProof, "proof parse failed")
	}
	pub, err := prover.PublicWitness(t, d)
	if err != nil {
		return nil, nil, nil, nil, model.Reject(model.CodeInvalidProof, "public witness rebuild failed")
	}
	if err := prover.Verify(pf, pub); err != nil {
		return nil, nil, nil, nil, model.Reject(model.CodeInvalidProof, "groth16 verify failed")
	}
	proofNS := time.Since(t3).Nanoseconds()

	if strictParity {
		if r := t.VerifyDel(prover, delRec, d); !r.IsOK() {
			return nil, nil, nil, nil, model.Reject(model.CodeInvalidProof, "VerifyDel cross-check failed: "+r.Reason)
		}
	}

	canon, err := model.CanonicalDeliveryBytes(d.I+1,
		hex.EncodeToString(host.EncodePoint(d.R, false)), hexC(d.C), hex.EncodeToString(d.Sig), hex.EncodeToString(d.Proof))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	sum := sha256.Sum256(canon)

	v := &Verdict{
		OK: true, TaskID: taskID, Index: d.I + 1,
		CertValid: fin.CertSigsValid, CertThreshold: fin.CertThreshold,
		AcceptedDigest: hex.EncodeToString(sum[:]),
		Timing: Timing{
			StateReadNS: stateReadNS, CertVerifyNS: certNS, FinalityCheckNS: finNS,
			ServerIndexNS: finProbeNS, SignatureVerifyNS: sigNS,
			ProofVerifyNS: proofNS, VerifyCoreNS: time.Since(coreStart).Nanoseconds(),
		},
	}
	return v, &rec, &cert, &fin, nil
}

func AcceptC5Delivery(l Ledger, taskID string, d *m1.Delivery, prover *m1.Prover) (*Verdict, error) {
	v, _, cert, _, err := VerifyC5DeliveryCore(l, taskID, d, prover)
	if err != nil {
		return nil, err
	}
	key := keyC5Del(taskID, d.I+1)
	if b, err := l.GetState(key); err != nil {
		return nil, err
	} else if len(b) != 0 {
		return nil, model.Reject(model.CodeDuplicateDelivery, "duplicate accepted contribution")
	}
	rec, err := bridge.DeliveryToModel(d, taskID, cert.CertHash, v.AcceptedDigest)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	tw := time.Now()
	if err := l.PutState(key, raw); err != nil {
		return nil, err
	}
	v.Timing.StateWritePrepareNS = time.Since(tw).Nanoseconds()
	return v, nil
}

func CountAcceptedDeliveries(l Ledger, taskID string) (int, []int, error) {
	keys, err := rangeKeys(l, PrefixC5Del+taskID+":")
	if err != nil {
		return 0, nil, err
	}
	sort.Strings(keys)
	idx := make([]int, 0, len(keys))
	for _, k := range keys {
		b, err := l.GetState(k)
		if err != nil {
			return 0, nil, err
		}
		var rec model.AcceptedDeliveryRecord
		if err := json.Unmarshal(b, &rec); err != nil {
			continue
		}
		idx = append(idx, rec.Index)
	}
	sort.Ints(idx)
	return len(idx), idx, nil
}

func RegisterSchemeATask(l Ledger, rec *model.SchemeATaskRecord) (*Verdict, error) {
	t0 := time.Now()
	if err := rec.Validate(); err != nil {
		return nil, err
	}
	if _, err := bridge.SAParamsFromRecord(rec); err != nil {
		return nil, err
	}
	if rec.ProfileID == "P-SA-256-DIAG" {
		return nil, model.Reject(model.CodeProfileMismatch, "256-bit profile is diagnostic-only and cannot be registered as a main comparison point")
	}
	paramsHash := bridge.SchemeAParamsHash(rec)
	if b, err := l.GetState(KeySATask + rec.TaskID); err != nil {
		return nil, err
	} else if len(b) != 0 {
		var prev model.SchemeATaskRecord
		if err := json.Unmarshal(b, &prev); err != nil {
			return nil, model.Reject(model.CodeMalformedRecord, "corrupt stored scheme A task")
		}
		if prev.PHex == rec.PHex && prev.HHex == rec.HHex && prev.ProfileID == rec.ProfileID {
			return &Verdict{OK: true, TaskID: rec.TaskID, Notes: []string{"idempotent re-registration"}}, nil
		}
		return nil, model.Reject(model.CodeTaskExists, "scheme A task exists with different params")
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	if err := l.PutState(KeySATask+rec.TaskID, raw); err != nil {
		return nil, err
	}
	if err := l.PutState(KeySAParamsHash+rec.TaskID, []byte(paramsHash)); err != nil {
		return nil, err
	}
	return &Verdict{OK: true, TaskID: rec.TaskID, Notes: []string{"registered", "params_hash=" + paramsHash}, Timing: Timing{StateWritePrepareNS: time.Since(t0).Nanoseconds()}}, nil
}

func VerifySchemeAOutputCore(l Ledger, taskID string, sub *model.SchemeAOutputSubmission) (*Verdict, *model.SchemeATaskRecord, error) {
	return verifySchemeAOutputCore(l, taskID, sub, false)
}

func VerifySchemeAOutputCoreColdStrict(l Ledger, taskID string, sub *model.SchemeAOutputSubmission) (*Verdict, *model.SchemeATaskRecord, error) {
	return verifySchemeAOutputCore(l, taskID, sub, true)
}

func verifySchemeAOutputCore(l Ledger, taskID string, sub *model.SchemeAOutputSubmission, coldStrict bool) (*Verdict, *model.SchemeATaskRecord, error) {
	start := time.Now()
	raw, err := l.GetState(KeySATask + taskID)
	if err != nil {
		return nil, nil, err
	}
	if len(raw) == 0 {
		return nil, nil, model.Reject(model.CodeTaskNotFound, "scheme A task not registered")
	}
	var rec model.SchemeATaskRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, nil, model.Reject(model.CodeMalformedRecord, "corrupt stored scheme A task")
	}
	readNS := time.Since(start).Nanoseconds()
	if sub == nil {
		return nil, nil, model.Reject(model.CodeMalformedRecord, "nil submission")
	}
	if sub.ServerIndex < 1 || sub.ServerIndex > rec.Servers {
		return nil, nil, model.Reject(model.CodeInvalidIndex, "server index out of range")
	}
	if len(sub.Cts) != rec.W {
		return nil, nil, model.Reject(model.CodeShapeMismatch, fmt.Sprintf("ciphertext count %d != w %d", len(sub.Cts), rec.W))
	}

	tb := time.Now()
	if !coldStrict {
		stored, err := l.GetState(KeySAParamsHash + taskID)
		if err != nil {
			return nil, nil, err
		}
		if len(stored) == 0 {
			return nil, nil, model.Reject(model.CodeMalformedGroup, "params hash not registered")
		}
		if string(stored) != bridge.SchemeAParamsHash(&rec) {
			return nil, nil, model.Reject(model.CodeMalformedGroup, "registered params hash mismatch")
		}
	}
	bindNS := time.Since(tb).Nanoseconds()

	tg := time.Now()
	var sp *bridge.SAPublicParams
	if coldStrict {
		sp, err = bridge.SAParamsFromRecord(&rec)
	} else {
		sp, err = bridge.SAParamsFromRecordRegistered(&rec)
	}
	if err != nil {
		return nil, nil, err
	}
	staticNS := time.Since(tg).Nanoseconds()

	td := time.Now()
	width := bridge.WidthForPrimeBits(rec.PrimeBits)
	cts, pfs, err := bridge.DecodeSchemeAOutput(sub, width)
	if err != nil {
		return nil, nil, err
	}
	decodeNS := time.Since(td).Nanoseconds()

	t := &Timing{
		StateReadNS: readNS, StaticGroupValidationNS: staticNS,
		RecordDecodeNS: decodeNS, GroupCheckNS: bindNS,
	}

	if sp.GroupCheck == "qr" {
		tq := time.Now()
		for _, ct := range cts {
			if !bridge.GroupMembershipOK(sp.Params, ct.C0) || !bridge.GroupMembershipOK(sp.Params, ct.C1) {
				return nil, nil, model.Reject(model.CodeSubgroupViolation, "ciphertext outside QR subgroup")
			}
		}
		t.GroupCheckNS += time.Since(tq).Nanoseconds()
	}

	tz := time.Now()
	groupOrder := schemeaGroupOrder(sp.Params.P)
	if _, err := bridge.VerifyZKPoCsBoundToCiphertexts(sp, cts, pfs, groupOrder); err != nil {
		return nil, nil, err
	}
	t.ZKPoCVerifyNS = time.Since(tz).Nanoseconds()

	tc := time.Now()
	expected, err := bridge.DecodeSchemeAElement(rec.ExpectedCommitmentsHex[sub.ServerIndex-1], width)
	if err != nil {
		return nil, nil, err
	}
	ok, err := bridge.VerifyCiphertextsAgainstCommitment(sp.Params, cts, expected)
	if err != nil {
		return nil, nil, err
	}
	t.CommitmentVerifyNS = time.Since(tc).Nanoseconds()
	if !ok {
		return nil, nil, model.Reject(model.CodeCommitmentMismatch, "weighted ciphertext != registered commitment")
	}
	coreNS := time.Since(start).Nanoseconds()
	t.VerifyCoreNS = coreNS
	t.LedgerLogicNS = coreNS - (t.StateReadNS + t.GroupCheckNS + t.StaticGroupValidationNS +
		t.RecordDecodeNS + t.ZKPoCVerifyNS + t.CommitmentVerifyNS)
	if t.LedgerLogicNS < 0 {
		t.LedgerLogicNS = 0
	}

	sizes, err := schemeAOutputSizes(sub)
	if err != nil {
		return nil, nil, err
	}
	canon, err := model.CanonicalSchemeAOutputBytes(sub, width)
	if err != nil {
		return nil, nil, err
	}
	sum := sha256.Sum256(canon)
	path := "SA-REGISTERED"
	if coldStrict {
		path = "SA-COLD-STRICT"
	}
	return &Verdict{
		OK: true, TaskID: taskID, Index: sub.ServerIndex,
		AcceptedDigest: hex.EncodeToString(sum[:]),
		Timing:         *t,
		Notes:          []string{sizes, "accounting_path=" + path},
	}, &rec, nil
}

func AcceptSchemeAOutput(l Ledger, taskID string, sub *model.SchemeAOutputSubmission) (*Verdict, error) {
	v, rec, err := VerifySchemeAOutputCore(l, taskID, sub)
	if err != nil {
		return nil, err
	}
	key := keySAOut(taskID, sub.ServerIndex)
	if b, err := l.GetState(key); err != nil {
		return nil, err
	} else if len(b) != 0 {
		return nil, model.Reject(model.CodeDuplicateSAOutput, "duplicate accepted server contribution")
	}
	width := bridge.WidthForPrimeBits(rec.PrimeBits)
	ctsBytes := len(sub.Cts) * 2 * width
	zkpBytes := len(sub.ZKPoCs) * 7 * width
	acc := &model.AcceptedSchemeAOutput{
		Schema: model.SchemaID, TaskID: taskID, ServerIndex: sub.ServerIndex,
		DigestHex:  v.AcceptedDigest,
		CtsBytes:   ctsBytes,
		ZKPoCBytes: zkpBytes,
		GroupCheck: rec.GroupCheck,
	}
	raw, err := json.Marshal(acc)
	if err != nil {
		return nil, err
	}
	tw := time.Now()
	if err := l.PutState(key, raw); err != nil {
		return nil, err
	}
	v.Timing.StateWritePrepareNS = time.Since(tw).Nanoseconds()
	return v, nil
}

func CountAcceptedSAOutputs(l Ledger, taskID string) (int, []int, error) {
	keys, err := rangeKeys(l, PrefixSAOut+taskID+":")
	if err != nil {
		return 0, nil, err
	}
	sort.Strings(keys)
	idx := make([]int, 0, len(keys))
	for _, k := range keys {
		b, err := l.GetState(k)
		if err != nil {
			return 0, nil, err
		}
		var rec model.AcceptedSchemeAOutput
		if err := json.Unmarshal(b, &rec); err != nil {
			continue
		}
		idx = append(idx, rec.ServerIndex)
	}
	sort.Ints(idx)
	return len(idx), idx, nil
}