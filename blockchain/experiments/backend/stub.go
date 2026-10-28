package backend


import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"c5full/internal/c5/m1"

	"c5full/blockchain/bridge"
	"c5full/blockchain/fabric/chaincode/model"
	"c5full/blockchain/fabric/chaincode/verify"
	"c5full/blockchain/tests/harness"
)

type StubC5 struct {
	L        *harness.MemLedger
	Verifier *m1.Prover
	last     map[string]Timing
}

func NewStubC5(l *harness.MemLedger, verifier *m1.Prover) *StubC5 {
	if l == nil {
		l = harness.NewMemLedger()
	}
	return &StubC5{L: l, Verifier: verifier, last: map[string]Timing{}}
}

func (s *StubC5) Kind() string { return "in-process-stub" }

func (s *StubC5) Ledger() *harness.MemLedger { return s.L }

func (s *StubC5) TimingOf(r *Reply) Timing {
	if r == nil {
		return Timing{}
	}
	return s.last[r.TxID]
}

func (s *StubC5) wrap(t0 time.Time, v *verify.Verdict, err error) (*Reply, error) {
	raw, _ := json.Marshal(v)
	txid := fmt.Sprintf("stub-%d", time.Now().UnixNano())
	tt := Timing{
		LocalNS:            time.Since(t0).Nanoseconds(),
		TotalNS:            time.Since(t0).Nanoseconds(),
		CommitStatusWaitNS: 0,
	}
	s.last[txid] = tt
	rep := &Reply{Raw: raw, TxID: txid, Status: "OK", MeasuredBy: "in-process-stub"}
	if err != nil {
		rep.Status = codeOf(err)
	}
	return rep, err
}

func (s *StubC5) RegisterC5Task(_ context.Context, rec *model.PublicTaskRecord) (*Reply, error) {
	t0 := time.Now()
	v, err := verify.RegisterC5Task(s.L, rec)
	return s.wrap(t0, v, err)
}

func (s *StubC5) FinalizeC5State(_ context.Context, taskID string, cert *model.CertificateRecord) (*Reply, error) {
	t0 := time.Now()
	v, _, err := verify.FinalizeC5State(s.L, taskID, cert)
	return s.wrap(t0, v, err)
}

func (s *StubC5) VerifyC5Delivery(_ context.Context, taskID, payloadHex string) (*Reply, error) {
	t0 := time.Now()
	raw, err := hex.DecodeString(payloadHex)
	if err != nil {
		return s.wrap(t0, nil, model.Reject(model.CodeMalformedRecord, "payload is not hex"))
	}
	idx, rHex, cHex, sigHex, proofHex, err := model.ParseCanonicalDeliveryBytes(raw)
	if err != nil {
		return s.wrap(t0, nil, err)
	}
	taskN, taskL, err := stubTaskShape(s.L, taskID)
	if err != nil {
		return s.wrap(t0, nil, err)
	}
	d, err := bridge.DecodeDelivery(idx, rHex, cHex, sigHex, proofHex, taskN, taskL)
	if err != nil {
		return s.wrap(t0, nil, err)
	}
	v, err := verify.AcceptC5Delivery(s.L, taskID, d, s.Verifier)
	return s.wrap(t0, v, err)
}

func (s *StubC5) QueryC5FinalizedState(_ context.Context, taskID string) (*Reply, error) {
	t0 := time.Now()
	fin, err := verify.QueryC5FinalizedState(s.L, taskID)
	if err != nil {
		return s.wrap(t0, nil, err)
	}
	raw, _ := json.Marshal(fin)
	rep, err := s.wrap(t0, &verify.Verdict{OK: true}, nil)
	rep.Raw = raw
	return rep, err
}

func (s *StubC5) QueryC5AcceptedDeliveries(_ context.Context, taskID string) (*Reply, error) {
	t0 := time.Now()
	n, idx, err := verify.CountAcceptedDeliveries(s.L, taskID)
	if err != nil {
		return s.wrap(t0, nil, err)
	}
	raw, _ := json.Marshal(map[string]any{"count": n, "indices": idx})
	rep, err := s.wrap(t0, &verify.Verdict{OK: true}, nil)
	rep.Raw = raw
	return rep, err
}

// ---- Scheme A stub ----

type StubSA struct {
	L    *harness.MemLedger
	last map[string]Timing
}

func NewStubSA(l *harness.MemLedger) *StubSA {
	if l == nil {
		l = harness.NewMemLedger()
	}
	return &StubSA{L: l, last: map[string]Timing{}}
}

func (s *StubSA) Kind() string { return "in-process-stub" }

func (s *StubSA) Ledger() *harness.MemLedger { return s.L }

func (s *StubSA) TimingOf(r *Reply) Timing {
	if r == nil {
		return Timing{}
	}
	return s.last[r.TxID]
}

func (s *StubSA) wrap(t0 time.Time, v *verify.Verdict, err error) (*Reply, error) {
	raw, _ := json.Marshal(v)
	txid := fmt.Sprintf("stub-sa-%d", time.Now().UnixNano())
	s.last[txid] = Timing{LocalNS: time.Since(t0).Nanoseconds(), TotalNS: time.Since(t0).Nanoseconds()}
	rep := &Reply{Raw: raw, TxID: txid, Status: "OK", MeasuredBy: "in-process-stub"}
	if err != nil {
		rep.Status = codeOf(err)
	}
	return rep, err
}

func (s *StubSA) RegisterSchemeATask(_ context.Context, rec *model.SchemeATaskRecord) (*Reply, error) {
	t0 := time.Now()
	v, err := verify.RegisterSchemeATask(s.L, rec)
	return s.wrap(t0, v, err)
}

func (s *StubSA) VerifySchemeAOutput(_ context.Context, taskID, submissionJSON string) (*Reply, error) {
	t0 := time.Now()
	var sub model.SchemeAOutputSubmission
	if err := json.Unmarshal([]byte(submissionJSON), &sub); err != nil {
		return s.wrap(t0, nil, model.Reject(model.CodeMalformedRecord, "submission is not valid JSON"))
	}
	sub.TaskID = taskID
	v, err := verify.AcceptSchemeAOutput(s.L, taskID, &sub)
	return s.wrap(t0, v, err)
}

func (s *StubSA) QuerySchemeAAcceptedOutputs(_ context.Context, taskID string) (*Reply, error) {
	t0 := time.Now()
	n, idx, err := verify.CountAcceptedSAOutputs(s.L, taskID)
	if err != nil {
		return s.wrap(t0, nil, err)
	}
	raw, _ := json.Marshal(map[string]any{"count": n, "indices": idx})
	rep, err := s.wrap(t0, &verify.Verdict{OK: true}, nil)
	rep.Raw = raw
	return rep, err
}

// ---- helpers ----

func stubTaskShape(l *harness.MemLedger, taskID string) (int, int, error) {
	b, err := l.GetState(verify.KeyC5Task + taskID)
	if err != nil {
		return 0, 0, err
	}
	if len(b) == 0 {
		return 0, 0, model.Reject(model.CodeTaskNotFound, "task not registered")
	}
	var rec model.PublicTaskRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return 0, 0, model.Reject(model.CodeMalformedRecord, "corrupt task")
	}
	return rec.N, rec.L, nil
}

func codeOf(err error) string {
	if err == nil {
		return "OK"
	}
	if re, ok := model.IsReject(err); ok {
		return re.Code
	}
	return "ERR:" + err.Error()
}
