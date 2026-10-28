//	proposal_build_ns     contract.NewProposal(...)
package c5

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"

	"c5full/blockchain/experiments/backend"
	"c5full/blockchain/fabric/chaincode/model"
	"c5full/blockchain/fabric/client/gateway"
)

const measuredBy = "fabric-gateway"

type FabricC5 struct {
	gw *gateway.Client

	mu      sync.Mutex
	timings map[*backend.Reply]backend.Timing
}

var (
	_ backend.C5Backend        = (*FabricC5)(nil)
	_ backend.BenchmarkBackend = (*FabricC5)(nil)
)

func NewFabricC5(gw *gateway.Client) *FabricC5 {
	return &FabricC5{gw: gw, timings: map[*backend.Reply]backend.Timing{}}
}

func (f *FabricC5) Kind() string { return "fabric" }

func (f *FabricC5) TimingOf(r *backend.Reply) backend.Timing {
	if r == nil {
		return backend.Timing{}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.timings[r]
}

func (f *FabricC5) RegisterC5Task(ctx context.Context, rec *model.PublicTaskRecord) (*backend.Reply, error) {
	b, err := json.Marshal(rec)
	if err != nil {
		return nil, fmt.Errorf("c5: marshal task record: %w", err)
	}
	return f.submit(ctx, "C5Contract:RegisterC5Task", string(b))
}

func (f *FabricC5) FinalizeC5State(ctx context.Context, taskID string, cert *model.CertificateRecord) (*backend.Reply, error) {
	b, err := json.Marshal(cert)
	if err != nil {
		return nil, fmt.Errorf("c5: marshal certificate: %w", err)
	}
	return f.submit(ctx, "C5Contract:FinalizeC5State", taskID, string(b))
}

func (f *FabricC5) VerifyC5Delivery(ctx context.Context, taskID, payloadHex string) (*backend.Reply, error) {
	return f.submit(ctx, "C5Contract:VerifyC5Delivery", taskID, payloadHex)
}

func (f *FabricC5) QueryC5FinalizedState(_ context.Context, taskID string) (*backend.Reply, error) {
	return f.evaluate("C5Contract:QueryC5FinalizedState", taskID)
}

func (f *FabricC5) QueryC5AcceptedDeliveries(_ context.Context, taskID string) (*backend.Reply, error) {
	return f.evaluate("C5Contract:QueryC5AcceptedDeliveries", taskID)
}

func (f *FabricC5) BenchmarkVerifyC5(ctx context.Context, taskID, payloadHex, benchRequestID string) (*backend.Reply, error) {
	return f.submit(ctx, "BenchmarkContract:BenchmarkVerifyC5", taskID, payloadHex, benchRequestID)
}

func (f *FabricC5) BenchmarkVerifySchemeA(ctx context.Context, taskID, submissionJSON, benchRequestID string) (*backend.Reply, error) {
	return f.submit(ctx, "BenchmarkContract:BenchmarkVerifySchemeA", taskID, submissionJSON, benchRequestID)
}

func (f *FabricC5) Profile(_ context.Context) ([]byte, error) {
	b, _, err := f.gw.EvaluatePhased("C5Contract:C5ChaincodeProfile")
	return b, err
}

// ---- helpers ---------------------------------------------------------------

func DeliveryPayloadHex(index int, rHex string, cHex []string, sigHex, proofHex string) (string, error) {
	b, err := model.CanonicalDeliveryBytes(index, rHex, cHex, sigHex, proofHex)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (f *FabricC5) submit(ctx context.Context, fn string, args ...string) (*backend.Reply, error) {
	res, err := f.gw.SubmitPhased(ctx, fn, args...)
	if res == nil {
		return nil, err
	}
	rep := &backend.Reply{
		Raw:        res.Payload,
		TxID:       res.TxID,
		BlockNum:   res.BlockNumber,
		Status:     res.Status,
		MeasuredBy: measuredBy,
	}
	f.remember(rep, backend.Timing{
		ProposalBuildNS:    res.Timing.ProposalBuildNS,
		EndorsementWaitNS:  res.Timing.EndorsementWaitNS,
		SubmitOrderNS:      res.Timing.SubmitOrderNS,
		CommitStatusWaitNS: res.Timing.CommitStatusWaitNS,
		TotalNS:            res.Timing.TotalNS,
	})
	return rep, err
}

func (f *FabricC5) evaluate(fn string, args ...string) (*backend.Reply, error) {
	b, elapsedNS, err := f.gw.EvaluatePhased(fn, args...)
	rep := &backend.Reply{
		Raw:        b,
		Status:     "VALID",
		MeasuredBy: measuredBy,
	}
	if err != nil {
		rep.Status = "EVALUATE_FAILED"
	}
	f.remember(rep, backend.Timing{TotalNS: elapsedNS})
	return rep, err
}

func (f *FabricC5) remember(r *backend.Reply, t backend.Timing) {
	f.mu.Lock()
	f.timings[r] = t
	f.mu.Unlock()
}
