package schemea

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"c5full/blockchain/experiments/backend"
	"c5full/blockchain/fabric/chaincode/model"
	"c5full/blockchain/fabric/client/gateway"
)

const measuredBy = "fabric-gateway"

type FabricSchemeA struct {
	gw *gateway.Client

	mu      sync.Mutex
	timings map[*backend.Reply]backend.Timing
}

var _ backend.SchemeABackend = (*FabricSchemeA)(nil)

func NewFabricSchemeA(gw *gateway.Client) *FabricSchemeA {
	return &FabricSchemeA{gw: gw, timings: map[*backend.Reply]backend.Timing{}}
}

func (f *FabricSchemeA) Kind() string { return "fabric" }

func (f *FabricSchemeA) TimingOf(r *backend.Reply) backend.Timing {
	if r == nil {
		return backend.Timing{}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.timings[r]
}

func (f *FabricSchemeA) RegisterSchemeATask(ctx context.Context, rec *model.SchemeATaskRecord) (*backend.Reply, error) {
	b, err := json.Marshal(rec)
	if err != nil {
		return nil, fmt.Errorf("schemea: marshal task record: %w", err)
	}
	return f.submit(ctx, "SchemeAContract:RegisterSchemeATask", string(b))
}

func (f *FabricSchemeA) VerifySchemeAOutput(ctx context.Context, taskID, submissionJSON string) (*backend.Reply, error) {
	return f.submit(ctx, "SchemeAContract:VerifySchemeAOutput", taskID, submissionJSON)
}

func (f *FabricSchemeA) QuerySchemeAAcceptedOutputs(_ context.Context, taskID string) (*backend.Reply, error) {
	b, elapsedNS, err := f.gw.EvaluatePhased("SchemeAContract:QuerySchemeAAcceptedOutputs", taskID)
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

func (f *FabricSchemeA) PayloadSizeReport(sub *model.SchemeAOutputSubmission, elemWidth int) (int, error) {
	b, err := model.CanonicalSchemeAOutputBytes(sub, elemWidth)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// ---- helpers ---------------------------------------------------------------

func (f *FabricSchemeA) submit(ctx context.Context, fn string, args ...string) (*backend.Reply, error) {
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

func (f *FabricSchemeA) remember(r *backend.Reply, t backend.Timing) {
	f.mu.Lock()
	f.timings[r] = t
	f.mu.Unlock()
}
