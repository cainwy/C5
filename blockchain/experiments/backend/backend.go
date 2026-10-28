package backend

import (
	"context"

	"c5full/blockchain/fabric/chaincode/model"
)

type Timing struct {
	ProposalBuildNS    int64 `json:"proposal_build_ns,omitempty"`
	EndorsementWaitNS  int64 `json:"endorsement_wait_ns,omitempty"`
	SubmitOrderNS      int64 `json:"submit_order_ns,omitempty"`
	CommitStatusWaitNS int64 `json:"commit_status_wait_ns,omitempty"`
	LocalNS            int64 `json:"local_core_ns,omitempty"`
	TotalNS            int64 `json:"total_ns"`
}

type Reply struct {
	Raw        []byte `json:"raw"`
	TxID       string `json:"tx_id,omitempty"`
	BlockNum   uint64 `json:"block_number,omitempty"`
	Status     string `json:"status"`
	MeasuredBy string `json:"measured_by"` // "fabric-gateway" | "in-process-stub"
}

type C5Backend interface {
	RegisterC5Task(ctx context.Context, rec *model.PublicTaskRecord) (*Reply, error)
	FinalizeC5State(ctx context.Context, taskID string, cert *model.CertificateRecord) (*Reply, error)
	VerifyC5Delivery(ctx context.Context, taskID, payloadHex string) (*Reply, error)
	QueryC5FinalizedState(ctx context.Context, taskID string) (*Reply, error)
	QueryC5AcceptedDeliveries(ctx context.Context, taskID string) (*Reply, error)
	TimingOf(reply *Reply) Timing
	Kind() string // "fabric" | "in-process-stub"
}

type SchemeABackend interface {
	RegisterSchemeATask(ctx context.Context, rec *model.SchemeATaskRecord) (*Reply, error)
	VerifySchemeAOutput(ctx context.Context, taskID, submissionJSON string) (*Reply, error)
	QuerySchemeAAcceptedOutputs(ctx context.Context, taskID string) (*Reply, error)
	TimingOf(reply *Reply) Timing
	Kind() string
}

type BenchmarkBackend interface {
	BenchmarkVerifyC5(ctx context.Context, taskID, payloadHex, benchRequestID string) (*Reply, error)
	BenchmarkVerifySchemeA(ctx context.Context, taskID, submissionJSON, benchRequestID string) (*Reply, error)
	Kind() string
}
