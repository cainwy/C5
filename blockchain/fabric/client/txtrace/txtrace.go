package txtrace

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const SchemaID = "c5-blockchain-txtrace-v1"

type Meta struct {
	Schema         string `json:"schema"`
	ExperimentID   string `json:"experiment_id"`
	Scheme         string `json:"scheme"`
	Backend        string `json:"backend"`
	NetworkProfile string `json:"network_profile"`
}

type Record struct {
	Schema             string `json:"schema"`
	ExperimentID       string `json:"experiment_id"`
	Scheme             string `json:"scheme"`
	Backend            string `json:"backend"`
	NetworkProfile     string `json:"network_profile"`
	Seq                int    `json:"seq"`
	Function           string `json:"function"`
	TxID               string `json:"tx_id,omitempty"`
	BlockNumber        uint64 `json:"block_number,omitempty"`
	Status             string `json:"status"`
	ProposalBuildNS    int64  `json:"proposal_build_ns,omitempty"`
	EndorsementWaitNS  int64  `json:"endorsement_wait_ns,omitempty"`
	SubmitOrderNS      int64  `json:"submit_order_ns,omitempty"`
	CommitStatusWaitNS int64  `json:"commit_status_wait_ns,omitempty"`
	TotalNS            int64  `json:"total_tx_latency_ns"`
	AppPayloadBytes    int    `json:"app_payload_bytes,omitempty"`
	TSUTC              string `json:"ts_utc"`
}

type Tracer struct {
	mu      sync.Mutex
	path    string
	f       *os.File
	meta    Meta
	next    int
	records []Record
}

func NewTracer(path string, meta Meta) (*Tracer, error) {
	if meta.Schema == "" {
		meta.Schema = SchemaID
	}
	t := &Tracer{path: path, meta: meta, next: 1}
	if path == "" {
		return t, nil
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("txtrace: mkdir: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("txtrace: open: %w", err)
	}
	t.f = f
	return t, nil
}

func (t *Tracer) Record(r Record) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if r.Schema == "" {
		r.Schema = t.meta.Schema
	}
	if r.ExperimentID == "" {
		r.ExperimentID = t.meta.ExperimentID
	}
	if r.Scheme == "" {
		r.Scheme = t.meta.Scheme
	}
	if r.Backend == "" {
		r.Backend = t.meta.Backend
	}
	if r.NetworkProfile == "" {
		r.NetworkProfile = t.meta.NetworkProfile
	}
	if r.Seq <= 0 {
		r.Seq = t.next
	}
	t.next = r.Seq + 1
	if r.TSUTC == "" {
		r.TSUTC = time.Now().UTC().Format(time.RFC3339Nano)
	}

	t.records = append(t.records, r)
	if t.f == nil {
		return nil
	}
	b, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("txtrace: marshal: %w", err)
	}
	if _, err := t.f.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("txtrace: write: %w", err)
	}
	return nil
}

func (t *Tracer) Records() []Record {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Record, len(t.records))
	copy(out, t.records)
	return out
}

func (t *Tracer) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.f == nil {
		return nil
	}
	err := t.f.Close()
	t.f = nil
	return err
}
