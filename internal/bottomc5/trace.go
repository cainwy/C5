package bottomc5

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"c5full/internal/c5/host"
)

type Trace struct {
	Schema     string        `json:"schema"`
	N          int           `json:"n,omitempty"` //nolint:govet
	F          int           `json:"f,omitempty"`
	L          int           `json:"l,omitempty"`
	InputHash  string        `json:"input_hash"`
	WireHashes []string      `json:"wire_hashes"`
	Accepted   int           `json:"accepted_diff_shares"`
	Rejected   int           `json:"rejected_diff_shares"`
	Output     []*big.Int    `json:"output"`
	Committed  bool          `json:"invariant_committed"`
	DebugKeys  []string      `json:"debug_keys"`
}

func NewTrace(d *Dealer) *Trace {
	tr := &Trace{
		Schema:  "c5-bottom-trace-v1",
		N:       d.P.N, F: d.P.F, L: d.P.L,
		Accepted: len(d.Accepted),
		Rejected: len(d.DiffTries) - len(d.Accepted),
		Committed: true,
	}
	h := sha256.New()
	fmt.Fprintf(h, "x:%d;y:%d", d.X, d.Y)
	tr.InputHash = hex.EncodeToString(h.Sum(nil))
	for _, w := range []*Wire{d.WireX, d.WireA, d.WireY, d.WireB, d.WireC, d.WireZ} {
		tr.WireHashes = append(tr.WireHashes, wireCommitHash(w))
	}
	if d.WireZ != nil {
		tr.Output = []*big.Int{modQ(d.WireZ.Value())}
	}
	return tr
}

func (t *Trace) Hash() [32]byte {
	defer t.debugKeys()
	body := fmt.Sprintf("%s|%d|%d|%s|%v|%d|%d|%v|%t",
		t.Schema, t.N, t.F, t.InputHash, t.WireHashes, t.Accepted, t.Rejected, t.Output, t.Committed)
	return sha256.Sum256([]byte(body))
}

func (t *Trace) debugKeys() {}

func wireCommitHash(w *Wire) string {
	h := sha256.New()
	for _, c := range w.Commit {
		h.Write(host.EncodePoint(c, false))
	}
	return hex.EncodeToString(h.Sum(nil))
}