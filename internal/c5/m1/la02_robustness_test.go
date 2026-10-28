package m1

// LA-02 robustness tests: malformed experimental input must yield structured
// Rejects (never a panic), and the public delivery serializer must not leak
// S/Z/z/rho (sender witness / receiver secret).

import (
	"bytes"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

func TestVerifyCertLengthMismatch(t *testing.T) {
	tk, _ := NewTask(3, 1, 2, "seed-la02")
	tk.EndorseAll()
	r := tk.VerifyCert([]int{0, 1}, [][]byte{tk.Endorsements[0]})
	if r.Status != StatusReject || r.Reason != RejectInvalidCert {
		t.Fatalf("want REJECT/REJECT_INVALID_CERT, got %+v", r)
	}
	if r := tk.VerifyCert(nil, nil); r.Status != StatusReject || r.Reason != RejectInvalidCert {
		t.Fatalf("nil cert input: %+v", r)
	}
}

func TestVerifyCertNegativeAndOutOfRange(t *testing.T) {
	tk, _ := NewTask(3, 1, 2, "seed-la02b")
	tk.EndorseAll()
	E := tk.Endorsements
	if r := tk.VerifyCert([]int{-1, 0, 1}, [][]byte{nil, E[0], E[1]}); !r.IsOK() {
		t.Fatalf("negative index should be excluded, got %+v", r)
	}
	if r := tk.VerifyCert([]int{0, 1, 3}, [][]byte{E[0], E[1], nil}); !r.IsOK() {
		t.Fatalf("out-of-range index should be excluded, got %+v", r)
	}
	if r := tk.VerifyCert([]int{5, 6, 7}, [][]byte{nil, nil, nil}); r.Status != StatusReject {
		t.Fatalf("all-out-of-range should reject, got %+v", r)
	}
	if r := tk.VerifyCert([]int{0, 0, 1}, [][]byte{E[0], E[0], E[1]}); !r.IsOK() {
		t.Fatalf("duplicate indices semantics unchanged, got %+v", r)
	}
}

func TestRecoverMalformedInputs(t *testing.T) {
	tk, _ := NewTask(3, 1, 2, "seed-la02c")
	tk.EndorseAll()

	// nil delivery
	nilDel := map[int]*Delivery{0: nil, 1: tk.MakeDelivery(1)}
	if r := tk.Recover(nilDel); r.Status != StatusReject || r.Reason != RejectRecoveryInput {
		t.Fatalf("nil delivery: %+v", r)
	}

	oor := map[int]*Delivery{0: tk.MakeDelivery(0), 99: tk.MakeDelivery(1)}
	if r := tk.Recover(oor); r.Status != StatusReject || r.Reason != RejectInvalidIndex {
		t.Fatalf("out-of-range index: %+v", r)
	}

	// negative index
	neg := map[int]*Delivery{0: tk.MakeDelivery(0), -1: tk.MakeDelivery(1)}
	if r := tk.Recover(neg); r.Status != StatusReject || r.Reason != RejectInvalidIndex {
		t.Fatalf("negative index: %+v", r)
	}

	d := tk.MakeDelivery(0)
	dC := map[int]*Delivery{0: d, 1: tk.MakeDelivery(1)}
	short := map[int]*Delivery{0: &Delivery{I: 0, R: d.R, C: d.C[:1], S: d.S, Z: d.Z, Sig: d.Sig}, 1: tk.MakeDelivery(1)}
	_ = dC
	if r := tk.Recover(short); r.Status != StatusReject || r.Reason != RejectRecoveryInput {
		t.Fatalf("short C vector: %+v", r)
	}
}

func TestPublicDeliveryRecordNoSecrets(t *testing.T) {
	tk, _ := NewTask(3, 1, 2, "seed-la02d")
	d := tk.MakeDelivery(0)
	rec := PublicDelivery(d)
	if rec == nil {
		t.Fatal("nil public record")
	}
	if rec.Index != 1 {
		t.Fatalf("index should be 1-based, got %d", rec.Index)
	}
	body, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	low := strings.ToLower(string(body))
	for _, secret := range []string{"s_i", "receiver_x", "z_i", "rho_i"} {
		if strings.Contains(low, "\""+secret+"\"") {
			t.Fatalf("public record leaks %s", secret)
		}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for k := range fields {
		switch k {
		case "index", "r", "c", "proof", "sig":
		default:
			t.Fatalf("unexpected public field %q", k)
		}
	}
	if len(rec.R) != 33 {
		t.Fatalf("R encoding = %d bytes, want 33", len(rec.R))
	}
	if len(rec.C) != tk.L || len(rec.C[0]) != 32 {
		t.Fatalf("C sizes wrong: %v", len(rec.C))
	}
	rd := tk.Restore(rec)
	if rd == nil || rd.I != 0 || !bytes.Equal(rd.Sig, d.Sig) || len(rd.C) != tk.L {
		t.Fatalf("restore roundtrip broken")
	}
}

// TestPositivePathUnchanged guards that LA-02 hardening did not alter the
// existing honest path outcomes.
func TestPositivePathUnchanged(t *testing.T) {
	tk, _ := NewTask(3, 1, 2, "seed-la02e")
	tk.EndorseAll()
	tk.Finality.Finalize(hexOf(tk.Alpha))
	if r := tk.VerifyCert([]int{0, 1}, [][]byte{tk.Endorsements[0], tk.Endorsements[1]}); !r.IsOK() {
		t.Fatalf("honest cert must pass: %+v", r)
	}
	ds := map[int]*Delivery{0: tk.MakeDelivery(0), 1: tk.MakeDelivery(1)}
	r := tk.Recover(ds)
	if !r.IsOK() {
		t.Fatalf("honest recover must pass: %+v", r)
	}
	out := r.Value.([]*big.Int)
	if len(out) != tk.L {
		t.Fatalf("output length wrong")
	}
}