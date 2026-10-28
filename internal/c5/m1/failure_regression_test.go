package m1

// M3-6 setup/library/failure regression: verify that distinct failure classes
// are reported with distinct reason codes (never collapsed into one "proof
// failed"). These cases do not need a Prover (proof params unavailable is
// itself one of the classes under test).

import (
	"testing"

	"c5full/internal/c5/host"
)

func TestFailureRegression(t *testing.T) {
	tk, err := NewTask(3, 1, 2, "seed-fail")
	if err != nil {
		t.Fatalf("NewTask: %v", err)
	}
	tk.EndorseAll()
	tk.Finality.Finalize(hexOf(tk.Alpha))

	validCert := []int{0, 1}
	validSigs := [][]byte{tk.Endorsements[0], tk.Endorsements[1]}
	rec := &DeliveryRecord{CertIndices: validCert, CertSigs: validSigs}

	// 1. proof parameters unavailable (p == nil) -> UNAVAILABLE, distinct class
	d := tk.MakeDelivery(0)
	if r := tk.VerifyDel(nil, rec, d); r.Status != StatusUnavailable || r.Reason != UnavailableProofParams {
		t.Fatalf("unavailable proof params not classified: status=%s reason=%s", r.Status, r.Reason)
	}

	// 2. invalid server index -> REJECT_INVALID_INDEX (checked before proof)
	d2 := tk.MakeDelivery(0)
	d2.I = tk.N
	if r := tk.VerifyDel(nil, rec, d2); r.Reason != RejectInvalidIndex {
		t.Fatalf("invalid index not classified: %s", r.Reason)
	}

	// 3. invalid delivery signature -> REJECT_INVALID_SIGNATURE
	d3 := tk.MakeDelivery(0)
	d3.Sig = append([]byte{}, d3.Sig...)
	d3.Sig[0] ^= 0xff
	if r := tk.VerifyDel(nil, rec, d3); r.Reason != RejectInvalidSignature {
		t.Fatalf("invalid signature not classified: %s", r.Reason)
	}

	// 4. invalid certificate -> REJECT_INVALID_CERT
	badSig := append([]byte{}, tk.Endorsements[0]...)
	badSig[0] ^= 0xff
	recBad := &DeliveryRecord{CertIndices: validCert, CertSigs: [][]byte{badSig, tk.Endorsements[1]}}
	if r := tk.VerifyDel(nil, recBad, d); r.Reason != RejectInvalidCert {
		t.Fatalf("invalid cert not classified: %s", r.Reason)
	}

	// 5. finality pending -> FINALITY_PENDING (distinct from reject)
	tk2, _ := NewTask(3, 1, 2, "seed-fail2")
	tk2.EndorseAll()
	rec2 := &DeliveryRecord{CertIndices: validCert, CertSigs: [][]byte{tk2.Endorsements[0], tk2.Endorsements[1]}}
	d4 := tk2.MakeDelivery(0)
	if r := tk2.VerifyDel(nil, rec2, d4); r.Status != StatusFinalityPending {
		t.Fatalf("finality pending not classified: %s", r.Status)
	}

	// 6. malformed point / field via host parser -> parse error (distinct from proof)
	if _, err := host.DecodePoint(make([]byte, 33), true); err == nil {
		t.Fatalf("malformed point not rejected")
	}
	if _, err := host.DecodeScalar(make([]byte, 33)); err == nil {
		t.Fatalf("malformed field not rejected")
	}

	t.Log("failure regression: 6 distinct failure classes verified")
}
