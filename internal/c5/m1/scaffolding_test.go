package m1

// M3-2 scaffolding tests: Shamir reconstruction, Pedersen opening, certificate
// validity vs finality separation, and receiver recovery (mask decapsulation +
// Shamir interpolation). No proof yet (M3-3 adds the Groth16 path).

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"

	"c5full/internal/c5/host"
	"c5full/internal/c5/params"
)

func TestShamirReconstruction(t *testing.T) {
	f := 2
	p := NewOutputPoly(f)
	v := p.Value()
	// evaluate f+1 shares at distinct points 1,2,3
	xs := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)}
	zs := make([]*big.Int, f+1)
	for i, x := range xs {
		z, _ := p.ShareAt(x)
		zs[i] = z
	}
	got := Reconstruct(xs, zs)
	if got.Cmp(v) != 0 {
		t.Fatalf("reconstruct mismatch: got %x want %x", got, v)
	}
}

func TestPedersenOpeningConsistency(t *testing.T) {
	f := 1
	p := NewOutputPoly(f)
	xi := big.NewInt(7)
	z, rho := p.ShareAt(xi)
	C := p.ExpectedCommitment(xi)
	if !host.PointEqual(C, host.Pedersen(z, rho)) {
		t.Fatalf("expected commitment != Pedersen opening")
	}
}

func TestCertFinalitySeparation(t *testing.T) {
	// n=3, f=1 -> n-f = 2 endorsements required
	tk, err := NewTask(3, 1, 2, "seed-cert")
	if err != nil {
		t.Fatalf("NewTask: %v", err)
	}
	tk.EndorseAll()

	// valid cert: 2 signatures
	idx := []int{0, 1}
	sigs := [][]byte{tk.Endorsements[0], tk.Endorsements[1]}
	if r := tk.VerifyCert(idx, sigs); !r.IsOK() {
		t.Fatalf("valid cert rejected: %+v", r)
	}

	// insufficient cert: 1 signature (< n-f)
	if r := tk.VerifyCert([]int{0}, [][]byte{tk.Endorsements[0]}); r.Status != StatusReject {
		t.Fatalf("insufficient cert not rejected: %+v", r)
	}

	// invalid signature
	bad := append([]byte{}, tk.Endorsements[0]...)
	bad[0] ^= 0xff
	if r := tk.VerifyCert([]int{0, 1}, [][]byte{bad, tk.Endorsements[1]}); r.Status != StatusReject {
		t.Fatalf("invalid sig not rejected: %+v", r)
	}

	// finality is separate: before finalize, cert may be valid but state pending
	alpha := hexOf(tk.Alpha)
	if r := tk.VerifyFinalized(); r.Status != StatusFinalityPending {
		t.Fatalf("pre-finalize should be pending: %+v", r)
	}

	// finalize -> authoritative
	if !tk.Finality.Finalize(alpha) {
		t.Fatalf("finalize failed")
	}
	if r := tk.VerifyFinalized(); !r.IsOK() {
		t.Fatalf("post-finalize should be OK: %+v", r)
	}
	// a different state id cannot be finalized
	if tk.Finality.Finalize("deadbeef") {
		t.Fatalf("conflicting finalize should fail")
	}
}

func TestReceiverRecovery(t *testing.T) {
	tk, err := NewTask(3, 1, 3, "seed-recover")
	if err != nil {
		t.Fatalf("NewTask: %v", err)
	}
	want := tk.OutputValues()

	// f+1 = 2 honest deliveries
	del := map[int]*Delivery{}
	for i := 0; i < 2; i++ {
		del[i] = tk.MakeDelivery(i)
	}
	r := tk.Recover(del)
	if !r.IsOK() {
		t.Fatalf("recover failed: %+v", r)
	}
	got := r.Value.([]*big.Int)
	for j := 0; j < tk.L; j++ {
		if got[j].Cmp(want[j]) != 0 {
			t.Fatalf("output[%d] mismatch: got %x want %x", j, got[j], want[j])
		}
	}

	// insufficient (< f+1) -> InsufficientThreshold, not reject
	r = tk.Recover(map[int]*Delivery{0: del[0]})
	if r.Status != StatusInsufficientThreshold {
		t.Fatalf("<f+1 should be INSUFFICIENT_THRESHOLD: %+v", r)
	}
}

func TestDeliveryEnvelopeSignature(t *testing.T) {
	tk, err := NewTask(3, 1, 2, "seed-sig")
	if err != nil {
		t.Fatalf("NewTask: %v", err)
	}
	d := tk.MakeDelivery(0)
	if !tk.verifyDeliverySig(d) {
		t.Fatalf("honest delivery signature rejected")
	}
	// tamper ciphertext -> signature breaks
	d.C[0] = new(big.Int).Add(d.C[0], big.NewInt(1)).Mod(new(big.Int), params.Q)
	if tk.verifyDeliverySig(d) {
		t.Fatalf("tampered delivery signature accepted")
	}
}

// compile-time sanity: secp256k1 imported for type references in tests.
var _ = secp256k1.G1Affine{}
