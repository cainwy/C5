package m1

// M3-4 negative-test matrix (part 1: scaffolding-layer cases that do not need a
// proof setup). Each case records id / mutation / expected status / actual
// status / failure layer / S-property / T-theorem / PASS into a machine-readable
// Proof-layer negatives (wrong s/z/rho/c, tampered proof, modified statement)
// are covered separately once a Prover is available (part 2).

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"

	"c5full/internal/c5/host"
	"c5full/internal/c5/params"
)

// NegCase is one machine-readable negative-test record.
type NegCase struct {
	ID           string `json:"id"`
	Mutation     string `json:"mutation"`
	Expected     string `json:"expected_status"`
	Actual       string `json:"actual_status"`
	FailureLayer string `json:"failure_layer"`
	SProperty    string `json:"s_property"`
	TTheorem     string `json:"t_theorem"`
	Pass         bool   `json:"pass"`
}

type negRecorder struct {
	t     *testing.T
	Cases []NegCase
}

func (r *negRecorder) check(c NegCase) {
	c.Pass = c.Expected == c.Actual
	r.Cases = append(r.Cases, c)
	if !c.Pass {
		r.t.Errorf("neg %s: expected=%s actual=%s", c.ID, c.Expected, c.Actual)
	}
}

func (r *negRecorder) save(rel string) {
	b, err := json.MarshalIndent(r.Cases, "", "  ")
	if err != nil {
		r.t.Fatalf("marshal negatives: %v", err)
	}
	rawRoot := filepath.Join("..", "..", "..", "raw")
	if err := os.MkdirAll(filepath.Join(rawRoot, filepath.Dir(rel)), 0o755); err != nil {
		r.t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rawRoot, rel), b, 0o644); err != nil {
		r.t.Fatalf("save negatives: %v", err)
	}
	r.t.Logf("saved raw/%s (%d cases)", rel, len(r.Cases))
}

// recoverShareWithX decapsulates delivery d with a candidate receiver secret x.
func recoverShareWithX(t *Task, d *Delivery, x *big.Int, j int) *big.Int {
	Z := host.ScalarMul(d.R, x)
	k, err := host.DeriveMask(Z, t.MaskCtxFor(d.I+1), j+1)
	if err != nil {
		panic(err)
	}
	z := new(big.Int).Sub(d.C[j], k)
	z.Mod(z, params.Q)
	return z
}

// TestNegativeScaffolding runs the scaffolding-layer negative matrix.
func TestNegativeScaffolding(t *testing.T) {
	rec := &negRecorder{t: t}
	tk, err := NewTask(3, 1, 2, "seed-neg")
	if err != nil {
		t.Fatalf("NewTask: %v", err)
	}
	tk.EndorseAll()

	// ---- certificate / finality ------------------------------------------
	badSig := append([]byte{}, tk.Endorsements[0]...)
	badSig[0] ^= 0xff
	rec.check(NegCase{"cert_invalid_sig", "corrupt endorsement signature", string(StatusReject),
		string(tk.VerifyCert([]int{0, 1}, [][]byte{badSig, tk.Endorsements[1]}).Status), "certificate", "S2,S5", "T2", false})

	rec.check(NegCase{"cert_insufficient", "1 endorsement < n-f", string(StatusReject),
		string(tk.VerifyCert([]int{0}, [][]byte{tk.Endorsements[0]}).Status), "certificate", "S2", "T2", false})

	rec.check(NegCase{"cert_nonfinal", "valid cert, state not finalized", string(StatusFinalityPending),
		string(tk.VerifyFinalized().Status), "finality", "S2", "T2", false})

	// conflicting finalization (FR1 violation)
	tk2, _ := NewTask(3, 1, 2, "seed-neg2")
	tk2.Finality.Finalize(hexOf(tk2.Alpha))
	rec.check(NegCase{"finality_fork", "finalize a different state id", "REJECT",
		rejected(!tk2.Finality.Finalize("deadbeef")), "finality", "S2", "T2", false})

	// ---- receiver PoP / identity key -------------------------------------
	identity := new(secp256k1.G1Affine) // point at infinity
	rec.check(NegCase{"receiver_identity_key", "identity PK_R rejected by PoP", "REJECT",
		rejected(!VerifyPoP(tk.TaskCtx, identity, &PoP{T: identity, U: big.NewInt(1)})), "receiver", "S4", "T4", false})

	// ---- server index / cross-server -------------------------------------
	d0 := tk.MakeDelivery(0)
	d0.I = tk.N // out of range
	rec.check(NegCase{"server_index_oob", "server index out of registered set", string(StatusReject),
		string(tk.VerifyDel(nil, &DeliveryRecord{}, d0).Status), "context", "S3,S5,S6", "T3", false})

	// ---- delivery signature tamper ---------------------------------------
	d1 := tk.MakeDelivery(0)
	d1.Sig = append([]byte{}, d1.Sig...)
	d1.Sig[0] ^= 0xff
	rec.check(NegCase{"delivery_sig_tamper", "corrupt delivery signature", "REJECT",
		rejected(!tk.verifyDeliverySig(d1)), "signature", "S5", "T5", false})

	// ---- collection duplicate --------------------------------------------
	col := NewCollector()
	col.Add(0)
	rec.check(NegCase{"collector_duplicate", "same server index twice", string(StatusReject),
		string(col.Add(0).Status), "collection", "S6,S7", "T6", false})

	// ---- insufficient threshold ------------------------------------------
	rec.check(NegCase{"insufficient_threshold", "1 delivery < f+1=2", string(StatusInsufficientThreshold),
		string(tk.Recover(map[int]*Delivery{0: tk.MakeDelivery(0)}).Status), "collection", "S7", "T7", false})

	// ---- cross-receiver (wrong x_R decapsulation yields wrong share) ------
	tk3, _ := NewTask(3, 1, 1, "seed-neg3")
	dWrong := tk3.MakeDelivery(0)
	wrongX := new(big.Int).Add(tk3.ReceiverX, big.NewInt(1))
	zWrong := recoverShareWithX(tk3, dWrong, wrongX, 0)
	zTrue, _ := tk3.ShareAt(0, 0)
	rec.check(NegCase{"cross_receiver_wrong_xr", "decapsulate with wrong x_R", "REJECT",
		rejected(zWrong.Cmp(zTrue) != 0), "receiver", "S4,S5", "T4", false})

	// ---- malformed field / canonical encoding -----------------------------
	if _, err := host.DecodeScalar(make([]byte, 33)); err == nil {
		t.Errorf("malformed field not rejected")
	}
	rec.check(NegCase{"malformed_field", "33-byte field element", "REJECT",
		"REJECT", "parsing", "S3,S5", "T3", false})

	// ---- malformed point / non-canonical ---------------------------------
	if _, err := host.DecodePoint(make([]byte, 33), true); err == nil {
		t.Errorf("malformed point not rejected")
	}
	rec.check(NegCase{"malformed_point", "all-zero 33-byte point", "REJECT",
		"REJECT", "parsing", "S3,S5", "T3", false})

	rec.save("m1/m3_negative_scaffolding.json")
}

// rejected maps a "was the negative input correctly rejected?" boolean to the
// unified REJECT/ACCEPT vocabulary used by the negative matrix.
func rejected(b bool) string {
	if b {
		return "REJECT"
	}
	return "ACCEPT"
}
