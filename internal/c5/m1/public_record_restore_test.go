package m1


import (
	"bytes"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"

	"c5full/internal/c5/host"
	"c5full/internal/c5/params"
)

func TestRestoreRoundtripHappy(t *testing.T) {
	tk, err := NewTask(3, 1, 1, "restore-rt")
	if err != nil {
		t.Fatal(err)
	}
	d := tk.MakeDelivery(0)
	rec := PublicDelivery(d)

	got := tk.Restore(rec)
	if got == nil {
		t.Fatal("Restore(nil) on legal record")
	}
	if got.I != d.I {
		t.Fatalf("index: got %d want %d", got.I, d.I)
	}
	if !host.PointEqual(got.R, d.R) {
		t.Fatal("R mismatch after roundtrip (C5-F01 regression)")
	}
	if len(got.C) != len(d.C) {
		t.Fatalf("C length %d != %d", len(got.C), len(d.C))
	}
	for j := range d.C {
		if got.C[j].Cmp(d.C[j]) != 0 {
			t.Fatalf("C[%d] mismatch", j)
		}
	}
	if !bytes.Equal(got.Sig, d.Sig) {
		t.Fatal("sig mismatch")
	}
	if !bytes.Equal(got.Proof, d.Proof) {
		t.Fatal("proof mismatch")
	}
	zero := new(secp256k1.G1Affine)
	if host.PointEqual(got.R, zero) {
		t.Fatal("Restore left R at zero point (the C5-F01 bug)")
	}
}

func TestRestoreNilInputs(t *testing.T) {
	tk, _ := NewTask(3, 1, 1, "restore-nil")
	if tk.Restore(nil) != nil {
		t.Fatal("nil record must yield nil")
	}
	var nilTask *Task
	if nilTask.Restore(&PublicDeliveryRecord{Index: 1}) != nil {
		t.Fatal("nil task must yield nil")
	}
}

func TestRestoreMalformedCases(t *testing.T) {
	tk, _ := NewTask(3, 1, 1, "restore-neg")
	base := PublicDelivery(tk.MakeDelivery(0))

	mut := func(f func(r *PublicDeliveryRecord)) *PublicDeliveryRecord {
		r := *base
		r.C = append([][]byte(nil), base.C...)
		if base.Proof != nil {
			r.Proof = append([]byte(nil), base.Proof...)
		}
		r.Sig = append([]byte(nil), base.Sig...)
		f(&r)
		return &r
	}

	cases := []struct {
		name string
		rec  *PublicDeliveryRecord
	}{
		{"identity_point", mut(func(r *PublicDeliveryRecord) { r.R = []byte{0x00} })},
		{"bad_sec1_prefix", mut(func(r *PublicDeliveryRecord) { r.R[0] = 0x04 })},
		{"short_point", mut(func(r *PublicDeliveryRecord) { r.R = r.R[:16] })},
		{"x_ge_p", mut(func(r *PublicDeliveryRecord) {
			b := make([]byte, 33)
			b[0] = 0x02
			for i := 1; i < 33; i++ {
				b[i] = 0xFF
			}
			r.R = b
		})},
		{"index_zero", mut(func(r *PublicDeliveryRecord) { r.Index = 0 })},
		{"index_out_of_range", mut(func(r *PublicDeliveryRecord) { r.Index = tk.N + 1 })},
		{"c_length_mismatch", mut(func(r *PublicDeliveryRecord) {
			r.C = append(r.C, make([]byte, 32))
		})},
		{"c_short_element", mut(func(r *PublicDeliveryRecord) { r.C[0] = r.C[0][:16] })},
		{"c_out_of_field", mut(func(r *PublicDeliveryRecord) {
			for i := range r.C[0] {
				r.C[0][i] = 0xFF // ≥ q
			}
		})},
		{"c_out_of_field_exact_q", mut(func(r *PublicDeliveryRecord) {
			qb := make([]byte, 32)
			params.Q.FillBytes(qb)
			r.C[0] = qb
		})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Restore panicked on %s: %v", tc.name, r)
				}
			}()
			if got := tk.Restore(tc.rec); got != nil {
				t.Fatalf("malformed %s must be rejected (nil), got delivery", tc.name)
			}
		})
	}
}

func TestRestoreOffCurveX(t *testing.T) {
	tk, _ := NewTask(3, 1, 1, "restore-offcurve")
	for x := int64(2); x < 1000; x++ {
		b := make([]byte, 33)
		b[0] = 0x02
		new(big.Int).SetInt64(x).FillBytes(b[1:])
		if _, err := host.DecodePoint(b, false); err != nil {
			rec := &PublicDeliveryRecord{
				Index: 1, R: b,
				C: [][]byte{make([]byte, 32)},
			}
			if got := tk.Restore(rec); got != nil {
				t.Fatalf("off-curve x=%d must be rejected", x)
			}
			return
		}
	}
	t.Fatal("no off-curve x found in range (unexpected)")
}
