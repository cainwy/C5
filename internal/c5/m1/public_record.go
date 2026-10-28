package m1

// PublicDeliveryRecord is the explicit public serialization of a server
// delivery contribution. LA-02: it must NEVER contain the sender witness
// (S = s_i), the shared point (Z = s_i*PK_R), or any (z_i,rho_i) opening
// plaintext — those are private to the sender/receiver and would constitute
// witness leakage in a public raw artifact.

import (
	"math/big"

	"c5full/internal/c5/host"
	"c5full/internal/c5/params"
)

// PublicDeliveryRecord holds only public fields of one delivery.
type PublicDeliveryRecord struct {
	Index int      `json:"index"`
	R     []byte   `json:"r"`
	C     [][]byte `json:"c"`
	Proof []byte   `json:"proof,omitempty"`
	Sig   []byte   `json:"sig"`
}

// PublicDelivery converts a Delivery to its public form.
func PublicDelivery(d *Delivery) *PublicDeliveryRecord {
	if d == nil {
		return nil
	}
	rec := &PublicDeliveryRecord{
		Index: d.I + 1,
		R:     host.EncodePoint(d.R, false),
		C:     make([][]byte, len(d.C)),
		Proof: d.Proof,
		Sig:   d.Sig,
	}
	for j, cj := range d.C {
		rec.C[j] = fieldBytes(cj)
	}
	return rec
}

// Restore validates a public record against the task and rebuilds the
// parseable Delivery **without the private fields**.
func (t *Task) Restore(rec *PublicDeliveryRecord) *Delivery {
	if rec == nil || t == nil {
		return nil
	}
	if rec.Index < 1 || rec.Index > t.N {
		return nil
	}
	pt, err := host.DecodePoint(rec.R, false)
	if err != nil || pt == nil || pt.IsInfinity() || !pt.IsOnCurve() {
		return nil
	}
	if len(rec.C) != t.L {
		return nil
	}
	c := make([]*big.Int, t.L)
	for j, cj := range rec.C {
		if len(cj) != 32 {
			return nil
		}
		x := new(big.Int).SetBytes(cj)
		if x.Cmp(params.Q) >= 0 {
			return nil
		}
		c[j] = x
	}
	return &Delivery{
		I:        rec.Index - 1,
		R:        pt,
		C:        c,
		Sig:      rec.Sig,
		Proof:    rec.Proof,
		HasProof: rec.Proof != nil,
	}
}
