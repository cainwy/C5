package m1

// VerifyDel implements AP1 alg 4 (public delivery verification) over the M1
// scaffolding + the AP2 Groth16 backend. It keeps the three independent checks
// — certificate validity, delivery signature, and proof — in the required order
// and returns distinct reject codes so failures are never collapsed into one
// "proof failed".

// DeliveryRecord is the authoritative state + certificate context a verifier
// resolves before checking an individual delivery (AP1 §8.1).
type DeliveryRecord struct {
	CertIndices []int
	CertSigs    [][]byte
}

// VerifyDel checks a single delivery contribution Del_i against the finalized
// authoritative state. It returns OK if accepted, or a structured Reject /
// FinalityPending result otherwise.
func (t *Task) VerifyDel(p *Prover, rec *DeliveryRecord, d *Delivery) Result {
	// 0. certificate validity (threshold + signatures over (tau,alpha))
	if r := t.VerifyCert(rec.CertIndices, rec.CertSigs); !r.IsOK() {
		return r
	}
	// 1. authoritative finality (F_Record), distinct from cert validity
	if r := t.VerifyFinalized(); !r.IsOK() {
		return r
	}
	// 2. server index in the registered server set
	if d.I < 0 || d.I >= t.N {
		return Reject(RejectInvalidIndex)
	}
	// 3. delivery signature over m_i^del = (tau, alpha, PK_R, i, E_i, pi)
	if !t.verifyDeliverySig(d) {
		return Reject(RejectInvalidSignature)
	}
	// 4. proof verification against the compiled public statement
	//    (distinct failure classes: unavailable params vs invalid proof)
	if p == nil {
		return Unavailable(UnavailableProofParams)
	}
	pf, err := p.ParseProof(d.Proof)
	if err != nil {
		return Reject(RejectInvalidProof)
	}
	pub, err := p.PublicWitness(t, d)
	if err != nil {
		return Reject(RejectInvalidProof)
	}
	if err := p.Verify(pf, pub); err != nil {
		return Reject(RejectInvalidProof)
	}
	return Ok(d.I)
}

// CollectAndRecover drives the collector over a set of deliveries, runs
// VerifyDel on each, keeps distinct valid indices, and attempts recovery once
// the threshold is met.
func (t *Task) CollectAndRecover(p *Prover, rec *DeliveryRecord, deliveries []*Delivery) Result {
	col := NewCollector()
	valid := map[int]*Delivery{}
	for _, d := range deliveries {
		if r := t.VerifyDel(p, rec, d); r.IsOK() {
			col.Add(d.I)
			valid[d.I] = d
		}
	}
	if col.Available() < t.F+1 {
		return Insufficient(col.Available(), t.F+1)
	}
	return t.Recover(valid)
}
