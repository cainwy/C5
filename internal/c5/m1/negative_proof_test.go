package m1

// M3-4 negative-test matrix (part 2: proof-layer cases). These need a Prover
// (Groth16 setup ~400s for L=1), so run this test in its own process. Each
// malicious witness must fail to prove (R1/R3/R4/R5 constraint violation), and
// a tampered proof must fail verification.

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

func incM1(x *big.Int) *big.Int { return new(big.Int).Add(x, big.NewInt(1)) }

// TestNegativeProof runs the proof-layer negative matrix on L=1, f=1.
func TestNegativeProof(t *testing.T) {
	tk, err := NewTask(3, 1, 1, "seed-negproof")
	if err != nil {
		t.Fatalf("NewTask: %v", err)
	}
	p, err := NewProver(1, len(tk.MaskCtxFor(1)))
	if err != nil {
		t.Fatalf("NewProver: %v", err)
	}
	t.Logf("proof negatives: constraints=%d", p.Constraints())

	d := tk.MakeDelivery(0)
	rec := &negRecorder{t: t}

	// honest proves (sanity)
	if err := p.ProveWitness(buildRdElWitness(tk, d)); err != nil {
		t.Fatalf("honest witness failed to prove: %v", err)
	}

	// --- R1: wrong s -------------------------------------------------------
	ws := buildRdElWitness(tk, d)
	ws.S = emulated.ValueOf[emulated.Secp256k1Fr](incM1(d.S))
	rec.check(NegCase{"proof_wrong_s", "s+1 with unchanged R", "REJECT",
		rejected(p.ProveWitness(ws) != nil), "proof", "S3", "T3", false})

	// --- R3: wrong z -------------------------------------------------------
	wz := buildRdElWitness(tk, d)
	z0, _ := tk.ShareAt(0, 0)
	wz.Zs[0] = emulated.ValueOf[emulated.Secp256k1Fr](incM1(z0))
	rec.check(NegCase{"proof_wrong_z", "z+1 with unchanged C", "REJECT",
		rejected(p.ProveWitness(wz) != nil), "proof", "S3", "T3", false})

	// --- R3: wrong rho -----------------------------------------------------
	wr := buildRdElWitness(tk, d)
	_, rho0 := tk.ShareAt(0, 0)
	wr.Rhos[0] = emulated.ValueOf[emulated.Secp256k1Fr](incM1(rho0))
	rec.check(NegCase{"proof_wrong_rho", "rho+1 with unchanged C", "REJECT",
		rejected(p.ProveWitness(wr) != nil), "proof", "S3", "T3", false})

	// --- R5: modified ciphertext ------------------------------------------
	wc := buildRdElWitness(tk, d)
	wc.Cpt[0] = emulated.ValueOf[emulated.Secp256k1Fr](incM1(d.C[0]))
	rec.check(NegCase{"proof_modified_c", "c+1 (public ciphertext)", "REJECT",
		rejected(p.ProveWitness(wc) != nil), "proof", "S3,S5", "T3", false})

	// --- R4: context mutation (modified MaskCtx) ---------------------------
	wctx := buildRdElWitness(tk, d)
	mut := append([]byte{}, tk.MaskCtxFor(1)...)
	mut[0] ^= 0x01
	wctx.MaskCtx = uints.NewU8Array(mut)
	rec.check(NegCase{"proof_context_mutation", "flip one MaskCtx byte", "REJECT",
		rejected(p.ProveWitness(wctx) != nil), "proof", "S5", "T5", false})

	// --- tampered proof ----------------------------------------------------
	_, proofBytes, pub, err := p.Prove(tk, d)
	if err != nil {
		t.Fatalf("honest prove: %v", err)
	}
	bad := append([]byte{}, proofBytes...)
	bad[len(bad)/2] ^= 0xff
	tampered, err := p.ParseProof(bad)
	if err != nil {
		rec.check(NegCase{"proof_tampered", "corrupt proof bytes (deserialize)", "REJECT",
			rejected(true), "proof", "S3", "T3", false})
	} else if err := p.Verify(tampered, pub); err != nil {
		rec.check(NegCase{"proof_tampered", "corrupt proof bytes (verify)", "REJECT",
			rejected(true), "proof", "S3", "T3", false})
	} else {
		rec.check(NegCase{"proof_tampered", "corrupt proof bytes", "REJECT",
			rejected(false), "proof", "S3", "T3", false})
	}

	rec.save("m1/m3_negative_proof.json")
}
