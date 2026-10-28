package circuit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"runtime"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"

	"c5full/internal/c5/host"
)

// TestPlonkSmoke (M5 backup backend, mandatory second attempt): PLONK-KZG over
// the SAME R_del inner circuit (L=1, f=1). The kzg SRS comes from
// test/unsafekzg and is TEST-ONLY by definition (not a production ceremony).
// If this configuration exceeds local memory, the failure is recorded as a
// backend-specific feasibility boundary and Groth16 remains the main backend.
func TestPlonkSmoke(t *testing.T) {
	inst, err := host.SynthInstance(1, 1, 20260903, 1, 0)
	if err != nil {
		t.Fatalf("SynthInstance: %v", err)
	}
	type traits struct {
		CompileS float64 `json:"compile_s"`
		SrsS     float64 `json:"srs_s"`
		SetupS   float64 `json:"setup_s"`
		ProveS   float64 `json:"prove_s"`
		VerifyMs float64 `json:"verify_ms"`
		ProofB   int     `json:"proof_bytes"`
		PKB      int     `json:"pk_bytes"`
		VKB      int     `json:"vk_bytes"`
		HeapMiB  uint64  `json:"heap_mib"`
		ProofSHA string  `json:"proof_sha256"`
		Result   string  `json:"result"`
	}
	tr := &traits{Result: "attempt"}

	tt := time.Now()
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, emptyRdEl(len(inst.MaskCtx)))
	if err != nil {
		t.Fatalf("plonk compile: %v", err)
	}
	tr.CompileS = time.Since(tt).Seconds()
	t.Logf("plonk scs constraints=%d", ccs.GetNbConstraints())

	tt = time.Now()
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs) // TEST-ONLY SRS
	if err != nil {
		t.Fatalf("kzg srs: %v", err)
	}
	tr.SrsS = time.Since(tt).Seconds()

	tt = time.Now()
	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		t.Fatalf("plonk setup: %v", err)
	}
	tr.SetupS = time.Since(tt).Seconds()

	good := rdelWitness(inst)
	sec, err := frontend.NewWitness(good, ecc.BLS12_381.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	pub, err := sec.Public()
	if err != nil {
		t.Fatalf("public: %v", err)
	}
	tt = time.Now()
	var proof plonk.Proof
	proof, err = plonk.Prove(ccs, pk, sec)
	if err != nil {
		t.Fatalf("plonk prove: %v", err)
	}
	tr.ProveS = time.Since(tt).Seconds()

	tt = time.Now()
	if err := plonk.Verify(proof, vk, pub); err != nil {
		t.Fatalf("plonk verify: %v", err)
	}
	tr.VerifyMs = time.Since(tt).Seconds() * 1000

	var pb bytes.Buffer
	if _, err := proof.WriteTo(&pb); err != nil {
		t.Fatalf("proof.WriteTo: %v", err)
	}
	tr.ProofB = pb.Len()
	sm := sha256.Sum256(pb.Bytes())
	tr.ProofSHA = hex.EncodeToString(sm[:])
	var pkb, vkb bytes.Buffer
	if _, err := pk.WriteTo(&pkb); err != nil {
		t.Fatalf("pk.WriteTo: %v", err)
	}
	if _, err := vk.WriteTo(&vkb); err != nil {
		t.Fatalf("vk.WriteTo: %v", err)
	}
	tr.PKB, tr.VKB = pkb.Len(), vkb.Len()

	var ms runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&ms)
	tr.HeapMiB = ms.HeapAlloc >> 20
	tr.Result = "PASS (honest prove+verify; SRS test-only)"
	t.Logf("PLONK-KZG PASS: prove=%.1fs verify=%.1fms proof=%dB pk=%dB vk=%dB",
		tr.ProveS, tr.VerifyMs, tr.ProofB, tr.PKB, tr.VKB)

	if b, err := json.MarshalIndent(tr, "", "  "); err == nil {
		save(t, "plonk/m5_plonk_smoke.json", b)
	}
}