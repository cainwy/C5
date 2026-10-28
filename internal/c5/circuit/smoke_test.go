package circuit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"

	"c5full/internal/c5/host"
)

type smokeStat struct {
	CompileS float64 `json:"compile_s"`
	SetupS   float64 `json:"setup_s"`
	ProveS   float64 `json:"prove_s"`
	VerifyMs float64 `json:"verify_ms"`
	ProofB   int     `json:"proof_bytes"`
	PKB      int     `json:"pk_bytes"`
	VKB      int     `json:"vk_bytes"`
	HeapMiB  uint64  `json:"heap_mib"`
	TotalMiB uint64  `json:"total_alloc_mib"`
	ProofSHA string  `json:"proof_sha256"`
}

// TestGroth16Smoke (M5 main backend): compile->setup->prove->verify->serialize,
// proof-level negative table, tampered public statement + tampered proof, and
// provenance digests. Runs on the real R_del inner circuit (L=1, f=1).
func TestGroth16Smoke(t *testing.T) {
	// NOTE: needs c5full/internal/c5/circuit's rdelWitness+emptyRdEl.
	inst, err := host.SynthInstance(1, 1, 20260903, 1, 0)
	if err != nil {
		t.Fatalf("SynthInstance: %v", err)
	}
	st := &smokeStat{}

	tt := time.Now()
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, emptyRdEl(len(inst.MaskCtx)))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	st.CompileS = time.Since(tt).Seconds()

	tt = time.Now()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	st.SetupS = time.Since(tt).Seconds()
	t.Logf("compile=%.1fs setup=%.1fs constraints=%d", st.CompileS, st.SetupS, ccs.GetNbConstraints())

	// serialize keys
	var pkBuf, vkBuf bytes.Buffer
	if _, err := pk.WriteTo(&pkBuf); err != nil {
		t.Fatalf("pk.WriteTo: %v", err)
	}
	if _, err := vk.WriteTo(&vkBuf); err != nil {
		t.Fatalf("vk.WriteTo: %v", err)
	}
	st.PKB, st.VKB = pkBuf.Len(), vkBuf.Len()

	// honest prove+verify
	good := rdelWitness(inst)
	sec, err := frontend.NewWitness(good, ecc.BLS12_381.ScalarField())
	if err != nil {
		t.Fatalf("honest witness: %v", err)
	}
	pub, err := sec.Public()
	if err != nil {
		t.Fatalf("honest public: %v", err)
	}
	tt = time.Now()
	pf, err := groth16.Prove(ccs, pk, sec)
	if err != nil {
		t.Fatalf("honest prove: %v", err)
	}
	st.ProveS = time.Since(tt).Seconds()

	var proofBuf bytes.Buffer
	if _, err := pf.WriteTo(&proofBuf); err != nil {
		t.Fatalf("proof.WriteTo: %v", err)
	}
	st.ProofB = proofBuf.Len()
	sum := sha256.Sum256(proofBuf.Bytes())
	st.ProofSHA = hex.EncodeToString(sum[:])

	tt = time.Now()
	if err := groth16.Verify(pf, vk, pub); err != nil {
		t.Fatalf("honest verify failed: %v", err)
	}
	st.VerifyMs = time.Since(tt).Seconds() * 1000

	var ms runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&ms)
	st.HeapMiB, st.TotalMiB = ms.HeapAlloc>>20, ms.TotalAlloc>>20
	t.Logf("prove=%.1fs verify=%.1fms proof=%dB sha256=%s", st.ProveS, st.VerifyMs, st.ProofB, st.ProofSHA[:12]+"...")

	// ---- proof-level negative table (each returns a label) -----------------
	rejects := map[string]error{}
	rejects["wrong_s"] = expectReject(ccs, pk, mutRdel(inst, func(w *RdEl) { w.S = emulated.ValueOf[emulated.Secp256k1Fr](inc(inst.S)) }))
	rejects["wrong_z"] = expectReject(ccs, pk, mutRdel(inst, func(w *RdEl) { w.Zs[0] = emulated.ValueOf[emulated.Secp256k1Fr](inc(inst.Zlist[0])) }))
	rejects["wrong_rho"] = expectReject(ccs, pk, mutRdel(inst, func(w *RdEl) { w.Rhos[0] = emulated.ValueOf[emulated.Secp256k1Fr](inc(inst.Rholist[0])) }))
	rejects["modified_c"] = expectReject(ccs, pk, mutRdel(inst, func(w *RdEl) { w.Cpt[0] = emulated.ValueOf[emulated.Secp256k1Fr](inc(inst.Clist[0])) }))
	rejects["modified_C_point"] = expectReject(ccs, pk, mutRdel(inst, func(w *RdEl) {
		w.C[0] = *pAff(inc(inst.PKR.X.BigInt(new(big.Int))), inst.PKR.Y.BigInt(new(big.Int)))
	}))
	rejects["wrong_receiver_PKR"] = expectReject(ccs, pk, mutRdel(inst, func(w *RdEl) {
		w.PKR = *pAff(inc(inst.PKR.X.BigInt(new(big.Int))), inst.PKR.Y.BigInt(new(big.Int)))
	}))
	rejects["context_mutation"] = expectReject(ccs, pk, mutRdel(inst, func(w *RdEl) {
		c := append([]byte{}, inst.MaskCtx...)
		c[0] ^= 0x01
		w.MaskCtx = uints.NewU8Array(c)
	}))
	rejects["zero_s"] = expectReject(ccs, pk, mutRdel(inst, func(w *RdEl) { w.S = emulated.ValueOf[emulated.Secp256k1Fr](big.NewInt(0)) }))

	for name, e := range rejects {
		if e != nil {
			t.Fatalf("negative %s not rejected: %v", name, e)
		}
	}
	t.Logf("proof-level negatives rejected: %d cases OK", len(rejects))

	// ---- valid proof + modified public statement -> verify fail ------------
	modPub := mutRdel(inst, func(w *RdEl) { w.Cpt[0] = emulated.ValueOf[emulated.Secp256k1Fr](inc(inst.Clist[0])) })
	mpSec, err := frontend.NewWitness(modPub, ecc.BLS12_381.ScalarField())
	if err != nil {
		t.Fatalf("mod public witness: %v", err)
	}
	mpPub, err := mpSec.Public()
	if err != nil {
		t.Fatalf("mod public: %v", err)
	}
	if err := groth16.Verify(pf, vk, mpPub); err == nil {
		t.Fatal("verify accepted modified public statement")
	}

	// ---- tampered proof bytes -> reject -----------------------------------
	badBytes := append([]byte{}, proofBuf.Bytes()...)
	badBytes[len(badBytes)/2] ^= 0xff
	tampered, err := readProof(badBytes)
	if err != nil {
		t.Logf("tampered proof rejected at deserialize (malformed path): %v", err)
	} else if err := groth16.Verify(tampered, vk, pub); err == nil {
		t.Fatal("verify accepted tampered proof")
	} else {
		t.Logf("tampered proof rejected at verify: %v", err)
	}

	stOK := struct {
		smokeStat `json:"traits"`
		Negative  map[string]string `json:"negatives"`
		PubBytes  int               `json:"public_statement_bytes"`
		Seed      int               `json:"seed"`
	}{
		smokeStat: *st,
		Negative:  map[string]string{"result": "all 8 rejected"},
		PubBytes:  witnessLen(mpPub),
		Seed:      20260903,
	}
	if b, err := json.MarshalIndent(stOK, "", "  "); err == nil {
		save(t, "groth16/m5_groth16_smoke.json", b)
	}
}

func inc(x *big.Int) *big.Int { return new(big.Int).Add(x, big.NewInt(1)) }

// witnessLen serializes a witness to count exact public-statement bytes.
func witnessLen(w witness.Witness) int {
	var b bytes.Buffer
	_, _ = w.WriteTo(&b)
	return b.Len()
}

// mutRdel clones the honest witness and applies fn.
func mutRdel(inst *host.Instance, fn func(*RdEl)) *RdEl {
	w := rdelWitness(inst)
	fn(w)
	return w
}

// readProof decodes serialized Groth16 proof bytes with integrity checks.
func readProof(b []byte) (groth16.Proof, error) {
	p := groth16.NewProof(ecc.BLS12_381)
	_, err := p.ReadFrom(bytes.NewReader(b))
	return p, err
}

// save writes evidence to ap2_m0/raw relative to the package test cwd (src).
func save(t *testing.T, rel string, data []byte) {
	// test cwd is src/internal/circuit; ap2_m0/raw is three levels up.
	rawRoot := filepath.Join("..", "..", "..", "raw")
	dir := filepath.Join(rawRoot, filepath.Dir(rel))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Logf("mkdir: %v", err)
		return
	}
	if err := os.WriteFile(filepath.Join(rawRoot, rel), data, 0o644); err != nil {
		t.Logf("save %s: %v", rel, err)
		return
	}
	t.Logf("saved raw/%s (%d bytes)", rel, len(data))
}