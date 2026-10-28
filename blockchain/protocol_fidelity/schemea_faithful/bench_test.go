package schemeafaithful

import (
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFig4ScanFull(t *testing.T) {
	if testing.Short() {
		t.Skip("full scan skipped in -short")
	}
	cfg := DefaultBench()
	samples, err := RunFig4Scan(cfg, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]any{"config": cfg, "samples": samples}
	b, _ := json.MarshalIndent(out, "", "  ")
	dir := filepath.Join("..", "..", "..", "results", "raw")
	_ = os.MkdirAll(dir, 0o755)
	_ = os.WriteFile(filepath.Join(dir, "sf_fig4_scan_v1.0.json"), b, 0o644)

	for _, s := range samples {
		t.Logf("keylen=%5d  encrypt: med=%.3fms (paper %.2f)  verify: med=%.3fms (paper %.2f)",
			s.KeyLenBits, s.EncryptMsMed, s.EncryptPaperMs, s.VerifyMsMed, s.VerifyPaperMs)
	}
	ok, verdict := JudgeFig4(samples)
	if !ok {
		t.Errorf("Fig.4 self-test verdict: %s", verdict)
	} else {
		t.Logf("Fig.4 self-test verdict: %s", verdict)
	}
}

func TestFig4ScanShort(t *testing.T) {
	cfg := BenchConfig{
		KeyLens: []int{64, 128, 256}, Reps: 3, Seeds: 1,
		ElGamal: DefaultElGamal, ZK: DefaultZKPoC, N: 3, T: 2, M: 2,
	}
	samples, err := RunFig4Scan(cfg, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 3 {
		t.Fatalf("want 3 samples got %d", len(samples))
	}
	for _, s := range samples {
		t.Logf("keylen=%d enc=%.3fms ver=%.3fms", s.KeyLenBits, s.EncryptMsMed, s.VerifyMsMed)
	}
}

func TestCountOperationsTableIV(t *testing.T) {
	oc := CountOperations(5, 10, 3, 8)
	if oc.M != 5 || oc.N != 10 || oc.T != 3 || oc.W != 8 {
		t.Fatal("counts passthrough mismatch")
	}
	if oc.Rho < 0.29 || oc.Rho > 0.31 {
		t.Fatalf("rho=t/n=0.3 expected, got %f", oc.Rho)
	}
	if oc.ContractOps["zkpoc_verify_nw"] != 10*8 {
		t.Fatal("contract n·w ZKPoC verify count wrong")
	}
	if oc.ClientDecryptOps["partial_decrypt_mw"] != 5*8 {
		t.Fatal("client m·w decrypt count wrong")
	}
}

func TestCommAccountingTableVI(t *testing.T) {
	ca := ComputeCommAccounting(5, 10, 3, 8, 256)
	if ca.ECLen != 64 || ca.ProofLen != 128 || ca.CommLen != 32 || ca.DVLen != 32 {
		t.Fatalf("byte lengths wrong: %+v", ca)
	}
	// Client = 2·10·(48+64) + 3·32 + 3·8·(64+32) = 2240+96+2304 = 4640
	if ca.ClientBytes != 2240+96+2304 {
		t.Fatalf("client bytes %d != expected 4640", ca.ClientBytes)
	}
	// Server = 2·5·112 + 5·3·32 + 8·(64+128) = 1120+480+1536 = 3136
	if ca.ServerBytes != 1120+480+1536 {
		t.Fatalf("server bytes %d != expected 3136", ca.ServerBytes)
	}
	t.Logf("client=%dB server=%dB lc=%dB", ca.ClientBytes, ca.ServerBytes, ca.ClientLc)
}
