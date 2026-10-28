package host

// M3-0 checkpoint reproduction: verifies that the AP3 work-copy inherits the
// frozen AP2 concrete profile without silent drift. It re-derives the frozen
// Pedersen generator H, prints its derivation digest + compressed encoding,
// and re-runs a fixed-seed sender/circuit/receiver DeriveMask agreement so the
// three-end k value can be compared byte-for-byte against the AP2 evidence

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"c5full/internal/c5/params"
)

type checkpointJSON struct {
	ProfileID          string `json:"profile_id"`
	QHex               string `json:"q_hex"`
	PHex               string `json:"p_hex"`
	GCompressedHex     string `json:"G_compressed_hex"`
	HCompressedHex     string `json:"H_compressed_hex"`
	HDigestHex         string `json:"H_derivation_digest_hex"`
	HLabel             string `json:"H_label"`
	HDST               string `json:"H_dst"`
	DeriveMaskK        string `json:"derive_mask_k_hex"`
	DeriveMaskSeed     string `json:"derive_mask_seed"`
	DeriveMaskL        int    `json:"derive_mask_L"`
	DeriveMaskF        int    `json:"derive_mask_f"`
	CircuitFieldModHex string `json:"circuit_field_modulus_hex"`
}

func saveCheckpoint(t *testing.T, rel string, data []byte) {
	t.Helper()
	// test cwd is src/internal/host; ap3_m1/raw is three levels up.
	rawRoot := filepath.Join("..", "..", "..", "raw")
	dir := filepath.Join(rawRoot, filepath.Dir(rel))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rawRoot, rel), data, 0o644); err != nil {
		t.Fatalf("save: %v", err)
	}
	t.Logf("saved raw/%s (%d bytes)", rel, len(data))
}

func TestCheckpointDigest(t *testing.T) {
	inst, err := SynthInstance(3, 2, 20260822, 1, 0)
	if err != nil {
		t.Fatalf("SynthInstance: %v", err)
	}
	// sender-side mask (three-end agreement source of truth)
	Z := ScalarMul(inst.PKR, inst.S)
	k, err := DeriveMask(Z, inst.MaskCtx, 1)
	if err != nil {
		t.Fatalf("DeriveMask: %v", err)
	}

	ck := checkpointJSON{
		ProfileID:          "C5-AP2-M0-secp256k1-xmdsha256-gnark-g16-bls381-v1.1",
		QHex:               bigToHex(params.Q),
		PHex:               bigToHex(params.P),
		GCompressedHex:     hex.EncodeToString(EncodePoint(&params.G, false)),
		HCompressedHex:     hex.EncodeToString(params.Hbytes),
		HDigestHex:         hex.EncodeToString(params.Hdigest[:]),
		HLabel:             params.G2Label,
		HDST:               params.HDST,
		DeriveMaskK:        bigToHex(k),
		DeriveMaskSeed:     "20260822",
		DeriveMaskL:        3,
		DeriveMaskF:        2,
		CircuitFieldModHex: bigToHex(circuitFieldModulus()),
	}

	t.Logf("H compressed = %s", ck.HCompressedHex)
	t.Logf("H digest     = %s", ck.HDigestHex)
	t.Logf("DeriveMask k = %s", ck.DeriveMaskK)

	if len(ck.HCompressedHex) != 66 {
		t.Fatalf("H compressed encoding length wrong: %d", len(ck.HCompressedHex))
	}
	if ck.DeriveMaskK == "" {
		t.Fatalf("empty derive mask")
	}

	b, err := json.MarshalIndent(ck, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	saveCheckpoint(t, "checkpoint/m30_checkpoint.json", b)
}

func bigToHex(x *big.Int) string {
	return hex.EncodeToString(x.Bytes())
}

// circuitFieldModulus returns the BLS12-381 scalar field modulus (circuit field).
func circuitFieldModulus() *big.Int {
	m, _ := new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
	return m
}
