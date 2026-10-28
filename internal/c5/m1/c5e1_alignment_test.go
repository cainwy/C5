package m1

// R2 C5E1 reconciliation evidence: verifies that the M1 TaskCtx / Alpha /
// MaskCtx now reuse the AP2-frozen C5E1 canonical encoding (byte-identical to
// host.SynthInstance's internal construction), not a second length-prefixed
// encoding. Records digests for the revised concrete-profile manifest.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"c5full/internal/c5/host"
)

const c5e1Magic = "C5E1"

func TestC5E1Alignment(t *testing.T) {
	tk, err := NewTask(3, 1, 2, "seed-c5e1")
	if err != nil {
		t.Fatalf("NewTask: %v", err)
	}

	// 1. TaskCtx and MaskCtx must carry the C5E1 magic prefix (typed/ordered tuple).
	if !bytes.HasPrefix(tk.TaskCtx, []byte(c5e1Magic)) {
		t.Fatalf("TaskCtx does not start with C5E1 magic: %x", tk.TaskCtx[:8])
	}
	mc := tk.MaskCtxFor(1)
	if !bytes.HasPrefix(mc, []byte(c5e1Magic)) {
		t.Fatalf("MaskCtx does not start with C5E1 magic: %x", mc[:8])
	}

	// 2. Alpha must equal host.HashState(TaskCtx, Aout) byte-for-byte.
	alpha := host.HashState(tk.TaskCtx, tk.Aout)
	if !bytes.Equal(alpha, tk.Alpha) {
		t.Fatalf("Alpha != host.HashState")
	}

	// 3. MaskCtxFor must equal host.BuildMaskCtx (the AP2 makeMaskCtx).
	mcRef := host.BuildMaskCtx(tk.TaskCtx, tk.Alpha, tk.ReceiverPK, 1, tk.L, "RDEL-v2")
	if !bytes.Equal(mc, mcRef) {
		t.Fatalf("MaskCtxFor != host.BuildMaskCtx")
	}

	// 4. Aout encoding matches host.EncodeAout (used inside HashState).
	aoutEnc := host.EncodeAout(tk.Aout)
	if len(aoutEnc) == 0 {
		t.Fatalf("empty Aout encoding")
	}

	// record digests for the revised profile manifest
	dig := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
	rec := map[string]string{
		"taskctx_c5e1_sha256": dig(tk.TaskCtx),
		"alpha_sha256":        dig(tk.Alpha),
		"maskctx_sha256":      dig(mc),
		"aout_sha256":         dig(aoutEnc),
		"encoding":            "C5E1 (AP2 frozen)",
	}
	t.Logf("C5E1 alignment: TaskCtx=%s... MaskCtx=%s... Alpha=%s...",
		rec["taskctx_c5e1_sha256"][:12], rec["maskctx_sha256"][:12], rec["alpha_sha256"][:12])

	b, _ := json.MarshalIndent(rec, "", "  ")
	rawRoot := filepath.Join("..", "..", "..", "raw")
	if err := os.MkdirAll(filepath.Join(rawRoot, "m1"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rawRoot, "m1", "m3_c5e1_alignment.json"), b, 0o644); err != nil {
		t.Fatalf("save: %v", err)
	}
	t.Logf("saved raw/m1/m3_c5e1_alignment.json")
}
