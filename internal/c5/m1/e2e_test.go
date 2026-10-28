package m1

// M3-3 honest end-to-end tests. Run each in a separate process (setup is heavy:
// ~400s for L=1, ~700s for L=2) to avoid multi-setup OOM. Each test drives the
// full pipeline and writes machine-readable evidence to ap3_m1/raw/m1/.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func saveM1(t *testing.T, rel string, data []byte) {
	t.Helper()
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

func runAndSave(t *testing.T, n, f, L int, seed string, rel string) {
	res, err := RunE2E(n, f, L, seed)
	if err != nil {
		t.Fatalf("RunE2E L=%d: %v", L, err)
	}
	t.Logf("E2E L=%d f=%d constraints=%d setup=%.1fs prove=%v verify=%.3fs accepted=%v status=%s recoveredOK=%v",
		L, f, res.Constraints, res.SetupS, res.ProveS, res.VerifyS, res.Accepted, res.Status, res.RecoveredOK)
	if !res.RecoveredOK {
		t.Fatalf("recovered output != authoritative output (L=%d)", L)
	}
	if res.Status != string(StatusOK) {
		t.Fatalf("recovery status not OK: %s", res.Status)
	}
	if len(res.Accepted) < f+1 {
		t.Fatalf("accepted < f+1: %d", len(res.Accepted))
	}
	b, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	saveM1(t, rel, b)
}

// TestE2EL1F1 (M3-3 minimum): L=1 f=1 full honest end-to-end.
func TestE2EL1F1(t *testing.T) {
	runAndSave(t, 3, 1, 1, "ap3-e2e-l1f1", "m1/m3_e2e_L1_f1.json")
}

// TestE2EL2F1 (M3-3 multi-output): L=2 f=1 full honest end-to-end.
func TestE2EL2F1(t *testing.T) {
	runAndSave(t, 3, 1, 2, "ap3-e2e-l2f1", "m1/m3_e2e_L2_f1.json")
}
