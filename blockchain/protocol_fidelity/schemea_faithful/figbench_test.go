package schemeafaithful

import (
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func rawDir() string {
	dir := filepath.Join("..", "..", "..", "results", "raw")
	_ = os.MkdirAll(dir, 0o755)
	return dir
}

func saveJSON(t *testing.T, name string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(rawDir(), name)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("saved %s", p)
}

func TestFig56Model(t *testing.T) {
	cfg := DefaultFig567()
	cal, err := CalibrateOps(cfg, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("calibrated: Tsp=%.4f Tss=%.4f Tse=%.4f Tcg=%.4f Ted=%.4f Tsr=%.4f ms",
		cal.TspMs, cal.TssMs, cal.TseMs, cal.TcgMs, cal.TedMs, cal.TsrMs)
	fig5 := RunFig5Model(cfg, cal)
	fig6 := RunFig6Model(cfg)
	saveJSON(t, "sf_fig5_v1.0.json", map[string]any{"calibration": cal, "points": fig5})
	saveJSON(t, "sf_fig6_v1.0.json", map[string]any{"config": map[string]any{
		"Ns": cfg.Ns, "Rhos": cfg.Rhos, "PrimeBits": cfg.PrimeBits, "W": cfg.ElGamal.W(),
	}, "points": fig6})
	for _, rho := range []float64{0.3, 0.5, 0.7} {
		for _, n := range []int{3, 10, 30} {
			for _, p := range fig5 {
				if p.Rho == rho && p.N == n {
					t.Logf("fig5: n=%2d rho=%.1f t=%d Tc=%.3fms", p.N, p.Rho, p.T, p.TcMs)
				}
			}
			for _, p := range fig6 {
				if p.Rho == rho && p.N == n {
					t.Logf("fig6: n=%2d rho=%.1f t=%d Lc=%dB", p.N, p.Rho, p.T, p.LcBytes)
				}
			}
		}
	}
}

func TestFig7E2E(t *testing.T) {
	if testing.Short() {
		t.Skip("fig7 skipped in -short")
	}
	cfg := DefaultFig567()
	cfg.Ns = []int{3, 5, 10, 15, 20, 25, 30}
	logf, err := os.Create(filepath.Join(rawDir(), "fig7_run.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logf.Close()
	quiet := &quietT{t: t, f: logf}
	start := time.Now()
	pts, err := RunFig7E2E(cfg, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	quiet.Logf("fig7 total wall: %.1fs", time.Since(start).Seconds())
	saveJSON(t, "sf_fig7_v1.0.json", map[string]any{
		"config": map[string]any{"Ns": cfg.Ns, "KeyLens": cfg.KeyLens, "Reps": cfg.Reps},
		"points": pts,
	})
	for _, p := range pts {
		quiet.Logf("fig7: n=%2d kl=%4d total=%8.2fms procVer=%8.2fms decrypt=%8.2fms dist=%6.2fms valid=%v",
			p.N, p.KeyLen, p.TotalMs, p.ProcVerMs, p.DecryptMs, p.DistMs, p.Valid)
	}
	ok, verdict := JudgeFig567(nil, nil, pts)
	if !ok {
		t.Errorf("fig7 verdict: %s", verdict)
	} else {
		t.Logf("fig7 verdict: %s", verdict)
	}
}

type quietT struct {
	t *testing.T
	f *os.File
}

func (q *quietT) Logf(format string, args ...any) {
	_, _ = q.f.WriteString(time.Now().Format("15:04:05 ") + format + "\n")
}

func TestFig567Trend(t *testing.T) {
	cfg := DefaultFig567()
	cal, err := CalibrateOps(cfg, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fig5 := RunFig5Model(cfg, cal)
	fig6 := RunFig6Model(cfg)
	ok, verdict := JudgeFig567(fig5, fig6, nil)
	if !ok {
		t.Errorf("trend verdict: %s", verdict)
	} else {
		t.Logf("trend verdict: %s", verdict)
	}
}
