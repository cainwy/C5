package m1

// B0 + B3 baseline benchmarks. B0 is C5 minus the proof (direct private
// delivery); B3 is Scheme A's Lifted-ElGamal + bit-splitting + DLOG route
// (implemented in internal/schemea). Both have no Groth16 setup, so they can be
// measured many times for stable statistics. B1/B2/C5 reuse the AP2/AP3
// measured setup/prove/verify data (recorded in the result report).

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"c5full/internal/mpc/schemea"
)

func benchSave(t *testing.T, rel string, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	rawRoot := filepath.Join("..", "..", "..", "raw")
	os.MkdirAll(filepath.Join(rawRoot, filepath.Dir(rel)), 0o755)
	os.WriteFile(filepath.Join(rawRoot, rel), b, 0o644)
	t.Logf("saved raw/%s", rel)
}

func median(sorted []float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}

func stats(xs []float64) (medianV, mean, std, iqr, minV, maxV float64) {
	// insertion sort
	s := append([]float64{}, xs...)
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
	medianV = median(s)
	sum := 0.0
	for _, x := range s {
		sum += x
	}
	mean = sum / float64(len(s))
	ss := 0.0
	for _, x := range s {
		ss += (x - mean) * (x - mean)
	}
	std = sqrt(ss / float64(len(s)))
	q1 := s[len(s)/4]
	q3 := s[(3*len(s))/4]
	iqr = q3 - q1
	minV, maxV = s[0], s[len(s)-1]
	return
}

func sqrt(x float64) float64 {
	if x <= 0 {
		return 0
	}
	z := x
	for i := 0; i < 30; i++ {
		z = (z + x/z) / 2
	}
	return z
}

// TestBenchB0 measures B0 (direct private delivery, no proof): delivery
// generation (DH + mask + ciphertext) and receiver recovery (decapsulation +
// Shamir). No Groth16 proof.
func TestBenchB0(t *testing.T) {
	const reps = 20
	tk, _ := NewTask(3, 1, 4, "ap4-b0")
	tk.EndorseAll()
	tk.Finality.Finalize(hexOf(tk.Alpha))

	deliveries := map[int]*Delivery{}
	for i := 0; i < 2; i++ {
		deliveries[i] = tk.MakeDelivery(i)
	}

	genTimes := make([]float64, reps)
	recTimes := make([]float64, reps)
	for r := 0; r < reps; r++ {
		// delivery generation for f+1 servers
		t0 := time.Now()
		ds := map[int]*Delivery{}
		for i := 0; i < 2; i++ {
			ds[i] = tk.MakeDelivery(i)
		}
		genTimes[r] = time.Since(t0).Seconds() * 1000 // ms

		// receiver recovery
		t1 := time.Now()
		res := tk.Recover(ds)
		if !res.IsOK() {
			t.Fatalf("B0 recover failed")
		}
		recTimes[r] = time.Since(t1).Seconds() * 1000
	}

	gm, gmMean, gstd, giqr, gmin, gmax := stats(genTimes)
	rm, rMean, rstd, riqr, rmin, rmax := stats(recTimes)

	out := map[string]any{
		"baseline": "B0", "L": 4, "n": 3, "f": 1, "reps": reps,
		"server_delivery_gen_ms": map[string]float64{"median": gm, "mean": gmMean, "std": gstd, "iqr": giqr, "min": gmin, "max": gmax},
		"receiver_recovery_ms":   map[string]float64{"median": rm, "mean": rMean, "std": rstd, "iqr": riqr, "min": rmin, "max": rmax},
		"proof": "none (B0 has no public proof)",
	}
	t.Logf("B0 L=4: delivery_gen median=%.4fms recovery median=%.4fms", gm, rm)
	benchSave(t, "ap4_b0_bench.json", out)
}

// TestBenchB3 measures Scheme A's output-processing route (L=1 share, k=256,
// chunk_bits=32, 8 chunks): server partition+encrypt, client decrypt+DLOG+
// recompose. Group prime 256-bit (paper-reproduction view; security note in
// report) and 2048-bit (security-normalized view) are both measured.
func TestBenchB3(t *testing.T) {
	for _, primeBits := range []int{256, 2048} {
		const reps = 5
		p := schemea.NewParams(primeBits, 256, 32, 42)
		z := new(big.Int).Lsh(big.NewInt(0xdeadbeef), 64)
		z.Or(z, big.NewInt(0x12345678))
		r := big.NewInt(0xabcdef)

		encTimes := make([]float64, reps)
		decTimes := make([]float64, reps)
		verTimes := make([]float64, reps)
		for i := 0; i < reps; i++ {
			t0 := time.Now()
			cts, _ := p.EncryptShare(z, r)
			encTimes[i] = time.Since(t0).Seconds() * 1000

			t1 := time.Now()
			_ = p.HomomorphicVerify(cts, z, r)
			verTimes[i] = time.Since(t1).Seconds() * 1000

			t2 := time.Now()
			got := p.RecoverShare(cts)
			if got.Cmp(z) != 0 {
				t.Fatalf("B3 recover mismatch")
			}
			decTimes[i] = time.Since(t2).Seconds() * 1000
		}
		em, emMean, estd, eiqr, emin, emax := stats(encTimes)
		dm, dmMean, dstd, diqr, dmin, dmax := stats(decTimes)
		vm, vmMean, vstd, viqr, vmin, vmax := stats(verTimes)

		out := map[string]any{
			"baseline": "B3", "prime_bits": primeBits, "k": 256, "chunk_bits": 32, "num_chunks": 8, "reps": reps,
			"server_encrypt_ms":  map[string]float64{"median": em, "mean": emMean, "std": estd, "iqr": eiqr, "min": emin, "max": emax},
			"homomorphic_verify_ms": map[string]float64{"median": vm, "mean": vmMean, "std": vstd, "iqr": viqr, "min": vmin, "max": vmax},
			"client_decrypt_dlog_ms": map[string]float64{"median": dm, "mean": dmMean, "std": dstd, "iqr": diqr, "min": dmin, "max": dmax},
			"dlog_method":           "BSGS (strengthened; paper literal 2^32 table infeasible)",
		}
		t.Logf("B3 prime=%dbit: encrypt median=%.3fms verify median=%.3fms decrypt+dlog median=%.3fms", primeBits, em, vm, dm)
		benchSave(t, map[int]string{256: "ap4_b3_bench_256.json", 2048: "ap4_b3_bench_2048.json"}[primeBits], out)
	}
}
