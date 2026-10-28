package m1

// AP4-REVISE receiver/client-side benchmarks (R1/R2/R3/R6).
// These measure the H1 "low receiver-side overhead" quantities with formal
// repetition (>=10 reps) and save raw JSON to c5/raw/. They do NOT modify the
// R_del circuit, S1-S7, receiver binding or the AP2/AP3 concrete profile; they
// only time the existing reference implementation.
//   - TestBenchReceiverRecoveryC5     : C5 designated-receiver recovery stages.
//   - TestBenchReceiverRecoverySchemeA: Scheme A client recovery stages (256/2048/3072-bit).
//   - TestBenchReceiverComm           : receiver/client communication byte accounting.
//   - TestBenchProveVerifyL1          : C5/B2 L=1 prove+verify steady-state (>=10 reps).

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"

	"c5full/internal/c5/host"
	"c5full/internal/c5/params"
	"c5full/internal/mpc/schemea"
)

func sinceMs(t time.Time) float64 { return time.Since(t).Seconds() * 1000 }

func statMap(xs []float64) map[string]float64 {
	m, mean, std, iqr, mn, mx := stats(xs)
	return map[string]float64{"median": m, "mean": mean, "std": std, "iqr": iqr, "min": mn, "max": mx}
}

func saveRaw(t *testing.T, rel string, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	rawRoot := filepath.Join("..", "..", "..", "raw")
	os.MkdirAll(filepath.Join(rawRoot, filepath.Dir(rel)), 0o755)
	os.WriteFile(filepath.Join(rawRoot, rel), b, 0o644)
	t.Logf("saved raw/%s", rel)
}

// recoverC5Stages runs the C5 designated-receiver recovery one time, returning
// per-stage wall times (ms). decapsulation (Z_i=[x_R]R_i) is cached per server
// (the natural implementation); mask derivation and subtraction are per
// (server, coordinate); Shamir reconstruction is per coordinate.
func recoverC5Stages(tk *Task, ds map[int]*Delivery, chosen []int) (decap, mask, sub, sham, total float64) {
	t0 := time.Now()
	Zs := make([]*secp256k1.G1Affine, len(chosen))
	for s, i := range chosen {
		Zs[s] = host.ScalarMul(ds[i].R, tk.ReceiverX)
	}
	decap = sinceMs(t0)

	t1 := time.Now()
	ks := make([][]*big.Int, len(chosen))
	for s, i := range chosen {
		maskCtx := tk.MaskCtxFor(i + 1)
		ks[s] = make([]*big.Int, tk.L)
		for j := 0; j < tk.L; j++ {
			k, _ := host.DeriveMask(Zs[s], maskCtx, j+1)
			ks[s][j] = k
		}
	}
	mask = sinceMs(t1)

	t2 := time.Now()
	shares := make([][]*big.Int, tk.L)
	for j := 0; j < tk.L; j++ {
		shares[j] = make([]*big.Int, len(chosen))
		for s, i := range chosen {
			z := new(big.Int).Sub(ds[i].C[j], ks[s][j])
			z.Mod(z, params.Q)
			shares[j][s] = z
		}
	}
	sub = sinceMs(t2)

	t3 := time.Now()
	xs := make([]*big.Int, len(chosen))
	for s, i := range chosen {
		xs[s] = tk.Xi[i]
	}
	out := make([]*big.Int, tk.L)
	for j := 0; j < tk.L; j++ {
		out[j] = Reconstruct(xs, shares[j])
	}
	sham = sinceMs(t3)
	total = decap + mask + sub + sham
	return
}

// TestBenchReceiverRecoveryC5 measures C5 receiver recovery stages for L=1,2,4.
func TestBenchReceiverRecoveryC5(t *testing.T) {
	const reps = 10
	for _, L := range []int{1, 2, 4} {
		tk, _ := NewTask(3, 1, L, "ap4-revise-c5-recv")
		ds := map[int]*Delivery{}
		for i := 0; i < 2; i++ {
			ds[i] = tk.MakeDelivery(i)
		}
		chosen := chosenIndices(ds, tk.F+1)

		// one-time correctness check (recovered == authoritative output)
		_, _, _, _, _ = recoverC5Stages(tk, ds, chosen)
		var got []*big.Int
		{
			_, _, _, _, _ = recoverC5Stages(tk, ds, chosen)
			// recompute directly for the equality check
			Zs := make([]*secp256k1.G1Affine, len(chosen))
			for s, i := range chosen {
				Zs[s] = host.ScalarMul(ds[i].R, tk.ReceiverX)
			}
			xs := make([]*big.Int, len(chosen))
			for s, i := range chosen {
				xs[s] = tk.Xi[i]
			}
			got = make([]*big.Int, L)
			for j := 0; j < L; j++ {
				zs := make([]*big.Int, len(chosen))
				for s, i := range chosen {
					k, _ := host.DeriveMask(Zs[s], tk.MaskCtxFor(i+1), j+1)
					z := new(big.Int).Sub(ds[i].C[j], k)
					z.Mod(z, params.Q)
					zs[s] = z
				}
				got[j] = Reconstruct(xs, zs)
			}
		}
		want := tk.OutputValues()
		if !vecEqual(want, got) {
			t.Fatalf("L=%d recovery mismatch", L)
		}

		decap := make([]float64, reps)
		mask := make([]float64, reps)
		sub := make([]float64, reps)
		sham := make([]float64, reps)
		total := make([]float64, reps)
		for r := 0; r < reps; r++ {
			d, m, s, sh, tt := recoverC5Stages(tk, ds, chosen)
			decap[r], mask[r], sub[r], sham[r], total[r] = d, m, s, sh, tt
		}

		out := map[string]any{
			"baseline": "C5", "L": L, "n": 3, "f": 1, "reps": reps,
			"decapsulation_ms":        statMap(decap),
			"mask_derivation_ms":      statMap(mask),
			"field_subtraction_ms":    statMap(sub),
			"shamir_reconstruction_ms": statMap(sham),
			"total_recovery_ms":       statMap(total),
		}
		saveRaw(t, "ap4_revise_receiver_recovery_c5_L"+itoa(L)+".json", out)
		t.Logf("C5 L=%d total recovery median=%.4fms (decap=%.4f mask=%.4f sub=%.4f sham=%.4f)",
			L, out["total_recovery_ms"].(map[string]float64)["median"],
			out["decapsulation_ms"].(map[string]float64)["median"],
			out["mask_derivation_ms"].(map[string]float64)["median"],
			out["field_subtraction_ms"].(map[string]float64)["median"],
			out["shamir_reconstruction_ms"].(map[string]float64)["median"])
	}
}

func itoa(x int) string { return strconv.Itoa(x) }

// shamirOverInts is a negligible-cost Shamir reconstruction proxy over two
// shares at evaluation points 1 and 2 (Scheme A eq. (22)): z = 2*z0 - z1.
func shamirOverInts(z0, z1 *big.Int) *big.Int {
	t0 := new(big.Int).Mul(big.NewInt(2), z0)
	t1 := new(big.Int).Neg(z1)
	return new(big.Int).Add(t0, t1)
}

// TestBenchReceiverRecoverySchemeA measures Scheme A client recovery stages.
func TestBenchReceiverRecoverySchemeA(t *testing.T) {
	const reps = 10
	for _, primeBits := range []int{256, 2048, 3072} {
		p := schemea.NewParams(primeBits, 256, 32, 42)
		// two distinct server shares (f+1=2), k=256 bit, chunk_bits=32 -> 8 chunks
		z0 := new(big.Int).Lsh(big.NewInt(0xdeadbeef), 64)
		z0.Or(z0, big.NewInt(0x12345678))
		z1 := new(big.Int).Lsh(big.NewInt(0xcafebabe), 64)
		z1.Or(z1, big.NewInt(0x87654321))
		r := big.NewInt(0xabcdef)

		// server-side encryption precomputed ONCE (not timed; client recovery input)
		cts0, _ := p.EncryptShare(z0, r)
		cts1, _ := p.EncryptShare(z1, r)

		decrypt := make([]float64, reps)
		dlog := make([]float64, reps)
		recomb := make([]float64, reps)
		sham := make([]float64, reps)
		total := make([]float64, reps)
		for i := 0; i < reps; i++ {
			t0 := time.Now()
			gv0 := p.DecryptShareThreshold(cts0)
			gv1 := p.DecryptShareThreshold(cts1)
			decrypt[i] = sinceMs(t0)

			t1 := time.Now()
			v0 := make([]*big.Int, p.NumChunks)
			v1 := make([]*big.Int, p.NumChunks)
			for j := 0; j < p.NumChunks; j++ {
				v0[j] = p.BSGS(gv0[j])
				v1[j] = p.BSGS(gv1[j])
			}
			dlog[i] = sinceMs(t1)

			t2 := time.Now()
			zz0 := p.Recombine(v0)
			zz1 := p.Recombine(v1)
			recomb[i] = sinceMs(t2)

			t3 := time.Now()
			_ = shamirOverInts(zz0, zz1)
			sham[i] = sinceMs(t3)

			total[i] = decrypt[i] + dlog[i] + recomb[i] + sham[i]
		}

		// correctness sanity (first reconstruction equals expected shares)
		gv0 := p.DecryptShareThreshold(cts0)
		v0 := make([]*big.Int, p.NumChunks)
		for j := 0; j < p.NumChunks; j++ {
			v0[j] = p.BSGS(gv0[j])
		}
		if p.Recombine(v0).Cmp(z0) != 0 {
			t.Fatalf("schemea prime=%d recover mismatch", primeBits)
		}

		out := map[string]any{
			"baseline": "B3-SchemeA", "prime_bits": primeBits, "k": 256, "chunk_bits": 32, "num_chunks": p.NumChunks, "reps": reps,
			"threshold_decrypt_ms":  statMap(decrypt),
			"bsgs_dlog_ms":          statMap(dlog),
			"recompose_ms":          statMap(recomb),
			"shamir_reconstruction_ms": statMap(sham),
			"total_recovery_ms":     statMap(total),
			"dlog_method":           "BSGS (strengthened; baby table rebuilt per call in reference impl; conservative for Scheme A)",
		}
		saveRaw(t, "ap4_revise_receiver_recovery_schemea_"+itoa(primeBits)+".json", out)
		t.Logf("SchemeA prime=%dbit total recovery median=%.3fms (decrypt=%.3f dlog=%.3f recomb=%.4f sham=%.4f)",
			primeBits, out["total_recovery_ms"].(map[string]float64)["median"],
			out["threshold_decrypt_ms"].(map[string]float64)["median"],
			out["bsgs_dlog_ms"].(map[string]float64)["median"],
			out["recompose_ms"].(map[string]float64)["median"],
			out["shamir_reconstruction_ms"].(map[string]float64)["median"])
	}
}

// TestBenchReceiverComm computes receiver/client communication bytes (R2),
// both measured (actual serialization) and formula-derived.
func TestBenchReceiverComm(t *testing.T) {
	// C5 per-delivery receiver payload: R_i (33B compressed) + L field ct (32B each) + index (4B)
	c5RBytes := 33
	c5FieldBytes := 32
	c5IndexBytes := 4

	type c5View struct {
		L              int
		PerDeliveryMin int // R + L*ct + index
		FPlus1Delivs   int // (f+1)*(per-delivery)
		PerCoordMin    int // per output coordinate (f+1 deliveries amortized)
		SelfVerifyAdd  int // + proof(292) + sig(64) per delivery (View B extra)
	}
	var c5 []c5View
	for _, L := range []int{1, 2, 4} {
		perDel := c5RBytes + L*c5FieldBytes + c5IndexBytes
		f1 := 2 * perDel
		perCoord := f1 / L
		c5 = append(c5, c5View{L: L, PerDeliveryMin: perDel, FPlus1Delivs: f1, PerCoordMin: perCoord, SelfVerifyAdd: 292 + 64})
	}

	// Scheme A per-share output route: w partitions x (2 ct group elts + 1 decryption temp elt)
	// group element bytes = ceil(primeBits/8)
	type saView struct {
		PrimeBits      int
		GroupElemBytes int
		W              int
		PerShare       int // w * 3 * group bytes
		FPlus1Shares   int // (f+1) * per-share
	}
	var sa []saView
	for _, pb := range []int{256, 2048, 3072} {
		geb := (pb + 7) / 8
		w := 8
		perShare := w * 3 * geb
		sa = append(sa, saView{PrimeBits: pb, GroupElemBytes: geb, W: w, PerShare: perShare, FPlus1Shares: 2 * perShare})
	}

	// measured serialization cross-check (C5)
	tk, _ := NewTask(3, 1, 1, "ap4-revise-comm")
	d := tk.MakeDelivery(0)
	measR := len(host.EncodePoint(d.R, false))
	measC := len(fieldBytes(d.C[0]))

	out := map[string]any{
		"C5": map[string]any{
			"note":           "View A (recovery-minimal): R_i(33B compressed) + L*field_ct(32B) + index(4B); proof/cert not consumed by receiver",
			"R_bytes":        measR,
			"field_ct_bytes": measC,
			"index_bytes":    c5IndexBytes,
			"views":          c5,
		},
		"SchemeA": map[string]any{
			"note":  "View A: per output share, w=8 partitions x (2 Lifted-ElGamal ct group elts + 1 decryption temp elt); paper-faithful route repeated per coordinate",
			"views": sa,
		},
	}
	saveRaw(t, "ap4_revise_receiver_comm.json", out)
	t.Logf("C5 L=1 (f+1=2) receiver min=%dB; SchemeA 256bit=%dB 2048bit=%dB 3072bit=%dB",
		c5[0].FPlus1Delivs, sa[0].FPlus1Shares, sa[1].FPlus1Shares, sa[2].FPlus1Shares)
}

// TestBenchProveVerifyL1 runs C5/B2 L=1 prove+verify steady-state (>=10 reps).
func TestBenchProveVerifyL1(t *testing.T) {
	const reps = 10
	tk, _ := NewTask(3, 1, 1, "ap4-revise-prove-l1")
	maskCtxLen := len(tk.MaskCtxFor(1))
	p, err := NewProver(1, maskCtxLen)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	d := tk.MakeDelivery(0)

	prove := make([]float64, reps)
	verify := make([]float64, reps)
	for r := 0; r < reps; r++ {
		t0 := time.Now()
		pf, _, pub, err := p.Prove(tk, d)
		if err != nil {
			t.Fatalf("prove failed: %v", err)
		}
		prove[r] = sinceMs(t0)

		t1 := time.Now()
		if err := p.Verify(pf, pub); err != nil {
			t.Fatalf("verify failed: %v", err)
		}
		verify[r] = sinceMs(t1)
	}

	out := map[string]any{
		"baseline": "C5/B2", "L": 1, "reps": reps, "constraints": p.Constraints(),
		"prove_ms":  statMap(prove),
		"verify_ms": statMap(verify),
		"note":      "setup single-observation (reported separately); prove/verify steady-state here; prove_ms stores milliseconds",
	}
	saveRaw(t, "ap4_revise_prove_verify_L1.json", out)
	t.Logf("C5/B2 L=1 prove median=%.2fs verify median=%.3fms", out["prove_ms"].(map[string]float64)["median"]/1000, out["verify_ms"].(map[string]float64)["median"])
}
