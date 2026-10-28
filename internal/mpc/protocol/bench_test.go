package protocol

// OPEN-EVIDENCE-01 / AP4-style benchmarks for the repaired complete-MPC
// pipeline (Scheme A route). Measures the phases that the comparison of
// "complete MPC → private output delivery → client recovery" focuses on:
//	client-side recovery cost & recovery communication (the H1 receiver/client
//	axis from AP4-REVISE), private-output delivery (server encrypt), and the
//	communication the client must fetch.

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"c5full/internal/mpc/mpccore"
	"c5full/internal/mpc/params"
	"c5full/internal/mpc/schemea"
)

func st(xs []int64) map[string]float64 {
	f := make([]float64, len(xs))
	for i, v := range xs {
		f[i] = float64(v)
	}
	sort.Float64s(f)
	sum := 0.0
	for _, v := range f {
		sum += v
	}
	n := len(f)
	med := f[n/2]
	if n%2 == 0 {
		med = (f[n/2-1] + f[n/2]) / 2
	}
	return map[string]float64{"median_ms": med, "mean_ms": sum / float64(n)}
}

func saveJSON(t *testing.T, rel string, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	p := filepath.Join("..", "..", "raw", rel)
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.WriteFile(p, b, 0o644)
	t.Logf("saved raw/%s", rel)
}

// TestBenchCompleteMPC runs the repaired Scheme-A pipeline and records
// per-phase latency + communication, saving raw JSON for the comparison.
func TestBenchCompleteMPC(t *testing.T) {
	const reps = 5
	n, thr := 3, 2 // t = f+1
	eg := schemea.NewEx(params.GMOD, 256, 32, 42)
	grp := mpccore.NewParams(eg.P, eg.G, eg.H, thr, n)

	x := big.NewInt(123456789)
	y := big.NewInt(987654321)

	dists := make([]int64, reps)
	muls := make([]int64, reps)
	vers := make([]int64, reps)
	encs := make([]int64, reps)
	recs := make([]int64, reps)
	var cbytes, vbytes, rbytes int

	for r := 0; r < reps; r++ {
		cli := grp.NewClient(x, y, int64(20260908+r))
		tr := cli.MakeTriple(int64(20260908 + r))

		t0 := time.Now()
		srvs := make([]*mpccore.ServerNode, thr)
		for i := 0; i < thr; i++ {
			srvs[i] = cli.BuildServer(i, tr)
		}
		dists[r] = time.Since(t0).Milliseconds()

		t1 := time.Now()
		idcs := make([]*big.Int, thr)
		dv := make([]*big.Int, thr)
		ev := make([]*big.Int, thr)
		for i := 0; i < thr; i++ {
			bl := srvs[i].Reveal()
			idcs[i] = big.NewInt(int64(bl.Idx + 1))
			dv[i] = bl.Di
			ev[i] = bl.Ei
		}
		d := reconstruct(idcs, dv)
		e := reconstruct(idcs, ev)
		mrs := make([]*mpccore.MulResult, thr)
		for i := 0; i < thr; i++ {
			mrs[i] = srvs[i].LocalMulPublic(tr, cli.GetPdel(), d, e)
		}
		muls[r] = time.Since(t1).Milliseconds()

		t2 := time.Now()
		ok, _ := cli.VerifyMul(tr, srvs, d, e)
		if !ok {
			t.Fatalf("VerifyMul failed at rep %d", r)
		}
		vers[r] = time.Since(t2).Milliseconds()

		t3 := time.Now()
		cts := make([][]*schemea.Ciphertext, thr)
		for i := 0; i < thr; i++ {
			c, _ := eg.EncryptShare(mrs[i].Zi, mrs[i].ZBlind)
			cts[i] = c
		}
		encs[r] = time.Since(t3).Milliseconds()

		t4 := time.Now()
		zvals := make([]*big.Int, thr)
		for i := 0; i < thr; i++ {
			zvals[i] = eg.RecoverShare(cts[i])
		}
		res := reconstruct(idcs, zvals)
		recs[r] = time.Since(t4).Milliseconds()

		geb := eg.NumChunks * 3 * ((eg.PrimeBits + 7) / 8)
		cbytes = thr * geb
		geb2 := eg.NumChunks*2*((eg.PrimeBits+7)/8) + eg.NumChunks*4*((eg.PrimeBits+7)/8)
		vbytes = thr * geb2
		rbytes = thr * 2 * ((eg.PrimeBits + 7) / 8)
		_ = res
	}

	out := map[string]any{
		"baseline": "SchemeA-complete-MPC (repaired)",
		"group":    "P=2*GMOD+1 safe prime, subgroup order GMOD (256-bit)",
		"n":        n, "threshold_t": thr,
		"reps": reps,
		"client_recovery_ms":        st(recs),
		"server_encrypt_ms":         st(encs),
		"server_multiply_ms":        st(muls),
		"public_verify_ms":          st(vers),
		"client_vss_distribute_ms":  st(dists),
		"client_recovery_bytes":     cbytes,
		"server_to_verifier_bytes":  vbytes,
		"reveal_bytes":              rbytes,
		"note": "client recovery is t x Lifted-ElGamal decrypt + BSGS DLOG + recompose + Shamir (H1 axis)",
	}
	saveJSON(t, "mpc_complete_bench.json", out)
	t.Logf("MPC recovery median=%.2fms encrypt=%.2fms ClientRecoverBytes=%d ServerToVerifierBytes=%d",
		out["client_recovery_ms"].(map[string]float64)["median_ms"],
		out["server_encrypt_ms"].(map[string]float64)["median_ms"], cbytes, vbytes)
}

// reconstruct uses the same Lagrange interpolation as vss.Reconstruct over Z_GMOD.
func reconstruct(idcs, vals []*big.Int) *big.Int {
	sum := big.NewInt(0)
	for i := range idcs {
		l := lag(idcs, i)
		t := new(big.Int).Mul(l, vals[i])
		sum.Add(sum, t).Mod(sum, params.GMOD)
	}
	return sum
}

func lag(xs []*big.Int, i int) *big.Int {
	acc := big.NewInt(1)
	for l, xl := range xs {
		if l == i {
			continue
		}
		num := new(big.Int).Neg(xl)
		num.Mod(num, params.GMOD)
		den := new(big.Int).Sub(xs[i], xl)
		den.Mod(den, params.GMOD)
		inv := new(big.Int).ModInverse(den, params.GMOD)
		acc.Mul(acc, num).Mul(acc, inv).Mod(acc, params.GMOD)
	}
	return acc
}