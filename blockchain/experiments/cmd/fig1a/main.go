// Command fig1a measures the off-chain half of Fig. 1: the cost of verifying one
// delivery's public material in-process, split into proof verification and the
// accompanying commitment check.
//	our scheme   one Groth16 verification of R_del (292 B proof)
//	Gai et al.   w chunk-wise ZKPoC verifications (1024-bit and 3072-bit moduli,
//	             exponent domain P-1) plus the Eq. (18) commitment check
// The chaincode half of Fig. 1 is produced by cmd/fig1b from real Fabric runs.
package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"c5full/internal/mpc/schemea"

	"c5full/blockchain/bridge"
	"c5full/blockchain/experiments/analysis/stats"
	"c5full/blockchain/repro/schemea/paperfixture"
	"c5full/blockchain/tests/harness"
)

var (
	qpcProc *syscall.Proc
	qpcFreq float64
)

func qpcInit() {
	k32, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return
	}
	p, err := k32.FindProc("QueryPerformanceCounter")
	if err != nil {
		return
	}
	f, err := k32.FindProc("QueryPerformanceFrequency")
	if err != nil {
		return
	}
	var freq int64
	r1, _, _ := f.Call(uintptr(unsafe.Pointer(&freq)))
	if r1 == 0 || freq <= 0 {
		return
	}
	qpcFreq = float64(freq)
	qpcProc = p
}

func qpcNow() int64 {
	if qpcProc == nil {
		return time.Now().UnixNano()
	}
	var c int64
	qpcProc.Call(uintptr(unsafe.Pointer(&c)))
	return c
}

func qpcNS(start, end int64) int64 {
	if qpcProc == nil || qpcFreq <= 0 {
		return end - start
	}
	return int64(float64(end-start) / qpcFreq * 1e9)
}

type row struct {
	Scheme      string `json:"scheme"`
	Profile     string `json:"profile"`
	ModulusBits int    `json:"modulus_bits"`
	Security    string `json:"security_label"`
	Metric      string `json:"metric"`
	Rep         int    `json:"rep"`
	ValueNS     int64  `json:"value_ns"`
	ProofBytes  int    `json:"proof_bytes,omitempty"`
	ZKPoCBytes  int    `json:"zkpoc_bytes,omitempty"`
	Chunks      int    `json:"chunks,omitempty"`
	Boundary    string `json:"boundary"`
}

func main() {
	artifacts := flag.String("artifacts", "./artifacts/c5_l1_507", "Groth16 verification key directory")
	c5fx := flag.String("c5-fixture", "./fixtures/c5_l1_507.json", "C5 fixture with a pre-generated delivery proof")
	profiles := flag.String("profiles", "1024,3072", "Gai et al. modulus widths to measure")
	reps := flag.Int("reps", 30, "measured repetitions")
	warmup := flag.Int("warmup", 3, "warmup repetitions (discarded)")
	servers := flag.Int("n", 3, "Gai et al. server count")
	mClients := flag.Int("m", 3, "Gai et al. cooperating clients")
	tShare := flag.Int("t", 2, "Gai et al. secret-sharing threshold")
	outDir := flag.String("out", "./data/fig1a", "output directory")
	flag.Parse()

	qpcInit()
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fail(err)
	}

	rows := measureC5(*artifacts, *c5fx, *reps, *warmup)
	for _, tok := range strings.Split(*profiles, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		bits, err := strconv.Atoi(tok)
		if err != nil {
			fail(fmt.Errorf("bad -profiles token %q", tok))
		}
		rows = append(rows, measureSA(bits, *servers, *mClients, *tShare, *reps, *warmup)...)
	}

	writeRaw(filepath.Join(*outDir, "fig1a_raw.jsonl"), rows)
	sum, csvRows := summarize(rows)
	writeJSON(filepath.Join(*outDir, "fig1a_summary.json"), sum)
	writeCSV(filepath.Join(*outDir, "fig1a_proof_verification.csv"), csvRows)
	fmt.Printf("FIG1A_OK rows=%d out=%s\n", len(rows), *outDir)
	for _, r := range csvRows {
		fmt.Printf("  %-9s %-8s %-18s median=%9.3f ms (n=%s)\n", r[0], r[1], r[2], mustF(r[4]), r[5])
	}
}

func measureC5(artifacts, fixture string, reps, warmup int) []row {
	verifier, man, err := bridge.LoadVKOnlyVerifierFromDir(artifacts, 1, 507)
	if err != nil {
		fail(fmt.Errorf("load verification key: %w", err))
	}
	cfx, err := harness.LoadC5Fixture(fixture)
	if err != nil {
		fail(fmt.Errorf("load C5 fixture: %w", err))
	}
	taskRec, err := cfx.TaskRecord()
	if err != nil {
		fail(err)
	}
	alpha := cfx.CertJSONAlpha()
	pubTask, err := bridge.RebuildPublicTask(taskRec, &alpha)
	if err != nil {
		fail(err)
	}
	d := harness.MustDecodePayload(cfx.Deliveries[0].PayloadHex, taskRec)
	pf, err := verifier.ParseProof(d.Proof)
	if err != nil {
		fail(err)
	}
	pub, err := verifier.PublicWitness(pubTask, d)
	if err != nil {
		fail(err)
	}
	if man.Constraints != 891908 {
		fail(fmt.Errorf("canonical constraint count drifted: %d", man.Constraints))
	}

	out := make([]row, 0, reps)
	for i := 0; i < warmup; i++ {
		if err := verifier.Verify(pf, pub); err != nil {
			fail(fmt.Errorf("C5 warmup verify: %w", err))
		}
	}
	for i := 0; i < reps; i++ {
		t0 := qpcNow()
		if err := verifier.Verify(pf, pub); err != nil {
			fail(fmt.Errorf("C5 verify: %w", err))
		}
		out = append(out, row{
			Scheme: "Our", Profile: "C5", ModulusBits: 381,
			Security: "~128-bit (BLS12-381)", Metric: "proof_verification",
			Rep: i, ValueNS: qpcNS(t0, qpcNow()), ProofBytes: len(d.Proof),
			Boundary: "one Groth16 verification of R_del (in-process, no Fabric)",
		})
	}
	return out
}

func measureSA(bits, servers, mClients, tShare, reps, warmup int) []row {
	pid, ok := schemea.ProfileIDForBits(bits)
	if !ok {
		fail(fmt.Errorf("unsupported modulus width %d (want 1024|2048|3072)", bits))
	}
	security := map[int]string{
		1024: "~80-bit (largest key length in Gai et al.)",
		2048: "~112-bit",
		3072: "~128-bit (security-matched)",
	}[bits]

	pf, err := paperfixture.Build(pid, servers, mClients, tShare,
		big.NewInt(0x1234567), big.NewInt(0x89abcde), "off", fmt.Sprintf("fig1a-sa-%d", bits))
	if err != nil {
		fail(fmt.Errorf("paperfixture(%s): %w", pid, err))
	}
	rec, err := pf.Fixture.TaskRecord()
	if err != nil {
		fail(err)
	}
	sp, err := bridge.SAParamsFromRecord(rec)
	if err != nil {
		fail(err)
	}
	width := pf.Fixture.Width()
	sub0, err := pf.Fixture.Submission(0)
	if err != nil {
		fail(err)
	}
	cts, proofs, err := bridge.DecodeSchemeAOutput(sub0, width)
	if err != nil {
		fail(err)
	}
	order := new(big.Int).Sub(sp.Params.P, big.NewInt(1))
	expected, err := bridge.DecodeSchemeAElement(rec.ExpectedCommitmentsHex[0], width)
	if err != nil {
		fail(err)
	}

	base := row{
		Scheme: "Gai", Profile: fmt.Sprintf("Gai(%d)", bits), ModulusBits: bits,
		Security: security, ZKPoCBytes: pf.Fixture.Outputs[0].ZKPoCBytes, Chunks: pf.Fixture.W,
	}
	out := make([]row, 0, 2*reps)
	for i := 0; i < warmup; i++ {
		if _, err := bridge.VerifyZKPoCsBoundToCiphertexts(sp, cts, proofs, order); err != nil {
			fail(fmt.Errorf("Gai warmup ZKPoC: %w", err))
		}
		if _, err := bridge.VerifyCiphertextsAgainstCommitment(sp.Params, cts, expected); err != nil {
			fail(fmt.Errorf("Gai warmup commitment: %w", err))
		}
	}
	for i := 0; i < reps; i++ {
		t0 := qpcNow()
		if _, err := bridge.VerifyZKPoCsBoundToCiphertexts(sp, cts, proofs, order); err != nil {
			fail(fmt.Errorf("Gai ZKPoC: %w", err))
		}
		r1 := base
		r1.Metric, r1.Rep, r1.ValueNS = "proof_verification", i, qpcNS(t0, qpcNow())
		r1.Boundary = fmt.Sprintf("%d chunk-wise ZKPoC verifications (Eq. 13/14), exponent domain P-1", pf.Fixture.W)
		out = append(out, r1)

		t1 := qpcNow()
		ok, err := bridge.VerifyCiphertextsAgainstCommitment(sp.Params, cts, expected)
		if err != nil {
			fail(fmt.Errorf("Gai commitment: %w", err))
		}
		if !ok {
			fail(fmt.Errorf("Gai commitment mismatch at %d-bit", bits))
		}
		r2 := base
		r2.Metric, r2.Rep, r2.ValueNS = "commitment_check", i, qpcNS(t1, qpcNow())
		r2.Boundary = "Eq. (18) homomorphic commitment equality"
		out = append(out, r2)
	}
	return out
}

type key struct{ scheme, profile, metric string }

func summarize(rows []row) (map[string]any, [][]string) {
	groups := map[key][]int64{}
	meta := map[key]row{}
	order := []key{}
	for _, r := range rows {
		k := key{r.Scheme, r.Profile, r.Metric}
		if _, seen := groups[k]; !seen {
			order = append(order, k)
		}
		groups[k] = append(groups[k], r.ValueNS)
		meta[k] = r
	}
	sum := map[string]any{
		"schema": "c5-fig1a-v1",
		"groups": []any{},
	}
	gs := []any{}
	csvRows := [][]string{}
	for _, k := range order {
		s := stats.Summarize(groups[k])
		m := meta[k]
		gs = append(gs, map[string]any{
			"scheme": k.scheme, "profile": k.profile, "modulus_bits": m.ModulusBits,
			"security_label": m.Security, "metric": k.metric, "boundary": m.Boundary,
			"stat": s, "proof_bytes": m.ProofBytes, "zkpoc_bytes": m.ZKPoCBytes, "chunks": m.Chunks,
		})
		csvRows = append(csvRows, []string{
			k.scheme, k.profile, k.metric, strconv.Itoa(m.ModulusBits),
			fmt.Sprintf("%.6f", float64(s.MedianNS)/1e6), strconv.Itoa(s.N),
			fmt.Sprintf("%.6f", float64(s.MinNS)/1e6), fmt.Sprintf("%.6f", float64(s.MaxNS)/1e6),
			m.Security, m.Boundary,
		})
	}
	sum["groups"] = gs
	return sum, csvRows
}

func writeCSV(path string, rows [][]string) {
	f, err := os.Create(path)
	if err != nil {
		fail(err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	_ = w.Write([]string{"scheme", "profile", "metric", "modulus_bits", "median_ms",
		"reps", "min_ms", "max_ms", "security_label", "boundary"})
	for _, r := range rows {
		_ = w.Write(r)
	}
}

func writeRaw(path string, rows []row) {
	f, err := os.Create(path)
	if err != nil {
		fail(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, r := range rows {
		if err := enc.Encode(r); err != nil {
			fail(err)
		}
	}
}

func writeJSON(path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fail(err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		fail(err)
	}
}

func mustF(s string) float64 { v, _ := strconv.ParseFloat(s, 64); return v }

func fail(err error) {
	fmt.Fprintf(os.Stderr, "FIG1A_FAILED: %v\n", err)
	os.Exit(1)
}
