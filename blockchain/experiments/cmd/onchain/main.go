// Command onchain runs the Fabric-backed experiments: Fig. 1(b) chaincode
// verification, Table 1 cumulative transaction times, and the end-to-end task
// comparison. Every run submits real transactions to a live Fabric network.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"c5full/internal/c5/m1"
	"c5full/internal/c5/params"

	"c5full/blockchain/bridge"
	"c5full/blockchain/experiments/analysis/stats"
	"c5full/blockchain/experiments/backend"
	"c5full/blockchain/fabric/chaincode/model"
	"c5full/blockchain/fabric/client/c5"
	"c5full/blockchain/fabric/client/gateway"
	"c5full/blockchain/tests/harness"
)

const schema = "c5-blockchain-exp-v1"

func peakRSSMB() float64 {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "VmHWM:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				kb, err := strconv.ParseInt(f[1], 10, 64)
				if err == nil {
					return float64(kb) / 1024.0
				}
			}
		}
	}
	return -1
}

type e2eRaw struct {
	Schema       string `json:"schema"`
	ExperimentID string `json:"experiment_id"`
	Scheme       string `json:"scheme"`
	Backend      string `json:"backend"`
	Rep          int    `json:"rep"`
	Profile      string `json:"profile"`
	Task         struct {
		N int `json:"n"`
		F int `json:"f"`
		L int `json:"l"`
	} `json:"task"`
	Fabric         map[string]any   `json:"fabric"`
	NetworkProfile string           `json:"network_profile"`
	SourceHash     string           `json:"source_hash"`
	BlockchainHash string           `json:"blockchain_source_hash"`
	VKHash         string           `json:"vk_hash"`
	TimingNS       map[string]int64 `json:"timing_ns"`
	Bytes          map[string]int   `json:"bytes"`
	Correctness    map[string]any   `json:"correctness"`
	Status         string           `json:"status"`
	FailureReason  string           `json:"failure_reason"`
	MeasurementTag string           `json:"measurement_status"`
}

func main() {
	fs := flag.NewFlagSet("onchain", flag.ExitOnError)
	artifacts := fs.String("artifacts", "./artifacts/c5_l1_507", "Groth16 setup directory (needs pk.bin)")
	outDir := fs.String("out", "./data/onchain", "output directory")
	reps := fs.Int("reps", 10, "measured repetitions")
	backendKind := fs.String("backend", "stub", "stub | fabric")
	n := fs.Int("n", 3, "server count")
	f := fs.Int("f", 1, "fault tolerance")
	l := fs.Int("l", 1, "output dimension")
	seed := fs.String("seed", "onchain-v1", "deterministic seed")
	samples := fs.String("samples", defaultSamplesDir(), "fabric-samples root (needed for -backend fabric)")
	org := fs.String("org", "1", "organization: 1 | 2")
	peer := fs.String("peer", "localhost:7051", "peer endpoint")
	channel := fs.String("channel", "mychannel", "Fabric channel")
	chaincode := fs.String("chaincode", "c5bc", "chaincode name")
	schemeKind := fs.String("scheme", "c5", "c5 | schemea")
	threshold := fs.Int("t", 2, "Gai et al. secret-sharing threshold")
	mClients := fs.Int("m", 2, "Gai et al. cooperating clients, the base of the Eq. (20) product")
	configs := fs.String("configs", "", "server matrix such as n3_f1,n5_f2,n9_f4; enables matrix mode")
	saProfile := fs.Int("sa-profile", 3072, "Gai et al. modulus width: 1024|2048|3072")
	warmups := fs.Int("warmups", 2, "warmup repetitions discarded from statistics")
	exp := fs.String("exp", "", "empty = task end-to-end; e2e01 = staged measurement")
	_ = fs.Parse(os.Args[1:])

	if *schemeKind == "schemea" {
		if *backendKind != "fabric" {
			fmt.Fprintf(os.Stderr, "the Gai et al. path requires -backend fabric, got %q\n", *backendKind)
			os.Exit(2)
		}
		if *configs != "" {
			runSchemeAMatrix(*outDir, *configs, *reps, *warmups, *mClients, *saProfile, *seed,
				*samples, *org, *peer, *channel, *chaincode)
			return
		}
		runSchemeAE2E(*outDir, *reps, *n, *mClients, *threshold, *seed,
			*samples, *org, *peer, *channel, *chaincode)
		return
	}
	if *schemeKind != "c5" {
		fmt.Fprintf(os.Stderr, "unknown scheme %q (want c5|schemea)\n", *schemeKind)
		os.Exit(2)
	}

	if *exp != "" {
		fmt.Fprintf(os.Stderr, "unknown -exp %q (no staged experiments remain)\n", *exp)
		os.Exit(2)
	}

	if *configs != "" {
		if *backendKind != "fabric" {
			fmt.Fprintf(os.Stderr, "the matrix mode requires -backend fabric, got %q\n", *backendKind)
			os.Exit(2)
		}
		runC5Matrix(*outDir, *configs, *reps, *warmups, *seed, *artifacts,
			*samples, *org, *peer, *channel, *chaincode)
		return
	}

	prover, man, err := bridge.LoadFullProverFromDir(*artifacts)
	must(err)
	if man.Constraints != 891908 || man.MaskCtxLen != 507 {
		must(fmt.Errorf("canonical profile drift"))
	}
	verifier, _, err := bridge.LoadVKOnlyVerifierFromDir(*artifacts, 1, 507)
	must(err)

	var (
		be      backend.C5Backend
		fabInfo map[string]any
	)
	if *backendKind == "fabric" {
		cfg, err := gateway.ConfigFromTestNetwork(*samples, *org, *peer, *channel, *chaincode)
		must(err)
		gw, err := gateway.Connect(cfg)
		must(err)
		defer gw.Close()
		be = c5.NewFabricC5(gw)
		fabInfo = map[string]any{
			"version": "2.5.7", "channel": cfg.Channel, "chaincode": cfg.Chaincode,
			"org": cfg.MSPID, "peer": cfg.PeerEndpoint,
			"endorsement_policy": "AND('Org1MSP.peer','Org2MSP.peer')",
		}
		fmt.Printf("ONCHAIN backend=fabric channel=%s chaincode=%s peer=%s\n",
			cfg.Channel, cfg.Chaincode, cfg.PeerEndpoint)
	} else if *backendKind != "stub" {
		fmt.Fprintf(os.Stderr, "unknown backend %q (want stub|fabric)\n", *backendKind)
		os.Exit(2)
	}

	rows := []e2eRaw{}
	for rep := 0; rep < *reps; rep++ {
		r := runOne(prover, verifier, man.SHA256VK, *n, *f, *l,
			fmt.Sprintf("%s::rep%d", *seed, rep), rep, be, fabInfo, m1.BottomBundleOpts{})
		rows = append(rows, r)
		fmt.Printf("ONCHAIN rep=%d status=%s total=%.1fms prove=%.1fms verify=%.1fms recovery_ok=%v\n",
			rep, r.Status, ms(r.TimingNS["full_response"]), ms(r.TimingNS["proof_generation"]),
			ms(r.TimingNS["fabric_verify_tx_total"]), r.Correctness["recovered_equals_xy"])
	}
	must(os.MkdirAll(*outDir, 0o755))
	writeJSONL(filepath.Join(*outDir, "e2e_c5_raw.jsonl"), rows)
	writeJSON(filepath.Join(*outDir, "e2e_c5_summary.json"), summarize(rows, *backendKind))
	fmt.Printf("ONCHAIN_OK reps=%d backend=%s out=%s\n", len(rows), *backendKind, *outDir)
	for _, r := range rows {
		if r.Status != "PASS" {
			os.Exit(1)
		}
	}
}

func defaultSamplesDir() string {
	if v := os.Getenv("FABRIC_SAMPLES_DIR"); v != "" {
		return v
	}
	return "./third_party/fabric-samples"
}

func copyFabricInfo(src map[string]any) map[string]any {
	out := make(map[string]any, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func runOne(prover, verifier *m1.Prover, vkHash string, n, f, l int, seed string, rep int,
	beIn backend.C5Backend, fabInfo map[string]any, bopts m1.BottomBundleOpts) e2eRaw {
	useFabric := beIn != nil
	r := e2eRaw{
		Schema: schema, ExperimentID: "E2E-C5", Scheme: "C5",
		Backend: "in-process-stub", Rep: rep,
		Profile:        "C5-BC-1 (L=1, MaskCtx=507B, constraints=891908)",
		NetworkProfile: "LOCAL(in-process stub)",
		VKHash:         vkHash,
		TimingNS:       map[string]int64{},
		Bytes:          map[string]int{},
		Correctness:    map[string]any{},
		MeasurementTag: "MEASURED(stub ledger)",
		Fabric:         map[string]any{},
	}
	if useFabric {
		r.Backend = "fabric"
		r.NetworkProfile = "LOCAL(client and network co-located; no client-link simulation)"
		r.MeasurementTag = "MEASURED(on real Fabric 2.5.7, fabric-gateway)"
		r.Fabric = copyFabricInfo(fabInfo)
	}
	r.Task.N, r.Task.F, r.Task.L = n, f, l

	fullStart := time.Now()
	x, y := big.NewInt(0x1234567+int64(rep)), big.NewInt(0x89abcde-int64(rep))
	t0 := time.Now()
	baseRNG := harness.NewHashSeedReader("onchain::e2e::" + seed)
	bundle, tr, bt, nonDeg, err := m1.ComposeBundleTimed(n, f, x, y, baseRNG, bopts)
	if err != nil {
		r.Status, r.FailureReason = "FAILED", "mpc: "+err.Error()
		return r
	}
	r.TimingNS["bottom_preprocess"] = time.Since(t0).Nanoseconds()
	r.TimingNS["bottom_input_share"] = bt.InputShareNS
	r.TimingNS["bottom_triple_prep"] = bt.TriplePrepNS
	r.TimingNS["bottom_online_mul"] = bt.OnlineMulNS()
	r.TimingNS["bottom_bundle"] = bt.BundleNS
	r.Correctness["beaver_non_degenerate"] = nonDeg
	r.Correctness["beaver_faithful_requested"] = bopts.FaithfulBeaver

	t1 := time.Now()
	if bad := m1.VerifyBundleInvariant(bundle); bad != -1 {
		r.Status, r.FailureReason = "FAILED", fmt.Sprintf("bundle invariant violated at %d", bad)
		return r
	}
	r.TimingNS["committed_output"] = time.Since(t1).Nanoseconds()
	if tr != nil {
		h := tr.Hash()
		r.Correctness["bottom_trace_sha256"] = hex.EncodeToString(h[:])
	}

	t2 := time.Now()
	cfg := m1.ReceiverConfig{ReceiverX: big.NewInt(0xE2E0), Authorized: true, MakeSyntheticPoP: true}
	tk, err := m1.NewTaskFromCommittedOutput(bundle, cfg, harness.NewHashSeedReader("onchain::rcv::"+seed))
	if err != nil {
		r.Status, r.FailureReason = "FAILED", "adapter_reject: "+err.Error()
		return r
	}
	r.TimingNS["certificate"] = time.Since(t2).Nanoseconds()
	r.Correctness["maskctx_len"] = len(tk.MaskCtxFor(1))
	r.Correctness["constraints"] = prover.Constraints()
	if len(tk.MaskCtxFor(1)) != 507 || prover.Constraints() != 891908 {
		r.Status, r.FailureReason = "FAILED", "canonical drift (maskctx/constraints)"
		return r
	}

	tk.EndorseAll()
	certIdx := make([]int, 0, n-f)
	for i := 0; i < n-f; i++ {
		certIdx = append(certIdx, i)
	}
	cert, err := bridge.CertificateFromTask(tk, certIdx)
	must(err)
	cert.TaskID = fmt.Sprintf("onchain-%s", seed)

	taskRec, err := bridge.PublicTaskRecordFromTask(tk, cert.TaskID, "c5-l1-507", vkHash, 507, 891908)
	must(err)

	ctx := context.Background()
	be := beIn
	if be == nil {
		led := harness.NewMemLedger()
		be = backend.NewStubC5(led, verifier)
	}
	t3 := time.Now()
	regRep, err := be.RegisterC5Task(ctx, taskRec)
	if err != nil {
		r.Status, r.FailureReason = "FAILED", "register: "+err.Error()
		return r
	}
	finRep, err := be.FinalizeC5State(ctx, cert.TaskID, cert)
	if err != nil {
		r.Status, r.FailureReason = "FAILED", "finalize: "+err.Error()
		return r
	}
	r.TimingNS["fabric_finalize_tx"] = time.Since(t3).Nanoseconds()
	if useFabric {
		tt := be.TimingOf(finRep)
		r.TimingNS["fabric_commit_wait"] = tt.CommitStatusWaitNS
		r.TimingNS["fabric_endorsement_wait"] = tt.EndorsementWaitNS
		r.Fabric["tx_id"] = finRep.TxID
		r.Fabric["block_number"] = finRep.BlockNum
		r.Fabric["register_tx_id"] = regRep.TxID
		r.Fabric["register_block_number"] = regRep.BlockNum
	}
	_ = finRep

	deliveries := make([]*m1.Delivery, 0, f+1)
	ds := map[int]*m1.Delivery{}
	t4 := time.Now()
	var tDeliveryOnly, tProveOnly, tSignOnly int64
	for i := 0; i < f+1; i++ {
		td := time.Now()
		d := tk.MakeDeliveryWithRNG(i, harness.NewHashSeedReader(fmt.Sprintf("onchain::%s::del:%d", seed, i)))
		tDeliveryOnly += time.Since(td).Nanoseconds()
		tp := time.Now()
		_, pb, _, err := prover.Prove(tk, d)
		tProveOnly += time.Since(tp).Nanoseconds()
		if err != nil {
			r.Status, r.FailureReason = "FAILED", "prove: "+err.Error()
			return r
		}
		d.Proof = pb
		d.HasProof = true
		d.Sig = nil
		ts := time.Now()
		tk.SignWithProof(d)
		tSignOnly += time.Since(ts).Nanoseconds()
		deliveries = append(deliveries, d)
		ds[d.I] = d
	}
	r.TimingNS["proof_generation"] = time.Since(t4).Nanoseconds()
	r.TimingNS["server_prove"] = tProveOnly
	r.TimingNS["server_delivery_other"] = tDeliveryOnly + tSignOnly
	r.Bytes["proof_bytes_per_delivery"] = len(deliveries[0].Proof)
	r.TimingNS["delivery"] = r.TimingNS["proof_generation"]

	t5 := time.Now()
	var lastVerifyTiming backend.Timing
	verifyTxIDs := make([]string, 0, f+1)
	verifyTxEndorse := make([]int64, 0, f+1)
	verifyTxCommit := make([]int64, 0, f+1)
	verifyTxTotal := make([]int64, 0, f+1)
	for _, d := range deliveries {
		payload, err := model.CanonicalDeliveryBytes(d.I+1,
			hex.EncodeToString(pointBytes(d)), hexC(d.C), hex.EncodeToString(d.Sig), hex.EncodeToString(d.Proof))
		if err != nil {
			r.Status, r.FailureReason = "FAILED", "payload: "+err.Error()
			return r
		}
		vRep, err := be.VerifyC5Delivery(ctx, cert.TaskID, hex.EncodeToString(payload))
		if err != nil {
			r.Status, r.FailureReason = "FAILED", "verify_tx: "+err.Error()
			return r
		}
		lastVerifyTiming = be.TimingOf(vRep)
		verifyTxIDs = append(verifyTxIDs, vRep.TxID)
		verifyTxEndorse = append(verifyTxEndorse, lastVerifyTiming.EndorsementWaitNS)
		verifyTxCommit = append(verifyTxCommit, lastVerifyTiming.CommitStatusWaitNS)
		verifyTxTotal = append(verifyTxTotal, lastVerifyTiming.TotalNS)
	}
	r.TimingNS["fabric_verify_tx_total"] = time.Since(t5).Nanoseconds()
	r.TimingNS["verify_del"] = r.TimingNS["fabric_verify_tx_total"]
	if useFabric {
		r.TimingNS["fabric_verify_endorsement_wait"] = lastVerifyTiming.EndorsementWaitNS
		r.TimingNS["fabric_verify_commit_wait"] = lastVerifyTiming.CommitStatusWaitNS
		r.Fabric["verify_tx_ids"] = verifyTxIDs
		r.Fabric["verify_tx_endorsement_ns"] = verifyTxEndorse
		r.Fabric["verify_tx_commit_ns"] = verifyTxCommit
		r.Fabric["verify_tx_total_ns"] = verifyTxTotal
	}

	t6 := time.Now()
	rep2, err := be.QueryC5AcceptedDeliveries(ctx, cert.TaskID)
	if err != nil {
		r.Status, r.FailureReason = "FAILED", "query: "+err.Error()
		return r
	}
	r.TimingNS["receiver_query"] = time.Since(t6).Nanoseconds()
	var q struct {
		Count   int   `json:"count"`
		Indices []int `json:"indices"`
	}
	must(json.Unmarshal(rep2.Raw, &q))
	t7 := time.Now()
	rr := tk.Recover(ds)
	r.TimingNS["receiver_recovery"] = time.Since(t7).Nanoseconds()
	recoveredOK := false
	if rr.IsOK() {
		vals := rr.Value.([]*big.Int)
		exp := new(big.Int).Mod(new(big.Int).Mul(x, y), params.Q)
		recoveredOK = len(vals) == 1 && vals[0].Cmp(exp) == 0
		r.Correctness["recovered_hex"] = hex.EncodeToString(vals[0].Bytes())
		r.Correctness["expected_xy_mod_q_hex"] = hex.EncodeToString(exp.Bytes())
	}
	r.Correctness["recovered_equals_xy"] = recoveredOK
	r.Correctness["accepted_distinct"] = q.Count
	r.Correctness["accepted_indices"] = q.Indices
	r.Correctness["f_plus_1_satisfied"] = q.Count >= f+1
	r.Correctness["ledger_finality_alpha"] = cert.AlphaHex

	r.TimingNS["full_response"] = time.Since(fullStart).Nanoseconds()
	r.TimingNS["offline_preprocess"] = r.TimingNS["bottom_triple_prep"]
	r.TimingNS["online_total_excluding_preprocess"] =
		r.TimingNS["full_response"] - r.TimingNS["bottom_triple_prep"]
	r.Bytes["peak_rss_mb"] = int(peakRSSMB())
	if recoveredOK && q.Count >= f+1 {
		r.Status = "PASS"
	} else {
		r.Status, r.FailureReason = "FAILED", "recovery/threshold mismatch"
	}
	return r
}

func summarize(rows []e2eRaw, backendKind string) map[string]any {
	key := func(k string) []int64 {
		out := []int64{}
		for _, r := range rows {
			if r.Status == "PASS" {
				out = append(out, r.TimingNS[k])
			}
		}
		return out
	}
	stages := []string{"bottom_preprocess", "committed_output", "certificate", "proof_generation",
		"fabric_finalize_tx", "fabric_verify_tx_total", "receiver_query", "receiver_recovery", "full_response"}
	sum := map[string]any{}
	for _, s := range stages {
		sum[s] = stats.Summarize(key(s))
	}
	ok := 0
	for _, r := range rows {
		if r.Status == "PASS" {
			ok++
		}
	}
	scope := "blockchain-backed end-to-end on a stub ledger"
	honesty := map[string]any{
		"stub_is_not_fabric": true,
		"commit_wait":        "not applicable on the stub backend",
		"receiver_recovery":  "receiver-side mask derivation and Shamir reconstruction (local computation)",
	}
	if backendKind == "fabric" {
		scope = "blockchain-backed end-to-end on a real Fabric 2.5.7 test network"
		honesty = map[string]any{
			"stub_is_not_fabric":      false,
			"real_fabric":             true,
			"commit_wait":             "measured client-side; the orderer batch timeout (2 s) dominates",
			"receiver_recovery":       "receiver-side mask derivation and Shamir reconstruction (local computation)",
			"prover_excluded_from_tx": "Groth16 proving runs on the client and is reported as proof_generation, not as a Fabric phase",
		}
	}
	return map[string]any{
		"schema":        "c5-blockchain-exp-summary-v1",
		"experiment_id": "E2E-C5",
		"backend":       backendKind,
		"scope":         scope,
		"reps":          len(rows),
		"passed":        ok,
		"stages":        sum,
		"setup_accounting": map[string]any{
			"setup_separate": true,
			"note":           "setup is not part of per-transaction latency; artifacts are described in artifacts/c5_l1_507/manifest.json",
		},
		"honesty": honesty,
	}
}

func ms(ns int64) float64 { return float64(ns) / 1e6 }

func writeJSON(path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	must(err)
	must(os.MkdirAll(filepath.Dir(path), 0o755))
	must(os.WriteFile(path, append(b, '\n'), 0o644))
}

func writeJSONL[T any](path string, rows []T) {
	must(os.MkdirAll(filepath.Dir(path), 0o755))
	f, err := os.Create(path)
	must(err)
	defer f.Close()
	for _, r := range rows {
		b, err := json.Marshal(r)
		must(err)
		if _, err := f.Write(append(b, '\n')); err != nil {
			must(err)
		}
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "onchain: %v\n", err)
		os.Exit(1)
	}
}

func pointBytes(d *m1.Delivery) []byte {
	b := make([]byte, 33)
	b[0] = 0x02
	if d.R.Y.BigInt(new(big.Int)).Bit(0) == 1 {
		b[0] = 0x03
	}
	d.R.X.BigInt(new(big.Int)).FillBytes(b[1:])
	return b
}

func hexC(c []*big.Int) []string {
	out := make([]string, len(c))
	for i, x := range c {
		b := make([]byte, 32)
		new(big.Int).Mod(x, params.Q).FillBytes(b)
		out[i] = hex.EncodeToString(b)
	}
	return out
}
