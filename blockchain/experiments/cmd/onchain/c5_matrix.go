// c5_matrix.go runs our scheme over a matrix of server configurations and
// records the verification-phase transaction times used by Table 1.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"c5full/internal/c5/m1"

	"c5full/blockchain/bridge"
	"c5full/blockchain/experiments/analysis/stats"
	"c5full/blockchain/fabric/client/c5"
	"c5full/blockchain/fabric/client/gateway"
)

type c5MatrixRaw struct {
	Schema        string           `json:"schema"`
	ExperimentID  string           `json:"experiment_id"`
	Scheme        string           `json:"scheme"`
	Backend       string           `json:"backend"`
	Config        string           `json:"config"`
	Rep           int              `json:"rep"`
	Phase         string           `json:"phase"`
	Actors        map[string]int   `json:"actors"`
	Profile       string           `json:"profile"`
	Fabric        map[string]any   `json:"fabric"`
	Task          map[string]int   `json:"task"`
	VKHash        string           `json:"vk_hash"`
	TimingNS      map[string]int64 `json:"timing_ns"`
	Bytes         map[string]int   `json:"bytes"`
	Correctness   map[string]any   `json:"correctness"`
	Status        string           `json:"status"`
	FailureReason string           `json:"failure_reason"`
}

var c5SequentialStages = []string{
	"bottom_preprocess", "committed_output", "certificate", "proof_generation",
	"fabric_finalize_tx", "fabric_verify_tx_total", "receiver_query", "receiver_recovery",
}

func runC5Matrix(outDir, configSpec string, reps, warmups int, seed, artifacts,
	samples, org, peer, channel, chaincode string) {

	cfgs, err := parseSAConfigs(configSpec)
	must(err)

	prover, man, err := bridge.LoadFullProverFromDir(artifacts)
	must(err)
	if man.Constraints != 891908 || man.MaskCtxLen != 507 {
		must(fmt.Errorf("canonical profile drift: constraints=%d maskctx=%d", man.Constraints, man.MaskCtxLen))
	}
	verifier, _, err := bridge.LoadVKOnlyVerifierFromDir(artifacts, 1, 507)
	must(err)

	gwCfg, err := gateway.ConfigFromTestNetwork(samples, org, peer, channel, chaincode)
	must(err)
	gw, err := gateway.Connect(gwCfg)
	must(err)
	defer gw.Close()
	be := c5.NewFabricC5(gw)

	fmt.Printf("C5_MATRIX channel=%s chaincode=%s configs=%d reps=%d warmups=%d\n",
		gwCfg.Channel, gwCfg.Chaincode, len(cfgs), reps, warmups)

	fabInfo := map[string]any{
		"version": "2.5.7", "channel": gwCfg.Channel, "chaincode": gwCfg.Chaincode,
		"org": gwCfg.MSPID, "peer": gwCfg.PeerEndpoint,
		"endorsement_policy": "AND('Org1MSP.peer','Org2MSP.peer')",
	}

	rows := []c5MatrixRaw{}
	for _, c := range cfgs {
		cfgReps := reps
		if c.Reps > 0 {
			cfgReps = c.Reps
		}
		total := warmups + cfgReps
		for i := 0; i < total; i++ {
			phase := "measured"
			if i < warmups {
				phase = "warmup"
			}
			repSeed := fmt.Sprintf("%s::%s::rep%d", seed, c.Name, i)
			e := runOne(prover, verifier, man.SHA256VK, c.Servers, c.F, 1, repSeed, i, be, fabInfo,
				m1.BottomBundleOpts{})

			r := c5MatrixRaw{
				Schema: e.Schema, ExperimentID: "C5-MATRIX", Scheme: "C5",
				Backend: e.Backend, Config: c.Name, Rep: i, Phase: phase,
				Actors:      map[string]int{"n_servers": c.Servers, "f": c.F, "l": 1},
				Profile:     e.Profile,
				Fabric:      e.Fabric,
				Task:        map[string]int{"n": c.Servers, "f": c.F, "l": 1},
				VKHash:      e.VKHash,
				TimingNS:    e.TimingNS,
				Bytes:       e.Bytes,
				Correctness: e.Correctness,
				Status:      e.Status, FailureReason: e.FailureReason,
			}
			var seq int64
			for _, s := range c5SequentialStages {
				seq += r.TimingNS[s]
			}
			r.TimingNS["sequential_cpu_work"] = seq
			r.TimingNS["protocol_faithful_wall_clock"] = r.TimingNS["full_response"]
			rows = append(rows, r)

			fmt.Printf("C5_MATRIX %s rep=%d/%s status=%s bottom=%.0fms proof=%.0fms finalize=%.0fms verify=%.0fms query=%.0fms recover=%.0fms wall=%.0fms ok=%v\n",
				c.Name, i, phase, r.Status,
				ms(r.TimingNS["bottom_preprocess"]), ms(r.TimingNS["proof_generation"]),
				ms(r.TimingNS["fabric_finalize_tx"]), ms(r.TimingNS["fabric_verify_tx_total"]),
				ms(r.TimingNS["receiver_query"]), ms(r.TimingNS["receiver_recovery"]),
				ms(r.TimingNS["protocol_faithful_wall_clock"]), r.Correctness["recovered_equals_xy"])
			if r.Status != "PASS" {
				fmt.Fprintf(os.Stderr, "C5_MATRIX FAILED %s rep=%d: %s\n", c.Name, i, r.FailureReason)
				os.Exit(1)
			}
		}
	}
	must(os.MkdirAll(outDir, 0o755))
	writeJSONL(filepath.Join(outDir, "table1_c5_raw.jsonl"), rows)
	writeJSON(filepath.Join(outDir, "table1_c5_summary.json"), summarizeC5Matrix(rows, cfgs, warmups))
	fmt.Printf("C5_MATRIX_OK rows=%d out=%s\n", len(rows), outDir)
}

func summarizeC5Matrix(rows []c5MatrixRaw, cfgs []saMatrixConfig, warmups int) map[string]any {
	perConfig := map[string]any{}
	for _, c := range cfgs {
		pick := func(k string) []int64 {
			out := []int64{}
			for _, r := range rows {
				if r.Config == c.Name && r.Phase == "measured" && r.Status == "PASS" {
					if v, ok := r.TimingNS[k]; ok && v > 0 {
						out = append(out, v)
					}
				}
			}
			return out
		}
		perConfig[c.Name] = map[string]any{
			"n_servers": c.Servers, "f": c.F, "l": 1,
			"sequential_cpu_work_ns":          stats.Summarize(pick("sequential_cpu_work")),
			"protocol_faithful_wall_clock_ns": stats.Summarize(pick("protocol_faithful_wall_clock")),
			"bottom_preprocess_ns":            stats.Summarize(pick("bottom_preprocess")),
			"committed_output_ns":             stats.Summarize(pick("committed_output")),
			"certificate_ns":                  stats.Summarize(pick("certificate")),
			"proof_generation_ns":             stats.Summarize(pick("proof_generation")),
			"fabric_finalize_tx_ns":           stats.Summarize(pick("fabric_finalize_tx")),
			"fabric_verify_tx_total_ns":       stats.Summarize(pick("fabric_verify_tx_total")),
			"fabric_commit_wait_ns":           stats.Summarize(pick("fabric_commit_wait")),
			"receiver_query_ns":               stats.Summarize(pick("receiver_query")),
			"receiver_recovery_ns":            stats.Summarize(pick("receiver_recovery")),
			"measured_reps":                   len(pick("protocol_faithful_wall_clock")),
		}
	}
	ok, passed := 0, 0
	for _, r := range rows {
		passed++
		if r.Status == "PASS" {
			ok++
		}
	}
	return map[string]any{
		"schema":        "c5-blockchain-exp-summary-v1",
		"experiment_id": "C5-MATRIX",
		"scheme":        "C5",
		"backend":       "fabric",
		"scope":         "verification phase of our scheme on a real Fabric 2.5.7 test network",
		"profile":       "C5 (L=1, MaskCtx=507B, constraints=891908)",
		"configs":       configNames(cfgs),
		"warmups":       warmups,
		"rows":          passed,
		"passed":        ok,
		"per_config":    perConfig,
		"two_views": map[string]any{
			"sequential_cpu_work":          "sum of every measured stage",
			"protocol_faithful_wall_clock": "end-to-end wall clock on the real network",
			"must_not_mix":                 true,
		},
		"honesty": map[string]any{
			"real_fabric":        true,
			"stub_is_not_fabric": false,
			"full_chain_per_rep": "each repetition runs MPC, committed output, certificate, Fabric finality, f+1 deliveries with Groth16 proofs, on-chain verification, accepted query and recovery",
			"generate_ms":        "CPU contention from co-locating the client and the network is reported as measured",
		},
		"generated_utc": time.Now().UTC().Format(time.RFC3339),
	}
}
