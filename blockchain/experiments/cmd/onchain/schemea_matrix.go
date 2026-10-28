//
//	→ ZKPoC
//	sequential_cpu_work      = Σ_i(server_i processing + verify) + register + decrypt + reconstruct
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	schemeacore "c5full/internal/mpc/schemea"

	"c5full/blockchain/experiments/analysis/stats"
	"c5full/blockchain/experiments/backend"
	"c5full/blockchain/fabric/client/gateway"
	schemeaclient "c5full/blockchain/fabric/client/schemea"
	"c5full/blockchain/repro/schemea/paperfixture"
)

type saMatrixConfig struct {
	Name       string // "n3_f1"
	Servers    int    // n_servers
	F          int    // f
	TShareInit int
	Reps int
}

func parseSAConfigs(spec string) ([]saMatrixConfig, error) {
	out := []saMatrixConfig{}
	for _, raw := range strings.Split(spec, ",") {
		tok := strings.TrimSpace(raw)
		if tok == "" {
			continue
		}
		name, reps := tok, 0
		if i := strings.Index(tok, ":"); i >= 0 {
			name = strings.TrimSpace(tok[:i])
			if _, err := fmt.Sscanf(strings.TrimSpace(tok[i+1:]), "%d", &reps); err != nil {
				return nil, fmt.Errorf("bad reps in %q (want nN_fF:REPS)", tok)
			}
			if reps < 1 {
				return nil, fmt.Errorf("bad reps in %q: need >= 1", tok)
			}
		}
		var n, f int
		if _, err := fmt.Sscanf(name, "n%d_f%d", &n, &f); err != nil {
			return nil, fmt.Errorf("bad config %q (want nN_fF)", tok)
		}
		if n < 1 || f < 1 || f >= n {
			return nil, fmt.Errorf("bad config %q: need 1 <= f < n", tok)
		}
		out = append(out, saMatrixConfig{Name: name, Servers: n, F: f, TShareInit: f + 1, Reps: reps})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty config list")
	}
	return out, nil
}

type saMatrixRaw struct {
	Schema         string           `json:"schema"`
	ExperimentID   string           `json:"experiment_id"`
	Scheme         string           `json:"scheme"`
	Backend        string           `json:"backend"`
	Config         string           `json:"config"`
	Rep            int              `json:"rep"`
	Phase          string           `json:"phase"` // warmup | measured
	DecryptionMode string           `json:"decryption_mode"`
	Actors         map[string]int   `json:"actors"`
	Profile        string           `json:"profile"`
	NetworkProfile string           `json:"network_profile"`
	Fabric         map[string]any   `json:"fabric"`
	TimingNS       map[string]int64 `json:"timing_ns"`
	Bytes          map[string]int   `json:"bytes"`
	Correctness    map[string]any   `json:"correctness"`
	Status         string           `json:"status"`
	FailureReason  string           `json:"failure_reason"`
	MeasurementTag string           `json:"measurement_status"`
}

func runSchemeAMatrix(outDir, configSpec string, reps, warmups, mClients int, saBits int, seed string,
	samples, org, peer, channel, chaincode string) {
	cfgs, err := parseSAConfigs(configSpec)
	must(err)

	pid, ok := schemeacore.ProfileIDForBits(saBits)
	if !ok {
		must(fmt.Errorf("unsupported -sa-profile bits=%d (want 256|1024|2048|3072)", saBits))
	}
	profileDesc := fmt.Sprintf("%s (%d-bit, k=256, p=32, w=8) — SA-REGISTERED + SA-PAPER-DECRYPT", pid, saBits)

	cfg, err := gateway.ConfigFromTestNetwork(samples, org, peer, channel, chaincode)
	must(err)
	gw, err := gateway.Connect(cfg)
	must(err)
	defer gw.Close()
	sa := schemeaclient.NewFabricSchemeA(gw)

	fmt.Printf("BC-FINAL-MATRIX-SA backend=fabric channel=%s chaincode=%s configs=%d m_clients=%d reps=%d warmups=%d decrypt=SA-PAPER-DECRYPT sa_profile=%s\n",
		cfg.Channel, cfg.Chaincode, len(cfgs), mClients, reps, warmups, profileDesc)

	fabInfo := map[string]any{
		"version": "2.5.7", "channel": cfg.Channel, "chaincode": cfg.Chaincode,
		"org": cfg.MSPID, "peer": cfg.PeerEndpoint,
		"endorsement_policy": "AND('Org1MSP.peer','Org2MSP.peer')",
	}

	rows := []saMatrixRaw{}
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
			r := runSchemeAMatrixOne(sa, fabInfo, c, mClients, pid, profileDesc, seed, i, phase)
			rows = append(rows, r)
			fmt.Printf("BC-FINAL-MATRIX-SA %s rep=%d/%s status=%s reg=%.0fms per_tx=(%s) query=%.1fms eq20=%.0fms eq22=%.1fms wall=%.0fms cpuwork=%.0fms partials=%v/%v z_ok=%v\n",
				c.Name, i, phase, r.Status,
				ms(r.TimingNS["fabric_register_tx"]), perTxJoin(r.TimingNS, c.Servers),
				ms(r.TimingNS["sa_accepted_query"]),
				ms(r.TimingNS["client_decrypt_eq20_dlog_recompose"]),
				ms(r.TimingNS["output_reconstruction_eq22"]),
				ms(r.TimingNS["protocol_faithful_wall_clock"]),
				ms(r.TimingNS["sequential_cpu_work"]),
				r.Actors["number_of_decrypt_partials"], r.Actors["m_clients"],
				r.Correctness["reconstruction_ok"])
			if r.Status != "PASS" {
				fmt.Fprintf(os.Stderr, "BC-FINAL-MATRIX-SA FAILED %s rep=%d: %s\n", c.Name, i, r.FailureReason)
				os.Exit(1)
			}
		}
	}
	writeJSONL(filepath.Join(outDir, "table1_gai_raw.jsonl"), rows)
	writeJSON(filepath.Join(outDir, "table1_gai_summary.json"),
		summarizeSAMatrix(rows, cfgs, reps, warmups, mClients, profileDesc))
	fmt.Printf("BC_FINAL_MATRIX_SA_OK rows=%d out=%s\n", len(rows), outDir)
}

func perTxJoin(t map[string]int64, n int) string {
	parts := []string{}
	for i := 0; i < n; i++ {
		k := fmt.Sprintf("server_tx_%d", i+1)
		if v, ok := t[k]; ok {
			parts = append(parts, fmt.Sprintf("%.0f", ms(v)))
		}
	}
	return strings.Join(parts, "/")
}

func runSchemeAMatrixOne(sa *schemeaclient.FabricSchemeA, fabInfo map[string]any,
	c saMatrixConfig, mClients int, pid schemeacore.ProfileID, profileDesc, seed string, rep int, phase string) saMatrixRaw {
	r := saMatrixRaw{
		Schema: "c5-blockchain-exp-v1", ExperimentID: "BC-EXP-03-SA-CORRECTED", Scheme: "SchemeA",
		Backend: "fabric", Config: c.Name, Rep: rep, Phase: phase,
		DecryptionMode: "SA-PAPER-DECRYPT",
		Actors: map[string]int{
			"n_servers": c.Servers, "t_secret_sharing": c.TShareInit, "m_clients": mClients,
			"number_of_decrypt_partials": 0,
		},
		Profile:        profileDesc,
		NetworkProfile: "LOCAL(client and network co-located; no client-link simulation)",
		Fabric:         copyFabricInfo(fabInfo),
		TimingNS:       map[string]int64{},
		Bytes:          map[string]int{},
		Correctness:    map[string]any{},
		MeasurementTag: "MEASURED(FINAL_FULL_TASK_MATRIX_v1 on real Fabric test-network 2.5.7, fabric-gateway)",
	}
	fullStart := time.Now()
	repSeed := fmt.Sprintf("%s::%s::rep%d", seed, c.Name, rep)

	x := big.NewInt(0x1234567 + int64(rep))
	y := big.NewInt(0x89abcde - int64(rep))

	// ① share distribution + output processing + ZKPoC
	t0 := time.Now()
	pf, err := paperfixture.Build(pid, c.Servers, mClients, c.TShareInit, x, y, "off", repSeed)
	if err != nil {
		r.Status, r.FailureReason = "FAILED", "paperfixture: "+err.Error()
		return r
	}
	r.TimingNS["client_result_processing"] = time.Since(t0).Nanoseconds()
	rec, err := pf.Fixture.TaskRecord()
	if err != nil {
		r.Status, r.FailureReason = "FAILED", "task_record: "+err.Error()
		return r
	}
	var cpuProc int64
	for _, cost := range pf.Costs {
		cpuProc += cost.ProcessingNS + cost.VerifyNS
	}
	r.TimingNS["cpu_work_server_processing_and_verify"] = cpuProc
	r.Bytes["cts_bytes_per_server"] = pf.Fixture.Outputs[0].CtsBytes
	r.Bytes["zkpoc_bytes_per_server"] = pf.Fixture.Outputs[0].ZKPoCBytes
	r.Bytes["submission_payload_bytes_per_server"] = pf.Fixture.Outputs[0].PayloadBytes

	ctx := context.Background()
	taskID := pf.Fixture.TaskID

	// ② register
	t1 := time.Now()
	regRep, err := sa.RegisterSchemeATask(ctx, rec)
	if err != nil {
		r.Status, r.FailureReason = "FAILED", "register: "+err.Error()
		return r
	}
	r.TimingNS["fabric_register_tx"] = time.Since(t1).Nanoseconds()
	r.Fabric["register_tx_id"] = regRep.TxID
	r.Fabric["register_block_number"] = regRep.BlockNum

	var lastVerify backend.Timing
	var lastTxID string
	var lastBlock uint64
	txIDs := make([]string, 0, c.Servers)
	txEndorse := make([]int64, 0, c.Servers)
	txCommit := make([]int64, 0, c.Servers)
	txTotal := make([]int64, 0, c.Servers)
	for i := 0; i < c.Servers; i++ {
		ts := time.Now()
		rep, err := sa.VerifySchemeAOutput(ctx, taskID, pf.Fixture.Outputs[i].SubmissionJSON)
		if err != nil {
			r.Status, r.FailureReason = "FAILED", fmt.Sprintf("verify server %d: %v", i+1, err)
			return r
		}
		r.TimingNS[fmt.Sprintf("server_tx_%d", i+1)] = time.Since(ts).Nanoseconds()
		lastVerify = sa.TimingOf(rep)
		lastTxID, lastBlock = rep.TxID, rep.BlockNum
		txIDs = append(txIDs, rep.TxID)
		txEndorse = append(txEndorse, lastVerify.EndorsementWaitNS)
		txCommit = append(txCommit, lastVerify.CommitStatusWaitNS)
		txTotal = append(txTotal, lastVerify.TotalNS)
	}
	var txSum int64
	for i := 1; i <= c.Servers; i++ {
		txSum += r.TimingNS[fmt.Sprintf("server_tx_%d", i)]
	}
	r.TimingNS["fabric_verify_tx_total"] = txSum
	r.TimingNS["fabric_verify_endorsement_wait"] = lastVerify.EndorsementWaitNS
	r.TimingNS["fabric_verify_commit_wait"] = lastVerify.CommitStatusWaitNS
	r.Fabric["tx_id"] = lastTxID
	r.Fabric["block_number"] = lastBlock
	r.Fabric["verify_tx_ids"] = txIDs
	r.Fabric["verify_tx_endorsement_ns"] = txEndorse
	r.Fabric["verify_tx_commit_ns"] = txCommit
	r.Fabric["verify_tx_total_ns"] = txTotal

	// ④ accepted query
	t3 := time.Now()
	accRep, err := sa.QuerySchemeAAcceptedOutputs(ctx, taskID)
	if err != nil {
		r.Status, r.FailureReason = "FAILED", "query accepted: "+err.Error()
		return r
	}
	r.TimingNS["sa_accepted_query"] = time.Since(t3).Nanoseconds()
	var q struct {
		Count   int   `json:"count"`
		Indices []int `json:"indices"`
	}
	must(json.Unmarshal(accRep.Raw, &q))
	r.Correctness["accepted_count"] = q.Count
	r.Correctness["all_servers_accepted"] = q.Count == c.Servers

	t4 := time.Now()
	dsum, err := pf.DecryptServerShares(dlogBoundBits)
	if err != nil {
		r.Status, r.FailureReason = "FAILED", "paper decrypt: "+err.Error()
		return r
	}
	zs := dsum.Zs
	partialsPerProduct := dsum.PartialsPerProduct
	r.TimingNS["client_decrypt_eq20_dlog_recompose"] = time.Since(t4).Nanoseconds()
	r.TimingNS["client_decrypt_eq20_only"] = dsum.Eq20NS
	r.TimingNS["client_decrypt_dlog"] = dsum.DLOGNS
	r.Actors["number_of_decrypt_partials"] = partialsPerProduct
	r.Correctness["number_of_decrypt_partials"] = partialsPerProduct
	r.Correctness["decrypt_participants_equals_m_clients"] = partialsPerProduct == mClients
	r.Correctness["total_client_partials"] = dsum.TotalPartials
	r.Correctness["partitions_per_server"] = dsum.PartitionsPerServer

	t5 := time.Now()
	z, err := pf.Reconstruct(zs, c.TShareInit, c.TShareInit)
	if err != nil {
		r.Status, r.FailureReason = "FAILED", "Eq.(22): "+err.Error()
		return r
	}
	r.TimingNS["output_reconstruction_eq22"] = time.Since(t5).Nanoseconds()
	want := new(big.Int).Mul(x, y)
	want.Mod(want, paperfixture.ShareMod)
	r.Correctness["reconstruction_ok"] = z.Cmp(want) == 0
	r.Correctness["reconstructed_z_hex"] = z.Text(16)
	r.Correctness["expected_xy_hex"] = want.Text(16)
	r.Correctness["privacy"] = "only the w ciphertexts and w ZKPoC are submitted; plaintext shares and client keys stay off chain"

	r.TimingNS["sequential_cpu_work"] = cpuProc + r.TimingNS["fabric_register_tx"] +
		r.TimingNS["client_decrypt_eq20_dlog_recompose"] + r.TimingNS["output_reconstruction_eq22"]
	r.TimingNS["protocol_faithful_wall_clock"] = time.Since(fullStart).Nanoseconds()
	r.TimingNS["full_response"] = r.TimingNS["protocol_faithful_wall_clock"]
	r.TimingNS["protocol_faithful_wall_clock_excluding_dlog"] =
		r.TimingNS["protocol_faithful_wall_clock"] - r.TimingNS["client_decrypt_dlog"]
	r.Correctness["cpu_work_definition"] = "sum over i of (server_i processing + server_i verify) + register + decrypt + reconstruct"
	r.Correctness["wall_clock_definition"] = "end-to-end critical path measured on the real network"
	r.Correctness["headline_basis"] = "protocol_faithful_wall_clock"
	r.Correctness["dlog_normalized_view"] = "protocol_faithful_wall_clock_excluding_dlog, obtained by subtracting the bounded DLOG component of the same run"

	if r.Correctness["reconstruction_ok"] == true && q.Count == c.Servers && partialsPerProduct == mClients {
		r.Status = "PASS"
	} else {
		r.Status, r.FailureReason = "FAILED", "Eq.(20)/Eq.(22) mismatch"
	}
	return r
}

func summarizeSAMatrix(rows []saMatrixRaw, cfgs []saMatrixConfig, reps, warmups, mClients int, profileDesc string) map[string]any {
	perConfig := map[string]any{}
	setup := []map[string]any{}
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
		allTx := []int64{}
		for _, r := range rows {
			if r.Config != c.Name || r.Phase != "measured" || r.Status != "PASS" {
				continue
			}
			for i := 1; i <= c.Servers; i++ {
				allTx = append(allTx, r.TimingNS[fmt.Sprintf("server_tx_%d", i)])
			}
		}
		partialsOK := 0
		for _, r := range rows {
			if r.Config == c.Name && r.Phase == "measured" &&
				r.Correctness["decrypt_participants_equals_m_clients"] == true {
				partialsOK++
			}
		}
		perConfig[c.Name] = map[string]any{
			"n_servers": c.Servers, "f": c.F, "t_secret_sharing": c.TShareInit,
			"m_clients": mClients, "number_of_decrypt_partials": mClients,
			"decrypt_participants_assertion_passed":          partialsOK,
			"sequential_cpu_work_ns":                         stats.Summarize(pick("sequential_cpu_work")),
			"protocol_faithful_wall_clock_ns":                stats.Summarize(pick("protocol_faithful_wall_clock")),
			"protocol_faithful_wall_clock_excluding_dlog_ns": stats.Summarize(pick("protocol_faithful_wall_clock_excluding_dlog")),
			"cpu_work_server_processing_and_verify_ns":       stats.Summarize(pick("cpu_work_server_processing_and_verify")),
			"server_tx_per_tx_ns":                            stats.Summarize(allTx),
			"fabric_register_tx_ns":                          stats.Summarize(pick("fabric_register_tx")),
			"fabric_verify_endorsement_wait_ns":              stats.Summarize(pick("fabric_verify_endorsement_wait")),
			"fabric_verify_commit_wait_ns":                   stats.Summarize(pick("fabric_verify_commit_wait")),
			"sa_accepted_query_ns":                           stats.Summarize(pick("sa_accepted_query")),
			"client_result_processing_ns":                    stats.Summarize(pick("client_result_processing")),
			"client_decrypt_eq20_dlog_recompose_ns":          stats.Summarize(pick("client_decrypt_eq20_dlog_recompose")),
			"client_decrypt_eq20_only_ns":   stats.Summarize(pick("client_decrypt_eq20_only")),
			"client_decrypt_dlog_ns":        stats.Summarize(pick("client_decrypt_dlog")),
			"output_reconstruction_eq22_ns": stats.Summarize(pick("output_reconstruction_eq22")),
		}
		setup = append(setup, map[string]any{
			"scheme": "SchemeA", "config": c.Name, "n_servers": c.Servers, "f": c.F,
			"t_secret_sharing": c.TShareInit, "m_clients": mClients,
			"measured_reps": len(pick("protocol_faithful_wall_clock")),
		})
	}
	ok := 0
	for _, r := range rows {
		if r.Status == "PASS" {
			ok++
		}
	}
	return map[string]any{
		"schema":          "c5-blockchain-exp-summary-v1",
		"experiment_id":   "GAI-MATRIX",
		"scheme":          "SchemeA",
		"backend":         "fabric",
		"scope":           "verification and recovery phases of Gai et al. on a real Fabric 2.5.7 test network",
		"profile":         profileDesc,
		"decryption_mode": "SA-PAPER-DECRYPT",
		"paper_faithful":  true,
		"actors": map[string]any{
			"m_clients":                  mClients,
			"number_of_decrypt_partials": mClients,
			"t_secret_sharing_rule":      "t = f + 1, matching the delivery threshold of our scheme",
			"note":                       "n_servers, t_secret_sharing and m_clients are named separately; the number of decrypting participants is always m_clients",
		},
		"configs":       configNames(cfgs),
		"reps_measured": reps,
		"reps_note":     "the per-configuration measured repetition count is recorded in per_config.*.measured_reps and task_setup[].measured_reps",
		"warmups":       warmups,
		"rows":          len(rows),
		"passed":        ok,
		"per_config":    perConfig,
		"task_setup":    setup,
		"two_views": map[string]any{
			"sequential_cpu_work":          "sum over i of (server_i processing + verify) + register + decrypt + reconstruct",
			"protocol_faithful_wall_clock": "end-to-end critical path measured on the real network",
			"protocol_faithful_wall_clock_excluding_dlog": "subtracts the bounded DLOG (BSGS) component from the same run, " +
				"separating the protocol topology from the DLOG implementation choice",
			"must_not_mix": true,
		},
		"honesty": map[string]any{
			"real_fabric":        true,
			"stub_is_not_fabric": false,
			"full_chain_per_rep": "each repetition runs share distribution, output processing, ZKPoC, Fabric verification, " +
				"Eq. (20), DLOG, Eq. (21) and Eq. (22); no per-component medians are spliced together",
			"eq20":                    "t_j = prod over i of (C0_j)^{s_i} using all m client partials; fewer or more than m fail closed",
			"no_shamir_in_decryption": "the decryption path uses no Shamir or Lagrange combination; Lagrange is used only for Eq. (22)",
			"dlog":                    "bounded DLOG (bound 2^32); the paper's full table is infeasible and its time is not fabricated",
			"share_modulus":           "z_i is shared over a fixed 256-bit prime; the paper leaves this unspecified",
		},
	}
}

func configNames(cfgs []saMatrixConfig) []string {
	out := make([]string, len(cfgs))
	for i, c := range cfgs {
		out[i] = c.Name
	}
	return out
}
