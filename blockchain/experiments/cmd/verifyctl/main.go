// Command verifyctl generates the deterministic fixtures used by the on-chain
// experiments, so a Fabric run can replay a payload that matches the ledger.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"c5full/internal/mpc/schemea"

	"c5full/blockchain/bridge"
	"c5full/blockchain/tests/harness"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: verifyctl <fixture-c5|fixture-schemea> [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "fixture-c5":
		cmdFixtureC5(os.Args[2:])
	case "fixture-schemea":
		cmdFixtureSA(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		os.Exit(2)
	}
}

func cmdFixtureC5(args []string) {
	fs := flag.NewFlagSet("fixture-c5", flag.ExitOnError)
	artifacts := fs.String("artifacts", "./artifacts/c5_l1_507", "setup artifact directory (needs pk.bin)")
	out := fs.String("out", "../fixtures/c5_l1_507.json", "output fixture path")
	taskID := fs.String("task-id", "c5-canonical-1", "task id")
	n := fs.Int("n", 3, "server count")
	f := fs.Int("f", 1, "fault tolerance")
	l := fs.Int("l", 1, "output dimension")
	seed := fs.String("seed", "c5-canonical-v1", "deterministic fixture seed")
	_ = fs.Parse(args)

	t0 := time.Now()
	prover, m, err := bridge.LoadFullProverFromDir(*artifacts)
	if err != nil {
		fail("load prover (pk.bin is needed, prover host only): %v", err)
	}
	if m.Constraints != 891908 || m.L != 1 || m.MaskCtxLen != 507 {
		fail("canonical profile drift: L=%d maskctx=%d constraints=%d", m.L, m.MaskCtxLen, m.Constraints)
	}
	x := big.NewInt(0x1234567)
	y := big.NewInt(0x89abcde)
	fx, prov, err := harness.BuildC5FixtureFromBottomMPC(prover, *artifacts, *taskID, *n, *f, *l, x, y, *seed)
	if err != nil {
		fail("build fixture from MPC: %v", err)
	}
	if err := fx.Save(*out); err != nil {
		fail("save fixture: %v", err)
	}
	fmt.Printf("FIXTURE_C5_OK task=%s deliveries=%d payload_bytes=%d proof_bytes=%d vk_hash=%s out=%s\n",
		fx.TaskID, len(fx.Deliveries), fx.Deliveries[0].PayloadBytes, fx.Deliveries[0].ProofBytes, fx.VKHash, *out)
	fmt.Printf("maskctx_len=%d constraints=%d tau_len=%d alpha=%s build_ns=%d\n",
		fx.MaskCtxLen, fx.Constraints, prov.TauLen, prov.AlphaHex, time.Since(t0).Nanoseconds())
}

func cmdFixtureSA(args []string) {
	fs := flag.NewFlagSet("fixture-schemea", flag.ExitOnError)
	out := fs.String("out", "../fixtures/schemea_3072.json", "output fixture path")
	servers := fs.Int("servers", 3, "server count")
	profile := fs.String("profile", "P-SA-128", "P-SA-128 | P-SA-112 | P-SA-256-DIAG")
	groupCheck := fs.String("group-check", "off", "off | qr")
	seed := fs.String("seed", "sa-canonical-v1", "deterministic fixture seed")
	_ = fs.Parse(args)

	t0 := time.Now()
	fx, err := harness.BuildSchemeAFixture(profileOf(*profile), *servers, *groupCheck, *seed)
	if err != nil {
		fail("build Gai fixture: %v", err)
	}
	fx.Notes += fmt.Sprintf(" | build_ns=%d", time.Since(t0).Nanoseconds())
	if err := fx.Save(*out); err != nil {
		fail("save fixture: %v", err)
	}
	fmt.Printf("FIXTURE_SA_OK task=%s profile=%s prime_bits=%d servers=%d w=%d cts_bytes=%d zkpoc_bytes=%d payload_bytes=%d out=%s\n",
		fx.TaskID, fx.ProfileID, fx.PrimeBits, fx.Servers, fx.W, fx.Outputs[0].CtsBytes,
		fx.Outputs[0].ZKPoCBytes, fx.Outputs[0].PayloadBytes, *out)
}

func profileOf(s string) schemea.ProfileID {
	switch strings.TrimSpace(s) {
	case "P-SA-128":
		return schemea.PUB128
	case "P-SA-112":
		return schemea.PUB112
	case "P-SA-256-DIAG":
		return schemea.PUB256Diag
	default:
		fail("unknown profile %q (use P-SA-128 | P-SA-112 | P-SA-256-DIAG)", s)
		return ""
	}
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "VERIFYCTL_FAILED: "+format+"\n", a...)
	os.Exit(1)
}
