//	blockchain/artifacts/c5_l1_507/{ccs.bin,pk.bin,vk.bin,manifest.json}
//	go run ./experiments/cmd/setupgen \
//	    -out  ./artifacts/c5_l1_507 \
//	    -maskctx-len 507 -L 1
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"c5full/internal/c5/m1"

	"c5full/blockchain/bridge"
)

type manifest struct {
	Schema       string `json:"schema"`
	ArtifactDir  string `json:"artifact_dir"`
	ProfileID    string `json:"profile_id"`
	L            int    `json:"L"`
	MaskCtxLen   int    `json:"maskctx_len"`
	Constraints  int    `json:"constraints"`
	Curve        string `json:"curve"`
	Scheme       string `json:"scheme"`
	SetupRun     string `json:"setup_run_id"`
	CcsSource    string `json:"ccs_source"`
	CcsCachePath string `json:"ccs_cache_path,omitempty"`
	CompileNS    int64  `json:"compile_ns,omitempty"`
	SetupNS      int64  `json:"setup_ns"`
	SerializeNS  int64  `json:"serialize_ns"`
	SizeCCS      int64  `json:"size_ccs_bytes"`
	SizePK       int64  `json:"size_pk_bytes"`
	SizeVK       int64  `json:"size_vk_bytes"`
	SHA256CCS    string `json:"sha256_ccs"`
	SHA256PK     string `json:"sha256_pk"`
	SHA256VK     string `json:"sha256_vk"`
	GoVersion    string `json:"go_version"`
	GeneratedUTC string `json:"generated_utc"`
	PKDeployment string `json:"pk_deployment"`
	VKDeployment string `json:"vk_deployment"`
}

func main() {
	out := flag.String("out", "./artifacts/c5_l1_507", "output artifact dir")
	ccsCache := flag.String("ccs-cache", "", "optional setup-cache dir containing ccs.bin (read-only reuse of a frozen ccs)")
	L := flag.Int("L", 1, "number of outputs")
	maskLen := flag.Int("maskctx-len", 507, "mask context length in bytes")
	flag.Parse()

	if err := os.MkdirAll(*out, 0o755); err != nil {
		fail(err)
	}
	m := manifest{
		Schema:       "c5-blockchain-setup-artifact-v1",
		ArtifactDir:  filepath.ToSlash(*out),
		ProfileID:    "C5-BC-1: gnark v0.15.0 Groth16/BLS12-381, L=1, MaskCtx=507B",
		L:            *L,
		MaskCtxLen:   *maskLen,
		Curve:        "BLS12-381 (proof) / secp256k1 emulated (logical)",
		Scheme:       "groth16",
		SetupRun:     fmt.Sprintf("bc-setup-%d", time.Now().UTC().Unix()),
		GoVersion:    runtime.Version(),
		PKDeployment: "prover/client host only (NEVER in chaincode image)",
		VKDeployment: "chaincode image (sha256 pinned, verified at startup)",
	}

	var (
		ccsB, pkB, vkB []byte
		err            error
		p              *m1.Prover
	)

	if *ccsCache != "" {
		ccsPath := filepath.Join(*ccsCache, "ccs.bin")
		raw, rerr := os.ReadFile(ccsPath)
		if rerr != nil {
			fail(rerr)
		}
		p, err = bridge.DeserializeCCSOnly(*L, *maskLen, raw)
		if err != nil {
			fail(err)
		}
		m.CcsSource = "cache"
		m.CcsCachePath = filepath.ToSlash(ccsPath)
	} else {
		t0 := time.Now()
		p, err = m1.CompileOnly(*L, *maskLen)
		if err != nil {
			fail(err)
		}
		m.CompileNS = time.Since(t0).Nanoseconds()
		m.CcsSource = "fresh-compile"
	}
	m.Constraints = p.Constraints()
	if m.Constraints != 891908 {
		fail(fmt.Errorf("CANONICAL-DRIFT: constraints=%d want 891908", m.Constraints))
	}

	t1 := time.Now()
	if err := p.SetupKeys(); err != nil {
		fail(err)
	}
	m.SetupNS = time.Since(t1).Nanoseconds()

	t2 := time.Now()
	ccsB, pkB, vkB, err = p.SerializeSetup()
	if err != nil {
		fail(err)
	}
	m.SerializeNS = time.Since(t2).Nanoseconds()

	if err := writeArtifact(filepath.Join(*out, "ccs.bin"), ccsB); err != nil {
		fail(err)
	}
	if err := writeArtifact(filepath.Join(*out, "pk.bin"), pkB); err != nil {
		fail(err)
	}
	if err := writeArtifact(filepath.Join(*out, "vk.bin"), vkB); err != nil {
		fail(err)
	}
	m.SizeCCS, m.SizePK, m.SizeVK = int64(len(ccsB)), int64(len(pkB)), int64(len(vkB))
	m.SHA256CCS = sha256Hex(ccsB)
	m.SHA256PK = sha256Hex(pkB)
	m.SHA256VK = sha256Hex(vkB)
	m.GeneratedUTC = time.Now().UTC().Format(time.RFC3339)

	mb, _ := json.MarshalIndent(m, "", "  ")
	if err := writeArtifact(filepath.Join(*out, "manifest.json"), append(mb, '\n')); err != nil {
		fail(err)
	}
	fmt.Printf("SETUP_OK constraints=%d ccs=%dB pk=%dB vk=%dB vk_sha256=%s\n",
		m.Constraints, m.SizeCCS, m.SizePK, m.SizeVK, m.SHA256VK)
	fmt.Printf("setup_ns=%d ccs_source=%s\n", m.SetupNS, m.CcsSource)
}

func writeArtifact(path string, b []byte) error {
	return os.WriteFile(path, b, 0o644)
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "SETUP_FAILED: %v\n", err)
	os.Exit(1)
}
