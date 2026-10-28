package bridge


import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	bls12381cs "github.com/consensys/gnark/constraint/bls12-381"

	"c5full/internal/c5/m1"

	"c5full/blockchain/fabric/chaincode/model"
)

type SetupManifest struct {
	Schema       string `json:"schema"`
	ProfileID    string `json:"profile_id"`
	L            int    `json:"L"`
	MaskCtxLen   int    `json:"maskctx_len"`
	Constraints  int    `json:"constraints"`
	Curve        string `json:"curve"`
	Scheme       string `json:"scheme"`
	SetupRun     string `json:"setup_run_id"`
	CcsSource    string `json:"ccs_source"`
	SizeCCS      int64  `json:"size_ccs_bytes"`
	SizePK       int64  `json:"size_pk_bytes"`
	SizeVK       int64  `json:"size_vk_bytes"`
	SHA256CCS    string `json:"sha256_ccs"`
	SHA256PK     string `json:"sha256_pk"`
	SHA256VK     string `json:"sha256_vk"`
	PKDeployment string `json:"pk_deployment"`
	VKDeployment string `json:"vk_deployment"`
}

func LoadSetupManifest(dir string) (*SetupManifest, error) {
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var m SetupManifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if m.SHA256VK == "" || m.SizeVK <= 0 {
		return nil, fmt.Errorf("bridge: manifest missing vk hash/size")
	}
	return &m, nil
}

func LoadVKVerified(dir string, m *SetupManifest) (groth16.VerifyingKey, []byte, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "vk.bin"))
	if err != nil {
		return nil, nil, err
	}
	sum := sha256.Sum256(raw)
	got := hex.EncodeToString(sum[:])
	if m != nil && got != m.SHA256VK {
		return nil, nil, model.Reject(model.CodeVKMismatch, fmt.Sprintf("vk sha256 %s != manifest %s", got, m.SHA256VK))
	}
	if m != nil && m.SizeVK != 0 && int64(len(raw)) != m.SizeVK {
		return nil, nil, model.Reject(model.CodeVKMismatch, "vk size != manifest size")
	}
	vk := groth16.NewVerifyingKey(ecc.BLS12_381)
	if _, err := vk.ReadFrom(bytes.NewReader(raw)); err != nil {
		return nil, nil, fmt.Errorf("bridge: vk parse: %w", err)
	}
	return vk, raw, nil
}

func NewVKOnlyVerifier(vk groth16.VerifyingKey, L, maskCtxLen int) (*m1.Prover, error) {
	if vk == nil {
		return nil, model.Reject(model.CodeVKMismatch, "nil verifying key")
	}
	p := &m1.Prover{L: L, MaskCtxLen: maskCtxLen, Vk: vk}
	if p.Pk != nil || p.Ccs != nil {
		return nil, fmt.Errorf("bridge: VK-only verifier must not hold PK/CCS")
	}
	return p, nil
}

func LoadVKOnlyVerifierFromDir(dir string, L, maskCtxLen int) (*m1.Prover, *SetupManifest, error) {
	m, err := LoadSetupManifest(dir)
	if err != nil {
		return nil, nil, err
	}
	if L != 0 && m.L != L {
		return nil, nil, model.Reject(model.CodeProfileMismatch, "manifest L != requested L")
	}
	if maskCtxLen != 0 && m.MaskCtxLen != maskCtxLen {
		return nil, nil, model.Reject(model.CodeProfileMismatch, "manifest maskctx_len != requested")
	}
	vk, _, err := LoadVKVerified(dir, m)
	if err != nil {
		return nil, nil, err
	}
	p, err := NewVKOnlyVerifier(vk, m.L, m.MaskCtxLen)
	if err != nil {
		return nil, nil, err
	}
	return p, m, nil
}

func LoadFullProverFromDir(dir string) (*m1.Prover, *SetupManifest, error) {
	m, err := LoadSetupManifest(dir)
	if err != nil {
		return nil, nil, err
	}
	ccsB, err := os.ReadFile(filepath.Join(dir, "ccs.bin"))
	if err != nil {
		return nil, nil, err
	}
	pkB, err := os.ReadFile(filepath.Join(dir, "pk.bin"))
	if err != nil {
		return nil, nil, err
	}
	vkB, err := os.ReadFile(filepath.Join(dir, "vk.bin"))
	if err != nil {
		return nil, nil, err
	}
	for _, c := range []struct {
		name string
		raw  []byte
		want string
	}{
		{"ccs", ccsB, m.SHA256CCS}, {"pk", pkB, m.SHA256PK}, {"vk", vkB, m.SHA256VK},
	} {
		sum := sha256.Sum256(c.raw)
		if got := hex.EncodeToString(sum[:]); got != c.want {
			return nil, nil, model.Reject(model.CodeVKMismatch, c.name+" sha256 mismatch")
		}
	}
	p, err := m1.DeserializeSetup(m.L, m.MaskCtxLen, ccsB, pkB, vkB)
	if err != nil {
		return nil, nil, err
	}
	return p, m, nil
}

func DeserializeCCSOnly(L, maskCtxLen int, ccsB []byte) (*m1.Prover, error) {
	ccs := new(bls12381cs.R1CS)
	if _, err := ccs.ReadFrom(bytes.NewReader(ccsB)); err != nil {
		return nil, fmt.Errorf("bridge: ccs parse: %w", err)
	}
	return &m1.Prover{L: L, MaskCtxLen: maskCtxLen, Ccs: ccs}, nil
}

func ExpectedPublicWitnessSize(L, maskCtxLen int, withConstant bool) int {
	n := 16 + 12*L + maskCtxLen
	if withConstant {
		n++
	}
	return n
}

var canonicalConstraints = map[int]int{
	1: 891908,
	2: 1403640,
	4: 2427414,
}

func CanonicalConstraints(L, constraints int) bool {
	want, ok := canonicalConstraints[L]
	return ok && want == constraints
}

func CheckVKShape(vk groth16.VerifyingKey, L, maskCtxLen int, constraints int) error {
	want := ExpectedPublicWitnessSize(L, maskCtxLen, true)
	if got := vk.NbPublicWitness(); got != want && got != want-1 {
		return model.Reject(model.CodeProfileMismatch,
			fmt.Sprintf("vk.NbPublicWitness=%d want %d (or %d without constant)", got, want, want-1))
	}
	if constraints != 0 && !CanonicalConstraints(L, constraints) {
		return model.Reject(model.CodeProfileMismatch, "constraints != canonical profile for L")
	}
	return nil
}