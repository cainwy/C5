package contracts

import (
	"fmt"
	"os"
	"sync"

	"c5full/internal/c5/m1"

	"c5full/blockchain/bridge"
	"c5full/blockchain/fabric/chaincode/verify"
)

const EnvVKDir = "C5_VK_DIR"

type Resources struct {
	Verifier *m1.Prover
	Manifest *bridge.SetupManifest
	VKHash   string
}

var (
	resOnce sync.Once
	res     *Resources
	resErr  error
)

func InitResources(dir string) (*Resources, error) {
	if dir == "" {
		dir = os.Getenv(EnvVKDir)
	}
	if dir == "" {
		return nil, fmt.Errorf("contracts: %s not set (refusing to start without canonical VK)", EnvVKDir)
	}
	m, err := bridge.LoadSetupManifest(dir)
	if err != nil {
		return nil, fmt.Errorf("contracts: load manifest: %w", err)
	}
	if !verify.CanonicalConstraints(m.L, m.Constraints) {
		return nil, fmt.Errorf("contracts: canonical profile required (L in {1,2,4} with matched constraints), got L=%d constraints=%d",
			m.L, m.Constraints)
	}
	p, _, err := bridge.LoadVKOnlyVerifierFromDir(dir, m.L, m.MaskCtxLen)
	if err != nil {
		return nil, fmt.Errorf("contracts: load VK: %w", err)
	}
	if err := bridge.CheckVKShape(p.Vk, m.L, m.MaskCtxLen, m.Constraints); err != nil {
		return nil, fmt.Errorf("contracts: vk shape: %w", err)
	}
	return &Resources{Verifier: p, Manifest: m, VKHash: m.SHA256VK}, nil
}

func MustInitResources(dir string) (*Resources, error) {
	resOnce.Do(func() { res, resErr = InitResources(dir) })
	return res, resErr
}