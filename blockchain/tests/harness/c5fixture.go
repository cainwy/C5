package harness


import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"c5full/internal/c5/host"
	"c5full/internal/c5/m1"
	"c5full/internal/c5/params"

	"c5full/blockchain/bridge"
	"c5full/blockchain/fabric/chaincode/model"
)

var paramsQ = params.Q

type C5Delivery struct {
	Index         int    `json:"index"`
	PayloadHex    string `json:"payload_hex"`
	PayloadBytes  int    `json:"payload_bytes"`
	ProofBytes    int    `json:"proof_bytes"`
	SigBytes      int    `json:"sig_bytes"`
	PayloadSHA256 string `json:"payload_sha256"`
}

type C5Fixture struct {
	Schema         string `json:"schema"`
	TaskID         string `json:"task_id"`
	N, F, L        int
	Seed           string `json:"seed"`
	MaskCtxLen     int    `json:"maskctx_len"`
	Constraints    int    `json:"constraints"`
	VKHash         string `json:"vk_hash"`
	ArtifactsDir   string `json:"artifacts_dir"`
	TaskRecordJSON string       `json:"task_record_json"`
	CertJSON       string       `json:"cert_json"`
	Deliveries     []C5Delivery `json:"deliveries"`
	Malicious    *C5Delivery `json:"malicious_invalid_proof,omitempty"`
	GeneratedUTC string      `json:"generated_utc"`
	Notes        string      `json:"notes"`
}

//	NewTaskWithRNG → EndorseAll → MakeDeliveryWithRNG → Prove →
func BuildC5Fixture(prover *m1.Prover, artifactsDir, taskID string, n, f, L int, seed string) (*C5Fixture, error) {
	if prover == nil || prover.Pk == nil {
		return nil, fmt.Errorf("harness: canonical prover with PK is required to build a C5 fixture")
	}
	baseRNG := NewHashSeedReader("bc::" + seed)
	t, err := m1.NewTaskWithRNG(n, f, L, seed, baseRNG)
	if err != nil {
		return nil, err
	}
	if len(t.MaskCtxFor(1)) != prover.MaskCtxLen {
		return nil, fmt.Errorf("harness: maskctx len %d != prover profile %d", len(t.MaskCtxFor(1)), prover.MaskCtxLen)
	}
	if prover.Constraints() != 891908 {
		return nil, fmt.Errorf("harness: canonical constraints required, got %d", prover.Constraints())
	}
	t.EndorseAll()

	certIdx := make([]int, 0, n-f)
	for i := 0; i < n-f; i++ {
		certIdx = append(certIdx, i)
	}
	cert, err := bridge.CertificateFromTask(t, certIdx)
	if err != nil {
		return nil, err
	}
	cert.TaskID = taskID
	cert.CertHash = bridge.CertHash(cert)

	rec, err := bridge.PublicTaskRecordFromTask(t, taskID, "bc-c5-l1-507", vkHashOf(artifactsDir), prover.MaskCtxLen, prover.Constraints())
	if err != nil {
		return nil, err
	}
	recJSON, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	certJSON, err := json.Marshal(cert)
	if err != nil {
		return nil, err
	}

	fx := &C5Fixture{
		Schema: "c5-blockchain-fixture-v1", TaskID: taskID,
		N: n, F: f, L: L, Seed: seed,
		MaskCtxLen:   prover.MaskCtxLen,
		Constraints:  prover.Constraints(),
		VKHash:       vkHashOf(artifactsDir),
		ArtifactsDir: filepath.ToSlash(artifactsDir),
		TaskRecordJSON: string(recJSON),
		CertJSON:       string(certJSON),
		GeneratedUTC:   time.Now().UTC().Format(time.RFC3339),
		Notes:          "fixture 仅含 public 数据；witness (s_i, Z_i, z_i, rho_i) 不落盘",
	}
	for i := 0; i < f+1; i++ {
		d := t.MakeDeliveryWithRNG(i, NewHashSeedReader(fmt.Sprintf("bc::%s::del:%d", seed, i)))
		_, pb, _, err := prover.Prove(t, d)
		if err != nil {
			return nil, err
		}
		d.Proof = pb
		d.HasProof = true
		d.Sig = nil
		t.SignWithProof(d)
		if !m1.VerifyDeliverySignature(t, d) {
			return nil, fmt.Errorf("harness: delivery signature self-check failed for server %d", i)
		}
		payload, err := model.CanonicalDeliveryBytes(d.I+1,
			hex.EncodeToString(host.EncodePoint(d.R, false)), hexOfScalars(d.C), hex.EncodeToString(d.Sig), hex.EncodeToString(d.Proof))
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(payload)
		fx.Deliveries = append(fx.Deliveries, C5Delivery{
			Index: d.I + 1, PayloadHex: hex.EncodeToString(payload), PayloadBytes: len(payload),
			ProofBytes: len(d.Proof), SigBytes: len(d.Sig), PayloadSHA256: hex.EncodeToString(sum[:]),
		})
	}
	return fx, nil
}

func (fx *C5Fixture) CertJSONAlpha() string {
	c, err := fx.Certificate()
	if err != nil {
		return ""
	}
	return c.AlphaHex
}

func MustDecodePayload(payloadHex string, taskRec *model.PublicTaskRecord) *m1.Delivery {
	idx, rHex, cHex, sigHex, proofHex, err := model.ParseCanonicalDeliveryBytes(mustHex(payloadHex))
	if err != nil {
		panic("harness: decode payload: " + err.Error())
	}
	d, err := bridge.DecodeDelivery(idx, rHex, cHex, sigHex, proofHex, taskRec.N, taskRec.L)
	if err != nil {
		panic("harness: strict decode: " + err.Error())
	}
	return d
}

func (fx *C5Fixture) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(fx, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func LoadC5Fixture(path string) (*C5Fixture, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var fx C5Fixture
	if err := json.Unmarshal(b, &fx); err != nil {
		return nil, err
	}
	if fx.TaskID == "" || len(fx.Deliveries) == 0 {
		return nil, fmt.Errorf("harness: fixture incomplete")
	}
	return &fx, nil
}

func (fx *C5Fixture) TaskRecord() (*model.PublicTaskRecord, error) {
	var rec model.PublicTaskRecord
	if err := json.Unmarshal([]byte(fx.TaskRecordJSON), &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func (fx *C5Fixture) Certificate() (*model.CertificateRecord, error) {
	var c model.CertificateRecord
	if err := json.Unmarshal([]byte(fx.CertJSON), &c); err != nil {
		return nil, err
	}
	return &c, nil
}

type Tamper struct {
	Index    *int
	RHex     *string
	CHex     []string
	SigHex   *string
	ProofHex *string
	RawBytes []byte
	Label    string
}

func (t Tamper) Apply(fx *C5Fixture, base C5Delivery) (string, error) {
	if t.RawBytes != nil {
		return hex.EncodeToString(t.RawBytes), nil
	}
	raw, err := hex.DecodeString(base.PayloadHex)
	if err != nil {
		return "", err
	}
	idx, rHex, cHex, sigHex, proofHex, err := model.ParseCanonicalDeliveryBytes(raw)
	if err != nil {
		return "", err
	}
	if t.Index != nil {
		idx = *t.Index
	}
	if t.RHex != nil {
		rHex = *t.RHex
	}
	if t.CHex != nil {
		cHex = t.CHex
	}
	if t.SigHex != nil {
		sigHex = *t.SigHex
	}
	if t.ProofHex != nil {
		proofHex = *t.ProofHex
	}
	b, err := model.CanonicalDeliveryBytes(idx, rHex, cHex, sigHex, proofHex)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func FlipHexBit(h string, byteIdx int) (string, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return "", err
	}
	if byteIdx < 0 || byteIdx >= len(b) {
		return "", fmt.Errorf("harness: byte index out of range")
	}
	b[byteIdx] ^= 0x01
	return hex.EncodeToString(b), nil
}

func TruncateHex(h string, n int) (string, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return "", err
	}
	if n > len(b) {
		n = len(b)
	}
	return hex.EncodeToString(b[:n]), nil
}

func OffCurveR() string {
	for x := int64(1); x < 10000; x++ {
		pt, err := host.DecodePoint(compressX(x), true)
		if err != nil || pt == nil {
			return hex.EncodeToString(compressX(x))
		}
	}
	return ""
}

func compressX(x int64) []byte {
	b := make([]byte, 33)
	b[0] = 0x02
	new(big.Int).SetInt64(x).FillBytes(b[1:])
	return b
}

func NonCanonicalC() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = 0xFF
	}
	return hex.EncodeToString(b)
}

func RandomProofBytes(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func hexOfScalars(c []*big.Int) []string {
	out := make([]string, len(c))
	for i, x := range c {
		b := make([]byte, 32)
		new(big.Int).Mod(x, paramsQ).FillBytes(b)
		out[i] = hex.EncodeToString(b)
	}
	return out
}

func vkHashOf(dir string) string {
	m, err := bridge.LoadSetupManifest(dir)
	if err != nil {
		return ""
	}
	return m.SHA256VK
}