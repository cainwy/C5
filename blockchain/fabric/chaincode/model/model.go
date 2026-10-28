// Package model defines the **canonical public ledger model** of the C5
// blockchain deployment layer (BC).
package model

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

const SchemaID = "c5-blockchain-ledger-v1"

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

type RejectError struct {
	Code   string
	Detail string
}

func (e *RejectError) Error() string {
	if e.Detail == "" {
		return e.Code
	}
	return e.Code + ": " + e.Detail
}

func Reject(code, detail string) *RejectError { return &RejectError{Code: code, Detail: detail} }

func IsReject(err error) (*RejectError, bool) {
	var re *RejectError
	if errors.As(err, &re) {
		return re, true
	}
	return nil, false
}

const (
	CodeMalformedRecord     = "REJECT_MALFORMED_RECORD"
	CodeTaskExists          = "REJECT_TASK_ALREADY_EXISTS"
	CodeTaskNotFound        = "REJECT_TASK_NOT_FOUND"
	CodeInvalidCert         = "REJECT_INVALID_CERT"
	CodeCertMismatch        = "REJECT_CERT_MISMATCH"
	CodeAlphaMismatch       = "REJECT_ALPHA_MISMATCH"
	CodeFinalityConflict    = "FINALITY_CONFLICT"
	CodeFinalityPending     = "FINALITY_PENDING"
	CodeInvalidIndex        = "REJECT_INVALID_INDEX"
	CodeDuplicateDelivery   = "REJECT_DUPLICATE_FOR_COLLECTION"
	CodeInvalidSignature    = "REJECT_INVALID_SIGNATURE"
	CodeInvalidProof        = "REJECT_INVALID_PROOF"
	CodeNonCanonicalPoint   = "REJECT_NONCANONICAL_POINT"
	CodeNonCanonicalScalar  = "REJECT_NONCANONICAL_FIELD"
	CodeShapeMismatch       = "REJECT_SHAPE_MISMATCH"
	CodeVKMismatch          = "REJECT_VK_MISMATCH"
	CodeProfileMismatch     = "REJECT_PROFILE_MISMATCH"
	CodeMalformedGroup      = "REJECT_MALFORMED_GROUP_ELEMENT"
	CodeInvalidZKPoC        = "REJECT_INVALID_ZKPOC"
	CodeCommitmentMismatch  = "REJECT_COMMITMENT_MISMATCH"
	CodeDuplicateSAOutput   = "REJECT_DUPLICATE_SERVER_CONTRIBUTION"
	CodeSubgroupViolation   = "REJECT_SUBGROUP_CHECK"
	CodeBenchmarkNotAllowed = "REJECT_BENCHMARK_ENDPOINT_DISABLED"
)

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

type PublicTaskRecord struct {
	Schema     string `json:"schema"`
	TaskID     string `json:"task_id"`
	TaskVer    int    `json:"task_version"`
	N          int    `json:"n"`
	F          int    `json:"f"`
	L          int    `json:"l"`
	Tau        string `json:"tau"`
	TaskCtxHex string `json:"task_ctx_hex"`
	AlphaHex   string `json:"alpha_hex"`
	ReceiverPK string `json:"receiver_pk_hex"`
	XiDec      []string `json:"xi_dec"`
	AoutHex    [][]string `json:"aout_hex"`      // L x (f+1) compressed points
	ServerPub  []string `json:"server_pub_hex"`  // n x 32B Ed25519 public keys
	ParamSetID string `json:"param_set_id"`
	ProfileID  string `json:"delivery_profile_id"`
	VKID       string `json:"vk_id"`
	VKHash     string `json:"vk_hash"`
	MaskCtxLen int    `json:"maskctx_len"`
	Constraints int   `json:"constraints"`
}

func (r *PublicTaskRecord) Validate() error {
	if r == nil {
		return Reject(CodeMalformedRecord, "nil task record")
	}
	if r.Schema != SchemaID {
		return Reject(CodeMalformedRecord, "schema mismatch")
	}
	if r.TaskID == "" {
		return Reject(CodeMalformedRecord, "empty task_id")
	}
	if r.N <= 0 || r.F < 0 || r.L <= 0 || r.N < 2*r.F+1 {
		return Reject(CodeShapeMismatch, fmt.Sprintf("bad n/f/L = %d/%d/%d", r.N, r.F, r.L))
	}
	if len(r.XiDec) != r.N {
		return Reject(CodeShapeMismatch, "xi length != n")
	}
	for i, s := range r.XiDec {
		x, ok := new(big.Int).SetString(s, 10)
		if !ok || x.Sign() <= 0 {
			return Reject(CodeMalformedRecord, "bad xi")
		}
		if x.Cmp(big.NewInt(int64(i+1))) != 0 {
			return Reject(CodeProfileMismatch, "evaluation point != i")
		}
	}
	if len(r.AoutHex) != r.L {
		return Reject(CodeShapeMismatch, "aout rows != L")
	}
	for j := range r.AoutHex {
		if len(r.AoutHex[j]) != r.F+1 {
			return Reject(CodeShapeMismatch, "aout coefficients != f+1")
		}
		for _, p := range r.AoutHex[j] {
			if err := checkPointHex(p); err != nil {
				return err
			}
		}
	}
	if _, err := DecodePointHex(r.ReceiverPK); err != nil {
		return err
	}
	if len(r.ServerPub) != r.N {
		return Reject(CodeShapeMismatch, "server_pub length != n")
	}
	for _, pk := range r.ServerPub {
		b, err := hex.DecodeString(pk)
		if err != nil || len(b) != 32 {
			return Reject(CodeMalformedRecord, "bad ed25519 public key")
		}
	}
	if len(r.TaskCtxHex) == 0 {
		return Reject(CodeMalformedRecord, "empty task_ctx")
	}
	if _, err := decodeFixed(r.AlphaHex, 32); err != nil {
		return err
	}
	if _, err := decodeFixed(r.VKHash, 32); err != nil {
		return err
	}
	if r.MaskCtxLen <= 0 {
		return Reject(CodeShapeMismatch, "maskctx_len must be > 0")
	}
	if r.Constraints <= 0 {
		return Reject(CodeShapeMismatch, "constraints must be > 0")
	}
	return nil
}

func (r *PublicTaskRecord) AoutBytes() ([][][]byte, error) {
	out := make([][][]byte, len(r.AoutHex))
	for j := range r.AoutHex {
		row := make([][]byte, len(r.AoutHex[j]))
		for k, p := range r.AoutHex[j] {
			b, err := DecodePointHex(p)
			if err != nil {
				return nil, err
			}
			row[k] = b
		}
		out[j] = row
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// certificate / finality
// ---------------------------------------------------------------------------

type CertificateRecord struct {
	Schema  string   `json:"schema"`
	TaskID  string   `json:"task_id"`
	AlphaHex string  `json:"alpha_hex"`
	Indices []int    `json:"indices"`
	SigsHex []string `json:"sigs_hex"`
	CertHash string  `json:"cert_hash"`
}

func (c *CertificateRecord) ValidateCertShape(n int) error {
	if c == nil {
		return Reject(CodeInvalidCert, "nil certificate")
	}
	if len(c.Indices) == 0 || len(c.Indices) != len(c.SigsHex) {
		return Reject(CodeInvalidCert, "indices/sigs length mismatch")
	}
	for i, idx := range c.Indices {
		if idx < 0 || idx >= n {
			return Reject(CodeInvalidCert, "index out of range")
		}
		b, err := hex.DecodeString(c.SigsHex[i])
		if err != nil || len(b) != 64 {
			return Reject(CodeInvalidCert, "bad ed25519 signature encoding")
		}
	}
	if _, err := decodeFixed(c.AlphaHex, 32); err != nil {
		return err
	}
	return nil
}

type FinalizedStateRecord struct {
	Schema        string `json:"schema"`
	TaskID        string `json:"task_id"`
	TaskVer       int    `json:"task_version"`
	AlphaHex      string `json:"alpha_hex"`
	Finalized     bool   `json:"finalized"`
	CertHash      string `json:"cert_hash"`
	CertSigsValid int    `json:"cert_valid_endorsements"`
	CertThreshold int    `json:"cert_threshold"`
}

// ---------------------------------------------------------------------------
// accepted delivery
// ---------------------------------------------------------------------------

type AcceptedDeliveryRecord struct {
	Schema    string   `json:"schema"`
	TaskID    string   `json:"task_id"`
	Index     int      `json:"index"` // 1-based
	RHex      string   `json:"r_hex"`
	CHex      []string `json:"c_hex"`
	SigHex    string   `json:"sig_hex"`
	ProofHex  string   `json:"proof_hex"`
	DigestHex string   `json:"digest_hex"` // H(canonical binary payload)
	CertHash  string   `json:"cert_hash"`
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

type SchemeATaskRecord struct {
	Schema      string `json:"schema"`
	TaskID      string `json:"task_id"`
	ProfileID   string `json:"profile_id"`   // P-SA-128 / P-SA-112 / P-SA-256-DIAG
	PrimeBits   int    `json:"prime_bits"`
	PHex        string `json:"p_hex"`
	GHex        string `json:"g_hex"`
	HHex        string `json:"h_hex"`
	K           int    `json:"k"`
	ChunkBits   int    `json:"chunk_bits"`
	W           int    `json:"w"`
	GroupCheck  string `json:"group_membership_check"`
	Servers     int    `json:"servers"`
	ExpectedCommitmentsHex []string `json:"expected_commitments_hex"`
	PublishedByServers     bool     `json:"published_by_servers"`
}

func (r *SchemeATaskRecord) Validate() error {
	if r == nil {
		return Reject(CodeMalformedRecord, "nil scheme A task")
	}
	if r.Schema != SchemaID {
		return Reject(CodeMalformedRecord, "schema mismatch")
	}
	if r.TaskID == "" {
		return Reject(CodeMalformedRecord, "empty task_id")
	}
	if r.K != 256 || r.ChunkBits != 32 || r.W != 8 {
		return Reject(CodeProfileMismatch, fmt.Sprintf("main profile requires k=256,p=32,w=8 (got %d/%d/%d)", r.K, r.ChunkBits, r.W))
	}
	if r.PrimeBits != 3072 && r.PrimeBits != 2048 && r.PrimeBits != 1024 && r.PrimeBits != 256 {
		return Reject(CodeProfileMismatch, "unsupported prime_bits")
	}
	if r.GroupCheck != "qr" && r.GroupCheck != "off" {
		return Reject(CodeProfileMismatch, "group_membership_check must be qr|off")
	}
	if _, err := decodeFixed(r.PHex, (r.PrimeBits+7)/8); err != nil {
		return err
	}
	if _, err := decodeFixed(r.GHex, (r.PrimeBits+7)/8); err != nil {
		return err
	}
	if _, err := decodeFixed(r.HHex, (r.PrimeBits+7)/8); err != nil {
		return err
	}
	if r.Servers <= 0 || len(r.ExpectedCommitmentsHex) != r.Servers {
		return Reject(CodeShapeMismatch, "expected commitments != servers")
	}
	w := (r.PrimeBits + 7) / 8
	for _, c := range r.ExpectedCommitmentsHex {
		if _, err := decodeFixed(c, w); err != nil {
			return err
		}
	}
	if !r.PublishedByServers {
		return Reject(CodeMalformedRecord, "commitments must be published by servers")
	}
	return nil
}

type ZKPoCRecord struct {
	C0 string `json:"c0"`
	C1 string `json:"c1"`
	A0 string `json:"a0"`
	A1 string `json:"a1"`
	H  string `json:"h"`
	D  string `json:"d"`
	F  string `json:"f"`
}

type CiphertextRecord struct {
	C0 string `json:"c0"`
	C1 string `json:"c1"`
}

type SchemeAOutputSubmission struct {
	Schema      string             `json:"schema"`
	TaskID      string             `json:"task_id"`
	ServerIndex int                `json:"server_index"` // 1-based
	Cts         []CiphertextRecord `json:"cts"`
	ZKPoCs      []ZKPoCRecord      `json:"zkpocs"`
}

type AcceptedSchemeAOutput struct {
	Schema      string `json:"schema"`
	TaskID      string `json:"task_id"`
	ServerIndex int    `json:"server_index"`
	DigestHex   string `json:"digest_hex"`
	CtsBytes    int    `json:"cts_bytes"`
	ZKPoCBytes  int    `json:"zkpoc_bytes"`
	GroupCheck  string `json:"group_membership_check"`
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

//	u32 index | 33B R | u32 L | L*(32B C) | u32 |sig| sig | u32 |proof| proof
func CanonicalDeliveryBytes(index int, rHex string, cHex []string, sigHex, proofHex string) ([]byte, error) {
	r, err := DecodePointHex(rHex)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 64+32*len(cHex))
	var u [4]byte
	binary.LittleEndian.PutUint32(u[:], uint32(index))
	out = append(out, u[:]...)
	out = append(out, r...)
	binary.LittleEndian.PutUint32(u[:], uint32(len(cHex)))
	out = append(out, u[:]...)
	for _, c := range cHex {
		b, err := decodeFixed(c, 32)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return nil, Reject(CodeMalformedRecord, "bad sig hex")
	}
	binary.LittleEndian.PutUint32(u[:], uint32(len(sig)))
	out = append(out, u[:]...)
	out = append(out, sig...)
	proof, err := hex.DecodeString(proofHex)
	if err != nil {
		return nil, Reject(CodeMalformedRecord, "bad proof hex")
	}
	binary.LittleEndian.PutUint32(u[:], uint32(len(proof)))
	out = append(out, u[:]...)
	out = append(out, proof...)
	return out, nil
}

func ParseCanonicalDeliveryBytes(b []byte) (index int, rHex string, cHex []string, sigHex, proofHex string, err error) {
	rd := &byteReader{b: b}
	idx, err := rd.u32()
	if err != nil {
		return 0, "", nil, "", "", err
	}
	r, err := rd.nbytes(33)
	if err != nil {
		return 0, "", nil, "", "", err
	}
	l, err := rd.u32()
	if err != nil {
		return 0, "", nil, "", "", err
	}
	if l == 0 || l > 4096 {
		return 0, "", nil, "", "", Reject(CodeShapeMismatch, "bad L in payload")
	}
	cHex = make([]string, l)
	for i := 0; i < int(l); i++ {
		cb, err := rd.nbytes(32)
		if err != nil {
			return 0, "", nil, "", "", err
		}
		cHex[i] = hex.EncodeToString(cb)
	}
	sig, err := rd.varbytes()
	if err != nil {
		return 0, "", nil, "", "", err
	}
	proof, err := rd.varbytes()
	if err != nil {
		return 0, "", nil, "", "", err
	}
	if rd.off != len(b) {
		return 0, "", nil, "", "", Reject(CodeMalformedRecord, "trailing bytes")
	}
	if len(r) != 33 {
		return 0, "", nil, "", "", Reject(CodeNonCanonicalPoint, "bad R length")
	}
	return int(idx), hex.EncodeToString(r), cHex, hex.EncodeToString(sig), hex.EncodeToString(proof), nil
}

//	u32 server_index | u32 w | w*(W0||W1) | w*7*W
func CanonicalSchemeAOutputBytes(s *SchemeAOutputSubmission, elemWidth int) ([]byte, error) {
	if len(s.Cts) != len(s.ZKPoCs) || len(s.Cts) == 0 {
		return nil, Reject(CodeShapeMismatch, "cts/zkpocs length mismatch")
	}
	out := make([]byte, 0, 64+len(s.Cts)*(2+7)*elemWidth)
	var u [4]byte
	binary.LittleEndian.PutUint32(u[:], uint32(s.ServerIndex))
	out = append(out, u[:]...)
	binary.LittleEndian.PutUint32(u[:], uint32(len(s.Cts)))
	out = append(out, u[:]...)
	for i := range s.Cts {
		for _, h := range []string{s.Cts[i].C0, s.Cts[i].C1} {
			b, err := decodeFixed(h, elemWidth)
			if err != nil {
				return nil, err
			}
			out = append(out, b...)
		}
	}
	for i := range s.ZKPoCs {
		for _, h := range []string{s.ZKPoCs[i].C0, s.ZKPoCs[i].C1, s.ZKPoCs[i].A0, s.ZKPoCs[i].A1, s.ZKPoCs[i].H, s.ZKPoCs[i].D, s.ZKPoCs[i].F} {
			b, err := decodeFixed(h, elemWidth)
			if err != nil {
				return nil, err
			}
			out = append(out, b...)
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

func DecodePointHex(h string) ([]byte, error) { return decodeFixed(h, 33) }

func checkPointHex(h string) error {
	b, err := decodeFixed(h, 33)
	if err != nil {
		return err
	}
	if b[0] != 0x02 && b[0] != 0x03 {
		return Reject(CodeNonCanonicalPoint, "point prefix must be 0x02/0x03")
	}
	return nil
}

func decodeFixed(h string, n int) ([]byte, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, Reject(CodeMalformedRecord, "bad hex")
	}
	if len(b) != n {
		return nil, Reject(CodeNonCanonicalScalar, fmt.Sprintf("expected %d bytes got %d", n, len(b)))
	}
	return b, nil
}

func MarshalJSONCanonical(v any) ([]byte, error) { return json.Marshal(v) }

type byteReader struct {
	b   []byte
	off int
}

func (r *byteReader) u32() (uint32, error) {
	if r.off+4 > len(r.b) {
		return 0, Reject(CodeMalformedRecord, "short u32")
	}
	v := binary.LittleEndian.Uint32(r.b[r.off : r.off+4])
	r.off += 4
	return v, nil
}

func (r *byteReader) nbytes(n int) ([]byte, error) {
	if r.off+n > len(r.b) {
		return nil, Reject(CodeMalformedRecord, "short fixed field")
	}
	out := r.b[r.off : r.off+n]
	r.off += n
	return out, nil
}

func (r *byteReader) varbytes() ([]byte, error) {
	n, err := r.u32()
	if err != nil {
		return nil, err
	}
	if n > 1<<20 {
		return nil, Reject(CodeMalformedRecord, "oversized field")
	}
	return r.nbytes(int(n))
}