package bridge

//	∏_j C1_j^{2^{j·chunkBits}}  ==  C_share        (mod P)

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"strconv"

	"c5full/internal/mpc/schemea"

	"c5full/blockchain/fabric/chaincode/model"
)

type SAPublicParams struct {
	Params *schemea.Params
	GroupCheck string
}

func SAParamsFromRecord(rec *model.SchemeATaskRecord) (*SAPublicParams, error) {
	return saParamsFromRecord(rec, true)
}

func SAParamsFromRecordRegistered(rec *model.SchemeATaskRecord) (*SAPublicParams, error) {
	return saParamsFromRecord(rec, false)
}

func saParamsFromRecord(rec *model.SchemeATaskRecord, staticGroupValidation bool) (*SAPublicParams, error) {
	if err := rec.Validate(); err != nil {
		return nil, err
	}
	w := WidthForPrimeBits(rec.PrimeBits)
	P, err := decodeFixedBig(rec.PHex, w)
	if err != nil {
		return nil, err
	}
	G, err := decodeFixedBig(rec.GHex, w)
	if err != nil {
		return nil, err
	}
	H, err := decodeFixedBig(rec.HHex, w)
	if err != nil {
		return nil, err
	}
	if staticGroupValidation {
		if !schemea.ValidateGroup(P, G) {
			return nil, model.Reject(model.CodeMalformedGroup, "invalid (P,g) group")
		}
	} else {
		if P.Sign() <= 0 || G.Cmp(big.NewInt(1)) <= 0 || G.Cmp(P) >= 0 || H.Sign() <= 0 || H.Cmp(P) >= 0 {
			return nil, model.Reject(model.CodeMalformedGroup, "group element out of range")
		}
	}
	p := &schemea.Params{
		P: P, G: G, H: H,
		S:         nil,
		K:         rec.K,
		ChunkBits: rec.ChunkBits,
		NumChunks: rec.K / rec.ChunkBits,
		PrimeBits: rec.PrimeBits,
	}
	if p.NumChunks != rec.W {
		return nil, model.Reject(model.CodeShapeMismatch, "w != k/chunk_bits")
	}
	return &SAPublicParams{Params: p, GroupCheck: rec.GroupCheck}, nil
}

func SchemeAParamsHash(rec *model.SchemeATaskRecord) string {
	h := sha256.New()
	h.Write([]byte("SA-PARAMS/v1"))
	for _, s := range []string{
		rec.ProfileID, rec.PHex, rec.GHex, rec.HHex, rec.GroupCheck,
		strconv.Itoa(rec.PrimeBits), strconv.Itoa(rec.K),
		strconv.Itoa(rec.ChunkBits), strconv.Itoa(rec.W), strconv.Itoa(rec.Servers),
	} {
		h.Write([]byte{0x00})
		h.Write([]byte(s))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func WidthForPrimeBits(bits int) int { return (bits + 7) / 8 }

func WeightedCiphertextProduct(p *schemea.Params, cts []*schemea.Ciphertext) (*big.Int, error) {
	if len(cts) == 0 {
		return nil, model.Reject(model.CodeShapeMismatch, "empty ciphertext list")
	}
	prod := big.NewInt(1)
	for j := 0; j < len(cts); j++ {
		if cts[j] == nil || cts[j].C0 == nil || cts[j].C1 == nil {
			return nil, model.Reject(model.CodeMalformedGroup, "nil ciphertext element")
		}
		exp := new(big.Int).Lsh(big.NewInt(1), uint(j*p.ChunkBits))
		term := new(big.Int).Exp(cts[j].C1, exp, p.P)
		prod.Mul(prod, term)
		prod.Mod(prod, p.P)
	}
	return prod, nil
}

func VerifyCiphertextsAgainstCommitment(p *schemea.Params, cts []*schemea.Ciphertext, expectedCommitment *big.Int) (bool, error) {
	if expectedCommitment == nil || expectedCommitment.Sign() <= 0 || expectedCommitment.Cmp(p.P) >= 0 {
		return false, model.Reject(model.CodeCommitmentMismatch, "expected commitment out of range")
	}
	prod, err := WeightedCiphertextProduct(p, cts)
	if err != nil {
		return false, err
	}
	return prod.Cmp(expectedCommitment) == 0, nil
}

func GroupMembershipOK(p *schemea.Params, x *big.Int) bool {
	if x == nil || x.Sign() <= 0 || x.Cmp(p.P) >= 0 {
		return false
	}
	q := new(big.Int).Rsh(new(big.Int).Sub(p.P, big.NewInt(1)), 1)
	return new(big.Int).Exp(x, q, p.P).Cmp(big.NewInt(1)) == 0
}

var ErrZKPoCCiphertextMismatch = errors.New("bridge: zkpoc not bound to ciphertext")

func VerifyZKPoCsBoundToCiphertexts(sp *SAPublicParams, cts []*schemea.Ciphertext, pfs []*schemea.ZKPoC, groupOrder *big.Int) (int, error) {
	if len(cts) != len(pfs) || len(cts) == 0 {
		return 0, model.Reject(model.CodeShapeMismatch, "cts/zkpoc count mismatch")
	}
	for j := range cts {
		pf := pfs[j]
		if pf == nil {
			return 0, model.Reject(model.CodeInvalidZKPoC, "nil zkpoc")
		}
		if pf.C0.Cmp(cts[j].C0) != 0 || pf.C1.Cmp(cts[j].C1) != 0 {
			return 0, model.Reject(model.CodeInvalidZKPoC, "zkpoc transcript not bound to ciphertext")
		}
		if !sp.Params.VerifyZKPoC(pf, groupOrder) {
			return 0, model.Reject(model.CodeInvalidZKPoC, "VerifyZKPoC failed")
		}
	}
	return len(cts), nil
}

func EncodeSchemeAElement(x *big.Int, width int) string {
	b := make([]byte, width)
	if x != nil {
		new(big.Int).Mod(x, new(big.Int).Lsh(big.NewInt(1), uint(8*width))).FillBytes(b)
	}
	return hex.EncodeToString(b)
}

func DecodeSchemeAElement(h string, width int) (*big.Int, error) {
	b, err := decodeFixedBytes(h, width)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

func SubmissionFromEncrypt(taskID string, serverIdx1Based int, cts []*schemea.Ciphertext, pfs []*schemea.ZKPoC, width int) (*model.SchemeAOutputSubmission, error) {
	if len(cts) != len(pfs) || len(cts) == 0 {
		return nil, model.Reject(model.CodeShapeMismatch, "cts/zkpoc count mismatch")
	}
	s := &model.SchemeAOutputSubmission{
		Schema:      model.SchemaID,
		TaskID:      taskID,
		ServerIndex: serverIdx1Based,
		Cts:         make([]model.CiphertextRecord, len(cts)),
		ZKPoCs:      make([]model.ZKPoCRecord, len(pfs)),
	}
	for j := range cts {
		s.Cts[j] = model.CiphertextRecord{
			C0: EncodeSchemeAElement(cts[j].C0, width),
			C1: EncodeSchemeAElement(cts[j].C1, width),
		}
		pf := pfs[j]
		s.ZKPoCs[j] = model.ZKPoCRecord{
			C0: EncodeSchemeAElement(pf.C0, width),
			C1: EncodeSchemeAElement(pf.C1, width),
			A0: EncodeSchemeAElement(pf.A0, width),
			A1: EncodeSchemeAElement(pf.A1, width),
			H:  EncodeSchemeAElement(pf.H, width),
			D:  EncodeSchemeAElement(pf.D, width),
			F:  EncodeSchemeAElement(pf.F, width),
		}
	}
	return s, nil
}

func DecodeSchemeAOutput(s *model.SchemeAOutputSubmission, width int) ([]*schemea.Ciphertext, []*schemea.ZKPoC, error) {
	if s == nil {
		return nil, nil, model.Reject(model.CodeMalformedRecord, "nil submission")
	}
	if len(s.Cts) == 0 || len(s.Cts) != len(s.ZKPoCs) {
		return nil, nil, model.Reject(model.CodeShapeMismatch, "cts/zkpoc count mismatch")
	}
	cts := make([]*schemea.Ciphertext, len(s.Cts))
	for j := range s.Cts {
		c0, err := DecodeSchemeAElement(s.Cts[j].C0, width)
		if err != nil {
			return nil, nil, err
		}
		c1, err := DecodeSchemeAElement(s.Cts[j].C1, width)
		if err != nil {
			return nil, nil, err
		}
		if c0.Sign() == 0 || c1.Sign() == 0 {
			return nil, nil, model.Reject(model.CodeMalformedGroup, "zero group element")
		}
		cts[j] = &schemea.Ciphertext{C0: c0, C1: c1}
	}
	pfs := make([]*schemea.ZKPoC, len(s.ZKPoCs))
	for j := range s.ZKPoCs {
		r := s.ZKPoCs[j]
		vals := make([]*big.Int, 7)
		for k, h := range []string{r.C0, r.C1, r.A0, r.A1, r.H, r.D, r.F} {
			v, err := DecodeSchemeAElement(h, width)
			if err != nil {
				return nil, nil, err
			}
			vals[k] = v
		}
		pfs[j] = &schemea.ZKPoC{C0: vals[0], C1: vals[1], A0: vals[2], A1: vals[3], H: vals[4], D: vals[5], F: vals[6]}
	}
	return cts, pfs, nil
}

// ---- helpers --------------------------------------------------------------

func decodeFixedBig(h string, width int) (*big.Int, error) { return DecodeSchemeAElement(h, width) }

func decodeFixedBytes(h string, n int) ([]byte, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, model.Reject(model.CodeMalformedRecord, "bad hex")
	}
	if len(b) != n {
		return nil, model.Reject(model.CodeNonCanonicalScalar, "wrong fixed width")
	}
	return b, nil
}