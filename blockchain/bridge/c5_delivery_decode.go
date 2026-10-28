package bridge


import (
	"encoding/hex"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"

	"c5full/internal/c5/host"
	"c5full/internal/c5/m1"
	"c5full/internal/c5/params"

	"c5full/blockchain/fabric/chaincode/model"
)

const MaxProofBytes = 1024

func DecodeDelivery(index int, rHex string, cHex []string, sigHex, proofHex string, taskN, taskL int) (*m1.Delivery, error) {
	if taskN <= 0 || taskL <= 0 {
		return nil, model.Reject(model.CodeShapeMismatch, "bad task shape")
	}
	if index < 1 || index > taskN {
		return nil, model.Reject(model.CodeInvalidIndex, "index out of range")
	}

	rBytes, err := hex.DecodeString(rHex)
	if err != nil {
		return nil, model.Reject(model.CodeMalformedRecord, "R hex decode failed")
	}
	if len(rBytes) != 33 {
		return nil, model.Reject(model.CodeNonCanonicalPoint, "R must be 33 bytes compressed")
	}
	if rBytes[0] != 0x02 && rBytes[0] != 0x03 {
		return nil, model.Reject(model.CodeNonCanonicalPoint, "R prefix must be 0x02/0x03")
	}
	rPt, derr := host.DecodePoint(rBytes, true /* nonidentity */)
	if derr != nil {
		return nil, model.Reject(model.CodeNonCanonicalPoint, "R not a valid curve point")
	}
	if rPt.IsInfinity() || !rPt.IsOnCurve() {
		return nil, model.Reject(model.CodeNonCanonicalPoint, "R is identity or off-curve")
	}

	if len(cHex) != taskL {
		return nil, model.Reject(model.CodeShapeMismatch, "C length != L")
	}
	cVals := make([]*big.Int, taskL)
	for j, ch := range cHex {
		b, err := hex.DecodeString(ch)
		if err != nil || len(b) != 32 {
			return nil, model.Reject(model.CodeNonCanonicalScalar, "C element must be 32 bytes")
		}
		x := new(big.Int).SetBytes(b)
		if x.Cmp(params.Q) >= 0 {
			return nil, model.Reject(model.CodeNonCanonicalScalar, "C element >= q")
		}
		cVals[j] = x
	}

	// ---- sig / proof ----------------------------------------------------
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return nil, model.Reject(model.CodeMalformedRecord, "sig hex decode failed")
	}
	if len(sig) != 64 {
		return nil, model.Reject(model.CodeInvalidSignature, "signature must be 64 bytes")
	}
	proof, err := hex.DecodeString(proofHex)
	if err != nil {
		return nil, model.Reject(model.CodeMalformedRecord, "proof hex decode failed")
	}
	if len(proof) == 0 || len(proof) > MaxProofBytes {
		return nil, model.Reject(model.CodeInvalidProof, "proof length out of range")
	}

	return &m1.Delivery{
		I:        index - 1,
		R:        rPt,
		C:        cVals,
		Sig:      sig,
		Proof:    proof,
		HasProof: true,
	}, nil
}

func DecodeDeliveryFromModel(rec *model.AcceptedDeliveryRecord, taskN, taskL int) (*m1.Delivery, error) {
	if rec == nil {
		return nil, model.Reject(model.CodeMalformedRecord, "nil delivery record")
	}
	return DecodeDelivery(rec.Index, rec.RHex, rec.CHex, rec.SigHex, rec.ProofHex, taskN, taskL)
}

func DeliveryToModel(d *m1.Delivery, taskID, certHash, digestHex string) (*model.AcceptedDeliveryRecord, error) {
	if d == nil || d.R == nil {
		return nil, model.Reject(model.CodeMalformedRecord, "nil delivery")
	}
	rBytes := host.EncodePointAllowInf(d.R)
	if len(rBytes) != 33 {
		return nil, model.Reject(model.CodeNonCanonicalPoint, "delivery R is not an ordinary point")
	}
	rec := &model.AcceptedDeliveryRecord{
		Schema:    model.SchemaID,
		TaskID:    taskID,
		Index:     d.I + 1,
		RHex:      hex.EncodeToString(rBytes),
		CHex:      make([]string, len(d.C)),
		SigHex:    hex.EncodeToString(d.Sig),
		ProofHex:  hex.EncodeToString(d.Proof),
		DigestHex: digestHex,
		CertHash:  certHash,
	}
	for j, c := range d.C {
		rec.CHex[j] = hex.EncodeToString(fieldBytes32(c))
	}
	return rec, nil
}

func fieldBytes32(x *big.Int) []byte {
	b := make([]byte, 32)
	new(big.Int).Mod(x, params.Q).FillBytes(b)
	return b
}

var _ = func(d *m1.Delivery) *secp256k1.G1Affine { return d.R }