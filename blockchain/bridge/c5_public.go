package bridge

//	ReceiverX  == nil
//	ServerPriv == nil
//	Outputs    == nil

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"

	"c5full/internal/c5/host"
	"c5full/internal/c5/m1"

	"c5full/blockchain/fabric/chaincode/model"
)

var ErrNotPublicOnly = errors.New("bridge: task is not public-only")

func RebuildPublicTask(rec *model.PublicTaskRecord, finalizedAlphaHex *string) (*m1.Task, error) {
	if err := rec.Validate(); err != nil {
		return nil, err
	}
	xi := make([]*big.Int, rec.N)
	for i, s := range rec.XiDec {
		x, ok := new(big.Int).SetString(s, 10)
		if !ok {
			return nil, model.Reject(model.CodeMalformedRecord, "bad xi")
		}
		xi[i] = x
	}
	pkBytes, err := model.DecodePointHex(rec.ReceiverPK)
	if err != nil {
		return nil, err
	}
	pkR, err := host.DecodePoint(pkBytes, true)
	if err != nil {
		return nil, model.Reject(model.CodeNonCanonicalPoint, "receiver PK not on curve")
	}
	aout := make([][]*secp256k1.G1Affine, rec.L)
	for j := range rec.AoutHex {
		aout[j] = make([]*secp256k1.G1Affine, len(rec.AoutHex[j]))
		for k, h := range rec.AoutHex[j] {
			b, err := model.DecodePointHex(h)
			if err != nil {
				return nil, err
			}
			p, err := host.DecodePoint(b, true)
			if err != nil {
				return nil, model.Reject(model.CodeNonCanonicalPoint, "aout point not on curve")
			}
			aout[j][k] = p
		}
	}
	taskCtx, err := hex.DecodeString(rec.TaskCtxHex)
	if err != nil {
		return nil, model.Reject(model.CodeMalformedRecord, "task_ctx hex decode failed")
	}
	alpha, err := hex.DecodeString(rec.AlphaHex)
	if err != nil || len(alpha) != 32 {
		return nil, model.Reject(model.CodeMalformedRecord, "alpha must be 32 bytes")
	}
	pubs := make([]ed25519.PublicKey, rec.N)
	for i, h := range rec.ServerPub {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, model.Reject(model.CodeMalformedRecord, "bad server public key")
		}
		pubs[i] = ed25519.PublicKey(b)
	}

	t := &m1.Task{
		N: rec.N, F: rec.F, L: rec.L,
		Seed:       rec.Tau,
		Xi:         xi,
		ReceiverPK: pkR,
		Aout:       aout,
		TaskCtx:    taskCtx,
		Alpha:      alpha,
		TaskVer:    rec.TaskVer,
		ServerPub:  pubs,
		ReceiverX:  nil,
		ServerPriv: nil,
		Outputs:    nil,
	}
	t.Finality = m1.NewFinalityRecord(rec.TaskVer)
	if finalizedAlphaHex != nil {
		if *finalizedAlphaHex != rec.AlphaHex {
			return nil, model.Reject(model.CodeAlphaMismatch, "ledger finality alpha != registered alpha")
		}
		if !t.Finality.Finalize(rec.AlphaHex) {
			return nil, model.Reject(model.CodeFinalityConflict, "finality record rejected alpha")
		}
	}
	if err := assertPublicOnly(t); err != nil {
		return nil, err
	}
	return t, nil
}

func assertPublicOnly(t *m1.Task) error {
	if t.ReceiverX != nil || t.ServerPriv != nil || t.Outputs != nil {
		return ErrNotPublicOnly
	}
	return nil
}

func VerifyRegisteredCtx(rec *model.PublicTaskRecord) error {
	t, err := RebuildPublicTask(rec, nil)
	if err != nil {
		return err
	}
	want := host.EncodeC5E1([][2]string{
		{"pid", "C5"}, {"ver", "\x00\x01"}, {"domainId", "post-mpc-delivery"},
		{"tau", rec.Tau}, {"taskVersion", string(host.U32Bytes(rec.TaskVer))}, {"serverSetId", "srvset"},
		{"receiverId", "rcvr"}, {"PK_R", string(host.EncodePoint(t.ReceiverPK, false))},
		{"n", string(host.U32Bytes(rec.N))}, {"f", string(host.U32Bytes(rec.F))}, {"L", string(host.U32Bytes(rec.L))},
		{"paramSetId", rec.ParamSetID},
		{"deliveryProfileId", rec.ProfileID},
	})
	if !bytesEqual(want, t.TaskCtx) {
		return model.Reject(model.CodeShapeMismatch, "task_ctx mismatch vs canonical reconstruction")
	}
	gotAlpha := host.HashState(t.TaskCtx, t.Aout)
	if !bytesEqual(gotAlpha, t.Alpha) {
		return model.Reject(model.CodeAlphaMismatch, "alpha != H(DST||TaskCtx||Aout)")
	}
	if len(t.MaskCtxFor(1)) != rec.MaskCtxLen {
		return model.Reject(model.CodeProfileMismatch, "maskctx length drift")
	}
	return nil
}

func PublicTaskRecordFromTask(t *m1.Task, taskID, vkID, vkHash string, maskCtxLen, constraints int) (*model.PublicTaskRecord, error) {
	if t == nil || t.ReceiverPK == nil {
		return nil, model.Reject(model.CodeMalformedRecord, "nil task")
	}
	rec := &model.PublicTaskRecord{
		Schema:      model.SchemaID,
		TaskID:      taskID,
		TaskVer:     t.TaskVer,
		N:           t.N,
		F:           t.F,
		L:           t.L,
		Tau:         t.Seed,
		TaskCtxHex:  hex.EncodeToString(t.TaskCtx),
		AlphaHex:    hex.EncodeToString(t.Alpha),
		ReceiverPK:  hex.EncodeToString(host.EncodePoint(t.ReceiverPK, false)),
		XiDec:       make([]string, t.N),
		AoutHex:     make([][]string, t.L),
		ServerPub:   make([]string, t.N),
		ParamSetID:  "secp256k1-rfc9380xmd-v1",
		ProfileID:   "gnark-v0.15.0-groth16-bls12-381-v1",
		VKID:        vkID,
		VKHash:      vkHash,
		MaskCtxLen:  maskCtxLen,
		Constraints: constraints,
	}
	for i := 0; i < t.N; i++ {
		rec.XiDec[i] = t.Xi[i].String()
		rec.ServerPub[i] = hex.EncodeToString(t.ServerPub[i])
	}
	for j := 0; j < t.L; j++ {
		rec.AoutHex[j] = make([]string, len(t.Aout[j]))
		for k, p := range t.Aout[j] {
			rec.AoutHex[j][k] = hex.EncodeToString(host.EncodePoint(p, false))
		}
	}
	if err := rec.Validate(); err != nil {
		return nil, err
	}
	return rec, nil
}

func CertificateFromTask(t *m1.Task, indices []int) (*model.CertificateRecord, error) {
	if t == nil {
		return nil, model.Reject(model.CodeMalformedRecord, "nil task")
	}
	sigs := make([]string, len(indices))
	for k, i := range indices {
		if i < 0 || i >= t.N || t.Endorsements[i] == nil {
			return nil, model.Reject(model.CodeInvalidCert, "missing endorsement")
		}
		sigs[k] = hex.EncodeToString(t.Endorsements[i])
	}
	c := &model.CertificateRecord{
		Schema:   model.SchemaID,
		TaskID:   "",
		AlphaHex: hex.EncodeToString(t.Alpha),
		Indices:  append([]int(nil), indices...),
		SigsHex:  sigs,
	}
	c.CertHash = CertHash(c)
	return c, nil
}

func CertHash(c *model.CertificateRecord) string {
	h := sha256.Sum256(certCanonicalBytes(c))
	return hex.EncodeToString(h[:])
}

func certCanonicalBytes(c *model.CertificateRecord) []byte {
	out := []byte("C5-BC-CERT/v1")
	out = append(out, 0x00)
	out = append(out, []byte(c.TaskID)...)
	out = append(out, 0x00)
	ab, _ := hex.DecodeString(c.AlphaHex)
	out = append(out, ab...)
	for i, idx := range c.Indices {
		out = append(out, host.U32Bytes(idx)...)
		sb, _ := hex.DecodeString(c.SigsHex[i])
		out = append(out, host.U32Bytes(len(sb))...)
		out = append(out, sb...)
	}
	return out
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func CertIndexSet(c *model.CertificateRecord) map[int]bool {
	m := map[int]bool{}
	for _, i := range c.Indices {
		m[i] = true
	}
	return m
}