package bridge


import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"c5full/internal/c5/host"
	"c5full/internal/c5/m1"
	"c5full/internal/c5/params"

	"c5full/blockchain/fabric/chaincode/model"
)

func sampleDeliveryHex(t *testing.T) (index int, rHex string, cHex []string, sigHex string) {
	t.Helper()
	tr, err := m1.NewTaskWithRNG(3, 1, 1, "decoder", strings.NewReader(strings.Repeat("A", 4096)))
	if err != nil {
		t.Fatalf("task: %v", err)
	}
	d := tr.MakeDeliveryWithRNG(0, strings.NewReader(strings.Repeat("B", 4096)))
	rec := m1.PublicDelivery(d)
	return rec.Index, hex.EncodeToString(rec.R), hexListOf(rec.C), hex.EncodeToString(rec.Sig)
}

func hexListOf(c [][]byte) []string {
	out := make([]string, len(c))
	for i := range c {
		out[i] = hex.EncodeToString(c[i])
	}
	return out
}

func TestDecodeDeliveryHappyPath(t *testing.T) {
	idx, rHex, cHex, sigHex := sampleDeliveryHex(t)
	d, err := DecodeDelivery(idx, rHex, cHex, sigHex, "00", 3, 1)
	if err != nil {
		t.Fatalf("unexpected reject: %v", err)
	}
	if d.R.IsInfinity() {
		t.Fatal("R must be set to the decoded point (upstream Restore bug must not be reproduced)")
	}
	if want, err := host.DecodePoint(mustHex(t, rHex), true); err != nil || !host.PointEqual(d.R, want) {
		t.Fatal("decoded R must equal the encoded point")
	}
}

func TestDecodeDeliveryRejectMatrix(t *testing.T) {
	idx, rHex, cHex, sigHex := sampleDeliveryHex(t)
	off := offCurvePointHex(t)
	if _, err := host.DecodePoint(mustHex(t, off), true); err == nil {
		t.Fatalf("test fixture bug: %s is actually on the curve", off)
	}
	cases := []struct {
		name     string
		index    int
		rHex     string
		cHex     []string
		sigHex   string
		proofHex string
		want     string
	}{
		{"index zero", 0, rHex, cHex, sigHex, "00", model.CodeInvalidIndex},
		{"index too large", 4, rHex, cHex, sigHex, "00", model.CodeInvalidIndex},
		{"r infinity", idx, strings.Repeat("00", 33), cHex, sigHex, "00", model.CodeNonCanonicalPoint},
		{"r wrong prefix", idx, "04" + strings.Repeat("11", 32), cHex, sigHex, "00", model.CodeNonCanonicalPoint},
		{"r short", idx, strings.Repeat("02", 32), cHex, sigHex, "00", model.CodeNonCanonicalPoint},
		{"r off curve", idx, off, cHex, sigHex, "00", model.CodeNonCanonicalPoint},
		{"c count", idx, rHex, []string{cHex[0], cHex[0]}, sigHex, "00", model.CodeShapeMismatch},
		{"c range", idx, rHex, []string{strings.Repeat("ff", 32)}, sigHex, "00", model.CodeNonCanonicalScalar},
		{"c short", idx, rHex, []string{strings.Repeat("11", 31)}, sigHex, "00", model.CodeNonCanonicalScalar},
		{"sig length", idx, rHex, cHex, strings.Repeat("11", 63), "00", model.CodeInvalidSignature},
		{"sig hex", idx, rHex, cHex, "zz", "00", model.CodeMalformedRecord},
		{"proof empty", idx, rHex, cHex, sigHex, "", model.CodeInvalidProof},
		{"proof oversized", idx, rHex, cHex, sigHex, strings.Repeat("aa", MaxProofBytes+2), model.CodeInvalidProof},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("decoder must never panic, got %v", r)
				}
			}()
			_, err := DecodeDelivery(tc.index, tc.rHex, tc.cHex, tc.sigHex, tc.proofHex, 3, 1)
			if err == nil {
				t.Fatalf("expected reject %s, got accept", tc.want)
			}
			re, ok := model.IsReject(err)
			if !ok {
				t.Fatalf("expected *model.RejectError, got %T: %v", err, err)
			}
			if re.Code != tc.want {
				t.Fatalf("expected code %s, got %s (%s)", tc.want, re.Code, re.Detail)
			}
		})
	}
}

func TestUpstreamRestoreBugEvidence(t *testing.T) {
	tr, err := m1.NewTaskWithRNG(3, 1, 1, "decoder", strings.NewReader(strings.Repeat("A", 4096)))
	if err != nil {
		t.Fatalf("task: %v", err)
	}
	d := tr.MakeDeliveryWithRNG(0, strings.NewReader(strings.Repeat("B", 4096)))
	rec := m1.PublicDelivery(d)
	restored := tr.Restore(rec)
	if restored == nil || restored.R == nil {
		t.Fatal("upstream Restore returned nil")
	}
	if !restored.R.IsInfinity() {
		t.Skip("RESTORE-FIXED-UPSTREAM: upstream now assigns the decoded point; bridge decoder still used for canonical-only parsing")
	}
	if restored.HasProof != (rec.Proof != nil) {
		t.Fatal("has-proof flag mismatch")
	}
}

func TestSchemeAEncodeDecodeRoundTrip(t *testing.T) {
	width := WidthForPrimeBits(3072)
	x := new(big.Int).Sub(params.Q, big.NewInt(1))
	h := EncodeSchemeAElement(x, width)
	if len(h) != width*2 {
		t.Fatalf("encoded length = %d, want %d", len(h), width*2)
	}
	got, err := DecodeSchemeAElement(h, width)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Cmp(x) != 0 {
		t.Fatal("round-trip mismatch")
	}
	if _, err := DecodeSchemeAElement(h[2:], width); err == nil {
		t.Fatal("short encoding must be rejected")
	}
}

func mustHex(t *testing.T, h string) []byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

func offCurvePointHex(t *testing.T) string {
	t.Helper()
	for x := int64(1); x < 100000; x++ {
		b := make([]byte, 33)
		b[0] = 0x02
		new(big.Int).SetInt64(x).FillBytes(b[1:])
		if _, err := host.DecodePoint(b, true); err != nil {
			return hex.EncodeToString(b)
		}
	}
	t.Fatal("no off-curve x found (unexpected)")
	return ""
}