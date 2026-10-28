package harness


import (
	"encoding/hex"
	"fmt"
	"sort"

	"c5full/blockchain/fabric/chaincode/model"
)

type CaseResult struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Scheme      string `json:"scheme"`
	Expectation string `json:"expectation"`
	Observed    string `json:"observed"`
	Pass        bool   `json:"pass"`
	Detail      string `json:"detail,omitempty"`
	Note        string `json:"note,omitempty"`
}

type Matrix struct {
	Cases  []CaseResult `json:"cases"`
	Passed int          `json:"passed"`
	Failed int          `json:"failed"`
}

func (m *Matrix) Add(r CaseResult) {
	if r.Pass {
		m.Passed++
	} else {
		m.Failed++
	}
	m.Cases = append(m.Cases, r)
}

func (m *Matrix) OK() bool { return m.Failed == 0 }

func (m *Matrix) Codes() []string {
	set := map[string]bool{}
	for _, c := range m.Cases {
		if c.Observed != "" {
			set[c.Observed] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (m *Matrix) FailedIDs() []string {
	out := []string{}
	for _, c := range m.Cases {
		if !c.Pass {
			out = append(out, c.ID)
		}
	}
	sort.Strings(out)
	return out
}

func codeOf(err error) string {
	if err == nil {
		return ""
	}
	if re, ok := model.IsReject(err); ok {
		return re.Code
	}
	return "ERR:" + err.Error()
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func guard(f func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("PANIC: %v", r)
		}
	}()
	return f()
}

func expectReject(m *Matrix, id, cat, scheme, wantCode string, f func() error, note string) {
	err := guard(f)
	got := codeOf(err)
	pass := err != nil && (wantCode == "" || got == wantCode)
	m.Add(CaseResult{
		ID: id, Category: cat, Scheme: scheme,
		Expectation: "reject(" + wantCode + ")", Observed: got, Pass: pass,
		Detail: errString(err), Note: note,
	})
}

func expectOK(m *Matrix, id, cat, scheme string, f func() error, note string) {
	err := guard(f)
	m.Add(CaseResult{
		ID: id, Category: cat, Scheme: scheme,
		Expectation: "accept", Observed: codeOf(err), Pass: err == nil,
		Detail: errString(err), Note: note,
	})
}

func mergeMatrix(dst, src *Matrix) {
	for _, c := range src.Cases {
		dst.Add(c)
	}
}

func mustHex(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic("harness: bad hex")
	}
	return b
}

func hexList(c []string) [][]byte {
	out := make([][]byte, len(c))
	for i := range c {
		out[i] = mustHex(c[i])
	}
	return out
}

func decodeSigs(c *model.CertificateRecord) [][]byte {
	out := make([][]byte, len(c.SigsHex))
	for i := range c.SigsHex {
		out[i] = mustHex(c.SigsHex[i])
	}
	return out
}

func intPtr(i int) *int { return &i }

func strPtr(s string) *string { return &s }

func truncate(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16] + "..."
}

func baseProofHex(d C5Delivery) string {
	_, _, _, _, proofHex, err := model.ParseCanonicalDeliveryBytes(mustHex(d.PayloadHex))
	if err != nil {
		return ""
	}
	return proofHex
}

func baseSigHex(d C5Delivery) string {
	_, _, _, sigHex, _, err := model.ParseCanonicalDeliveryBytes(mustHex(d.PayloadHex))
	if err != nil {
		return ""
	}
	return sigHex
}