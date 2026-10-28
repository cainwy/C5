package model


//	E_{i,alpha} = C(F_{i,alpha}, G_{i,alpha}) = g^{F_{i,alpha}} h^{G_{i,alpha}}
type SchemeAInputCommitmentRecord struct {
	Schema string `json:"schema"`
	TaskID string `json:"task_id"`
	PolyCommitmentsHex [][]string `json:"poly_commitments_hex"`
	BeaverCommitmentsHex map[string]BeaverCommitmentSetRecord `json:"beaver_commitments_hex"`
	MulDiffCommitmentsHex map[string]string `json:"mul_diff_commitments_hex"`
}

type BeaverCommitmentSetRecord struct {
	CAHex string `json:"ca_hex"`
	CBHex string `json:"cb_hex"`
	CCHex string `json:"cc_hex"`
}

func (r *SchemeAInputCommitmentRecord) Validate() error {
	if r == nil {
		return Reject(CodeMalformedRecord, "nil input commitment record")
	}
	if r.Schema != SchemaID {
		return Reject(CodeMalformedRecord, "schema mismatch")
	}
	if r.TaskID == "" {
		return Reject(CodeMalformedRecord, "empty task_id")
	}
	if len(r.PolyCommitmentsHex) == 0 {
		return Reject(CodeShapeMismatch, "no polynomial commitments")
	}
	if len(r.BeaverCommitmentsHex) == 0 {
		return Reject(CodeShapeMismatch, "no Beaver commitments")
	}
	if len(r.MulDiffCommitmentsHex) == 0 {
		return Reject(CodeShapeMismatch, "no multiplication-difference commitments")
	}
	return nil
}

// submit d_i and e_i to the blockchain."
type SchemeAMulIntermediateRecord struct {
	Schema      string `json:"schema"`
	TaskID      string `json:"task_id"`
	ServerIndex int    `json:"server_index"` // 1-based

	DHex string `json:"d_hex"`
	EHex string `json:"e_hex"`

	CxHex string `json:"cx_hex"` // g^{x_i} h^{r_{x,i}}
	CaHex string `json:"ca_hex"` // g^{a_i} h^{r_{a,i}}
	CdHex string `json:"cd_hex"` // g^{d_i} h^{delta_i}
	CyHex string `json:"cy_hex"`
	CbHex string `json:"cb_hex"`
	CeHex string `json:"ce_hex"` // g^{e_i} h^{epsilon_i}
}

func (r *SchemeAMulIntermediateRecord) Validate() error {
	if r == nil {
		return Reject(CodeMalformedRecord, "nil multiplication intermediate")
	}
	if r.Schema != SchemaID {
		return Reject(CodeMalformedRecord, "schema mismatch")
	}
	if r.TaskID == "" {
		return Reject(CodeMalformedRecord, "empty task_id")
	}
	if r.ServerIndex < 1 {
		return Reject(CodeInvalidIndex, "server_index must be >= 1")
	}
	for _, h := range []string{r.DHex, r.EHex, r.CxHex, r.CaHex, r.CdHex, r.CyHex, r.CbHex, r.CeHex} {
		if h == "" {
			return Reject(CodeShapeMismatch, "empty field in multiplication intermediate")
		}
	}
	return nil
}

const (
	KeySAInputCommPrefix = "sa_incommit:"
	KeySAMulIntermPrefix = "sa_mulinterm:"
	KeySADerivedCzPrefix = "sa_derivedcz:"
)
