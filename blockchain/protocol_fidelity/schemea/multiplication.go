package schemea

import (
	"errors"
	"fmt"
	"math/big"

	"c5full/internal/mpc/schemea"
)

var (
	ErrMulShape        = errors.New("sa-fidelity: multiplication intermediate shape invalid")
	ErrMulEq17Commit   = errors.New("sa-fidelity: Eq.(17) commitment relation failed")
	ErrMulEq16Derive   = errors.New("sa-fidelity: Eq.(16) output commitment derivation failed")
	ErrMulMissingState = errors.New("sa-fidelity: required on-chain commitment state missing")
	ErrMulDupServer    = errors.New("sa-fidelity: duplicate server index")
	ErrMulBadIndex     = errors.New("sa-fidelity: server index out of range")
)

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

//	d_i = s_{alpha,i} - a_i
//	e_i = s_{beta,i} - b_i
type MulIntermediate struct {
	Schema      string `json:"schema"`
	TaskID      string `json:"task_id"`
	ServerIndex int    `json:"server_index"`

	DHex string `json:"d_hex"`
	EHex string `json:"e_hex"`

	CxHex string `json:"cx_hex"`
	CaHex string `json:"ca_hex"`
	CdHex string `json:"cd_hex"`
	CyHex string `json:"cy_hex"`
	CbHex string `json:"cb_hex"`
	CeHex string `json:"ce_hex"`
}

type MulState struct {
	Params *schemea.Params
	CC map[int]*big.Int
	CDe map[int]*big.Int
}

func PedersenCommit(p *schemea.Params, v, r *big.Int) (*big.Int, error) {
	if p == nil || p.P == nil || p.G == nil || p.H == nil {
		return nil, fmt.Errorf("%w: nil params", ErrMulShape)
	}
	if v == nil || r == nil {
		return nil, fmt.Errorf("%w: nil value/blinding", ErrMulShape)
	}
	gv := new(big.Int).Exp(p.G, v, p.P)
	hr := new(big.Int).Exp(p.H, r, p.P)
	out := new(big.Int).Mul(gv, hr)
	out.Mod(out, p.P)
	return out, nil
}

func MulMod(p *schemea.Params, a, b *big.Int) *big.Int {
	out := new(big.Int).Mul(a, b)
	return out.Mod(out, p.P)
}

//	cx_i ?= ca_i · cd_i
//	cy_i ?= cb_i · ce_i
func VerifyEq17(p *schemea.Params, m *MulIntermediate) (bool, error) {
	if err := checkMulShape(p, m); err != nil {
		return false, err
	}
	cx, err := decodeElem(m.CxHex, p)
	if err != nil {
		return false, err
	}
	ca, err := decodeElem(m.CaHex, p)
	if err != nil {
		return false, err
	}
	cd, err := decodeElem(m.CdHex, p)
	if err != nil {
		return false, err
	}
	cy, err := decodeElem(m.CyHex, p)
	if err != nil {
		return false, err
	}
	cb, err := decodeElem(m.CbHex, p)
	if err != nil {
		return false, err
	}
	ce, err := decodeElem(m.CeHex, p)
	if err != nil {
		return false, err
	}

	// cx_i ?= ca_i · cd_i
	if MulMod(p, ca, cd).Cmp(cx) != 0 {
		return false, fmt.Errorf("%w: cx != ca*cd (server %d)", ErrMulEq17Commit, m.ServerIndex)
	}
	// cy_i ?= cb_i · ce_i
	if MulMod(p, cb, ce).Cmp(cy) != 0 {
		return false, fmt.Errorf("%w: cy != cb*ce (server %d)", ErrMulEq17Commit, m.ServerIndex)
	}
	return true, nil
}

//	cz_i = cc_i · cea_i · cdb_i · c(de)_i
//	cdb_i = cb_i^{d_i}
func VerifyEq16(p *schemea.Params, m *MulIntermediate, st *MulState) (*big.Int, error) {
	if err := checkMulShape(p, m); err != nil {
		return nil, err
	}
	if st == nil {
		return nil, fmt.Errorf("%w: nil MulState", ErrMulMissingState)
	}
	d, err := decodeScalar(m.DHex)
	if err != nil {
		return nil, err
	}
	e, err := decodeScalar(m.EHex)
	if err != nil {
		return nil, err
	}
	ca, err := decodeElem(m.CaHex, p)
	if err != nil {
		return nil, err
	}
	cb, err := decodeElem(m.CbHex, p)
	if err != nil {
		return nil, err
	}

	cc, ok := st.CC[m.ServerIndex]
	if !ok || cc == nil {
		return nil, fmt.Errorf("%w: cc_%d", ErrMulMissingState, m.ServerIndex)
	}
	cde, ok := st.CDe[m.ServerIndex]
	if !ok || cde == nil {
		return nil, fmt.Errorf("%w: c(de)_%d", ErrMulMissingState, m.ServerIndex)
	}

	// cea_i = ca_i^{e_i}
	cea := new(big.Int).Exp(ca, e, p.P)
	// cdb_i = cb_i^{d_i}
	cdb := new(big.Int).Exp(cb, d, p.P)

	// cz_i = cc_i · cea_i · cdb_i · c(de)_i
	cz := MulMod(p, cc, cea)
	cz = MulMod(p, cz, cdb)
	cz = MulMod(p, cz, cde)

	if cz.Sign() == 0 {
		return nil, fmt.Errorf("%w: degenerate cz", ErrMulEq16Derive)
	}
	return cz, nil
}

//	cz_i = cx_i · cy_i
func VerifyAdditionEq15(p *schemea.Params, cxHex, cyHex string) (*big.Int, error) {
	if p == nil || p.P == nil {
		return nil, fmt.Errorf("%w: nil params", ErrMulShape)
	}
	cx, err := decodeElem(cxHex, p)
	if err != nil {
		return nil, err
	}
	cy, err := decodeElem(cyHex, p)
	if err != nil {
		return nil, err
	}
	cz := MulMod(p, cx, cy)
	if cz.Sign() == 0 {
		return nil, fmt.Errorf("%w: degenerate cz (addition)", ErrMulEq16Derive)
	}
	return cz, nil
}

func DeriveOutputCommitmentChain(p *schemea.Params, m *MulIntermediate, st *MulState) (*big.Int, error) {
	ok, err := VerifyEq17(p, m)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrMulEq17Commit
	}
	return VerifyEq16(p, m, st)
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

//	E_{i,alpha} = C(F_{i,alpha}, G_{i,alpha}) = g^{F_{i,alpha}} h^{G_{i,alpha}}
type InputCommitments struct {
	Schema string `json:"schema"`
	TaskID string `json:"task_id"`
	// PolyCommitmentsHex[client][alpha] = E_{i,alpha}
	PolyCommitmentsHex [][]string `json:"poly_commitments_hex"`
	// BeaverCommitmentsHex[serverIndex(1-based)] = {ca, cb, cc}
	BeaverCommitmentsHex map[string]BeaverCommitmentSet `json:"beaver_commitments_hex"`
}

type BeaverCommitmentSet struct {
	CAHex string `json:"ca_hex"`
	CBHex string `json:"cb_hex"`
	CCHex string `json:"cc_hex"`
}

//	g^{s_{i,j}} h^{t_{i,j}}  ?=  prod_{alpha=0}^{t-1} E_{i,alpha}^{j^alpha}
func VerifyShareAgainstPolyCommitments(p *schemea.Params, polyCommits []*big.Int, j int, sHex, tHex string) (bool, error) {
	if p == nil || p.P == nil {
		return false, fmt.Errorf("%w: nil params", ErrMulShape)
	}
	if len(polyCommits) == 0 {
		return false, fmt.Errorf("%w: empty poly commitments", ErrMulShape)
	}
	if j < 1 {
		return false, fmt.Errorf("%w: server index j=%d must be >= 1", ErrMulBadIndex, j)
	}
	s, err := decodeScalar(sHex)
	if err != nil {
		return false, err
	}
	t, err := decodeScalar(tHex)
	if err != nil {
		return false, err
	}
	lhs, err := PedersenCommit(p, s, t)
	if err != nil {
		return false, err
	}
	rhs := big.NewInt(1)
	jBig := big.NewInt(int64(j))
	for alpha, E := range polyCommits {
		if E == nil {
			return false, fmt.Errorf("%w: nil E_{i,%d}", ErrMulShape, alpha)
		}
		exp := new(big.Int).Exp(jBig, big.NewInt(int64(alpha)), nil)
		term := new(big.Int).Exp(E, exp, p.P)
		rhs.Mul(rhs, term)
		rhs.Mod(rhs, p.P)
	}
	return lhs.Cmp(rhs) == 0, nil
}

func DedupeServers(idxs []int) (unique []int, duplicates []int) {
	seen := map[int]bool{}
	for _, i := range idxs {
		if seen[i] {
			duplicates = append(duplicates, i)
			continue
		}
		seen[i] = true
		unique = append(unique, i)
	}
	return unique, duplicates
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func checkMulShape(p *schemea.Params, m *MulIntermediate) error {
	if p == nil || p.P == nil {
		return fmt.Errorf("%w: nil params", ErrMulShape)
	}
	if m == nil {
		return fmt.Errorf("%w: nil intermediate", ErrMulShape)
	}
	if m.ServerIndex < 1 {
		return fmt.Errorf("%w: server_index %d must be >= 1", ErrMulBadIndex, m.ServerIndex)
	}
	for _, h := range []string{m.DHex, m.EHex, m.CxHex, m.CaHex, m.CdHex, m.CyHex, m.CbHex, m.CeHex} {
		if h == "" {
			return fmt.Errorf("%w: empty field", ErrMulShape)
		}
	}
	return nil
}

func decodeElem(h string, p *schemea.Params) (*big.Int, error) {
	v, err := decodeScalar(h)
	if err != nil {
		return nil, err
	}
	if v.Sign() <= 0 || v.Cmp(p.P) >= 0 {
		return nil, fmt.Errorf("%w: group element out of range", ErrMulShape)
	}
	return v, nil
}

func decodeScalar(h string) (*big.Int, error) {
	b, err := hexDecode(h)
	if err != nil {
		return nil, fmt.Errorf("%w: bad hex", ErrMulShape)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("%w: empty scalar", ErrMulShape)
	}
	return new(big.Int).SetBytes(b), nil
}
