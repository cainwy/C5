package schemeafaithful


import (
	"math/big"
)

type ContractState struct {
	G   *Group
	H   *big.Int
	CX map[int]*big.Int
	CY map[int]*big.Int
	CA map[int]*big.Int
	CB map[int]*big.Int
	CC map[int]*big.Int
	RA map[int]*big.Int
	RB map[int]*big.Int
	RP *ResharePoly
	CZ map[int]*big.Int
}

func NewContractState(g *Group, h *big.Int, rp *ResharePoly) *ContractState {
	return &ContractState{
		G: g, H: h, RP: rp,
		CX: map[int]*big.Int{}, CY: map[int]*big.Int{},
		CA: map[int]*big.Int{}, CB: map[int]*big.Int{}, CC: map[int]*big.Int{},
		RA: map[int]*big.Int{}, RB: map[int]*big.Int{},
		CZ: map[int]*big.Int{},
	}
}

type MulIntermediates struct {
	Server int
	D, E   *big.Int
	RD, RE *big.Int
}

func (st *ContractState) VerifyIntermediate(m *MulIntermediates) (bool, error) {
	if m == nil || m.Server < 1 {
		return false, errf(ErrBadCommit, "bad intermediates")
	}
	cx, ok1 := st.CX[m.Server]
	ca, ok2 := st.CA[m.Server]
	cy, ok3 := st.CY[m.Server]
	cb, ok4 := st.CB[m.Server]
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return false, errf(ErrBadCommit, "missing registered commitment (server %d)", m.Server)
	}
	cd := st.G.Commit(st.H, m.D, m.RD)
	if st.G.Mul(ca, cd).Cmp(cx) != 0 {
		return false, nil
	}
	ce := st.G.Commit(st.H, m.E, m.RE)
	if st.G.Mul(cb, ce).Cmp(cy) != 0 {
		return false, nil
	}
	return true, nil
}

//	c^z_i = c^c_i · (c^a_i)^e · (c^b_i)^d · E'(i)^{d·e}
func (st *ContractState) DeriveMulCommitment(m *MulIntermediates) (*big.Int, error) {
	return st.DeriveMulCommitmentG(m, m.D, m.E)
}

func (st *ContractState) DeriveMulCommitmentG(m *MulIntermediates, dGlob, eGlob *big.Int) (*big.Int, error) {
	ok, err := st.VerifyIntermediate(m)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errf(ErrBadCommit, "eq(17) failed (server %d)", m.Server)
	}
	i := m.Server
	cc := st.CC[i]
	ca, cb := st.CA[i], st.CB[i]
	cea := st.G.Pow(ca, eGlob)
	cdb := st.G.Pow(cb, dGlob)
	de := new(big.Int).Mul(dGlob, eGlob)
	cde := st.G.DeCommit(st.RP, de, i)
	cz := st.G.Mul(st.G.Mul(st.G.Mul(cc, cea), cdb), cde)
	st.CZ[i] = cz
	return cz, nil
}

func (st *ContractState) ReconstructGlobals(muls []*MulIntermediates, t int, mod *big.Int) (*big.Int, *big.Int, error) {
	if len(muls) < t {
		return nil, nil, errf(ErrBadCommit, "need %d intermediates, got %d", t, len(muls))
	}
	dShares := make([]*Share, t)
	eShares := make([]*Share, t)
	for k := 0; k < t; k++ {
		dShares[k] = &Share{J: muls[k].Server, S: muls[k].D}
		eShares[k] = &Share{J: muls[k].Server, S: muls[k].E}
	}
	d, err := Reconstruct(dShares, mod)
	if err != nil {
		return nil, nil, err
	}
	e, err := Reconstruct(eShares, mod)
	if err != nil {
		return nil, nil, err
	}
	return d, e, nil
}

func (st *ContractState) DeriveAddCommitment(server int) (*big.Int, error) {
	cx, ok1 := st.CX[server]
	cy, ok2 := st.CY[server]
	if !ok1 || !ok2 {
		return nil, errf(ErrBadCommit, "missing input commitments (server %d)", server)
	}
	cz := st.G.Mul(cx, cy)
	st.CZ[server] = cz
	return cz, nil
}

func (st *ContractState) VerifyCiphertextAgainstCommitment(server int, cts []*CipherText, cfg ElGamalConfig) (bool, error) {
	cz, ok := st.CZ[server]
	if !ok {
		return false, errf(ErrBadCommit, "no derived commitment for server %d", server)
	}
	prod := st.G.HomomorphicProduct(cts, cfg)
	return prod.Cmp(cz) == 0, nil
}
