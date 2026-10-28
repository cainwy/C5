package schemeafaithful


import (
	"math/big"
	"time"
)

type FullTable struct {
	G    *big.Int
	P    *big.Int
	Mod  *big.Int
	tbl  map[string]*big.Int
	Size int
}

func (g *Group) NewFullTable(chunkBits int) (*FullTable, error) {
	if chunkBits > 20 {
		return nil, errf(ErrBadParams, "full table 2^%d infeasible (use BSGS)", chunkBits)
	}
	n := 1 << uint(chunkBits)
	t := &FullTable{G: g.G, P: g.P, Mod: g.ExpMod, tbl: make(map[string]*big.Int, n), Size: n}
	cur := big.NewInt(1)
	for i := 0; i < n; i++ {
		t.tbl[cur.String()] = big.NewInt(int64(i))
		cur = g.Mul(cur, g.G)
	}
	return t, nil
}

func (t *FullTable) Query(target *big.Int) *big.Int {
	if v, ok := t.tbl[target.String()]; ok {
		return v
	}
	return big.NewInt(-1)
}

func (g *Group) BSGS(target *big.Int, chunkBits int) *big.Int {
	bound := new(big.Int).Lsh(big.NewInt(1), uint(chunkBits))
	m := new(big.Int).Sqrt(bound)
	m.Add(m, big.NewInt(1)) // ceil
	mInt := int(m.Int64())

	baby := make(map[string]*big.Int, mInt)
	cur := big.NewInt(1)
	for i := 0; i < mInt; i++ {
		baby[cur.String()] = big.NewInt(int64(i))
		cur = g.Mul(cur, g.G)
	}
	gm := g.Pow(g.G, m)
	gmInv := new(big.Int).ModInverse(gm, g.P)
	gamma := new(big.Int).Set(target)
	for j := 0; j < mInt; j++ {
		if v, ok := baby[gamma.String()]; ok {
			res := new(big.Int).Mul(big.NewInt(int64(j)), m)
			return res.Add(res, v)
		}
		gamma = g.Mul(gamma, gmInv)
	}
	return big.NewInt(-1)
}

type BSGSTable struct {
	G, P    *big.Int
	Chunk   int
	Entries int
	BuildMs float64
	MemMB    float64
	m        *big.Int
	gmInv    *big.Int
	baby     map[string]*big.Int
	groupRef *Group
}

func (g *Group) NewBSGSTable(chunkBits int) (*BSGSTable, error) {
	if chunkBits < 1 || chunkBits > 40 {
		return nil, errf(ErrBadParams, "chunkBits %d out of range", chunkBits)
	}
	t0 := time.Now()
	bound := new(big.Int).Lsh(big.NewInt(1), uint(chunkBits))
	m := new(big.Int).Sqrt(bound)
	m.Add(m, big.NewInt(1)) // ceil
	mInt := int(m.Int64())
	baby := make(map[string]*big.Int, mInt)
	cur := big.NewInt(1)
	for i := 0; i < mInt; i++ {
		baby[cur.String()] = big.NewInt(int64(i))
		cur = g.Mul(cur, g.G)
	}
	gm := g.Pow(g.G, m)
	gmInv := new(big.Int).ModInverse(gm, g.P)
	if gmInv == nil {
		return nil, errf(ErrBadGroup, "g^-m not invertible")
	}
	buildMs := time.Since(t0).Seconds() * 1000
	memMB := float64(mInt) * 128 / (1024 * 1024)
	return &BSGSTable{
		G: g.G, P: g.P, Chunk: chunkBits, Entries: mInt,
		BuildMs: buildMs, MemMB: memMB,
		m: m, gmInv: gmInv, baby: baby, groupRef: g,
	}, nil
}

func (t *BSGSTable) Query(target *big.Int) *big.Int {
	g := t.groupRef
	gamma := new(big.Int).Set(target)
	for j := 0; j < t.Entries; j++ {
		if v, ok := t.baby[gamma.String()]; ok {
			res := new(big.Int).Mul(big.NewInt(int64(j)), t.m)
			return res.Add(res, v)
		}
		gamma = g.Mul(gamma, t.gmInv)
	}
	return big.NewInt(-1)
}

func (g *Group) RecoverPartition(ct *CipherText, partials []*big.Int, chunkBits int, table *FullTable) (*big.Int, error) {
	gv, err := g.ProductDecrypt(ct, partials)
	if err != nil {
		return nil, err
	}
	var v *big.Int
	if table != nil {
		v = table.Query(gv)
	} else {
		v = g.BSGS(gv, chunkBits)
	}
	if v.Sign() < 0 {
		return nil, errf(ErrDecrypt, "dlog not found")
	}
	return v, nil
}
