package sapaper

import (
	"fmt"
	"io"
	"math/big"

	"c5full/blockchain/protocol_fidelity/schemea_faithful"
)

const ProfileID = "SA-PAPER-3072-P32+BSGS"

const (
	ProfilePID = "SA-PAPER-P-256-P32+BSGS"
	ProfileNID = "SA-PAPER-N-3072-256-P32+BSGS"
	ProfileMID = "SA-PAPER-M-1024-256-P32+BSGS"
	ProfileSID = "SA-PAPER-3072-WIDE-STRESS"
)

var DeviationIDs = []string{"DEV-03", "DEV-04", "DEV-05", "DEV-06", "DEV-09", "AMB-01", "AMB-03", "AMB-05", "AMB-07", "AMB-09"}

const SecurityBits = 128

type Task struct {
	N, T, M int
	Group   *schemeafaithful.Group
	PubKey *big.Int
	AggregateS *big.Int
	KeySet *schemeafaithful.DecryptKeySet
	ZK schemeafaithful.ZKPoCConfig
	EG schemeafaithful.ElGamalConfig
	ScalarMod *big.Int
	Seed      string
	Profile *profileMeta
}

type ServerMaterial struct {
	Index int
	ZShare *big.Int
	ZBlind *big.Int
	Cts []*schemeafaithful.CipherText
	ZKPoCs []*schemeafaithful.ZKProof
	ExpectedCommitment *big.Int
	Intermediate *schemeafaithful.MulIntermediates
}

type Fixture struct {
	Task     *Task
	X, Y     *big.Int
	Expected *big.Int // z = x·y mod q
	Servers  []*ServerMaterial
	Contract *schemeafaithful.ContractState
}

func NewSAPaperTask(n, t, m int, seed string) (*Task, error) {
	grp, err := schemeafaithful.NewGroupRFC3526(3072)
	if err != nil {
		return nil, err
	}
	r := newSeedReader(seed + "::keypair")
	kp, err := grp.NewKeyPair(r)
	if err != nil {
		return nil, err
	}
	keyset, err := schemeafaithful.NewDecryptKeySet(kp.S, m, grp, r)
	if err != nil {
		return nil, err
	}
	k := ((grp.ScalarMod().BitLen() + 7) / 8) * 8
	return &Task{
		N: n, T: t, M: m,
		Group:      grp,
		PubKey:     kp.H,
		AggregateS: kp.S,
		KeySet:     keyset,
		ZK:         schemeafaithful.DefaultZKPoC,
		EG:         schemeafaithful.ElGamalConfig{K: k, ChunkBits: 32},
		ScalarMod:  grp.ScalarMod(),
		Seed:       seed,
	}, nil
}

type ProfileKind int

const (
	ProfileP ProfileKind = iota
	ProfileN
	ProfileM
	ProfileS
)

type profileMeta struct {
	ID        string
	PrimeBits int
	QBits     int
	ExplicitK bool
	K, Chunk int
	W    int
	Notes      string
	Deviations []string
}

func metaOf(pk ProfileKind) profileMeta {
	switch pk {
	case ProfileP:
		return profileMeta{
			ID:        ProfilePID,
			PrimeBits: 256, QBits: 255, // P=2q+1, P.BitLen()=256 ⇒ q.BitLen()=255
			ExplicitK: true, K: 256, Chunk: 32, W: 8,
			Notes:      "paper-oriented profile (256-bit safe-prime group, k=256/w=8; NOT security-normalized)",
			Deviations: []string{"DEV-03", "DEV-04", "DEV-05", "DEV-06", "DEV-09", "AMB-01", "AMB-03", "AMB-05", "AMB-07"},
		}
	case ProfileN:
		return profileMeta{
			ID:        ProfileNID,
			PrimeBits: 3072, QBits: 256,
			ExplicitK: true, K: 256, Chunk: 32, W: 8,
			Notes:      "security-normalized profile (P=3072/Q=256/ord(G)=Q; NIST L=3072,N=256→128-bit; k=256/w=8)",
			Deviations: []string{"DEV-03", "DEV-04", "DEV-05", "DEV-06", "DEV-09", "AMB-01", "AMB-03", "AMB-05", "AMB-07"},
		}
	case ProfileM:
		return profileMeta{
			ID:        ProfileMID,
			PrimeBits: 1024, QBits: 256,
			ExplicitK: true, K: 256, Chunk: 32, W: 8,
			Notes:      "Gai's original maximum key length (P=1024/Q=256/ord(G)=Q; k=256/w=8); only the modulus size differs from ProfileN",
			Deviations: []string{"DEV-03", "DEV-04", "DEV-05", "DEV-06", "DEV-09", "AMB-01", "AMB-03", "AMB-05", "AMB-07"},
		}
	default:
		return profileMeta{
			ID:        ProfileSID,
			PrimeBits: 3072, QBits: 3071,
			ExplicitK: false, K: 3072, Chunk: 32, W: 96,
			Notes:      "3072-bit wide-share stress profile (k=3072/w=96; appendix/sensitivity only, NOT main baseline)",
			Deviations: DeviationIDs,
		}
	}
}

func NewSATaskProfile(pk ProfileKind, n, t, m int, seed string) (*Task, error) {
	meta := metaOf(pk)
	var grp *schemeafaithful.Group
	var err error
	switch pk {
	case ProfileP:
		grp, err = schemeafaithful.NewGroupRandom(meta.PrimeBits, seedInt(seed))
		if err != nil {
			return nil, err
		}
	case ProfileN:
		P, Q, G, err2 := dsaParams3072_256(seedInt(seed + "::params"))
		if err2 != nil {
			return nil, err2
		}
		grp, err = schemeafaithful.NewGroupGeneral(P, Q, G)
		if err != nil {
			return nil, err
		}
	case ProfileM:
		P, Q, G, err2 := dsaParams1024_256(seedInt(seed + "::params"))
		if err2 != nil {
			return nil, err2
		}
		grp, err = schemeafaithful.NewGroupGeneral(P, Q, G)
		if err != nil {
			return nil, err
		}
	case ProfileS:
		return NewSAPaperTask(n, t, m, seed)
	default:
		return nil, errfProfile("unknown profile kind")
	}
	if err := checkProfileParams(grp, meta); err != nil {
		return nil, err
	}
	r := newSeedReader(seed + "::keypair")
	kp, err := grp.NewKeyPair(r)
	if err != nil {
		return nil, err
	}
	keyset, err := schemeafaithful.NewDecryptKeySet(kp.S, m, grp, r)
	if err != nil {
		return nil, err
	}
	if !meta.ExplicitK {
		return nil, errfProfile("profile meta missing explicit k")
	}
	return &Task{
		N: n, T: t, M: m,
		Group:      grp,
		PubKey:     kp.H,
		AggregateS: kp.S,
		KeySet:     keyset,
		ZK:         schemeafaithful.DefaultZKPoC,
		EG:         schemeafaithful.ElGamalConfig{K: meta.K, ChunkBits: meta.Chunk},
		ScalarMod:  grp.ScalarMod(),
		Seed:       seed,
		Profile:    &meta,
	}, nil
}

func checkProfileParams(grp *schemeafaithful.Group, meta profileMeta) error {
	if !grp.P.ProbablyPrime(32) {
		return errfProfile("P not prime")
	}
	if !grp.ExpMod.ProbablyPrime(32) {
		return errfProfile("Q not prime")
	}
	pm1 := new(big.Int).Sub(grp.P, big.NewInt(1))
	if new(big.Int).Mod(pm1, grp.ExpMod).Sign() != 0 {
		return errfProfile("Q does not divide P-1")
	}
	if grp.G.Cmp(big.NewInt(1)) == 0 {
		return errfProfile("degenerate G=1")
	}
	if new(big.Int).Exp(grp.G, grp.ExpMod, grp.P).Cmp(big.NewInt(1)) != 0 {
		return errfProfile("G^Q != 1")
	}
	if pk := kindOfID(meta.ID); pk == ProfileP || pk == ProfileN || pk == ProfileM {
		if meta.K != 256 || meta.Chunk != 32 || meta.K/meta.Chunk != 8 {
			return errfProfile("profile P/N/M must fix k=256,chunk=32,w=8")
		}
		if grp.ExpMod.BitLen() > meta.K {
			return errfProfile("Q.BitLen()=%d > k=%d: output share cannot fit", grp.ExpMod.BitLen(), meta.K)
		}
	}
	return nil
}

func kindOfID(id string) ProfileKind {
	switch id {
	case ProfilePID:
		return ProfileP
	case ProfileNID:
		return ProfileN
	case ProfileMID:
		return ProfileM
	default:
		return ProfileS
	}
}

func seedInt(seed string) int64 {
	h := fnv64(seed)
	return int64(h)
}

func fnv64(s string) uint64 {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

func dsaParams3072_256(seed int64) (P, Q, G *big.Int, err error) {
	return dsaParams(3072, 256, seed)
}

func dsaParams1024_256(seed int64) (P, Q, G *big.Int, err error) {
	return dsaParams(1024, 256, seed)
}

func dsaParams(pbits, qbits int, seed int64) (P, Q, G *big.Int, err error) {
	rng := randSeedReaderFromSeed(seed)
	two := big.NewInt(2)
	one := big.NewInt(1)
	for {
		q, e := crandPrime(rng, qbits)
		if e != nil {
			return nil, nil, nil, e
		}
		Q = q
		sBase, e2 := randEven(rng, pbits-qbits)
		if e2 != nil {
			return nil, nil, nil, e2
		}
		s := new(big.Int).Set(sBase)
		found := false
		for tries := 0; tries < 200000; tries++ {
			P = new(big.Int).Mul(Q, s)
			P.Add(P, one)
			if P.ProbablyPrime(32) {
				found = true
				break
			}
			s.Add(s, two)
		}
		if !found {
			continue
		}
		expG := new(big.Int).Sub(P, one)
		expG.Div(expG, Q)
		for tries := 0; tries < 100000; tries++ {
			h, e3 := randInRange(rng, two, new(big.Int).Sub(P, two))
			if e3 != nil {
				return nil, nil, nil, e3
			}
			G = new(big.Int).Exp(h, expG, P)
			if G.Cmp(one) != 0 {
				return P, Q, G, nil
			}
		}
	}
}

func crandPrime(rng *seedReader, bits int) (*big.Int, error) {
	if bits < 64 {
		return nil, errfProfile("prime bits too small")
	}
	for {
		q := randIntFromSeedReader(rng, new(big.Int).Lsh(big.NewInt(1), uint(bits-1)))
		q.SetBit(q, bits-1, 1)
		q.SetBit(q, 0, 1)
		if q.ProbablyPrime(32) {
			return q, nil
		}
	}
}

func randEven(rng *seedReader, bits int) (*big.Int, error) {
	x := randIntFromSeedReader(rng, new(big.Int).Lsh(big.NewInt(1), uint(bits-1)))
	x.SetBit(x, bits-1, 1)
	x.SetBit(x, 0, 0)
	return x, nil
}

func randInRange(rng *seedReader, lo, hi *big.Int) (*big.Int, error) {
	span := new(big.Int).Sub(hi, lo)
	span.Add(span, big.NewInt(1))
	x := randIntFromSeedReader(rng, span)
	x.Add(x, lo)
	return x, nil
}

func randIntFromSeedReader(r *seedReader, max *big.Int) *big.Int {
	bits := max.BitLen()
	bytes := (bits + 7) / 8
	for {
		buf := make([]byte, bytes)
		_, _ = r.Read(buf)
		x := new(big.Int).SetBytes(buf)
		if x.Cmp(max) < 0 {
			return x
		}
	}
}

func randSeedReaderFromSeed(seed int64) *seedReader {
	return newSeedReader(fmt.Sprintf("dsa-params::%d", seed))
}

func errfProfile(format string, a ...any) error {
	return fmt.Errorf("sapaper/profile: "+format, a...)
}

func (t *Task) BuildFixture(x, y *big.Int, seedSuffix string) (*Fixture, error) {
	g := t.Group
	mod := t.ScalarMod
	r := newSeedReader(t.Seed + "::" + seedSuffix)

	xSet, err := g.VSSShare(x, mustRand(r, mod), t.PubKey, t.T, t.N, r)
	if err != nil {
		return nil, err
	}
	ySet, err := g.VSSShare(y, mustRand(r, mod), t.PubKey, t.T, t.N, r)
	if err != nil {
		return nil, err
	}
	for i := 0; i < t.N; i++ {
		if ok, err := g.VerifyShare(t.PubKey, xSet.E, xSet.Shares[i]); err != nil || !ok {
			return nil, errfChannel()
		}
		if ok, err := g.VerifyShare(t.PubKey, ySet.E, ySet.Shares[i]); err != nil || !ok {
			return nil, errfChannel()
		}
	}
	for i := 0; i < t.N; i++ {
		key, err := schemeafaithful.NewChannelKey(256, r)
		if err != nil {
			return nil, err
		}
		sealed, err := key.Seal(lenPrefixed(xSet.Shares[i].S))
		if err != nil {
			return nil, err
		}
		pt, err := key.Open(sealed)
		if err != nil {
			return nil, err
		}
		got, err := decodeLenPrefixed(pt)
		if err != nil || got.Cmp(xSet.Shares[i].S) != 0 {
			return nil, errfChannel()
		}
	}

	rp, err := g.NewResharePoly(t.T, t.PubKey, r)
	if err != nil {
		return nil, err
	}
	st := schemeafaithful.NewContractState(g, t.PubKey, rp)
	triple, err := g.MakeTriple(t.T, t.N, schemeafaithful.TripleModeClient, t.PubKey, r)
	if err != nil {
		return nil, err
	}
	for i := 0; i < t.N; i++ {
		sx := polyEvalMod(xSet.Gc, big.NewInt(int64(i+1)), mod)
		sy := polyEvalMod(ySet.Gc, big.NewInt(int64(i+1)), mod)
		st.CX[i+1] = g.Commit(t.PubKey, xSet.Shares[i].S, sx)
		st.CY[i+1] = g.Commit(t.PubKey, ySet.Shares[i].S, sy)
		st.CA[i+1] = triple.CA[i]
		st.CB[i+1] = triple.CB[i]
		st.CC[i+1] = triple.CC[i]
		st.RA[i+1] = triple.RA[i]
		st.RB[i+1] = triple.RB[i]
	}

	dGlob, err := schemeafaithful.Reconstruct(diffShares(xSet, triple.A, t.T, mod), mod)
	if err != nil {
		return nil, err
	}
	eGlob, err := schemeafaithful.Reconstruct(diffShares(ySet, triple.B, t.T, mod), mod)
	if err != nil {
		return nil, err
	}

	fx := &Fixture{Task: t, X: x, Y: y, Contract: st}
	expect := new(big.Int).Mul(x, y)
	expect.Mod(expect, mod)
	fx.Expected = expect

	for i := 0; i < t.N; i++ {
		xi := xSet.Shares[i].S
		yi := ySet.Shares[i].S
		ai := triple.A.Shares[i].S
		bi := triple.B.Shares[i].S
		di, ei := schemeafaithful.MulReveal(xi, yi, ai, bi, mod)
		rx := polyEvalMod(xSet.Gc, big.NewInt(int64(i+1)), mod)
		ry := polyEvalMod(ySet.Gc, big.NewInt(int64(i+1)), mod)
		rdi := new(big.Int).Sub(rx, triple.RA[i])
		rdi.Mod(rdi, mod)
		rei := new(big.Int).Sub(ry, triple.RB[i])
		rei.Mod(rei, mod)
		inter := &schemeafaithful.MulIntermediates{Server: i + 1, D: di, E: ei, RD: rdi, RE: rei}

		de := new(big.Int).Mul(dGlob, eGlob)
		dei, rdei := g.DeShare(rp, de, i+1)
		zi, zri := g.MulLocal(triple.C.Shares[i].S, ai, bi, dGlob, eGlob, dei,
			triple.RA[i], triple.RB[i], triple.RC[i], rdei)

		enc, err := g.EncryptShare(t.PubKey, zi, zri, t.EG, r)
		if err != nil {
			return nil, err
		}
		vs := g.Split(zi, t.EG)
		pfs := make([]*schemeafaithful.ZKProof, len(enc.Cts))
		for j, ct := range enc.Cts {
			pf, err := g.MakeZKPoC(t.PubKey, ct, vs[j], enc.Ls()[j], t.ZK, r)
			if err != nil {
				return nil, err
			}
			pfs[j] = pf
		}
		cz, err := st.DeriveMulCommitmentG(inter, dGlob, eGlob)
		if err != nil {
			return nil, err
		}
		fx.Servers = append(fx.Servers, &ServerMaterial{
			Index: i + 1, ZShare: zi, ZBlind: zri,
			Cts: enc.Cts, ZKPoCs: pfs, ExpectedCommitment: cz, Intermediate: inter,
		})
	}
	return fx, nil
}

func (fx *Fixture) VerifyServer(serverIdx1Based int) (bool, error) {
	t := fx.Task
	sm := fx.Servers[serverIdx1Based-1]
	g := t.Group
	for j, ct := range sm.Cts {
		ok, err := g.VerifyZKPoC(t.PubKey, ct, sm.ZKPoCs[j], t.ZK)
		if err != nil || !ok {
			return false, err
		}
	}
	prod := g.HomomorphicProduct(sm.Cts, t.EG)
	return prod.Cmp(sm.ExpectedCommitment) == 0, nil
}

func (fx *Fixture) TamperServerCiphertext(serverIdx1Based, chunk int) {
	ct := fx.Servers[serverIdx1Based-1].Cts[chunk]
	ct.C1 = new(big.Int).Add(ct.C1, big.NewInt(1))
	ct.C1.Mod(ct.C1, fx.Task.Group.P)
}

func (fx *Fixture) RecoverOutputWithTable(serverIndices []int, bsgsTable *schemeafaithful.BSGSTable) (*big.Int, error) {
	t := fx.Task
	g := t.Group
	mod := t.ScalarMod
	zvals := make([]*big.Int, len(serverIndices))
	for k, idx := range serverIndices {
		sm := fx.Servers[idx-1]
		vs := make([]*big.Int, len(sm.Cts))
		for j, ct := range sm.Cts {
			partials := make([]*big.Int, t.M)
			for c := 0; c < t.M; c++ {
				partials[c] = g.PartialDecrypt(ct, t.KeySet.Shares[c])
			}
			gv, err := g.ProductDecrypt(ct, partials)
			if err != nil {
				return nil, err
			}
			var v *big.Int
			if bsgsTable != nil {
				v = bsgsTable.Query(gv)
			} else {
				v = g.BSGS(gv, t.EG.ChunkBits)
			}
			if v.Sign() < 0 {
				return nil, errfDecrypt(idx)
			}
			vs[j] = v
		}
		zvals[k] = g.Recombine(vs, t.EG)
		if zvals[k].Cmp(fx.Servers[idx-1].ZShare) != 0 {
			return nil, errfDecrypt(idx)
		}
	}
	shares := make([]*schemeafaithful.Share, len(serverIndices))
	for k, idx := range serverIndices {
		shares[k] = &schemeafaithful.Share{J: idx, S: zvals[k]}
	}
	return schemeafaithful.Reconstruct(shares, mod)
}

func (fx *Fixture) RecoverOutput(serverIndices []int) (*big.Int, error) {
	return fx.RecoverOutputWithTable(serverIndices, nil)
}

func (fx *Fixture) VerifyServerBytes(serverIdx1Based int) (ctBytes, poKBytes int) {
	g := fx.Task.Group
	sm := fx.Servers[serverIdx1Based-1]
	for j := range sm.Cts {
		ctBytes += g.CipherTextBytes(sm.Cts[j])
		poKBytes += g.ZKProofBytes(sm.ZKPoCs[j])
	}
	return ctBytes, poKBytes
}

func (fx *Fixture) RecoverBytes(serverIndices []int) int {
	t := fx.Task
	g := t.Group
	total := 0
	for _, idx := range serverIndices {
		sm := fx.Servers[idx-1]
		for j := range sm.Cts {
			total += g.CipherTextBytes(sm.Cts[j])
			total += t.M * g.PartialDecryptBytes()
			total += 4                             // server index u32
		}
	}
	return total
}

func lenPrefixed(x *big.Int) []byte {
	b := x.Bytes()
	out := make([]byte, 4+len(b))
	out[0] = byte(len(b))
	out[1] = byte(len(b) >> 8)
	out[2] = byte(len(b) >> 16)
	out[3] = byte(len(b) >> 24)
	copy(out[4:], b)
	return out
}

func decodeLenPrefixed(b []byte) (*big.Int, error) {
	if len(b) < 4 {
		return nil, errfChannel()
	}
	n := int(b[0]) | int(b[1])<<8 | int(b[2])<<16 | int(b[3])<<24
	if n != len(b)-4 {
		return nil, errfChannel()
	}
	return new(big.Int).SetBytes(b[4:]), nil
}

func mustRand(r io.Reader, mod *big.Int) *big.Int {
	v, err := schemeafaithful.RandScalar(mod, r)
	if err != nil {
		panic(err)
	}
	return v
}

func polyEvalMod(coeff []*big.Int, x, m *big.Int) *big.Int {
	acc := big.NewInt(0)
	for i := len(coeff) - 1; i >= 0; i-- {
		acc.Mul(acc, x)
		acc.Add(acc, coeff[i])
		acc.Mod(acc, m)
	}
	return acc
}

func diffShares(vSet, tSet *schemeafaithful.ShareSet, count int, mod *big.Int) []*schemeafaithful.Share {
	out := make([]*schemeafaithful.Share, count)
	for i := 0; i < count; i++ {
		d := new(big.Int).Sub(vSet.Shares[i].S, tSet.Shares[i].S)
		d.Mod(d, mod)
		out[i] = &schemeafaithful.Share{J: i + 1, S: d}
	}
	return out
}
