package schemeafaithful

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func testGroup(t *testing.T, bits int) *Group {
	t.Helper()
	g, err := NewGroupRandom(bits, int64(bits*7919))
	if err != nil {
		t.Fatalf("NewGroupRandom: %v", err)
	}
	return g
}

func TestGroupRFC3526(t *testing.T) {
	for _, bits := range []int{2048, 3072} {
		g, err := NewGroupRFC3526(bits)
		if err != nil {
			t.Fatalf("bits=%d: %v", bits, err)
		}
		if g.Bits != bits {
			t.Fatalf("bits mismatch: got %d want %d", g.Bits, bits)
		}
		// g^q == 1
		if g.Pow(g.G, g.ExpMod).Cmp(big.NewInt(1)) != 0 {
			t.Fatalf("g^q != 1 for bits=%d", bits)
		}
	}
}

func TestGroupBadBits(t *testing.T) {
	if _, err := NewGroupRandom(8, 1); err == nil {
		t.Fatal("bits=8 must be rejected")
	}
	if _, err := NewGroupRFC3526(1024); err == nil {
		t.Fatal("no 1024-bit RFC3526 prime should error")
	}
}

func TestVSSShareVerifyReconstruct(t *testing.T) {
	g := testGroup(t, 256)
	mod := g.ScalarMod()
	hKP, _ := g.NewKeyPair(rand.Reader)
	secret := big.NewInt(123456789)
	rho, _ := RandScalar(mod, rand.Reader)
	set, err := g.VSSShare(secret, rho, hKP.H, 3, 5, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, sh := range set.Shares {
		ok, err := g.VerifyShare(hKP.H, set.E, sh)
		if err != nil || !ok {
			t.Fatalf("share j=%d verify failed: %v", sh.J, err)
		}
	}
	got, err := Reconstruct(set.Shares[:3], mod)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cmp(new(big.Int).Mod(secret, mod)) != 0 {
		t.Fatalf("reconstruct mismatch: got %v", got)
	}
	got2, _ := Reconstruct(set.Shares[:2], mod)
	if got2.Cmp(new(big.Int).Mod(secret, mod)) == 0 {
		t.Fatal("t-1 shares must not reconstruct secret")
	}
	dup := []*Share{set.Shares[0], set.Shares[0]}
	if _, err := Reconstruct(dup, mod); err == nil {
		t.Fatal("duplicate index must be rejected")
	}
}

func TestVSSShareNilReject(t *testing.T) {
	g := testGroup(t, 256)
	hKP, _ := g.NewKeyPair(rand.Reader)
	if _, err := g.VSSShare(nil, big.NewInt(1), hKP.H, 2, 3, rand.Reader); err == nil {
		t.Fatal("nil secret must be rejected")
	}
	if _, err := g.VSSShare(big.NewInt(1), nil, hKP.H, 2, 3, rand.Reader); err == nil {
		t.Fatal("nil rho must be rejected")
	}
	if _, err := g.VSSShare(big.NewInt(1), big.NewInt(1), hKP.H, 5, 3, rand.Reader); err == nil {
		t.Fatal("n<t must be rejected")
	}
}

func TestChannelRoundtripAndWrongKey(t *testing.T) {
	k1, _ := NewChannelKey(256, rand.Reader)
	k2, _ := NewChannelKey(256, rand.Reader)
	msg := []byte("hello secret share")
	sealed, err := k1.Seal(msg)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := k1.Open(sealed)
	if err != nil || string(pt) != string(msg) {
		t.Fatalf("roundtrip failed: %v", err)
	}
	if _, err := k2.Open(sealed); err == nil {
		t.Fatal("wrong key must fail")
	}
	sealed[len(sealed)-1] ^= 0xFF
	if _, err := k1.Open(sealed); err == nil {
		t.Fatal("tampered ciphertext must fail")
	}
	for _, kl := range []int{128, 192, 256} {
		if _, err := NewChannelKey(kl, rand.Reader); err != nil {
			t.Fatalf("keylen %d: %v", kl, err)
		}
	}
	if _, err := NewChannelKey(100, rand.Reader); err == nil {
		t.Fatal("keylen 100 must be rejected")
	}
}

func TestOperators(t *testing.T) {
	g := testGroup(t, 256)
	mod := g.ScalarMod()
	x, _ := RandScalar(mod, rand.Reader)
	y, _ := RandScalar(mod, rand.Reader)
	c, _ := RandScalar(mod, rand.Reader)
	if AddOp(x, y, mod).Cmp(new(big.Int).Add(x, y).Mod(new(big.Int).Add(x, y), mod)) != 0 {
		t.Fatal("AddOp mismatch")
	}
	if ConstMulOp(c, x, mod).Cmp(new(big.Int).Mul(c, x).Mod(new(big.Int).Mul(c, x), mod)) != 0 {
		t.Fatal("ConstMulOp mismatch")
	}
	if ConstAddOp(c, x, mod).Cmp(new(big.Int).Add(c, x).Mod(new(big.Int).Add(c, x), mod)) != 0 {
		t.Fatal("ConstAddOp mismatch")
	}
	a := big.NewInt(0)
	b := big.NewInt(0)
	d, _ := RandScalar(mod, rand.Reader)
	e, _ := RandScalar(mod, rand.Reader)
	de := new(big.Int).Mul(d, e)
	ci := new(big.Int).Mul(x, y)
	ci.Sub(ci, de)
	ci.Mod(ci, mod)
	dei := new(big.Int).Mul(de, big.NewInt(1))
	z, _ := g.MulLocal(ci, a, b, d, e, dei, big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0))
	if z.Cmp(new(big.Int).Mul(x, y).Mod(new(big.Int).Mul(x, y), mod)) != 0 {
		t.Fatal("MulLocal algebra mismatch")
	}
}

func TestResharePolyDeCommit(t *testing.T) {
	g := testGroup(t, 256)
	hKP, _ := g.NewKeyPair(rand.Reader)
	rp, err := g.NewResharePoly(3, hKP.H, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	de := big.NewInt(987654321)
	vals := make([]*Share, 5)
	for j := 1; j <= 5; j++ {
		v, _ := g.DeShare(rp, de, j)
		vals[j-1] = &Share{J: j, S: v}
	}
	got, err := Reconstruct(vals[:3], g.ScalarMod())
	if err != nil {
		t.Fatal(err)
	}
	if got.Cmp(de) != 0 {
		t.Fatalf("de reshare reconstruct mismatch: got %v want %v", got, de)
	}
	for j := 1; j <= 3; j++ {
		v, bl := g.DeShare(rp, de, j)
		want := g.Commit(hKP.H, v, bl)
		if g.DeCommit(rp, de, j).Cmp(want) != 0 {
			t.Fatalf("DeCommit mismatch at j=%d", j)
		}
	}
}

func TestElGamalEncryptShare(t *testing.T) {
	g := testGroup(t, 256)
	hKP, _ := g.NewKeyPair(rand.Reader)
	cfg := DefaultElGamal
	z := new(big.Int).Lsh(big.NewInt(0xdeadbeef), 64)
	r, _ := RandScalar(g.ScalarMod(), rand.Reader)
	es, err := g.EncryptShare(hKP.H, z, r, cfg, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(es.Cts) != cfg.W() {
		t.Fatalf("got %d ciphertexts want %d", len(es.Cts), cfg.W())
	}
	prod := g.HomomorphicProduct(es.Cts, cfg)
	want := g.Commit(hKP.H, z, r)
	if prod.Cmp(want) != 0 {
		t.Fatal("homomorphic product != commitment (honest)")
	}
	tampered := make([]*CipherText, len(es.Cts))
	for j, ct := range es.Cts {
		tc := &CipherText{C0: ct.C0, C1: ct.C1}
		tampered[j] = tc
	}
	tampered[3].C1 = g.Mul(tampered[3].C1, g.G)
	if g.HomomorphicProduct(tampered, cfg).Cmp(want) == 0 {
		t.Fatal("tampered C1 must change product")
	}
	vs := g.Split(z, cfg)
	if g.Recombine(vs, cfg).Cmp(z) != 0 {
		t.Fatal("split/recombine mismatch")
	}
}

func TestZKPoCHonestAndNegative(t *testing.T) {
	g := testGroup(t, 256)
	hKP, _ := g.NewKeyPair(rand.Reader)
	v := big.NewInt(0x1234)
	l, _ := RandScalar(g.ExpMod, rand.Reader)
	ct := g.EncryptPartition(hKP.H, v, l)
	pf, err := g.MakeZKPoC(hKP.H, ct, v, l, DefaultZKPoC, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := g.VerifyZKPoC(hKP.H, ct, pf, DefaultZKPoC)
	if err != nil || !ok {
		t.Fatalf("honest ZKPoC must pass: ok=%v err=%v", ok, err)
	}
	ct2 := g.EncryptPartition(hKP.H, big.NewInt(0x9999), l)
	ok2, err := g.VerifyZKPoC(hKP.H, ct2, pf, DefaultZKPoC)
	if err != nil {
		t.Fatal(err)
	}
	if ok2 {
		t.Fatal("ZKPoC must reject ciphertext of different message (soundness)")
	}
	bad := &ZKProof{A0: pf.A0, A1: pf.A1, D: new(big.Int).Add(pf.D, big.NewInt(1)), F: pf.F}
	ok3, _ := g.VerifyZKPoC(hKP.H, ct, bad, DefaultZKPoC)
	if ok3 {
		t.Fatal("tampered proof must fail")
	}
	pf2, _ := g.MakeZKPoC(hKP.H, ct, v, l, DefaultZKPoC, rand.Reader)
	if pf2.A0.Cmp(pf.A0) == 0 {
		t.Fatal("ZKPoC randomness must vary")
	}
}

func TestContractVerifyChain(t *testing.T) {
	g := testGroup(t, 256)
	hKP, _ := g.NewKeyPair(rand.Reader)
	h := hKP.H
	mod := g.ScalarMod()
	rp, _ := g.NewResharePoly(2, h, rand.Reader)
	st := NewContractState(g, h, rp)

	x, _ := RandScalar(mod, rand.Reader)
	y, _ := RandScalar(mod, rand.Reader)
	rx, _ := RandScalar(mod, rand.Reader)
	ry, _ := RandScalar(mod, rand.Reader)
	xSet, _ := g.VSSShare(x, rx, h, 2, 3, rand.Reader)
	ySet, _ := g.VSSShare(y, ry, h, 2, 3, rand.Reader)
	tr, err := g.MakeTriple(2, 3, TripleModeClient, h, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		sxi := polyEval(xSet.Gc, big.NewInt(int64(i+1)), mod)
		syi := polyEval(ySet.Gc, big.NewInt(int64(i+1)), mod)
		st.CX[i+1] = g.Commit(h, xSet.Shares[i].S, sxi)
		st.CY[i+1] = g.Commit(h, ySet.Shares[i].S, syi)
		st.CA[i+1] = tr.CA[i]
		st.CB[i+1] = tr.CB[i]
		st.CC[i+1] = tr.CC[i]
		st.RA[i+1] = tr.RA[i]
		st.RB[i+1] = tr.RB[i]
	}
	d1 := new(big.Int).Sub(xSet.Shares[0].S, tr.A.Shares[0].S)
	d1.Mod(d1, mod)
	e1 := new(big.Int).Sub(ySet.Shares[0].S, tr.B.Shares[0].S)
	e1.Mod(e1, mod)
	de := new(big.Int).Mul(d1, e1)
	dei1, rdei1 := g.DeShare(rp, de, 1)
	zi, zri := g.MulLocal(tr.C.Shares[0].S, tr.A.Shares[0].S, tr.B.Shares[0].S,
		d1, e1, dei1, tr.RA[0], tr.RB[0], tr.RC[0], rdei1)
	rx1 := polyEval(xSet.Gc, big.NewInt(1), mod)
	ry1 := polyEval(ySet.Gc, big.NewInt(1), mod)
	rdi := new(big.Int).Sub(rx1, tr.RA[0])
	rdi.Mod(rdi, mod)
	rei := new(big.Int).Sub(ry1, tr.RB[0])
	rei.Mod(rei, mod)
	mul := &MulIntermediates{Server: 1, D: d1, E: e1, RD: rdi, RE: rei}
	cz, err := st.DeriveMulCommitmentG(mul, d1, e1)
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultElGamal
	es, _ := g.EncryptShare(h, zi, zri, cfg, rand.Reader)
	ok, err := st.VerifyCiphertextAgainstCommitment(1, es.Cts, cfg)
	if err != nil || !ok {
		t.Fatalf("honest eq(18) must pass: ok=%v err=%v", ok, err)
	}
	if cz.Cmp(g.Commit(h, zi, zri)) != 0 {
		t.Fatal("derived cz != direct commitment")
	}
	bad := &MulIntermediates{Server: 1, D: new(big.Int).Add(mul.D, big.NewInt(1)), E: mul.E, RD: mul.RD, RE: mul.RE}
	if _, err := st.DeriveMulCommitmentG(bad, d1, e1); err == nil {
		t.Fatal("tampered d_i must fail eq(17) chain (z algebra breaks)")
	}
	if _, err := st.DeriveMulCommitmentG(&MulIntermediates{Server: 99, D: mul.D, E: mul.E, RD: mul.RD, RE: mul.RE}, d1, e1); err == nil {
		t.Fatal("unregistered server must be rejected")
	}
	st2 := NewContractState(g, h, rp)
	st2.CX[1] = g.Commit(h, x, rx)
	st2.CY[1] = g.Commit(h, y, ry)
	czAdd, err := st2.DeriveAddCommitment(1)
	if err != nil {
		t.Fatal(err)
	}
	if czAdd.Cmp(g.Commit(h, new(big.Int).Add(x, y).Mod(new(big.Int).Add(x, y), mod),
		new(big.Int).Add(rx, ry).Mod(new(big.Int).Add(rx, ry), mod))) != 0 {
		t.Fatal("eq(15) addition commitment mismatch")
	}
}

func TestDecryptProductAndDLOG(t *testing.T) {
	g := testGroup(t, 256)
	hKP, _ := g.NewKeyPair(rand.Reader)
	ks, err := NewDecryptKeySet(hKP.S, 3, g, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v := big.NewInt(0x42)
	l, _ := RandScalar(g.ExpMod, rand.Reader)
	ct := g.EncryptPartition(hKP.H, v, l)
	partials := make([]*big.Int, 3)
	for i, k := range ks.Shares {
		partials[i] = g.PartialDecrypt(ct, k)
	}
	gv, err := g.ProductDecrypt(ct, partials)
	if err != nil {
		t.Fatal(err)
	}
	table, err := g.NewFullTable(12)
	if err != nil {
		t.Fatal(err)
	}
	vT := table.Query(gv)
	vB := g.BSGS(gv, 12)
	if vT.Sign() < 0 || vB.Sign() < 0 {
		t.Fatal("dlog not found")
	}
	if vT.Cmp(vB) != 0 || vT.Cmp(v) != 0 {
		t.Fatalf("table %v vs bsgs %v vs truth %v", vT, vB, v)
	}
	gvPartial, err := g.ProductDecrypt(ct, partials[:2])
	if err != nil {
		t.Fatal(err)
	}
	if table.Query(gvPartial).Cmp(v) == 0 {
		t.Fatal("partial product must NOT decrypt to the correct v (additive keys, missing client)")
	}
	got, err := g.RecoverPartition(ct, partials, 12, table)
	if err != nil || got.Cmp(v) != 0 {
		t.Fatalf("RecoverPartition: %v", err)
	}
}

func TestE2EHonest(t *testing.T) {
	for _, mode := range []TripleMode{TripleModeClient, TripleModeServer} {
		g := testGroup(t, 256)
		cfg := PipelineConfig{
			T: 2, N: 3, M: 3, Mode: mode,
			ElGamal: DefaultElGamal,
			ZK:      DefaultZKPoC, Group: g,
		}
		x := big.NewInt(0xABCDEF12)
		y := big.NewInt(0x98765432)
		res, err := RunE2E(cfg, x, y, rand.Reader)
		if err != nil {
			t.Fatalf("mode=%d E2E error: %v", mode, err)
		}
		if !res.Valid {
			t.Fatalf("mode=%d E2E invalid: %s", mode, res.FirstReject)
		}
	}
}

func TestE2EPatentLayout(t *testing.T) {
	g := testGroup(t, 128)
	cfg := PipelineConfig{
		T: 2, N: 3, M: 2, Mode: TripleModeClient,
		ElGamal: PatentElGamal, // k=128,p=16,w=8
		ZK:      DefaultZKPoC, Group: g,
	}
	res, err := RunE2E(cfg, big.NewInt(0x1122), big.NewInt(0x3344), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("patent layout E2E invalid: %s", res.FirstReject)
	}
}

func TestE2ENegativeTamperedCiphertext(t *testing.T) {
	g := testGroup(t, 256)
	hKP, _ := g.NewKeyPair(rand.Reader)
	cfg := DefaultElGamal
	z := big.NewInt(12345)
	r, _ := RandScalar(g.ScalarMod(), rand.Reader)
	es, _ := g.EncryptShare(hKP.H, z, r, cfg, rand.Reader)
	es.Cts[2].C1 = g.Mul(es.Cts[2].C1, g.G)
	prod := g.HomomorphicProduct(es.Cts, cfg)
	want := g.Commit(hKP.H, z, r)
	if prod.Cmp(want) == 0 {
		t.Fatal("tampered ciphertext must be caught by eq(18)")
	}
}
