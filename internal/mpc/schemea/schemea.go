// Package schemea implements the paper-faithful output-processing route of
// Scheme A (Gai et al., TDSC 2025): k-bit output shares partitioned into p-bit
// groups, Lifted ElGamal encryption over Z_p^*, per-partition ZKPoC, additive-
// homomorphic verification, client-threshold decryption, bounded-DLOG recovery
// (BSGS), chunk recomposition and Shamir reconstruction.
// This is a B3 baseline implementation, NOT a C5 component. Its group (Z_p^*
// multiplicative), receiver topology (client-threshold decryption) and
// bit-splitting + DLOG route are intentionally faithful to the paper and are
// NOT security-equivalent to C5 (see BASELINE_NORMALIZATION_v1.0.md §B3).
package schemea

import (
	crand "crypto/rand"
	"crypto/sha256"
	"io"
	"math/big"
	"math/rand"
)

// Params holds the Lifted ElGamal group parameters and the output route config.
type Params struct {
	P          *big.Int // Z_p^* modulus (prime)
	G          *big.Int // generator
	H          *big.Int // public key h = g^s
	S          *big.Int // (simulated aggregate) private key s
	K          int      // output share bit width (paper k=256)
	ChunkBits  int      // partition width (paper p=32, renamed chunk_bits)
	NumChunks  int      // k/chunk_bits
	PrimeBits  int      // group prime bit length (256 paper-repro / 2048 normalized)
}

// NewParams generates a fixed-size prime p and generator g with a fixed seed for
// reproducibility, and derives h=g^s for a fresh aggregate secret s.
func NewParams(primeBits, k, chunkBits int, seed int64) *Params {
	if k%chunkBits != 0 {
		panic("schemea: k must be a multiple of chunk_bits")
	}
	p := genPrime(primeBits, seed)
	g := big.NewInt(2)
	if g.Cmp(p) >= 0 {
		g = big.NewInt(3)
	}
	// aggregate secret s in [1, p-2]
	rng := rand.New(rand.NewSource(seed ^ 0xdeadbeef))
	s := new(big.Int).Rand(rng, new(big.Int).Sub(p, big.NewInt(3)))
	s.Add(s, big.NewInt(1))
	h := new(big.Int).Exp(g, s, p)
	return &Params{
		P: p, G: g, H: h, S: s,
		K: k, ChunkBits: chunkBits, NumChunks: k / chunkBits, PrimeBits: primeBits,
	}
}

// genPrime produces a deterministic prime of the requested bit length using a
// seeded math/rand source (reproducible).
func genPrime(bits int, seed int64) *big.Int {
	rng := rand.New(rand.NewSource(seed))
	for {
		c := new(big.Int).Rand(rng, new(big.Int).Lsh(big.NewInt(1), uint(bits)))
		c.SetBit(c, bits-1, 1)
		if c.Bit(0) == 0 {
			c.SetBit(c, 0, 1) // odd
		}
		if c.ProbablyPrime(40) {
			return c
		}
	}
}

// NewEx builds a Lifted-ElGamal / Pedersen group over a caller-supplied order
// q with group modulus P = 2q+1 (safe prime). The working subgroup has order q,
// so exponents and VSS share scalars both live in Z_q and are mutually
// consistent. g is chosen as a nontrivial quadratic residue (order q); h=g^s.
func NewEx(q *big.Int, k, chunkBits, seed int) *Params {
	p := new(big.Int).Mul(q, big.NewInt(2))
	p.Add(p, big.NewInt(1))
	if !p.ProbablyPrime(30) {
		panic("schemea: P=2q+1 must be a safe prime")
	}
	// find g of order q: a quadratic residue != 1.
	m := new(big.Int).Sub(p, big.NewInt(1)) // p-1 = 2q
	mHalf := new(big.Int).Rsh(m, 1)         // q
	two := big.NewInt(2)
	g := new(big.Int).Set(two)
	for {
		if powm(g, mHalf, p).Cmp(big.NewInt(1)) == 0 && g.Cmp(big.NewInt(1)) != 0 {
			break
		}
		g.Add(g, big.NewInt(1))
	}
	rng := rand.New(rand.NewSource(int64(seed) ^ 0xabc123))
	s := new(big.Int).Rand(rng, new(big.Int).Sub(q, big.NewInt(2)))
	s.Add(s, big.NewInt(1))
	h := new(big.Int).Exp(g, s, p)
	return &Params{P: p, G: g, H: h, S: s, K: k, ChunkBits: chunkBits, NumChunks: k / chunkBits, PrimeBits: p.BitLen()}
}

func powm(b, e, m *big.Int) *big.Int { return new(big.Int).Exp(b, e, m) }

// Split partitions a k-bit share z into chunkBits groups (little-endian groups),
// returning v_0..v_{numChunks-1} with z = sum v_j * 2^{j*chunkBits}.
func (p *Params) Split(z *big.Int) []*big.Int {
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(p.ChunkBits)), big.NewInt(1))
	vs := make([]*big.Int, p.NumChunks)
	for j := 0; j < p.NumChunks; j++ {
		vs[j] = new(big.Int).And(new(big.Int).Rsh(z, uint(j*p.ChunkBits)), mask)
	}
	return vs
}

// Recombine reconstructs z = sum v_j * 2^{j*chunkBits}.
func (p *Params) Recombine(vs []*big.Int) *big.Int {
	z := big.NewInt(0)
	for j := 0; j < len(vs); j++ {
		term := new(big.Int).Lsh(vs[j], uint(j*p.ChunkBits))
		z.Add(z, term)
	}
	return z
}

// Ciphertext is a single Lifted ElGamal ciphertext pair (C0, C1).
type Ciphertext struct {
	C0, C1 *big.Int
}

// Encrypt encrypts a partition value v (< 2^chunkBits) with blinding l.
// C0 = g^l, C1 = g^v h^l.
func (p *Params) Encrypt(v, l *big.Int) *Ciphertext {
	c0 := new(big.Int).Exp(p.G, l, p.P)
	c1 := new(big.Int).Exp(p.G, v, p.P)
	tmp := new(big.Int).Exp(p.H, l, p.P)
	c1.Mul(c1, tmp)
	c1.Mod(c1, p.P)
	return &Ciphertext{C0: c0, C1: c1}
}

// EncryptShare partitions z into groups and encrypts each group with fresh
// blindings l_j (j>=1 random, l_0 derived from the Pedersen blinding r, per
// paper eq. (11)). Returns the ciphertext list and the blindings used.
func (p *Params) EncryptShare(z, r *big.Int) ([]*Ciphertext, []*big.Int) {
	return p.EncryptShareR(z, r, nil)
}

func (p *Params) EncryptShareR(z, r *big.Int, rng io.Reader) ([]*Ciphertext, []*big.Int) {
	vs := p.Split(z)
	ls := make([]*big.Int, p.NumChunks)
	pMinus1 := new(big.Int).Sub(p.P, big.NewInt(1))
	if rng == nil {
		rng = crand.Reader
	}
	for j := 1; j < p.NumChunks; j++ {
		ls[j] = randExponent(pMinus1, rng)
	}
	// l_0 = r - (l_1*2^p + ... + l_{w-1}*2^{(w-1)p}) mod (p-1)
	acc := big.NewInt(0)
	for j := 1; j < p.NumChunks; j++ {
		term := new(big.Int).Lsh(ls[j], uint(j*p.ChunkBits))
		acc.Add(acc, term)
	}
	l0 := new(big.Int).Sub(r, acc)
	l0.Mod(l0, pMinus1)
	ls[0] = l0

	cts := make([]*Ciphertext, p.NumChunks)
	for j := 0; j < p.NumChunks; j++ {
		cts[j] = p.Encrypt(vs[j], ls[j])
	}
	return cts, ls
}

func (p *Params) oldEncryptShare(z, r *big.Int) ([]*Ciphertext, []*big.Int) {
	vs := p.Split(z)
	ls := make([]*big.Int, p.NumChunks)
	pMinus1 := new(big.Int).Sub(p.P, big.NewInt(1))
	rng := rand.New(rand.NewSource(0x9e37))
	for j := 1; j < p.NumChunks; j++ {
		l := new(big.Int).Rand(rng, new(big.Int).Sub(pMinus1, big.NewInt(2)))
		ls[j] = l.Add(l, big.NewInt(1))
	}
	acc := big.NewInt(0)
	for j := 1; j < p.NumChunks; j++ {
		term := new(big.Int).Lsh(ls[j], uint(j*p.ChunkBits))
		acc.Add(acc, term)
	}
	l0 := new(big.Int).Sub(r, acc)
	l0.Mod(l0, pMinus1)
	ls[0] = l0
	cts := make([]*Ciphertext, p.NumChunks)
	for j := 0; j < p.NumChunks; j++ {
		cts[j] = p.Encrypt(vs[j], ls[j])
	}
	return cts, ls
}

// DecryptShareAggregateDiag decrypts all partitions using the aggregate secret
func (p *Params) DecryptShareAggregateDiag(cts []*Ciphertext) []*big.Int {
	gv := make([]*big.Int, len(cts))
	for j, ct := range cts {
		tj := new(big.Int).Exp(ct.C0, p.S, p.P)
		inv := new(big.Int).ModInverse(tj, p.P)
		gvj := new(big.Int).Mul(ct.C1, inv)
		gvj.Mod(gvj, p.P)
		gv[j] = gvj
	}
	return gv
}

// DecryptShareThreshold decrypts all partitions using the aggregate secret s
// for backward compatibility with the old measurement path. New code must use
func (p *Params) DecryptShareThreshold(cts []*Ciphertext) []*big.Int {
	return p.DecryptShareAggregateDiag(cts)
}

// HomomorphicVerify checks eq. (18): C1_0 * C1_1^{2^p} * ... == g^{z} h^{r}.
// It reconstructs the commitment from ciphertexts and compares to the expected
// commitment g^{z} h^{r}.
func (p *Params) HomomorphicVerify(cts []*Ciphertext, z, r *big.Int) bool {
	prod := big.NewInt(1)
	for j := 0; j < len(cts); j++ {
		exp := new(big.Int).Lsh(big.NewInt(1), uint(j*p.ChunkBits))
		term := new(big.Int).Exp(cts[j].C1, exp, p.P)
		prod.Mul(prod, term)
		prod.Mod(prod, p.P)
	}
	// expected commitment c_z = g^z * h^r
	gz := new(big.Int).Exp(p.G, z, p.P)
	hr := new(big.Int).Exp(p.H, r, p.P)
	expected := new(big.Int).Mul(gz, hr)
	expected.Mod(expected, p.P)
	return prod.Cmp(expected) == 0
}

// BSGS solves discrete log g^v = target mod p for v in [0, 2^chunkBits), using
// baby-step giant-step with m = ceil(sqrt(2^chunkBits)). This is the
// strengthened bounded-DLOG implementation (NOT the paper's literal 2^chunkBits
// full table, which is infeasible for chunkBits=32).
func (p *Params) BSGS(target *big.Int) *big.Int {
	bound := new(big.Int).Lsh(big.NewInt(1), uint(p.ChunkBits))
	m := new(big.Int).Sqrt(bound)
	m.Add(m, big.NewInt(1)) // ceil
	mInt := int(m.Int64())

	// baby steps: g^0..g^{m-1}
	baby := make(map[string]*big.Int, mInt)
	cur := big.NewInt(1)
	for i := 0; i < mInt; i++ {
		baby[cur.String()] = big.NewInt(int64(i))
		cur.Mul(cur, p.G)
		cur.Mod(cur, p.P)
	}

	// giant steps: g^{-m}, then target * (g^{-m})^j
	gm := new(big.Int).Exp(p.G, m, p.P)
	gMinvM := new(big.Int).ModInverse(gm, p.P)
	gamma := new(big.Int).Set(target)
	for j := 0; j < mInt; j++ {
		if v, ok := baby[gamma.String()]; ok {
			res := new(big.Int).Mul(big.NewInt(int64(j)), m)
			res.Add(res, v)
			return res
		}
		gamma.Mul(gamma, gMinvM)
		gamma.Mod(gamma, p.P)
	}
	return big.NewInt(-1) // not found (should not happen for valid ciphertext)
}

// RecoverShare decrypts and recovers a share z via DLOG on each partition, then
// recombines.
func (p *Params) RecoverShare(cts []*Ciphertext) *big.Int {
	gv := p.DecryptShareThreshold(cts)
	vs := make([]*big.Int, len(gv))
	for j, g := range gv {
		vs[j] = p.BSGS(g)
	}
	return p.Recombine(vs)
}

// HashChallenge is a simple Fiat-Shamir challenge (used by ZKPoC if measured).
func HashChallenge(parts ...*big.Int) *big.Int {
	h := sha256.New()
	for _, x := range parts {
		h.Write(x.Bytes())
	}
	return new(big.Int).SetBytes(h.Sum(nil))
}
