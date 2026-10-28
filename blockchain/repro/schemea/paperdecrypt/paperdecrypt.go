//	experiments/cmd/bce2e/schemea.go:210  p.NewDecryptionShareSet(threshold, servers, rng)
//	IV-C  Key generation : `n` players independently pick s_i, k_i = g^{s_i},
//	                       h = ∏ k_i = g^{Σ s_i}
//	IV-D-6 Eq.(20)       : t_j = ∏_{i=1}^{m} (C_j^0)^{s_i},  g^{v_j} = C_j^1 / t_j
package paperdecrypt

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"time"
)

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

type ActorCounts struct {
	NServers        int `json:"n_servers"`
	TSecretSharing  int `json:"t_secret_sharing"`
	MClients        int `json:"m_clients"`
	DecryptPartials int `json:"number_of_decrypt_partials"`
}

func (a ActorCounts) Check() error {
	if a.MClients < 1 {
		return &Err{"m_clients must be >= 1"}
	}
	if a.NServers < 1 {
		return &Err{"n_servers must be >= 1"}
	}
	if a.TSecretSharing < 1 {
		return &Err{"t_secret_sharing must be >= 1"}
	}
	if a.DecryptPartials != a.MClients {
		return &Err{fmt.Sprintf(
			"number_of_decrypt_partials(%d) != m_clients(%d): Eq. (20) requires all m clients to participate",
			a.DecryptPartials, a.MClients)}
	}
	return nil
}

type Err struct{ msg string }

func (e *Err) Error() string { return "paperdecrypt: " + e.msg }

// ---------------------------------------------------------------------------
// Client actors
// ---------------------------------------------------------------------------

type ClientActor struct {
	Index int      // 1-based
	P     *big.Int
	G     *big.Int

	s *big.Int
	k *big.Int
}

func (c *ClientActor) PublicShare() *big.Int { return new(big.Int).Set(c.k) }

//	t_i = (C0)^{s_i} mod p
func (c *ClientActor) PartialDecrypt(ct0 *big.Int) (*big.Int, error) {
	if ct0 == nil {
		return nil, &Err{"nil ciphertext C0"}
	}
	if ct0.Sign() <= 0 || ct0.Cmp(c.P) >= 0 {
		return nil, &Err{"C0 out of range"}
	}
	return new(big.Int).Exp(ct0, c.s, c.P), nil
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

type KeyRing struct {
	P       *big.Int
	G       *big.Int
	H       *big.Int       // h = ∏_{i=1}^{m} g^{s_i} = g^{Σ s_i}
	Clients []*ClientActor
	M       int            // m_clients
}

func NewKeyRing(P, G *big.Int, m int, rng io.Reader) (*KeyRing, error) {
	if P == nil || G == nil {
		return nil, &Err{"nil group parameter"}
	}
	if P.Sign() <= 0 || G.Sign() <= 0 || G.Cmp(P) >= 0 {
		return nil, &Err{"invalid group parameter"}
	}
	if m < 1 {
		return nil, &Err{"m_clients must be >= 1"}
	}
	if rng == nil {
		return nil, &Err{"rng required: no default crypto/rand source, to keep runs reproducible"}
	}
	order := new(big.Int).Sub(P, big.NewInt(1))
	ring := &KeyRing{P: P, G: G, H: big.NewInt(1), Clients: make([]*ClientActor, 0, m), M: m}
	for i := 0; i < m; i++ {
		si := randInRange(order, rng)
		ki := new(big.Int).Exp(G, si, P)
		ring.H.Mul(ring.H, ki)
		ring.H.Mod(ring.H, P)
		ring.Clients = append(ring.Clients, &ClientActor{
			Index: i + 1, P: P, G: G, s: si, k: ki,
		})
	}
	return ring, nil
}

func (r *KeyRing) PublicShares() []*big.Int {
	out := make([]*big.Int, len(r.Clients))
	for i, c := range r.Clients {
		out[i] = c.PublicShare()
	}
	return out
}

func (r *KeyRing) PublicDigest() string {
	h := sha256.New()
	fmt.Fprintf(h, "SA-PAPER-KEYRING/v1|p=%s|g=%s|h=%s|m=%d|", r.P.Text(16), r.G.Text(16), r.H.Text(16), r.M)
	for _, k := range r.PublicShares() {
		fmt.Fprintf(h, "%s:", k.Text(16))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

type Ciphertext struct {
	C0 *big.Int
	C1 *big.Int
}

func (r *KeyRing) ClientPartials(ct0 *big.Int) ([]int, []*big.Int, error) {
	idx := make([]int, 0, r.M)
	parts := make([]*big.Int, 0, r.M)
	for _, c := range r.Clients {
		p, err := c.PartialDecrypt(ct0)
		if err != nil {
			return nil, nil, err
		}
		idx = append(idx, c.Index)
		parts = append(parts, p)
	}
	return idx, parts, nil
}

//	t_j = ∏_{i=1}^{m} (C_j^0)^{s_i}
func Eq20Product(P *big.Int, partials []*big.Int, m int) (*big.Int, error) {
	if P == nil {
		return nil, &Err{"nil modulus"}
	}
	if m < 1 {
		return nil, &Err{"m must be >= 1"}
	}
	if len(partials) != m {
		return nil, &Err{fmt.Sprintf(
			"Eq.(20) requires all m=%d client partials, got %d", m, len(partials))}
	}
	t := big.NewInt(1)
	for i, p := range partials {
		if p == nil {
			return nil, &Err{fmt.Sprintf("nil partial at position %d", i)}
		}
		if p.Sign() == 0 || p.Cmp(P) >= 0 {
			return nil, &Err{fmt.Sprintf("partial %d out of range", i)}
		}
		t.Mul(t, p)
		t.Mod(t, P)
	}
	return t, nil
}

func RecoverGv(P, ct1, tj *big.Int) (*big.Int, error) {
	if P == nil || ct1 == nil || tj == nil {
		return nil, &Err{"nil input"}
	}
	inv := new(big.Int).ModInverse(tj, P)
	if inv == nil {
		return nil, &Err{"t_j not invertible mod p"}
	}
	out := new(big.Int).Mul(ct1, inv)
	return out.Mod(out, P), nil
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

func BSGSBounded(P, G, target *big.Int, boundBits int) (*big.Int, bool) {
	if boundBits < 1 || boundBits > 62 {
		return nil, false
	}
	w := (P.BitLen() + 7) / 8
	buf := make([]byte, w)
	key := func(x *big.Int) string { return string(x.FillBytes(buf)) }

	m := 1 << (boundBits / 2) // 2^(boundBits/2) baby steps
	baby := make(map[string]int, m)
	cur := big.NewInt(1)
	for i := 0; i < m; i++ {
		baby[key(cur)] = i
		cur.Mul(cur, G)
		cur.Mod(cur, P)
	}
	gm := new(big.Int).Exp(G, big.NewInt(int64(m)), P)
	gmInv := new(big.Int).ModInverse(gm, P)
	if gmInv == nil {
		return nil, false
	}
	gamma := new(big.Int).Set(target)
	for j := 0; j < m; j++ {
		if v, found := baby[key(gamma)]; found {
			res := big.NewInt(int64(j * m))
			return res.Add(res, big.NewInt(int64(v))), true
		}
		gamma.Mul(gamma, gmInv)
		gamma.Mod(gamma, P)
	}
	return nil, false
}

//	z_i = v_0 + v_1·2^p + ... + v_{k/p−1}·2^{(k/p−1)p}
func Recombine(vs []*big.Int, chunkBits int) *big.Int {
	z := big.NewInt(0)
	for j, v := range vs {
		term := new(big.Int).Lsh(v, uint(j*chunkBits))
		z.Add(z, term)
	}
	return z
}

type DecryptResult struct {
	V []*big.Int `json:"-"`
	Z *big.Int   `json:"-"`

	PartialsPerProduct int `json:"number_of_decrypt_partials"`
	TotalPartials int `json:"total_client_partials"`
	Partitions int `json:"partitions"`
	DLOGBoundBits int `json:"dlog_bound_bits"`
	MeasuredChunkBits int `json:"measured_chunk_bits"`

	DLOGNS int64 `json:"dlog_ns"`
	Eq20NS int64 `json:"eq20_ns"`
	PartialsNS int64 `json:"partials_ns"`
	RecombineNS int64 `json:"recombine_ns"`
	DLOGMode string `json:"dlog_mode"`
}

func (d *DecryptResult) AssertEq20Participants(mClients int) error {
	if d.PartialsPerProduct != mClients {
		return &Err{fmt.Sprintf(
			"number_of_decrypt_partials(%d) != m_clients(%d)", d.PartialsPerProduct, mClients)}
	}
	return nil
}

func (r *KeyRing) DecryptPartitions(cts []Ciphertext, chunkBits, dlogBoundBits int) (*DecryptResult, error) {
	if len(cts) == 0 {
		return nil, &Err{"no ciphertexts"}
	}
	res := &DecryptResult{
		V:                  make([]*big.Int, len(cts)),
		PartialsPerProduct: r.M,
		Partitions:         len(cts),
		DLOGBoundBits:      dlogBoundBits,
		MeasuredChunkBits:  chunkBits,
		DLOGMode:           "per-call-bsgs",
	}
	for j, ct := range cts {
		tEq := time.Now()
		tp := time.Now()
		_, parts, err := r.ClientPartials(ct.C0)
		res.PartialsNS += time.Since(tp).Nanoseconds()
		if err != nil {
			return nil, err
		}
		res.TotalPartials += len(parts)
		tj, err := Eq20Product(r.P, parts, r.M)
		if err != nil {
			return nil, err
		}
		gv, err := RecoverGv(r.P, ct.C1, tj)
		if err != nil {
			return nil, err
		}
		res.Eq20NS += time.Since(tEq).Nanoseconds()
		tD := time.Now()
		v, ok := BSGSBounded(r.P, r.G, gv, dlogBoundBits)
		res.DLOGNS += time.Since(tD).Nanoseconds()
		if !ok {
			return nil, &Err{fmt.Sprintf(
				"bounded DLOG found no solution for partition %d (bound 2^%d)", j, dlogBoundBits)}
		}
		res.V[j] = v
	}
	if err := res.AssertEq20Participants(r.M); err != nil {
		return nil, err
	}
	tR := time.Now()
	res.Z = Recombine(res.V, chunkBits)
	res.RecombineNS = time.Since(tR).Nanoseconds()
	return res, nil
}

func (r *KeyRing) DecryptPartitionsWithTable(cts []Ciphertext, chunkBits int,
	tbl *BabyGiantTable) (*DecryptResult, error) {

	if len(cts) == 0 {
		return nil, &Err{"no ciphertexts"}
	}
	if tbl == nil {
		return nil, &Err{"nil reusable DLOG table"}
	}
	if tbl.P.Cmp(r.P) != 0 || tbl.G.Cmp(r.G) != 0 {
		return nil, &Err{"reusable DLOG table group mismatch"}
	}
	res := &DecryptResult{
		V:                  make([]*big.Int, len(cts)),
		PartialsPerProduct: r.M,
		Partitions:         len(cts),
		DLOGBoundBits:      tbl.BoundBits,
		MeasuredChunkBits:  chunkBits,
		DLOGMode:           "reusable-table",
	}
	for j, ct := range cts {
		tEq := time.Now()
		tp := time.Now()
		_, parts, err := r.ClientPartials(ct.C0)
		res.PartialsNS += time.Since(tp).Nanoseconds()
		if err != nil {
			return nil, err
		}
		res.TotalPartials += len(parts)
		tj, err := Eq20Product(r.P, parts, r.M)
		if err != nil {
			return nil, err
		}
		gv, err := RecoverGv(r.P, ct.C1, tj)
		if err != nil {
			return nil, err
		}
		res.Eq20NS += time.Since(tEq).Nanoseconds()
		tD := time.Now()
		v, ok := tbl.Query(gv)
		res.DLOGNS += time.Since(tD).Nanoseconds()
		if !ok {
			return nil, &Err{fmt.Sprintf(
				"reusable-table DLOG found no solution for partition %d (bound 2^%d)",
				j, tbl.BoundBits)}
		}
		res.V[j] = v
	}
	if err := res.AssertEq20Participants(r.M); err != nil {
		return nil, err
	}
	tR := time.Now()
	res.Z = Recombine(res.V, chunkBits)
	res.RecombineNS = time.Since(tR).Nanoseconds()
	return res, nil
}

func VerifyProductIndependent(P, ct0 *big.Int, partials []*big.Int, sumShares *big.Int, m int) (bool, error) {
	t, err := Eq20Product(P, partials, m)
	if err != nil {
		return false, err
	}
	direct := new(big.Int).Exp(ct0, sumShares, P)
	return t.Cmp(direct) == 0, nil
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

//	share_i = F(i),  i = 1..n
func ShamirShare(secret *big.Int, t, n int, mod *big.Int, rng io.Reader) ([]*big.Int, error) {
	if mod == nil || mod.Sign() <= 0 {
		return nil, &Err{"invalid share modulus"}
	}
	if t < 1 || n < t {
		return nil, &Err{fmt.Sprintf("bad (t,n)=(%d,%d): need 1 <= t <= n", t, n)}
	}
	coeffs := make([]*big.Int, t)
	coeffs[0] = new(big.Int).Mod(secret, mod)
	for k := 1; k < t; k++ {
		coeffs[k] = randInRange(mod, rng)
	}
	shares := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		x := big.NewInt(int64(i + 1))
		acc := new(big.Int)
		for k := len(coeffs) - 1; k >= 0; k-- {
			acc.Mul(acc, x)
			acc.Add(acc, coeffs[k])
			acc.Mod(acc, mod)
		}
		shares[i] = acc
	}
	return shares, nil
}

//	z = Σ_{i=1}^{t} ( ∏_{j=1,j≠i}^{t} (−j)/(i−j) ) · z_i
func LagrangeReconstruct(shares []*big.Int, indices []int, t int, mod *big.Int) (*big.Int, error) {
	if len(shares) != len(indices) {
		return nil, &Err{"shares/indices length mismatch"}
	}
	if len(indices) < t {
		return nil, &Err{fmt.Sprintf("need >= t=%d shares for reconstruction, got %d", t, len(indices))}
	}
	for i := range indices {
		if indices[i] < 1 {
			return nil, &Err{"share index must be >= 1 (1-based)"}
		}
	}
	acc := big.NewInt(0)
	for i := range indices {
		num := big.NewInt(1)
		den := big.NewInt(1)
		for j := range indices {
			if i == j {
				continue
			}
			num.Mul(num, big.NewInt(int64(-indices[j])))
			num.Mod(num, mod)
			den.Mul(den, big.NewInt(int64(indices[i]-indices[j])))
			den.Mod(den, mod)
		}
		denInv := new(big.Int).ModInverse(den, mod)
		if denInv == nil {
			return nil, &Err{fmt.Sprintf("non-invertible denominator for share %d", indices[i])}
		}
		lam := new(big.Int).Mul(num, denInv)
		lam.Mod(lam, mod)
		term := new(big.Int).Mul(lam, shares[i])
		term.Mod(term, mod)
		acc.Add(acc, term)
		acc.Mod(acc, mod)
	}
	return acc, nil
}

func randInRange(mod *big.Int, rng io.Reader) *big.Int {
	w := (mod.BitLen() + 7) / 8
	buf := make([]byte, w+8)
	if _, err := io.ReadFull(rng, buf); err != nil {
		panic("paperdecrypt: rng read failed: " + err.Error())
	}
	x := new(big.Int).SetBytes(buf)
	x.Mod(x, new(big.Int).Sub(mod, big.NewInt(2)))
	return x.Add(x, big.NewInt(1))
}
