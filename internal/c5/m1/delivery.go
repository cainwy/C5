package m1

// Delivery generation, distinct-index collection and receiver recovery (M3-2).
// The proof field is filled in M3-3 (Compiled-C + Groth16); here the delivery
// envelope, mask derivation and Shamir reconstruction are already complete and
// match the AP2 frozen host semantics (host.DeriveMask, host.Pedersen).

import (
	"crypto/rand"
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"

	"c5full/internal/c5/host"
	"c5full/internal/c5/params"
)

// Delivery is a server's delivery contribution Del_i = (i, E_i, sig, proof).
type Delivery struct {
	I    int                  // server index (0-based)
	R    *secp256k1.G1Affine  // R_i = [s_i]G
	C    []*big.Int           // c_{i,j} ciphertext scalars
	S    *big.Int             // s_i (sender witness; not published)
	Z    *secp256k1.G1Affine  // Z_i = [s_i]PK_R (sender shared point)
	Sig  []byte               // delivery signature over m_i^del (without proof for M3-2)
	// proof fields (M3-3)
	Proof     []byte
	HasProof  bool
}

// MakeDelivery produces server i's honest delivery envelope (no proof yet).
// It derives k_{i,j} = DeriveMask([s_i]PK_R, MaskCtx_i, j) exactly as the
// host/receiver would, then c_{i,j} = z_{i,j} + k_{i,j} mod q.
func (t *Task) MakeDelivery(i int) *Delivery {
	return t.MakeDeliveryWithRNG(i, rand.Reader)
}

func (t *Task) MakeDeliveryWithRNG(i int, rng io.Reader) *Delivery {
	s := randScalarM1R(rng, true)
	R := host.ScalarMulBase(s)
	Z := host.ScalarMul(t.ReceiverPK, s)
	maskCtx := t.MaskCtxFor(i + 1)
	c := make([]*big.Int, t.L)
	for j := 0; j < t.L; j++ {
		z, _ := t.ShareAt(i, j)
		k, err := host.DeriveMask(Z, maskCtx, j+1)
		if err != nil {
			panic(err)
		}
		cj := new(big.Int).Add(z, k)
		cj.Mod(cj, params.Q)
		c[j] = cj
	}
	d := &Delivery{I: i, R: R, C: c, S: s, Z: Z}
	d.Sig = t.signDelivery(d)
	return d
}

// signDelivery signs the delivery transcript m_i^del = (tau, alpha, PK_R, i, E_i, pi)
// (AP1 eq. c5-delivery-sign-message). In M3-2 the proof is empty; M3-3 fills it
// and re-signs via SignWithProof.
func (t *Task) signDelivery(d *Delivery) []byte {
	return signTranscript(t.ServerPriv[d.I], params.DSTDeliverySig,
		t.TaskCtx, t.Alpha, host.EncodePoint(t.ReceiverPK, false), host.U32Bytes(d.I+1), t.encodeEnvelope(d), d.Proof)
}

// verifyDeliverySig checks the delivery signature (same transcript).
func (t *Task) verifyDeliverySig(d *Delivery) bool {
	return verifyTranscript(t.ServerPub[d.I], params.DSTDeliverySig, d.Sig,
		t.TaskCtx, t.Alpha, host.EncodePoint(t.ReceiverPK, false), host.U32Bytes(d.I+1), t.encodeEnvelope(d), d.Proof)
}

func VerifyDeliverySignature(t *Task, d *Delivery) bool {
	return t.verifyDeliverySig(d)
}

// SignWithProof re-signs a delivery after its proof has been attached.
func (t *Task) SignWithProof(d *Delivery) {
	d.Sig = t.signDelivery(d)
}

// encodeEnvelope canonicalizes E_i = (R_i, c_{i,1..L}) for the signed transcript.
func (t *Task) encodeEnvelope(d *Delivery) []byte {
	out := host.EncodePoint(d.R, false)
	for j := 0; j < t.L; j++ {
		out = append(out, u32LE(32)...)
		out = append(out, fieldBytes(d.C[j])...)
	}
	return out
}

type Collector struct {
	seen map[int]bool
	D    []int // distinct server indices (0-based)
}

func NewCollector() *Collector { return &Collector{seen: map[int]bool{}, D: []int{}} }

// Add records a distinct valid index; duplicate (same index) is rejected for
// collection and does not increase cardinality.
func (c *Collector) Add(i int) Result {
	if i < 0 || c.seen[i] {
		return Reject(RejectDuplicateForCollection)
	}
	c.seen[i] = true
	c.D = append(c.D, i)
	return Ok(len(c.D))
}

// Available returns the number of distinct valid available indices.
func (c *Collector) Available() int { return len(c.D) }

// ---- receiver recovery -----------------------------------------------------

// Recover reconstructs the output vector from f+1 deliveries, using the
// receiver secret x_R to decapsulate each mask. It returns OK(output) on
// success, Insufficient when < f+1 distinct indices, or a Reject on a malformed
// LA-02 hardening: before touching t.Xi[i] / d.C[j] every delivery is fully
// validated (nil, index range, C length), so malformed experimental input can
// never panic.
func (t *Task) Recover(deliveries map[int]*Delivery) Result {
	if len(deliveries) < t.F+1 {
		return Insufficient(len(deliveries), t.F+1)
	}
	// LA-02: validate every entry up front — nil delivery, index range, C length.
	for i, d := range deliveries {
		if d == nil {
			return Reject(RejectRecoveryInput)
		}
		if i < 0 || i >= t.N {
			return Reject(RejectInvalidIndex)
		}
		if len(d.C) != t.L {
			return Reject(RejectRecoveryInput)
		}
	}
	// choose first f+1 distinct indices (order-free; T6 guarantees consistency)
	xs := make([]*big.Int, 0, t.F+1)
	for i := range deliveries {
		xs = append(xs, t.Xi[i])
		if len(xs) == t.F+1 {
			break
		}
	}
	if len(xs) < t.F+1 {
		return Insufficient(len(xs), t.F+1)
	}
	// for each chosen server, decapsulate and recover shares
	out := make([]*big.Int, t.L)
	for j := 0; j < t.L; j++ {
		zs := make([]*big.Int, 0, t.F+1)
		for _, i := range chosenIndices(deliveries, t.F+1) {
			d := deliveries[i]
			maskCtx := t.MaskCtxFor(i + 1)
			Z := host.ScalarMul(d.R, t.ReceiverX) // [x_R]R_i = [s_i]PK_R
			k, err := host.DeriveMask(Z, maskCtx, j+1)
			if err != nil {
				return Reject(RejectRecoveryInput)
			}
			z := new(big.Int).Sub(d.C[j], k)
			z.Mod(z, params.Q)
			zs = append(zs, z)
		}
		xsel := make([]*big.Int, len(zs))
		for k, i := range chosenIndices(deliveries, t.F+1) {
			xsel[k] = t.Xi[i]
		}
		out[j] = Reconstruct(xsel, zs)
	}
	return Ok(out)
}

// chosenIndices returns the first f+1 delivery indices (map iteration order is
// not deterministic; T6 shows any distinct f+1 subset yields the same output,
// so this choice is safe). For determinism of tests, we sort by index.
func chosenIndices(deliveries map[int]*Delivery, k int) []int {
	all := make([]int, 0, len(deliveries))
	for i := range deliveries {
		all = append(all, i)
	}
	// simple insertion sort by index for determinism
	for a := 1; a < len(all); a++ {
		for b := a; b > 0 && all[b] < all[b-1]; b-- {
			all[b], all[b-1] = all[b-1], all[b]
		}
	}
	if len(all) > k {
		all = all[:k]
	}
	return all
}
