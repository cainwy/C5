package host

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"math/rand"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"

	"c5full/internal/c5/params"
)

// wire tuple (C5E1) helpers - typed, ordered, length-delimited, canonical.
const wireMagic = "C5E1"

func encTuple(fields [][2]string) []byte {
	out := []byte(wireMagic)
	out = append(out, 0, byte(len(fields))) // u16 big-endian count
	seen := map[string]bool{}
	for _, f := range fields {
		tag := f[0]
		val := []byte(f[1])
		if len(tag) == 0 || len(tag) > 255 || seen[tag] {
			panic(ErrParse)
		}
		seen[tag] = true
		out = append(out, byte(len(tag)))
		out = append(out, tag...)
		out = append(out, 0, 0, 0, byte(len(val))) // u32 length big-endian
		out = append(out, val...)
	}
	return out
}

func u16Bytes(x int) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(x))
	return b
}
func u32Bytes(x int) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(x))
	return b
}

// EncodeAout serializes A_out row-major with explicit per-point lengths.
func EncodeAout(aout [][]*secp256k1.G1Affine) []byte {
	out := u32Bytes(len(aout))
	if len(aout) > 0 {
		out = append(out, u32Bytes(len(aout[0]))...)
	} else {
		out = append(out, u32Bytes(0)...)
	}
	for _, row := range aout {
		for _, A := range row {
			eb := EncodePointAllowInf(A)
			out = append(out, u16Bytes(len(eb))...)
			out = append(out, eb...)
		}
	}
	return out
}

func HashState(taskCtx []byte, aout [][]*secp256k1.G1Affine) []byte {
	h := sha256.New()
	h.Write([]byte(params.DSTStateID))
	h.Write([]byte{0x00})
	h.Write(encTuple([][2]string{{"TaskCtx", string(taskCtx)}, {"Aout", string(EncodeAout(aout))}}))
	return h.Sum(nil)
}

// Instance holds a concrete synthetic delivery instance (matching semantic M0).
type Instance struct {
	L             int
	F             int
	I             int
	N             int
	Xi            *big.Int
	TaskCtx       []byte
	Alpha         []byte
	MaskCtx       []byte
	Aout          [][]*secp256k1.G1Affine
	PKR           *secp256k1.G1Affine
	XR            *big.Int
	S             *big.Int
	R             *secp256k1.G1Affine
	Z             *secp256k1.G1Affine
	Zlist         []*big.Int
	Rholist       []*big.Int
	Clist         []*big.Int
	RelationID    string
	ProofProfileID string
}

func randScalar(rng *rand.Rand, nonzero bool) *big.Int {
	for {
		x := new(big.Int).Rand(rng, params.Q)
		if !nonzero || x.Sign() != 0 {
			return x
		}
	}
}

func polyEval(coeffs []*big.Int, x *big.Int) *big.Int {
	acc := new(big.Int)
	for i := len(coeffs) - 1; i >= 0; i-- {
		acc.Mul(acc, x)
		acc.Add(acc, coeffs[i])
		acc.Mod(acc, params.Q)
	}
	return acc
}

func evalCom(Acoeffs []*secp256k1.G1Affine, x *big.Int) *secp256k1.G1Affine {
	acc := new(secp256k1.G1Affine) // identity
	pw := big.NewInt(1)
	for _, A := range Acoeffs {
		term := ScalarMul(A, pw)
		acc = AddPoints(acc, term)
		pw.Mul(pw, x).Mod(pw, params.Q)
	}
	return acc
}

func makeMaskCtx(taskCtx, alpha []byte, pkR *secp256k1.G1Affine, i, L int, relationID string) []byte {
	return encTuple([][2]string{
		{"pid", "C5"}, {"ver", "\x00\x01"}, {"domainId", "post-mpc-delivery"},
		{"TaskCtx", string(taskCtx)}, {"alpha", string(alpha)},
		{"PK_R", string(EncodePoint(pkR, false))},
		{"serverIndex", string(u32Bytes(i))}, {"L", string(u32Bytes(L))},
		{"relationId", relationID},
	})
}

// SynthInstance deterministically builds a concrete L,f instance from a seed.
func SynthInstance(Lf, f, seed, i, n int) (*Instance, error) {
	if n == 0 {
		n = 2*f + 1
	}
	if n < i {
		n = i
	}
	if Lf < 1 || f < 0 || i < 1 || n < 2*f+1 {
		return nil, fmt.Errorf("bad L/f/i/n")
	}
	rng := rand.New(rand.NewSource(int64(seed)))
	xr := randScalar(rng, true)
	pkR := ScalarMul(&params.G, xr)
	relationID := "RDEL-v2"
	proofProfileID := "gnark-v0.15.0-groth16-bls12-381-v1"
	taskCtx := encTuple([][2]string{
		{"pid", "C5"}, {"ver", "\x00\x01"}, {"domainId", "post-mpc-delivery"},
		{"tau", "dummy-reg"}, {"taskVersion", string(u32Bytes(1))},
		{"serverSetId", "srvset"}, {"receiverId", "rcvr"},
		{"PK_R", string(EncodePoint(pkR, false))},
		{"n", string(u32Bytes(n))}, {"f", string(u32Bytes(f))}, {"L", string(u32Bytes(Lf))},
		{"paramSetId", "secp256k1-rfc9380xmd-v1"},
		{"deliveryProfileId", proofProfileID},
	})
	xi := big.NewInt(int64(i))
	xi.Mod(xi, params.Q)
	if xi.Sign() == 0 {
		return nil, fmt.Errorf("xi must be nonzero")
	}
	var aout [][]*secp256k1.G1Affine
	var zcoeff, rhocoeff [][]*big.Int
	for j := 0; j < Lf; j++ {
		az := make([]*big.Int, f+1)
		ar := make([]*big.Int, f+1)
		row := make([]*secp256k1.G1Affine, f+1)
		for k := 0; k <= f; k++ {
			az[k] = randScalar(rng, false)
			ar[k] = randScalar(rng, false)
			row[k] = Pedersen(az[k], ar[k])
		}
		zcoeff = append(zcoeff, az)
		rhocoeff = append(rhocoeff, ar)
		aout = append(aout, row)
	}
	alpha := HashState(taskCtx, aout)
	maskCtx := makeMaskCtx(taskCtx, alpha, pkR, i, Lf, relationID)
	zlist := make([]*big.Int, Lf)
	rholist := make([]*big.Int, Lf)
	for j := 0; j < Lf; j++ {
		zlist[j] = polyEval(zcoeff[j], xi)
		rholist[j] = polyEval(rhocoeff[j], xi)
	}
	s := randScalar(rng, true)
	R := ScalarMul(&params.G, s)
	Z := ScalarMul(pkR, s)
	clist := make([]*big.Int, Lf)
	for j := 0; j < Lf; j++ {
		k, err := DeriveMask(Z, maskCtx, j+1)
		if err != nil {
			return nil, err
		}
		clist[j] = new(big.Int).Add(zlist[j], k)
		clist[j].Mod(clist[j], params.Q)
	}
	return &Instance{Lf, f, i, n, xi, taskCtx, alpha, maskCtx, aout, pkR, xr, s, R, Z, zlist, rholist, clist, relationID, proofProfileID}, nil
}

// Clone returns a shallow copy for negative tests.
func (inst *Instance) Clone() *Instance {
	c := *inst
	return &c
}

// ReceiverCheck verifies PK_R=[xR]G and [xR]R == [s]PK_R.
func (inst *Instance) ReceiverCheck() bool {
	if !PointEqual(ScalarMul(&params.G, inst.XR), inst.PKR) {
		return false
	}
	left := ScalarMul(inst.R, inst.XR)
	right := ScalarMul(inst.PKR, inst.S)
	return PointEqual(left, right)
}

// RelationCheck validates R1-R5 over the instance.
func (inst *Instance) RelationCheck(expectedProfile string, paramsAvailable bool) (bool, error) {
	if !paramsAvailable {
		return false, ErrParamUnavail
	}
	if expectedProfile != "" && inst.ProofProfileID != expectedProfile {
		return false, ErrProfile
	}
	// canonical round trips (parser smoke)
	if _, err := DecodePoint(EncodePoint(inst.PKR, false), true); err != nil {
		return false, err
	}
	if _, err := DecodePoint(EncodePoint(inst.R, false), true); err != nil {
		return false, err
	}
	// R1: s != 0 and R = [s]G
	if inst.S.Sign() == 0 {
		return false, nil
	}
	if !PointEqual(inst.R, ScalarMul(&params.G, inst.S)) {
		return false, nil
	}
	Z := ScalarMul(inst.PKR, inst.S)
	// R2-R5
	for j := 0; j < inst.L; j++ {
		C := evalCom(inst.Aout[j], inst.Xi)
		if !PointEqual(C, Pedersen(inst.Zlist[j], inst.Rholist[j])) {
			return false, nil
		}
		k, err := DeriveMask(Z, inst.MaskCtx, j+1)
		if err != nil {
			return false, err
		}
		want := new(big.Int).Add(inst.Zlist[j], k)
		want.Mod(want, params.Q)
		if inst.Clist[j].Cmp(want) != 0 {
			return false, nil
		}
	}
	return true, nil
}

// CompiledStatement computes the deterministic verifier-side A_out -> C_i.
func (inst *Instance) CompiledStatement() map[string]interface{} {
	C := make([]string, inst.L)
	for j := 0; j < inst.L; j++ {
		C[j] = fmt.Sprintf("%x", EncodePoint(evalCom(inst.Aout[j], inst.Xi), true))
	}
	return map[string]interface{}{
		"alpha":   fmt.Sprintf("%x", inst.Alpha),
		"i":       inst.I,
		"L":       inst.L,
		"xi":      fmt.Sprintf("%x", inst.Xi),
		"C":       C,
		"E_R":     fmt.Sprintf("%x", EncodePoint(inst.R, false)),
		"c":       clistHex(inst.Clist),
		"profile": inst.ProofProfileID,
	}
}

func clistHex(cl []*big.Int) []string {
	out := make([]string, len(cl))
	for i, x := range cl {
		out[i] = fmt.Sprintf("%x", x)
	}
	return out
}