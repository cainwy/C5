package m1

// Proof integration (M3-3): wraps the AP2-frozen R_del circuit (Compiled-C)
// with Groth16, building witnesses directly from the M1 Task/Delivery objects.
// This is the delivery-layer glue that connects the M1 scaffolding to the AP2
// real proof backend without changing the circuit or the host semantics.

import (
	"bytes"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"

	"c5full/internal/c5/circuit"
)

// toAffine converts a host secp256k1 affine point to an emulated circuit point.
func toAffine(p *secp256k1.G1Affine) sw_emulated.AffinePoint[emulated.Secp256k1Fp] {
	return sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
		X: emulated.ValueOf[emulated.Secp256k1Fp](p.X.BigInt(new(big.Int))),
		Y: emulated.ValueOf[emulated.Secp256k1Fp](p.Y.BigInt(new(big.Int))),
	}
}

// emptyRdEl builds an all-zero R_del template sized for L outputs and maskCtxLen
// mask bytes, used to register the exact witness schema at compile time.
func emptyRdEl(L, maskCtxLen int) *circuit.RdEl {
	return &circuit.RdEl{
		L:       L,
		C:       make([]sw_emulated.AffinePoint[emulated.Secp256k1Fp], L),
		Cpt:     make([]emulated.Element[emulated.Secp256k1Fr], L),
		MaskCtx: make([]uints.U8, maskCtxLen),
		Zs:      make([]emulated.Element[emulated.Secp256k1Fr], L),
		Rhos:    make([]emulated.Element[emulated.Secp256k1Fr], L),
	}
}

// buildRdElWitness builds the full R_del witness for server i's delivery. R2 is
// honored by feeding the outer-compiled C_j = EvalCom(A_j, xi_i) as public (the
// prover never injects an unbound C_j).
func buildRdElWitness(t *Task, d *Delivery) *circuit.RdEl {
	L := t.L
	C := make([]sw_emulated.AffinePoint[emulated.Secp256k1Fp], L)
	Cpt := make([]emulated.Element[emulated.Secp256k1Fr], L)
	Zs := make([]emulated.Element[emulated.Secp256k1Fr], L)
	Rhos := make([]emulated.Element[emulated.Secp256k1Fr], L)
	for j := 0; j < L; j++ {
		C[j] = toAffine(t.ExpectedCommitment(d.I, j))
		Cpt[j] = emulated.ValueOf[emulated.Secp256k1Fr](d.C[j])
		z, rho := t.ShareAt(d.I, j)
		Zs[j] = emulated.ValueOf[emulated.Secp256k1Fr](z)
		Rhos[j] = emulated.ValueOf[emulated.Secp256k1Fr](rho)
	}
	return &circuit.RdEl{
		L:       L,
		PKR:     toAffine(t.ReceiverPK),
		R:       toAffine(d.R),
		C:       C,
		Cpt:     Cpt,
		MaskCtx: uints.NewU8Array(t.MaskCtxFor(d.I + 1)),
		S:       emulated.ValueOf[emulated.Secp256k1Fr](d.S),
		Zs:      Zs,
		Rhos:    Rhos,
	}
}

// publicRdEl builds an R_del circuit with only public fields populated (secret
// fields zero), used to extract the verifier's public witness.
func publicRdEl(t *Task, d *Delivery) *circuit.RdEl {
	L := t.L
	C := make([]sw_emulated.AffinePoint[emulated.Secp256k1Fp], L)
	Cpt := make([]emulated.Element[emulated.Secp256k1Fr], L)
	for j := 0; j < L; j++ {
		C[j] = toAffine(t.ExpectedCommitment(d.I, j))
		Cpt[j] = emulated.ValueOf[emulated.Secp256k1Fr](d.C[j])
	}
	return &circuit.RdEl{
		L:       L,
		PKR:     toAffine(t.ReceiverPK),
		R:       toAffine(d.R),
		C:       C,
		Cpt:     Cpt,
		MaskCtx: uints.NewU8Array(t.MaskCtxFor(d.I + 1)),
		Zs:      make([]emulated.Element[emulated.Secp256k1Fr], L),
		Rhos:    make([]emulated.Element[emulated.Secp256k1Fr], L),
	}
}

// Prover holds a compiled R_del circuit and Groth16 keys for a fixed (L, maskCtxLen).
type Prover struct {
	L          int
	MaskCtxLen int
	Ccs        constraint.ConstraintSystem
	Pk         groth16.ProvingKey
	Vk         groth16.VerifyingKey
}

// NewProver compiles the R_del circuit (Compiled-C) and runs Groth16 setup.
// maskCtxLen must equal len(Task.MaskCtxFor(i)) for every i (it is fixed by the
// encoding, so a single representative length suffices).
func NewProver(L, maskCtxLen int) (*Prover, error) {
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, emptyRdEl(L, maskCtxLen))
	if err != nil {
		return nil, err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}
	return &Prover{L: L, MaskCtxLen: maskCtxLen, Ccs: ccs, Pk: pk, Vk: vk}, nil
}

// Constraints reports the number of R1CS constraints.
func (p *Prover) Constraints() int { return p.Ccs.GetNbConstraints() }

// Prove produces a Groth16 proof for server i's delivery and returns it with
// the serialized bytes and the public witness.
func (p *Prover) Prove(t *Task, d *Delivery) (groth16.Proof, []byte, witness.Witness, error) {
	w := buildRdElWitness(t, d)
	sec, err := frontend.NewWitness(w, ecc.BLS12_381.ScalarField())
	if err != nil {
		return nil, nil, nil, err
	}
	pub, err := sec.Public()
	if err != nil {
		return nil, nil, nil, err
	}
	pf, err := groth16.Prove(p.Ccs, p.Pk, sec)
	if err != nil {
		return nil, nil, nil, err
	}
	var buf bytes.Buffer
	if _, err := pf.WriteTo(&buf); err != nil {
		return nil, nil, nil, err
	}
	return pf, buf.Bytes(), pub, nil
}

// Verify checks a proof against the public statement for server i's delivery.
func (p *Prover) Verify(pf groth16.Proof, pub witness.Witness) error {
	return groth16.Verify(pf, p.Vk, pub)
}

// PublicWitness builds the verifier-side public witness from a delivery.
func (p *Prover) PublicWitness(t *Task, d *Delivery) (witness.Witness, error) {
	sec, err := frontend.NewWitness(publicRdEl(t, d), ecc.BLS12_381.ScalarField())
	if err != nil {
		return nil, err
	}
	return sec.Public()
}

// ParseProof deserializes Groth16 proof bytes.
func (p *Prover) ParseProof(b []byte) (groth16.Proof, error) {
	pf := groth16.NewProof(ecc.BLS12_381)
	_, err := pf.ReadFrom(bytes.NewReader(b))
	return pf, err
}

// ProveWitness attempts to prove an explicit R_del witness. It returns an error
// if the witness does not satisfy the constraints (used by the proof-layer
// negative matrix: a malicious witness must fail to prove).
func (p *Prover) ProveWitness(w *circuit.RdEl) error {
	sec, err := frontend.NewWitness(w, ecc.BLS12_381.ScalarField())
	if err != nil {
		return err
	}
	_, err = groth16.Prove(p.Ccs, p.Pk, sec)
	return err
}
