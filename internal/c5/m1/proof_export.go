package m1


import (
	"bytes"
	"io"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	bls12381cs "github.com/consensys/gnark/constraint/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func CompileOnly(L, maskCtxLen int) (*Prover, error) {
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, emptyRdEl(L, maskCtxLen))
	if err != nil {
		return nil, err
	}
	return &Prover{L: L, MaskCtxLen: maskCtxLen, Ccs: ccs}, nil
}

func (p *Prover) SetupKeys() error {
	if p.Ccs == nil {
		return &m1Error{"setup: nil ccs (compile first)"}
	}
	pk, vk, err := groth16.Setup(p.Ccs)
	if err != nil {
		return err
	}
	p.Pk, p.Vk = pk, vk
	return nil
}

func (p *Prover) HasKeys() bool { return p.Pk != nil && p.Vk != nil }

func (p *Prover) SerializeSetup() (ccsB, pkB, vkB []byte, err error) {
	if p.Ccs == nil || p.Pk == nil || p.Vk == nil {
		return nil, nil, nil, &m1Error{"serialize: incomplete setup"}
	}
	var cb, pb, vb bytes.Buffer
	if _, err = p.Ccs.WriteTo(&cb); err != nil {
		return nil, nil, nil, err
	}
	if _, err = p.Pk.WriteRawTo(&pb); err != nil {
		return nil, nil, nil, err
	}
	if _, err = p.Vk.WriteRawTo(&vb); err != nil {
		return nil, nil, nil, err
	}
	return cb.Bytes(), pb.Bytes(), vb.Bytes(), nil
}

func DeserializeSetup(L, maskCtxLen int, ccsB, pkB, vkB []byte) (*Prover, error) {
	ccs := new(bls12381cs.R1CS)
	if _, err := ccs.ReadFrom(bytes.NewReader(ccsB)); err != nil {
		return nil, err
	}
	pk := groth16.NewProvingKey(ecc.BLS12_381)
	if _, err := pk.ReadFrom(bytes.NewReader(pkB)); err != nil {
		return nil, err
	}
	vk := groth16.NewVerifyingKey(ecc.BLS12_381)
	if _, err := vk.ReadFrom(bytes.NewReader(vkB)); err != nil {
		return nil, err
	}
	return &Prover{L: L, MaskCtxLen: maskCtxLen, Ccs: ccs, Pk: pk, Vk: vk}, nil
}

var _ io.Reader = (*bytes.Reader)(nil)