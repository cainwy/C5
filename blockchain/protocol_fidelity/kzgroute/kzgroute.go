package kzgroute

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const maxDegree = 64

type Route struct {
	SRS *kzg.SRS
}

func Setup() (*Route, error) {
	alpha, err := rand.Int(rand.Reader, fr.Modulus())
	if err != nil {
		return nil, fmt.Errorf("kzgroute: alpha: %w", err)
	}
	srs, err := kzg.NewSRS(maxDegree+1, alpha)
	if err != nil {
		return nil, fmt.Errorf("kzgroute: srs: %w", err)
	}
	return &Route{SRS: srs}, nil
}

func (r *Route) CommitForCoordinate(coeffs []fr.Element) (kzg.Digest, error) {
	if len(coeffs) > maxDegree+1 {
		return kzg.Digest{}, fmt.Errorf("kzgroute: degree %d > %d", len(coeffs)-1, maxDegree)
	}
	return kzg.Commit(coeffs, r.SRS.Pk)
}

func (r *Route) OpenForServer(coeffs []fr.Element, xi *big.Int) (kzg.OpeningProof, error) {
	var point fr.Element
	point.SetBigInt(xi)
	return kzg.Open(coeffs, point, r.SRS.Pk)
}

func (r *Route) VerifyOpening(com kzg.Digest, point fr.Element, proof kzg.OpeningProof) error {
	return kzg.Verify(&com, &proof, point, r.SRS.Vk)
}

func BytesDigest() int { return 48 }

func BytesProof() int { return 80 }
