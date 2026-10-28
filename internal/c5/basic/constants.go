package basic

import (
	"math/big"

	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"

	"c5full/internal/c5/params"
)

// Hpoint is the production Pedersen second generator H, frozen in the params
// package (RFC-9380 hash-to-curve derivation), injected as a circuit constant
// so the prover cannot substitute its own H.
var Hpoint = sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
	X: emulated.ValueOf[emulated.Secp256k1Fp](params.H.X.BigInt(new(big.Int))),
	Y: emulated.ValueOf[emulated.Secp256k1Fp](params.H.Y.BigInt(new(big.Int))),
}