// Package bottomc5 implements the minimal C5-native bottom-MPC committed-output
// path required by `C5_Paper_v2_3.tex` (LA-04): paired Shamir/Pedersen
// additive sharing over the C5 field (secp256k1 scalar field, params.Q) with
//	field  q  = internal/c5/params.Q
//	(w_i, rho_{w,i})   = (F_w(xi_i), B_w(xi_i))
//	A_{w,k}            = a_{w,k}G + b_{w,k}H
//	EvalCom(A_w,xi_i)  = w_i G + rho_{w,i} H
package bottomc5

import (
	"math/big"

	"c5full/internal/c5/params"
)

func FieldOrder() *big.Int { return new(big.Int).Set(params.Q) }