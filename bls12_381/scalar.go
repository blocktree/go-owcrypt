package bls12_381

import (
	"math/big"

	"github.com/drand/kyber"
	"github.com/drand/kyber/group/mod"
)

var curveOrder, _ = new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)

func NewOwcryptScalar() kyber.Scalar {
	return mod.NewInt64(0, curveOrder)
}

func NewScalar(scalar []byte) kyber.Scalar {
	return mod.NewInt64(0, curveOrder).SetBytes(scalar)
}