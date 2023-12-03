/*
 * Copyright 2020 The openwallet Authors
 * This file is part of the openwallet library.
 *
 * The openwallet library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The openwallet library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 */
package owcrypt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"math/big"
)

var secp256r1 *secp256r1Curve

type secp256r1Curve struct {
	elliptic.CurveParams
}

func initsecp256r1Param() {
	secp256r1 = &secp256r1Curve{elliptic.CurveParams{Name: "secp256r1"}}
	secp256r1.P, _ = new(big.Int).SetString("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
	secp256r1.N, _ = new(big.Int).SetString("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
	secp256r1.B, _ = new(big.Int).SetString("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
	secp256r1.Gx, _ = new(big.Int).SetString("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)
	secp256r1.Gy, _ = new(big.Int).SetString("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)
	secp256r1.BitSize = 256
	// secp256r1 = &curveParam{elliptic.CurveParams{Name: "secp256r1"}}
	// secp256r1.CurveParams = *elliptic.P256().Params()
}

func (curve secp256r1Curve) Params() *elliptic.CurveParams {
	return &curve.CurveParams
}

func (curve *secp256r1Curve) polynomial(x *big.Int) *big.Int {
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	threeX := new(big.Int).Lsh(x, 1)
	threeX.Add(threeX, x)

	x3.Sub(x3, threeX)
	x3.Add(x3, curve.B)
	x3.Mod(x3, curve.P)

	return x3
}

func (curve *secp256r1Curve) IsOnCurve(x, y *big.Int) bool {
	if x.Sign() < 0 || x.Cmp(curve.P) >= 0 ||
		y.Sign() < 0 || y.Cmp(curve.P) >= 0 {
		return false
	}

	// y² = x³ - 3x + b
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, curve.P)

	return curve.polynomial(x).Cmp(y2) == 0
}

func (curve *secp256r1Curve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	z1 := zForAffine(x1, y1)
	return curve.affineFromJacobian(curve.doubleJacobian(x1, y1, z1))
}

// affineFromJacobian reverses the Jacobian transform. See the comment at the
// top of the file. If the point is ∞ it returns 0, 0.
func (curve *secp256r1Curve) affineFromJacobian(x, y, z *big.Int) (xOut, yOut *big.Int) {
	if z.Sign() == 0 {
		return new(big.Int), new(big.Int)
	}

	zinv := new(big.Int).ModInverse(z, curve.P)
	zinvsq := new(big.Int).Mul(zinv, zinv)

	xOut = new(big.Int).Mul(x, zinvsq)
	xOut.Mod(xOut, curve.P)
	zinvsq.Mul(zinvsq, zinv)
	yOut = new(big.Int).Mul(y, zinvsq)
	yOut.Mod(yOut, curve.P)
	return
}

func (curve *secp256r1Curve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	z1 := zForAffine(x1, y1)
	z2 := zForAffine(x2, y2)
	return curve.affineFromJacobian(curve.addJacobian(x1, y1, z1, x2, y2, z2))
}

// addJacobian takes two points in Jacobian coordinates, (x1, y1, z1) and
// (x2, y2, z2) and returns their sum, also in Jacobian form.
func (curve *secp256r1Curve) addJacobian(x1, y1, z1, x2, y2, z2 *big.Int) (*big.Int, *big.Int, *big.Int) {
	// See http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl
	x3, y3, z3 := new(big.Int), new(big.Int), new(big.Int)
	if z1.Sign() == 0 {
		x3.Set(x2)
		y3.Set(y2)
		z3.Set(z2)
		return x3, y3, z3
	}
	if z2.Sign() == 0 {
		x3.Set(x1)
		y3.Set(y1)
		z3.Set(z1)
		return x3, y3, z3
	}

	z1z1 := new(big.Int).Mul(z1, z1)
	z1z1.Mod(z1z1, curve.P)
	z2z2 := new(big.Int).Mul(z2, z2)
	z2z2.Mod(z2z2, curve.P)

	u1 := new(big.Int).Mul(x1, z2z2)
	u1.Mod(u1, curve.P)
	u2 := new(big.Int).Mul(x2, z1z1)
	u2.Mod(u2, curve.P)
	h := new(big.Int).Sub(u2, u1)
	xEqual := h.Sign() == 0
	if h.Sign() == -1 {
		h.Add(h, curve.P)
	}
	i := new(big.Int).Lsh(h, 1)
	i.Mul(i, i)
	j := new(big.Int).Mul(h, i)

	s1 := new(big.Int).Mul(y1, z2)
	s1.Mul(s1, z2z2)
	s1.Mod(s1, curve.P)
	s2 := new(big.Int).Mul(y2, z1)
	s2.Mul(s2, z1z1)
	s2.Mod(s2, curve.P)
	r := new(big.Int).Sub(s2, s1)
	if r.Sign() == -1 {
		r.Add(r, curve.P)
	}
	yEqual := r.Sign() == 0
	if xEqual && yEqual {
		return curve.doubleJacobian(x1, y1, z1)
	}
	r.Lsh(r, 1)
	v := new(big.Int).Mul(u1, i)

	x3.Set(r)
	x3.Mul(x3, x3)
	x3.Sub(x3, j)
	x3.Sub(x3, v)
	x3.Sub(x3, v)
	x3.Mod(x3, curve.P)

	y3.Set(r)
	v.Sub(v, x3)
	y3.Mul(y3, v)
	s1.Mul(s1, j)
	s1.Lsh(s1, 1)
	y3.Sub(y3, s1)
	y3.Mod(y3, curve.P)

	z3.Add(z1, z2)
	z3.Mul(z3, z3)
	z3.Sub(z3, z1z1)
	z3.Sub(z3, z2z2)
	z3.Mul(z3, h)
	z3.Mod(z3, curve.P)

	return x3, y3, z3
}

// doubleJacobian takes a point in Jacobian coordinates, (x, y, z), and
// returns its double, also in Jacobian form.
func (curve *secp256r1Curve) doubleJacobian(x, y, z *big.Int) (*big.Int, *big.Int, *big.Int) {
	// See http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
	delta := new(big.Int).Mul(z, z)
	delta.Mod(delta, curve.P)
	gamma := new(big.Int).Mul(y, y)
	gamma.Mod(gamma, curve.P)
	alpha := new(big.Int).Sub(x, delta)
	if alpha.Sign() == -1 {
		alpha.Add(alpha, curve.P)
	}
	alpha2 := new(big.Int).Add(x, delta)
	alpha.Mul(alpha, alpha2)
	alpha2.Set(alpha)
	alpha.Lsh(alpha, 1)
	alpha.Add(alpha, alpha2)

	beta := alpha2.Mul(x, gamma)

	x3 := new(big.Int).Mul(alpha, alpha)
	beta8 := new(big.Int).Lsh(beta, 3)
	beta8.Mod(beta8, curve.P)
	x3.Sub(x3, beta8)
	if x3.Sign() == -1 {
		x3.Add(x3, curve.P)
	}
	x3.Mod(x3, curve.P)

	z3 := new(big.Int).Add(y, z)
	z3.Mul(z3, z3)
	z3.Sub(z3, gamma)
	if z3.Sign() == -1 {
		z3.Add(z3, curve.P)
	}
	z3.Sub(z3, delta)
	if z3.Sign() == -1 {
		z3.Add(z3, curve.P)
	}
	z3.Mod(z3, curve.P)

	beta.Lsh(beta, 2)
	beta.Sub(beta, x3)
	if beta.Sign() == -1 {
		beta.Add(beta, curve.P)
	}
	y3 := alpha.Mul(alpha, beta)

	gamma.Mul(gamma, gamma)
	gamma.Lsh(gamma, 3)
	gamma.Mod(gamma, curve.P)

	y3.Sub(y3, gamma)
	if y3.Sign() == -1 {
		y3.Add(y3, curve.P)
	}
	y3.Mod(y3, curve.P)

	return x3, y3, z3
}

func (curve *secp256r1Curve) ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int) {
	Bz := new(big.Int).SetInt64(1)
	x, y, z := new(big.Int), new(big.Int), new(big.Int)

	for _, byte := range k {
		for bitNum := 0; bitNum < 8; bitNum++ {
			x, y, z = curve.doubleJacobian(x, y, z)
			if byte&0x80 == 0x80 {
				x, y, z = curve.addJacobian(Bx, By, Bz, x, y, z)
			}
			byte <<= 1
		}
	}

	return curve.affineFromJacobian(x, y, z)
}

func (curve *secp256r1Curve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	return curve.ScalarMult(curve.Gx, curve.Gy, k)
}

func secp256r1_decompress(in []byte) ([]byte, error) {
	if in == nil || len(in) != 33 || (in[0] != 0x02 && in[0] != 0x03) {
		return nil, errors.New("invalid input")
	}

	var ybit uint
	x := new(big.Int).SetBytes(in[1:])
	if in[0] == 0x02 {
		ybit = 0
	} else {
		ybit = 1
	}

	c := secp256r1

	var y, x3b, xa big.Int
	x3b.Mul(x, x)
	x3b.Mul(&x3b, x)
	xa.SetBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC})
	xa.Mul(&xa, x)
	x3b.Add(&x3b, c.B)
	x3b.Add(&x3b, &xa)
	x3b.Mod(&x3b, c.P)
	y.ModSqrt(&x3b, c.P)

	if y.Bit(0) != ybit {
		y.Sub(c.P, &y)
	}
	if y.Bit(0) != ybit {
		return nil, errors.New("incorrectly encoded X and Y bit")
	}

	ret := make([]byte, 65)
	ret[0] = 0x04
	copy(ret[1:33], in[1:])
	dy := y.Bytes()
	copy(ret[33+32-len(dy):], dy)

	return ret, nil
}

func secp256r1_recover_public(sig, msg []byte) ([]byte, error) {

	if sig == nil || msg == nil || len(sig) != 65 || len(msg) != 32 {
		return nil, errors.New("invalid data")
	}

	buf2 := make([]byte, 33)
	hash := make([]byte, 32)
	s := new(big.Int)
	R := new(ecdsa.PublicKey)
	G := new(ecdsa.PublicKey)

	copy(hash, msg)
	copy(buf2[1:], sig[:32])

	curve := secp256r1

	r_inv := new(big.Int).ModInverse(new(big.Int).SetBytes(sig[:32]), curve.N)
	G.Curve = curve
	G.X = curve.Gx
	G.Y = curve.Gy

	for k := 0; k < 2; k++ {
		if k == 0 {
			buf2[0] = 0x02
		}

		if k == 1 {
			buf2[0] = 0x03
		}

		if k == 0 {
			if sig[64] == 1 {
				s = new(big.Int).Sub(curve.N, new(big.Int).SetBytes(sig[32:64]))
			}
		}

		if k == 1 {
			if sig[64] == 0 {
				s = new(big.Int).Sub(curve.N, new(big.Int).SetBytes(sig[32:64]))
			}
		}

		buf1 := PointDecompress(buf2, ECC_CURVE_SECP256R1)

		R.Curve = curve
		R.X = new(big.Int).SetBytes(buf1[1:33])
		R.Y = new(big.Int).SetBytes(buf1[33:])

		point1 := new(ecdsa.PublicKey)
		point1.Curve = curve
		point1.X, point1.Y = curve.ScalarMult(R.X, R.Y, s.Bytes())
		point2 := new(ecdsa.PublicKey)
		point2.Curve = curve
		point2.X, point2.Y = curve.ScalarBaseMult(hash)
		point2.Y = point2.Y.Sub(curve.P, point2.Y)

		point1.X, point1.Y = curve.Add(point1.X, point1.Y, point2.X, point2.Y)
		point2.X, point2.Y = curve.ScalarMult(point1.X, point1.Y, r_inv.Bytes())

		if verifyesdsa(point2, hash, new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:64])) {
			pubkey := make([]byte, 64)
			x := point2.X.Bytes()
			y := point2.Y.Bytes()
			copy(pubkey[32-len(x):32], x)
			copy(pubkey[64-len(y):], y)

			return pubkey, nil
		}
	}
	return nil, errors.New("failed to decompress")
}
