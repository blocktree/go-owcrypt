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

var secp256r1 *curveParam

func initsecp256r1Param() {
	secp256r1 = &curveParam{elliptic.CurveParams{Name: "secp256r1"}}
	secp256r1.P, _  = new(big.Int).SetString("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
	secp256r1.N, _  = new(big.Int).SetString("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
	secp256r1.B, _  = new(big.Int).SetString("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
	secp256r1.Gx, _ = new(big.Int).SetString("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)
	secp256r1.Gy, _ = new(big.Int).SetString("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)
	secp256r1.BitSize = 256
}

func secp256r1_decompress(in []byte) ([]byte, error) {
	if in == nil || len(in) != 33 || (in[0] != 0x02 && in[0] != 0x03){
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
	xa.SetBytes([]byte{0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFC})
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

	for k := 0; k < 2; k ++ {
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