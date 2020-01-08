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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"github.com/blocktree/go-owcrypt/sm3"
	"io"
	"math/big"
)

var sm2_std *sm2_stdCurve

type sm2_stdCurve struct {
	*elliptic.CurveParams
	RInverse *big.Int
	a, b, gx, gy sm2_stdFieldElement
}

type sm2_stdFieldElement [9]uint32
type sm2_stdLargeFieldElement [17]uint64

const (
	bottom28Bits = 0xFFFFFFF
	bottom29Bits = 0x1FFFFFFF
)

func initsm2_stdParam() {
	sm2_std = &sm2_stdCurve{CurveParams: &elliptic.CurveParams{Name: "sm2_std"}}
	A, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
	sm2_std.P, _  = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	sm2_std.N, _  = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
	sm2_std.B, _  = new(big.Int).SetString("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
	sm2_std.Gx, _ = new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	sm2_std.Gy, _ = new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
	sm2_std.RInverse, _ = new(big.Int).SetString("7ffffffd80000002fffffffe000000017ffffffe800000037ffffffc80000002", 16)
	sm2_std.BitSize = 256

	sm2_stdFromBig(&sm2_std.a, A)
	sm2_stdFromBig(&sm2_std.gx, sm2_std.Gx)
	sm2_stdFromBig(&sm2_std.gy, sm2_std.Gy)
	sm2_stdFromBig(&sm2_std.b, sm2_std.B)
}

func (curve sm2_stdCurve) Params() *elliptic.CurveParams {
	return sm2_std.CurveParams
}

func (curve sm2_stdCurve) IsOnCurve(X, Y *big.Int) bool {
	var a, x, y, y2, x3 sm2_stdFieldElement

	sm2_stdFromBig(&x, X)
	sm2_stdFromBig(&y, Y)

	sm2_stdSquare(&x3, &x)
	sm2_stdMul(&x3, &x3, &x)
	sm2_stdMul(&a, &curve.a, &x)
	sm2_stdAdd(&x3, &x3, &a)
	sm2_stdAdd(&x3, &x3, &curve.b)

	sm2_stdSquare(&y2, &y)
	return sm2_stdToBig(&x3).Cmp(sm2_stdToBig(&y2)) == 0
}

func (curve sm2_stdCurve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	var X1, Y1, Z1, X2, Y2, Z2, X3, Y3, Z3 sm2_stdFieldElement

	z1 := zForAffine(x1, y1)
	z2 := zForAffine(x2, y2)
	sm2_stdFromBig(&X1, x1)
	sm2_stdFromBig(&Y1, y1)
	sm2_stdFromBig(&Z1, z1)
	sm2_stdFromBig(&X2, x2)
	sm2_stdFromBig(&Y2, y2)
	sm2_stdFromBig(&Z2, z2)
	sm2_stdPointAdd(&X1, &Y1, &Z1, &X2, &Y2, &Z2, &X3, &Y3, &Z3)
	return sm2_stdToAffine(&X3, &Y3, &Z3)
}

func (curve sm2_stdCurve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	var X1, Y1, Z1 sm2_stdFieldElement

	z1 := zForAffine(x1, y1)
	sm2_stdFromBig(&X1, x1)
	sm2_stdFromBig(&Y1, y1)
	sm2_stdFromBig(&Z1, z1)
	sm2_stdPointDouble(&X1, &Y1, &Z1, &X1, &Y1, &Z1)
	return sm2_stdToAffine(&X1, &Y1, &Z1)
}

func (curve sm2_stdCurve) ScalarMult(x1, y1 *big.Int, k []byte) (*big.Int, *big.Int) {
	var scalarReversed [32]byte
	var X, Y, Z, X1, Y1 sm2_stdFieldElement

	sm2_stdFromBig(&X1, x1)
	sm2_stdFromBig(&Y1, y1)
	sm2_stdGetScalar(&scalarReversed, k)
	sm2_stdScalarMult(&X, &Y, &Z, &X1, &Y1, &scalarReversed)
	return sm2_stdToAffine(&X, &Y, &Z)
}

func (curve sm2_stdCurve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	var scalarReversed [32]byte
	var X, Y, Z sm2_stdFieldElement

	sm2_stdGetScalar(&scalarReversed, k)
	sm2_stdScalarBaseMult(&X, &Y, &Z, &scalarReversed)
	return sm2_stdToAffine(&X, &Y, &Z)
}


var sm2_stdPrecomputed = [9 * 2 * 15 * 2]uint32{
	0x830053d, 0x328990f, 0x6c04fe1, 0xc0f72e5, 0x1e19f3c, 0x666b093, 0x175a87b, 0xec38276, 0x222cf4b,
	0x185a1bba, 0x354e593, 0x1295fac1, 0xf2bc469, 0x47c60fa, 0xc19b8a9, 0xf63533e, 0x903ae6b, 0xc79acba,
	0x15b061a4, 0x33e020b, 0xdffb34b, 0xfcf2c8, 0x16582e08, 0x262f203, 0xfb34381, 0xa55452, 0x604f0ff,
	0x41f1f90, 0xd64ced2, 0xee377bf, 0x75f05f0, 0x189467ae, 0xe2244e, 0x1e7700e8, 0x3fbc464, 0x9612d2e,
	0x1341b3b8, 0xee84e23, 0x1edfa5b4, 0x14e6030, 0x19e87be9, 0x92f533c, 0x1665d96c, 0x226653e, 0xa238d3e,
	0xf5c62c, 0x95bb7a, 0x1f0e5a41, 0x28789c3, 0x1f251d23, 0x8726609, 0xe918910, 0x8096848, 0xf63d028,
	0x152296a1, 0x9f561a8, 0x14d376fb, 0x898788a, 0x61a95fb, 0xa59466d, 0x159a003d, 0x1ad1698, 0x93cca08,
	0x1b314662, 0x706e006, 0x11ce1e30, 0x97b710, 0x172fbc0d, 0x8f50158, 0x11c7ffe7, 0xd182cce, 0xc6ad9e8,
	0x12ea31b2, 0xc4e4f38, 0x175b0d96, 0xec06337, 0x75a9c12, 0xb001fdf, 0x93e82f5, 0x34607de, 0xb8035ed,
	0x17f97924, 0x75cf9e6, 0xdceaedd, 0x2529924, 0x1a10c5ff, 0xb1a54dc, 0x19464d8, 0x2d1997, 0xde6a110,
	0x1e276ee5, 0x95c510c, 0x1aca7c7a, 0xfe48aca, 0x121ad4d9, 0xe4132c6, 0x8239b9d, 0x40ea9cd, 0x816c7b,
	0x632d7a4, 0xa679813, 0x5911fcf, 0x82b0f7c, 0x57b0ad5, 0xbef65, 0xd541365, 0x7f9921f, 0xc62e7a,
	0x3f4b32d, 0x58e50e1, 0x6427aed, 0xdcdda67, 0xe8c2d3e, 0x6aa54a4, 0x18df4c35, 0x49a6a8e, 0x3cd3d0c,
	0xd7adf2, 0xcbca97, 0x1bda5f2d, 0x3258579, 0x606b1e6, 0x6fc1b5b, 0x1ac27317, 0x503ca16, 0xa677435,
	0x57bc73, 0x3992a42, 0xbab987b, 0xfab25eb, 0x128912a4, 0x90a1dc4, 0x1402d591, 0x9ffbcfc, 0xaa48856,
	0x7a7c2dc, 0xcefd08a, 0x1b29bda6, 0xa785641, 0x16462d8c, 0x76241b7, 0x79b6c3b, 0x204ae18, 0xf41212b,
	0x1f567a4d, 0xd6ce6db, 0xedf1784, 0x111df34, 0x85d7955, 0x55fc189, 0x1b7ae265, 0xf9281ac, 0xded7740,
	0xf19468b, 0x83763bb, 0x8ff7234, 0x3da7df8, 0x9590ac3, 0xdc96f2a, 0x16e44896, 0x7931009, 0x99d5acc,
	0x10f7b842, 0xaef5e84, 0xc0310d7, 0xdebac2c, 0x2a7b137, 0x4342344, 0x19633649, 0x3a10624, 0x4b4cb56,
	0x1d809c59, 0xac007f, 0x1f0f4bcd, 0xa1ab06e, 0xc5042cf, 0x82c0c77, 0x76c7563, 0x22c30f3, 0x3bf1568,
	0x7a895be, 0xfcca554, 0x12e90e4c, 0x7b4ab5f, 0x13aeb76b, 0x5887e2c, 0x1d7fe1e3, 0x908c8e3, 0x95800ee,
	0xb36bd54, 0xf08905d, 0x4e73ae8, 0xf5a7e48, 0xa67cb0, 0x50e1067, 0x1b944a0a, 0xf29c83a, 0xb23cfb9,
	0xbe1db1, 0x54de6e8, 0xd4707f2, 0x8ebcc2d, 0x2c77056, 0x1568ce4, 0x15fcc849, 0x4069712, 0xe2ed85f,
	0x2c5ff09, 0x42a6929, 0x628e7ea, 0xbd5b355, 0xaf0bd79, 0xaa03699, 0xdb99816, 0x4379cef, 0x81d57b,
	0x11237f01, 0xe2a820b, 0xfd53b95, 0x6beb5ee, 0x1aeb790c, 0xe470d53, 0x2c2cfee, 0x1c1d8d8, 0xa520fc4,
	0x1518e034, 0xa584dd4, 0x29e572b, 0xd4594fc, 0x141a8f6f, 0x8dfccf3, 0x5d20ba3, 0x2eb60c3, 0x9f16eb0,
	0x11cec356, 0xf039f84, 0x1b0990c1, 0xc91e526, 0x10b65bae, 0xf0616e8, 0x173fa3ff, 0xec8ccf9, 0xbe32790,
	0x11da3e79, 0xe2f35c7, 0x908875c, 0xdacf7bd, 0x538c165, 0x8d1487f, 0x7c31aed, 0x21af228, 0x7e1689d,
	0xdfc23ca, 0x24f15dc, 0x25ef3c4, 0x35248cd, 0x99a0f43, 0xa4b6ecc, 0xd066b3, 0x2481152, 0x37a7688,
	0x15a444b6, 0xb62300c, 0x4b841b, 0xa655e79, 0xd53226d, 0xbeb348a, 0x127f3c2, 0xb989247, 0x71a277d,
	0x19e9dfcb, 0xb8f92d0, 0xe2d226c, 0x390a8b0, 0x183cc462, 0x7bd8167, 0x1f32a552, 0x5e02db4, 0xa146ee9,
	0x1a003957, 0x1c95f61, 0x1eeec155, 0x26f811f, 0xf9596ba, 0x3082bfb, 0x96df083, 0x3e3a289, 0x7e2d8be,
	0x157a63e0, 0x99b8941, 0x1da7d345, 0xcc6cd0, 0x10beed9a, 0x48e83c0, 0x13aa2e25, 0x7cad710, 0x4029988,
	0x13dfa9dd, 0xb94f884, 0x1f4adfef, 0xb88543, 0x16f5f8dc, 0xa6a67f4, 0x14e274e2, 0x5e56cf4, 0x2f24ef,
	0x1e9ef967, 0xfe09bad, 0xfe079b3, 0xcc0ae9e, 0xb3edf6d, 0x3e961bc, 0x130d7831, 0x31043d6, 0xba986f9,
	0x1d28055, 0x65240ca, 0x4971fa3, 0x81b17f8, 0x11ec34a5, 0x8366ddc, 0x1471809, 0xfa5f1c6, 0xc911e15,
	0x8849491, 0xcf4c2e2, 0x14471b91, 0x39f75be, 0x445c21e, 0xf1585e9, 0x72cc11f, 0x4c79f0c, 0xe5522e1,
	0x1874c1ee, 0x4444211, 0x7914884, 0x3d1b133, 0x25ba3c, 0x4194f65, 0x1c0457ef, 0xac4899d, 0xe1fa66c,
	0x130a7918, 0x9b8d312, 0x4b1c5c8, 0x61ccac3, 0x18c8aa6f, 0xe93cb0a, 0xdccb12c, 0xde10825, 0x969737d,
	0xf58c0c3, 0x7cee6a9, 0xc2c329a, 0xc7f9ed9, 0x107b3981, 0x696a40e, 0x152847ff, 0x4d88754, 0xb141f47,
	0x5a16ffe, 0x3a7870a, 0x18667659, 0x3b72b03, 0xb1c9435, 0x9285394, 0xa00005a, 0x37506c, 0x2edc0bb,
	0x19afe392, 0xeb39cac, 0x177ef286, 0xdf87197, 0x19f844ed, 0x31fe8, 0x15f9bfd, 0x80dbec, 0x342e96e,
	0x497aced, 0xe88e909, 0x1f5fa9ba, 0x530a6ee, 0x1ef4e3f1, 0x69ffd12, 0x583006d, 0x2ecc9b1, 0x362db70,
	0x18c7bdc5, 0xf4bb3c5, 0x1c90b957, 0xf067c09, 0x9768f2b, 0xf73566a, 0x1939a900, 0x198c38a, 0x202a2a1,
	0x4bbf5a6, 0x4e265bc, 0x1f44b6e7, 0x185ca49, 0xa39e81b, 0x24aff5b, 0x4acc9c2, 0x638bdd3, 0xb65b2a8,
	0x6def8be, 0xb94537a, 0x10b81dee, 0xe00ec55, 0x2f2cdf7, 0xc20622d, 0x2d20f36, 0xe03c8c9, 0x898ea76,
	0x8e3921b, 0x8905bff, 0x1e94b6c8, 0xee7ad86, 0x154797f2, 0xa620863, 0x3fbd0d9, 0x1f3caab, 0x30c24bd,
	0x19d3892f, 0x59c17a2, 0x1ab4b0ae, 0xf8714ee, 0x90c4098, 0xa9c800d, 0x1910236b, 0xea808d3, 0x9ae2f31,
	0x1a15ad64, 0xa48c8d1, 0x184635a4, 0xb725ef1, 0x11921dcc, 0x3f866df, 0x16c27568, 0xbdf580a, 0xb08f55c,
	0x186ee1c, 0xb1627fa, 0x34e82f6, 0x933837e, 0xf311be5, 0xfedb03b, 0x167f72cd, 0xa5469c0, 0x9c82531,
	0xb92a24b, 0x14fdc8b, 0x141980d1, 0xbdc3a49, 0x7e02bb1, 0xaf4e6dd, 0x106d99e1, 0xd4616fc, 0x93c2717,
	0x1c0a0507, 0xc6d5fed, 0x9a03d8b, 0xa1d22b0, 0x127853e3, 0xc4ac6b8, 0x1a048cf7, 0x9afb72c, 0x65d485d,
	0x72d5998, 0xe9fa744, 0xe49e82c, 0x253cf80, 0x5f777ce, 0xa3799a5, 0x17270cbb, 0xc1d1ef0, 0xdf74977,
	0x114cb859, 0xfa8e037, 0xb8f3fe5, 0xc734cc6, 0x70d3d61, 0xeadac62, 0x12093dd0, 0x9add67d, 0x87200d6,
	0x175bcbb, 0xb29b49f, 0x1806b79c, 0x12fb61f, 0x170b3a10, 0x3aaf1cf, 0xa224085, 0x79d26af, 0x97759e2,
	0x92e19f1, 0xb32714d, 0x1f00d9f1, 0xc728619, 0x9e6f627, 0xe745e24, 0x18ea4ace, 0xfc60a41, 0x125f5b2,
	0xc3cf512, 0x39ed486, 0xf4d15fa, 0xf9167fd, 0x1c1f5dd5, 0xc21a53e, 0x1897930, 0x957a112, 0x21059a0,
	0x1f9e3ddc, 0xa4dfced, 0x8427f6f, 0x726fbe7, 0x1ea658f8, 0x2fdcd4c, 0x17e9b66f, 0xb2e7c2e, 0x39923bf,
	0x1bae104, 0x3973ce5, 0xc6f264c, 0x3511b84, 0x124195d7, 0x11996bd, 0x20be23d, 0xdc437c4, 0x4b4f16b,
	0x11902a0, 0x6c29cc9, 0x1d5ffbe6, 0xdb0b4c7, 0x10144c14, 0x2f2b719, 0x301189, 0x2343336, 0xa0bf2ac,
}

func sm2_stdGetScalar(b *[32]byte, a []byte) {
	var scalarBytes []byte

	n := new(big.Int).SetBytes(a)
	if n.Cmp(sm2_std.N) >= 0 {
		n.Mod(n, sm2_std.N)
		scalarBytes = n.Bytes()
	} else {
		scalarBytes = a
	}
	for i, v := range scalarBytes {
		b[len(scalarBytes)-(1+i)] = v
	}
}

func sm2_stdPointAddMixed(xOut, yOut, zOut, x1, y1, z1, x2, y2 *sm2_stdFieldElement) {
	var z1z1, z1z1z1, s2, u2, h, i, j, r, rr, v, tmp sm2_stdFieldElement

	sm2_stdSquare(&z1z1, z1)
	sm2_stdAdd(&tmp, z1, z1)

	sm2_stdMul(&u2, x2, &z1z1)
	sm2_stdMul(&z1z1z1, z1, &z1z1)
	sm2_stdMul(&s2, y2, &z1z1z1)
	sm2_stdSub(&h, &u2, x1)
	sm2_stdAdd(&i, &h, &h)
	sm2_stdSquare(&i, &i)
	sm2_stdMul(&j, &h, &i)
	sm2_stdSub(&r, &s2, y1)
	sm2_stdAdd(&r, &r, &r)
	sm2_stdMul(&v, x1, &i)

	sm2_stdMul(zOut, &tmp, &h)
	sm2_stdSquare(&rr, &r)
	sm2_stdSub(xOut, &rr, &j)
	sm2_stdSub(xOut, xOut, &v)
	sm2_stdSub(xOut, xOut, &v)

	sm2_stdSub(&tmp, &v, xOut)
	sm2_stdMul(yOut, &tmp, &r)
	sm2_stdMul(&tmp, y1, &j)
	sm2_stdSub(yOut, yOut, &tmp)
	sm2_stdSub(yOut, yOut, &tmp)
}

// sm2_stdCopyConditional sets out=in if mask = 0xffffffff in constant time.
//
// On entry: mask is either 0 or 0xffffffff.
func sm2_stdCopyConditional(out, in *sm2_stdFieldElement, mask uint32) {
	for i := 0; i < 9; i++ {
		tmp := mask & (in[i] ^ out[i])
		out[i] ^= tmp
	}
}

func sm2_stdSelectAffinePoint(xOut, yOut *sm2_stdFieldElement, table []uint32, index uint32) {
	for i := range xOut {
		xOut[i] = 0
	}
	for i := range yOut {
		yOut[i] = 0
	}

	for i := uint32(1); i < 16; i++ {
		mask := i ^ index
		mask |= mask >> 2
		mask |= mask >> 1
		mask &= 1
		mask--
		for j := range xOut {
			xOut[j] |= table[0] & mask
			table = table[1:]
		}
		for j := range yOut {
			yOut[j] |= table[0] & mask
			table = table[1:]
		}
	}
}

func sm2_stdSelectJacobianPoint(xOut, yOut, zOut *sm2_stdFieldElement, table *[16][3]sm2_stdFieldElement, index uint32) {
	for i := range xOut {
		xOut[i] = 0
	}
	for i := range yOut {
		yOut[i] = 0
	}
	for i := range zOut {
		zOut[i] = 0
	}

	for i := uint32(1); i < 16; i++ {
		mask := i ^ index
		mask |= mask >> 2
		mask |= mask >> 1
		mask &= 1
		mask--
		for j := range xOut {
			xOut[j] |= table[i][0][j] & mask
		}
		for j := range yOut {
			yOut[j] |= table[i][1][j] & mask
		}
		for j := range zOut {
			zOut[j] |= table[i][2][j] & mask
		}
	}
}

func sm2_stdGetBit(scalar *[32]uint8, bit uint) uint32 {
	return uint32(((scalar[bit>>3]) >> (bit & 7)) & 1)
}

func sm2_stdScalarBaseMult(xOut, yOut, zOut *sm2_stdFieldElement, scalar *[32]uint8) {
	nIsInfinityMask := ^uint32(0)
	var px, py, tx, ty, tz sm2_stdFieldElement
	var pIsNoninfiniteMask, mask, tableOffset uint32

	for i := range xOut {
		xOut[i] = 0
	}
	for i := range yOut {
		yOut[i] = 0
	}
	for i := range zOut {
		zOut[i] = 0
	}

	for i := uint(0); i < 32; i++ {
		if i != 0 {
			sm2_stdPointDouble(xOut, yOut, zOut, xOut, yOut, zOut)
		}
		tableOffset = 0
		for j := uint(0); j <= 32; j += 32 {
			bit0 := sm2_stdGetBit(scalar, 31-i+j)
			bit1 := sm2_stdGetBit(scalar, 95-i+j)
			bit2 := sm2_stdGetBit(scalar, 159-i+j)
			bit3 := sm2_stdGetBit(scalar, 223-i+j)
			index := bit0 | (bit1 << 1) | (bit2 << 2) | (bit3 << 3)

			sm2_stdSelectAffinePoint(&px, &py, sm2_stdPrecomputed[tableOffset:], index)
			tableOffset += 30 * 9

			sm2_stdPointAddMixed(&tx, &ty, &tz, xOut, yOut, zOut, &px, &py)
			sm2_stdCopyConditional(xOut, &px, nIsInfinityMask)
			sm2_stdCopyConditional(yOut, &py, nIsInfinityMask)
			sm2_stdCopyConditional(zOut, &sm2_stdFactor[1], nIsInfinityMask)

			pIsNoninfiniteMask = nonZeroToAllOnes(index)
			mask = pIsNoninfiniteMask & ^nIsInfinityMask
			sm2_stdCopyConditional(xOut, &tx, mask)
			sm2_stdCopyConditional(yOut, &ty, mask)
			sm2_stdCopyConditional(zOut, &tz, mask)
			nIsInfinityMask &^= pIsNoninfiniteMask
		}
	}
}

func sm2_stdScalarMult(xOut, yOut, zOut, x, y *sm2_stdFieldElement, scalar *[32]uint8) {
	var precomp [16][3]sm2_stdFieldElement
	var px, py, pz, tx, ty, tz sm2_stdFieldElement
	var nIsInfinityMask, index, pIsNoninfiniteMask, mask uint32

	precomp[1][0] = *x
	precomp[1][1] = *y
	precomp[1][2] = sm2_stdFactor[1]

	for i := 2; i < 16; i += 2 {
		sm2_stdPointDouble(&precomp[i][0], &precomp[i][1], &precomp[i][2], &precomp[i/2][0], &precomp[i/2][1], &precomp[i/2][2])
		sm2_stdPointAddMixed(&precomp[i+1][0], &precomp[i+1][1], &precomp[i+1][2], &precomp[i][0], &precomp[i][1], &precomp[i][2], x, y)
	}

	for i := range xOut {
		xOut[i] = 0
	}
	for i := range yOut {
		yOut[i] = 0
	}
	for i := range zOut {
		zOut[i] = 0
	}
	nIsInfinityMask = ^uint32(0)

	for i := 0; i < 64; i++ {
		if i != 0 {
			sm2_stdPointDouble(xOut, yOut, zOut, xOut, yOut, zOut)
			sm2_stdPointDouble(xOut, yOut, zOut, xOut, yOut, zOut)
			sm2_stdPointDouble(xOut, yOut, zOut, xOut, yOut, zOut)
			sm2_stdPointDouble(xOut, yOut, zOut, xOut, yOut, zOut)
		}

		index = uint32(scalar[31-i/2])
		if (i & 1) == 1 {
			index &= 15
		} else {
			index >>= 4
		}
		
		sm2_stdSelectJacobianPoint(&px, &py, &pz, &precomp, index)
		sm2_stdPointAdd(xOut, yOut, zOut, &px, &py, &pz, &tx, &ty, &tz)
		sm2_stdCopyConditional(xOut, &px, nIsInfinityMask)
		sm2_stdCopyConditional(yOut, &py, nIsInfinityMask)
		sm2_stdCopyConditional(zOut, &pz, nIsInfinityMask)

		pIsNoninfiniteMask = nonZeroToAllOnes(index)
		mask = pIsNoninfiniteMask & ^nIsInfinityMask
		sm2_stdCopyConditional(xOut, &tx, mask)
		sm2_stdCopyConditional(yOut, &ty, mask)
		sm2_stdCopyConditional(zOut, &tz, mask)
		nIsInfinityMask &^= pIsNoninfiniteMask
	}
}

func sm2_stdPointToAffine(xOut, yOut, x, y, z *sm2_stdFieldElement) {
	var zInv, zInvSq sm2_stdFieldElement

	zz := sm2_stdToBig(z)
	zz.ModInverse(zz, sm2_std.P)
	sm2_stdFromBig(&zInv, zz)

	sm2_stdSquare(&zInvSq, &zInv)
	sm2_stdMul(xOut, x, &zInvSq)
	sm2_stdMul(&zInv, &zInv, &zInvSq)
	sm2_stdMul(yOut, y, &zInv)
}

func sm2_stdToAffine(x, y, z *sm2_stdFieldElement) (xOut, yOut *big.Int) {
	var xx, yy sm2_stdFieldElement

	sm2_stdPointToAffine(&xx, &yy, x, y, z)
	return sm2_stdToBig(&xx), sm2_stdToBig(&yy)
}

var sm2_stdFactor = []sm2_stdFieldElement{
	sm2_stdFieldElement{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
	sm2_stdFieldElement{0x2, 0x0, 0x1FFFFF00, 0x7FF, 0x0, 0x0, 0x0, 0x2000000, 0x0},
	sm2_stdFieldElement{0x4, 0x0, 0x1FFFFE00, 0xFFF, 0x0, 0x0, 0x0, 0x4000000, 0x0},
	sm2_stdFieldElement{0x6, 0x0, 0x1FFFFD00, 0x17FF, 0x0, 0x0, 0x0, 0x6000000, 0x0},
	sm2_stdFieldElement{0x8, 0x0, 0x1FFFFC00, 0x1FFF, 0x0, 0x0, 0x0, 0x8000000, 0x0},
	sm2_stdFieldElement{0xA, 0x0, 0x1FFFFB00, 0x27FF, 0x0, 0x0, 0x0, 0xA000000, 0x0},
	sm2_stdFieldElement{0xC, 0x0, 0x1FFFFA00, 0x2FFF, 0x0, 0x0, 0x0, 0xC000000, 0x0},
	sm2_stdFieldElement{0xE, 0x0, 0x1FFFF900, 0x37FF, 0x0, 0x0, 0x0, 0xE000000, 0x0},
	sm2_stdFieldElement{0x10, 0x0, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x0, 0x01},
}

func sm2_stdScalar(b *sm2_stdFieldElement, a int) {
	sm2_stdMul(b, b, &sm2_stdFactor[a])
}

func sm2_stdPointAdd(x1, y1, z1, x2, y2, z2, x3, y3, z3 *sm2_stdFieldElement) {
	var u1, u2, z22, z12, z23, z13, s1, s2, h, h2, r, r2, tm sm2_stdFieldElement

	if sm2_stdToBig(z1).Sign() == 0 {
		sm2_stdDup(x3, x2)
		sm2_stdDup(y3, y2)
		sm2_stdDup(z3, z2)
		return
	}

	if sm2_stdToBig(z2).Sign() == 0 {
		sm2_stdDup(x3, x1)
		sm2_stdDup(y3, y1)
		sm2_stdDup(z3, z1)
		return
	}

	sm2_stdSquare(&z12, z1)
	sm2_stdSquare(&z22, z2)

	sm2_stdMul(&z13, &z12, z1)
	sm2_stdMul(&z23, &z22, z2)

	sm2_stdMul(&u1, x1, &z22)
	sm2_stdMul(&u2, x2, &z12)

	sm2_stdMul(&s1, y1, &z23)
	sm2_stdMul(&s2, y2, &z13)

	if sm2_stdToBig(&u1).Cmp(sm2_stdToBig(&u2)) == 0 &&
		sm2_stdToBig(&s1).Cmp(sm2_stdToBig(&s2)) == 0 {
		sm2_stdPointDouble(x1, y1, z1, x1, y1, z1)
	}

	sm2_stdSub(&h, &u2, &u1)
	sm2_stdSub(&r, &s2, &s1)

	sm2_stdSquare(&r2, &r)
	sm2_stdSquare(&h2, &h)

	sm2_stdMul(&tm, &h2, &h)
	sm2_stdSub(x3, &r2, &tm)
	sm2_stdMul(&tm, &u1, &h2)
	sm2_stdScalar(&tm, 2)
	sm2_stdSub(x3, x3, &tm)

	sm2_stdMul(&tm, &u1, &h2)
	sm2_stdSub(&tm, &tm, x3)
	sm2_stdMul(y3, &r, &tm)
	sm2_stdMul(&tm, &h2, &h)
	sm2_stdMul(&tm, &tm, &s1)
	sm2_stdSub(y3, y3, &tm)

	sm2_stdMul(z3, z1, z2)
	sm2_stdMul(z3, z3, &h)
}

func sm2_stdPointDouble(x3, y3, z3, x, y, z *sm2_stdFieldElement) {
	var s, m, m2, x2, y2, z2, z4, y4, az4 sm2_stdFieldElement

	sm2_stdSquare(&x2, x)
	sm2_stdSquare(&y2, y)
	sm2_stdSquare(&z2, z)

	sm2_stdSquare(&z4, z)
	sm2_stdMul(&z4, &z4, z)
	sm2_stdMul(&z4, &z4, z)

	sm2_stdSquare(&y4, y)
	sm2_stdMul(&y4, &y4, y)
	sm2_stdMul(&y4, &y4, y)
	sm2_stdScalar(&y4, 8)

	sm2_stdMul(&s, x, &y2)
	sm2_stdScalar(&s, 4)

	sm2_stdDup(&m, &x2)
	sm2_stdScalar(&m, 3)
	sm2_stdMul(&az4, &sm2_std.a, &z4)
	sm2_stdAdd(&m, &m, &az4)

	sm2_stdSquare(&m2, &m)

	sm2_stdAdd(z3, y, z)
	sm2_stdSquare(z3, z3)
	sm2_stdSub(z3, z3, &z2)
	sm2_stdSub(z3, z3, &y2)

	sm2_stdSub(x3, &m2, &s)
	sm2_stdSub(x3, x3, &s)

	sm2_stdSub(y3, &s, x3)
	sm2_stdMul(y3, y3, &m)
	sm2_stdSub(y3, y3, &y4)
}

var sm2_stdZero31 = sm2_stdFieldElement{0x7FFFFFF8, 0x3FFFFFFC, 0x800003FC, 0x3FFFDFFC, 0x7FFFFFFC, 0x3FFFFFFC, 0x7FFFFFFC, 0x37FFFFFC, 0x7FFFFFFC}

func sm2_stdAdd(c, a, b *sm2_stdFieldElement) {
	carry := uint32(0)
	for i := 0; ; i++ {
		c[i] = a[i] + b[i]
		c[i] += carry
		carry = c[i] >> 29
		c[i] &= bottom29Bits
		i++
		if i == 9 {
			break
		}
		c[i] = a[i] + b[i]
		c[i] += carry
		carry = c[i] >> 28
		c[i] &= bottom28Bits
	}
	sm2_stdReduceCarry(c, carry)
}

func sm2_stdSub(c, a, b *sm2_stdFieldElement) {
	var carry uint32

	for i := 0; ; i++ {
		c[i] = a[i] - b[i]
		c[i] += sm2_stdZero31[i]
		c[i] += carry
		carry = c[i] >> 29
		c[i] &= bottom29Bits
		i++
		if i == 9 {
			break
		}
		c[i] = a[i] - b[i]
		c[i] += sm2_stdZero31[i]
		c[i] += carry
		carry = c[i] >> 28
		c[i] &= bottom28Bits
	}
	sm2_stdReduceCarry(c, carry)
}

func sm2_stdMul(c, a, b *sm2_stdFieldElement) {
	var tmp sm2_stdLargeFieldElement

	tmp[0] = uint64(a[0]) * uint64(b[0])
	tmp[1] = uint64(a[0])*(uint64(b[1])<<0) +
		uint64(a[1])*(uint64(b[0])<<0)
	tmp[2] = uint64(a[0])*(uint64(b[2])<<0) +
		uint64(a[1])*(uint64(b[1])<<1) +
		uint64(a[2])*(uint64(b[0])<<0)
	tmp[3] = uint64(a[0])*(uint64(b[3])<<0) +
		uint64(a[1])*(uint64(b[2])<<0) +
		uint64(a[2])*(uint64(b[1])<<0) +
		uint64(a[3])*(uint64(b[0])<<0)
	tmp[4] = uint64(a[0])*(uint64(b[4])<<0) +
		uint64(a[1])*(uint64(b[3])<<1) +
		uint64(a[2])*(uint64(b[2])<<0) +
		uint64(a[3])*(uint64(b[1])<<1) +
		uint64(a[4])*(uint64(b[0])<<0)
	tmp[5] = uint64(a[0])*(uint64(b[5])<<0) +
		uint64(a[1])*(uint64(b[4])<<0) +
		uint64(a[2])*(uint64(b[3])<<0) +
		uint64(a[3])*(uint64(b[2])<<0) +
		uint64(a[4])*(uint64(b[1])<<0) +
		uint64(a[5])*(uint64(b[0])<<0)
	tmp[6] = uint64(a[0])*(uint64(b[6])<<0) +
		uint64(a[1])*(uint64(b[5])<<1) +
		uint64(a[2])*(uint64(b[4])<<0) +
		uint64(a[3])*(uint64(b[3])<<1) +
		uint64(a[4])*(uint64(b[2])<<0) +
		uint64(a[5])*(uint64(b[1])<<1) +
		uint64(a[6])*(uint64(b[0])<<0)
	tmp[7] = uint64(a[0])*(uint64(b[7])<<0) +
		uint64(a[1])*(uint64(b[6])<<0) +
		uint64(a[2])*(uint64(b[5])<<0) +
		uint64(a[3])*(uint64(b[4])<<0) +
		uint64(a[4])*(uint64(b[3])<<0) +
		uint64(a[5])*(uint64(b[2])<<0) +
		uint64(a[6])*(uint64(b[1])<<0) +
		uint64(a[7])*(uint64(b[0])<<0)

	tmp[8] = uint64(a[0])*(uint64(b[8])<<0) +
		uint64(a[1])*(uint64(b[7])<<1) +
		uint64(a[2])*(uint64(b[6])<<0) +
		uint64(a[3])*(uint64(b[5])<<1) +
		uint64(a[4])*(uint64(b[4])<<0) +
		uint64(a[5])*(uint64(b[3])<<1) +
		uint64(a[6])*(uint64(b[2])<<0) +
		uint64(a[7])*(uint64(b[1])<<1) +
		uint64(a[8])*(uint64(b[0])<<0)
	tmp[9] = uint64(a[1])*(uint64(b[8])<<0) +
		uint64(a[2])*(uint64(b[7])<<0) +
		uint64(a[3])*(uint64(b[6])<<0) +
		uint64(a[4])*(uint64(b[5])<<0) +
		uint64(a[5])*(uint64(b[4])<<0) +
		uint64(a[6])*(uint64(b[3])<<0) +
		uint64(a[7])*(uint64(b[2])<<0) +
		uint64(a[8])*(uint64(b[1])<<0)
	tmp[10] = uint64(a[2])*(uint64(b[8])<<0) +
		uint64(a[3])*(uint64(b[7])<<1) +
		uint64(a[4])*(uint64(b[6])<<0) +
		uint64(a[5])*(uint64(b[5])<<1) +
		uint64(a[6])*(uint64(b[4])<<0) +
		uint64(a[7])*(uint64(b[3])<<1) +
		uint64(a[8])*(uint64(b[2])<<0)
	tmp[11] = uint64(a[3])*(uint64(b[8])<<0) +
		uint64(a[4])*(uint64(b[7])<<0) +
		uint64(a[5])*(uint64(b[6])<<0) +
		uint64(a[6])*(uint64(b[5])<<0) +
		uint64(a[7])*(uint64(b[4])<<0) +
		uint64(a[8])*(uint64(b[3])<<0)
	tmp[12] = uint64(a[4])*(uint64(b[8])<<0) +
		uint64(a[5])*(uint64(b[7])<<1) +
		uint64(a[6])*(uint64(b[6])<<0) +
		uint64(a[7])*(uint64(b[5])<<1) +
		uint64(a[8])*(uint64(b[4])<<0)
	tmp[13] = uint64(a[5])*(uint64(b[8])<<0) +
		uint64(a[6])*(uint64(b[7])<<0) +
		uint64(a[7])*(uint64(b[6])<<0) +
		uint64(a[8])*(uint64(b[5])<<0)
	tmp[14] = uint64(a[6])*(uint64(b[8])<<0) +
		uint64(a[7])*(uint64(b[7])<<1) +
		uint64(a[8])*(uint64(b[6])<<0)
	tmp[15] = uint64(a[7])*(uint64(b[8])<<0) +
		uint64(a[8])*(uint64(b[7])<<0)
	tmp[16] = uint64(a[8]) * (uint64(b[8]) << 0)
	sm2_stdReduceDegree(c, &tmp)
}

func sm2_stdSquare(b, a *sm2_stdFieldElement) {
	var tmp sm2_stdLargeFieldElement

	tmp[0] = uint64(a[0]) * uint64(a[0])
	tmp[1] = uint64(a[0]) * (uint64(a[1]) << 1)
	tmp[2] = uint64(a[0])*(uint64(a[2])<<1) +
		uint64(a[1])*(uint64(a[1])<<1)
	tmp[3] = uint64(a[0])*(uint64(a[3])<<1) +
		uint64(a[1])*(uint64(a[2])<<1)
	tmp[4] = uint64(a[0])*(uint64(a[4])<<1) +
		uint64(a[1])*(uint64(a[3])<<2) +
		uint64(a[2])*uint64(a[2])
	tmp[5] = uint64(a[0])*(uint64(a[5])<<1) +
		uint64(a[1])*(uint64(a[4])<<1) +
		uint64(a[2])*(uint64(a[3])<<1)
	tmp[6] = uint64(a[0])*(uint64(a[6])<<1) +
		uint64(a[1])*(uint64(a[5])<<2) +
		uint64(a[2])*(uint64(a[4])<<1) +
		uint64(a[3])*(uint64(a[3])<<1)
	tmp[7] = uint64(a[0])*(uint64(a[7])<<1) +
		uint64(a[1])*(uint64(a[6])<<1) +
		uint64(a[2])*(uint64(a[5])<<1) +
		uint64(a[3])*(uint64(a[4])<<1)

	tmp[8] = uint64(a[0])*(uint64(a[8])<<1) +
		uint64(a[1])*(uint64(a[7])<<2) +
		uint64(a[2])*(uint64(a[6])<<1) +
		uint64(a[3])*(uint64(a[5])<<2) +
		uint64(a[4])*uint64(a[4])
	tmp[9] = uint64(a[1])*(uint64(a[8])<<1) +
		uint64(a[2])*(uint64(a[7])<<1) +
		uint64(a[3])*(uint64(a[6])<<1) +
		uint64(a[4])*(uint64(a[5])<<1)
	tmp[10] = uint64(a[2])*(uint64(a[8])<<1) +
		uint64(a[3])*(uint64(a[7])<<2) +
		uint64(a[4])*(uint64(a[6])<<1) +
		uint64(a[5])*(uint64(a[5])<<1)
	tmp[11] = uint64(a[3])*(uint64(a[8])<<1) +
		uint64(a[4])*(uint64(a[7])<<1) +
		uint64(a[5])*(uint64(a[6])<<1)
	tmp[12] = uint64(a[4])*(uint64(a[8])<<1) +
		uint64(a[5])*(uint64(a[7])<<2) +
		uint64(a[6])*uint64(a[6])
	tmp[13] = uint64(a[5])*(uint64(a[8])<<1) +
		uint64(a[6])*(uint64(a[7])<<1)
	tmp[14] = uint64(a[6])*(uint64(a[8])<<1) +
		uint64(a[7])*(uint64(a[7])<<1)
	tmp[15] = uint64(a[7]) * (uint64(a[8]) << 1)
	tmp[16] = uint64(a[8]) * uint64(a[8])
	sm2_stdReduceDegree(b, &tmp)
}

func nonZeroToAllOnes(x uint32) uint32 {
	return ((x - 1) >> 31) - 1
}

var sm2_stdCarry = [8 * 9]uint32{
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x2, 0x0, 0x1FFFFF00, 0x7FF, 0x0, 0x0, 0x0, 0x2000000, 0x0,
	0x4, 0x0, 0x1FFFFE00, 0xFFF, 0x0, 0x0, 0x0, 0x4000000, 0x0,
	0x6, 0x0, 0x1FFFFD00, 0x17FF, 0x0, 0x0, 0x0, 0x6000000, 0x0,
	0x8, 0x0, 0x1FFFFC00, 0x1FFF, 0x0, 0x0, 0x0, 0x8000000, 0x0,
	0xA, 0x0, 0x1FFFFB00, 0x27FF, 0x0, 0x0, 0x0, 0xA000000, 0x0,
	0xC, 0x0, 0x1FFFFA00, 0x2FFF, 0x0, 0x0, 0x0, 0xC000000, 0x0,
	0xE, 0x0, 0x1FFFF900, 0x37FF, 0x0, 0x0, 0x0, 0xE000000, 0x0,
}

func sm2_stdReduceCarry(a *sm2_stdFieldElement, carry uint32) {
	a[0] += sm2_stdCarry[carry*9+0]
	a[2] += sm2_stdCarry[carry*9+2]
	a[3] += sm2_stdCarry[carry*9+3]
	a[7] += sm2_stdCarry[carry*9+7]
}

func sm2_stdReduceDegree(a *sm2_stdFieldElement, b *sm2_stdLargeFieldElement) {
	var tmp [18]uint32
	var carry, x, xMask uint32

	tmp[0] = uint32(b[0]) & bottom29Bits
	tmp[1] = uint32(b[0]) >> 29
	tmp[1] |= (uint32(b[0]>>32) << 3) & bottom28Bits
	tmp[1] += uint32(b[1]) & bottom28Bits
	carry = tmp[1] >> 28
	tmp[1] &= bottom28Bits
	for i := 2; i < 17; i++ {
		tmp[i] = (uint32(b[i-2] >> 32)) >> 25
		tmp[i] += (uint32(b[i-1])) >> 28
		tmp[i] += (uint32(b[i-1]>>32) << 4) & bottom29Bits
		tmp[i] += uint32(b[i]) & bottom29Bits
		tmp[i] += carry
		carry = tmp[i] >> 29
		tmp[i] &= bottom29Bits

		i++
		if i == 17 {
			break
		}
		tmp[i] = uint32(b[i-2]>>32) >> 25
		tmp[i] += uint32(b[i-1]) >> 29
		tmp[i] += ((uint32(b[i-1] >> 32)) << 3) & bottom28Bits
		tmp[i] += uint32(b[i]) & bottom28Bits
		tmp[i] += carry
		carry = tmp[i] >> 28
		tmp[i] &= bottom28Bits
	}
	tmp[17] = uint32(b[15]>>32) >> 25
	tmp[17] += uint32(b[16]) >> 29
	tmp[17] += uint32(b[16]>>32) << 3
	tmp[17] += carry

	for i := 0; ; i += 2 {

		tmp[i+1] += tmp[i] >> 29
		x = tmp[i] & bottom29Bits
		tmp[i] = 0
		if x > 0 {
			set4 := uint32(0)
			set7 := uint32(0)
			xMask = nonZeroToAllOnes(x)
			tmp[i+2] += (x << 7) & bottom29Bits
			tmp[i+3] += x >> 22
			if tmp[i+3] < 0x10000000 {
				set4 = 1
				tmp[i+3] += 0x10000000 & xMask
				tmp[i+3] -= (x << 10) & bottom28Bits
			} else {
				tmp[i+3] -= (x << 10) & bottom28Bits
			}
			if tmp[i+4] < 0x20000000 {
				tmp[i+4] += 0x20000000 & xMask
				tmp[i+4] -= set4
				tmp[i+4] -= x >> 18
				if tmp[i+5] < 0x10000000 {
					tmp[i+5] += 0x10000000 & xMask
					tmp[i+5] -= 1
					if tmp[i+6] < 0x20000000 {
						set7 = 1
						tmp[i+6] += 0x20000000 & xMask
						tmp[i+6] -= 1
					} else {
						tmp[i+6] -= 1
					}
				} else {
					tmp[i+5] -= 1
				}
			} else {
				tmp[i+4] -= set4
				tmp[i+4] -= x >> 18
			}
			if tmp[i+7] < 0x10000000 {
				tmp[i+7] += 0x10000000 & xMask
				tmp[i+7] -= set7
				tmp[i+7] -= (x << 24) & bottom28Bits
				tmp[i+8] += (x << 28) & bottom29Bits
				if tmp[i+8] < 0x20000000 {
					tmp[i+8] += 0x20000000 & xMask
					tmp[i+8] -= 1
					tmp[i+8] -= x >> 4
					tmp[i+9] += ((x >> 1) - 1) & xMask
				} else {
					tmp[i+8] -= 1
					tmp[i+8] -= x >> 4
					tmp[i+9] += (x >> 1) & xMask
				}
			} else {
				tmp[i+7] -= set7
				tmp[i+7] -= (x << 24) & bottom28Bits
				tmp[i+8] += (x << 28) & bottom29Bits
				if tmp[i+8] < 0x20000000 {
					tmp[i+8] += 0x20000000 & xMask
					tmp[i+8] -= x >> 4
					tmp[i+9] += ((x >> 1) - 1) & xMask
				} else {
					tmp[i+8] -= x >> 4
					tmp[i+9] += (x >> 1) & xMask
				}
			}

		}

		if i+1 == 9 {
			break
		}

		tmp[i+2] += tmp[i+1] >> 28
		x = tmp[i+1] & bottom28Bits
		tmp[i+1] = 0
		if x > 0 {
			set5 := uint32(0)
			set8 := uint32(0)
			set9 := uint32(0)
			xMask = nonZeroToAllOnes(x)
			tmp[i+3] += (x << 7) & bottom28Bits
			tmp[i+4] += x >> 21
			if tmp[i+4] < 0x20000000 {
				set5 = 1
				tmp[i+4] += 0x20000000 & xMask
				tmp[i+4] -= (x << 11) & bottom29Bits
			} else {
				tmp[i+4] -= (x << 11) & bottom29Bits
			}
			if tmp[i+5] < 0x10000000 {
				tmp[i+5] += 0x10000000 & xMask
				tmp[i+5] -= set5
				tmp[i+5] -= x >> 18
				if tmp[i+6] < 0x20000000 {
					tmp[i+6] += 0x20000000 & xMask
					tmp[i+6] -= 1
					if tmp[i+7] < 0x10000000 {
						set8 = 1
						tmp[i+7] += 0x10000000 & xMask
						tmp[i+7] -= 1
					} else {
						tmp[i+7] -= 1
					}
				} else {
					tmp[i+6] -= 1
				}
			} else {
				tmp[i+5] -= set5
				tmp[i+5] -= x >> 18
			}
			if tmp[i+8] < 0x20000000 {
				set9 = 1
				tmp[i+8] += 0x20000000 & xMask
				tmp[i+8] -= set8
				tmp[i+8] -= (x << 25) & bottom29Bits
			} else {
				tmp[i+8] -= set8
				tmp[i+8] -= (x << 25) & bottom29Bits
			}
			if tmp[i+9] < 0x10000000 {
				tmp[i+9] += 0x10000000 & xMask
				tmp[i+9] -= set9
				tmp[i+9] -= x >> 4
				tmp[i+10] += (x - 1) & xMask
			} else {
				tmp[i+9] -= set9
				tmp[i+9] -= x >> 4
				tmp[i+10] += x & xMask
			}
		}
	}

	carry = uint32(0)
	for i := 0; i < 8; i++ {
		a[i] = tmp[i+9]
		a[i] += carry
		a[i] += (tmp[i+10] << 28) & bottom29Bits
		carry = a[i] >> 29
		a[i] &= bottom29Bits

		i++
		a[i] = tmp[i+9] >> 1
		a[i] += carry
		carry = a[i] >> 28
		a[i] &= bottom28Bits
	}
	a[8] = tmp[17]
	a[8] += carry
	carry = a[8] >> 29
	a[8] &= bottom29Bits
	sm2_stdReduceCarry(a, carry)
}

func sm2_stdDup(b, a *sm2_stdFieldElement) {
	*b = *a
}

func sm2_stdFromBig(X *sm2_stdFieldElement, a *big.Int) {
	x := new(big.Int).Lsh(a, 257)
	x.Mod(x, sm2_std.P)
	for i := 0; i < 9; i++ {
		if bits := x.Bits(); len(bits) > 0 {
			X[i] = uint32(bits[0]) & bottom29Bits
		} else {
			X[i] = 0
		}
		x.Rsh(x, 29)
		i++
		if i == 9 {
			break
		}
		if bits := x.Bits(); len(bits) > 0 {
			X[i] = uint32(bits[0]) & bottom28Bits
		} else {
			X[i] = 0
		}
		x.Rsh(x, 28)
	}
}

func sm2_stdToBig(X *sm2_stdFieldElement) *big.Int {
	r, tm := new(big.Int), new(big.Int)
	r.SetInt64(int64(X[8]))
	for i := 7; i >= 0; i-- {
		if (i & 1) == 0 {
			r.Lsh(r, 29)
		} else {
			r.Lsh(r, 28)
		}
		tm.SetInt64(int64(X[i]))
		r.Add(r, tm)
	}
	r.Mul(r, sm2_std.RInverse)
	r.Mod(r, sm2_std.P)
	return r
}

func ZA(pub *ecdsa.PublicKey, uid []byte) ([]byte, error) {
	za := sm3.New()
	uidLen := len(uid)
	if uidLen >= 8192 {
		return []byte{}, errors.New("SM2: uid too large")
	}
	Entla := uint16(8 * uidLen)
	za.Write([]byte{byte((Entla >> 8) & 0xFF)})
	za.Write([]byte{byte(Entla & 0xFF)})
	za.Write(uid)
	za.Write(sm2_stdToBig(&sm2_std.a).Bytes())
	za.Write(sm2_std.B.Bytes())
	za.Write(sm2_std.Gx.Bytes())
	za.Write(sm2_std.Gy.Bytes())

	xBuf := make([]byte, 32)
	yBuf := make([]byte, 32)
	tmp := pub.X.Bytes()
	copy(xBuf[32-len(tmp):], tmp)
	tmp = pub.Y.Bytes()
	copy(yBuf[32-len(tmp):], tmp)

	za.Write(xBuf)
	za.Write(yBuf)
	return za.Sum(nil)[:32], nil
}

func msgHash(za, msg []byte) (*big.Int, error) {
	e := sm3.New()
	e.Write(za)
	e.Write(msg)
	return new(big.Int).SetBytes(e.Sum(nil)[:32]), nil
}

func sm2_std_sign(priv *ecdsa.PrivateKey, hash, uid []byte) (r, s *big.Int, v byte, err error) {

	var e *big.Int
	if uid == nil {
		if hash == nil || len(hash) != 32 {
			err = ErrMessageIllegal
			return
		}
		e = new(big.Int).SetBytes(hash)
	} else {
		za, err := ZA(&priv.PublicKey, uid)
		if err != nil {
			return nil, nil, 0, err
		}

		e, err = msgHash(za, hash)
		if err != nil {
			return nil, nil, 0, err
		}
	}

	entropylen := (priv.Curve.Params().BitSize + 7) / 16
	if entropylen > 32 {
		entropylen = 32
	}
	entropy := make([]byte, entropylen)
	_, err = io.ReadFull(rand.Reader, entropy)
	if err != nil {
		return
	}

	md := sha512.New()
	md.Write(priv.D.Bytes())
	md.Write(entropy)
	md.Write(hash)
	key := md.Sum(nil)[:32]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, 0, err
	}

	csprng := cipher.StreamReader{
		R: zeroReader,
		S: cipher.NewCTR(block, []byte(aesIV)),
	}

	c := priv.PublicKey.Curve
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, nil, 0, ErrUnknownCurve
	}
	var k , ry *big.Int

	for {
		for {
			k, err = randFieldElement(c, csprng)
			if err != nil {
				r = nil
				return
			}
			r, ry = priv.Curve.ScalarBaseMult(k.Bytes())
			r.Add(r, e)
			r.Mod(r, N)

			if ry.Mod(ry, big.NewInt(2)).Cmp(big.NewInt(1)) == 0 {
				v = 0x01
			} else {
				v = 0x00
			}

			if r.Sign() != 0 {
				break
			}
			if t := new(big.Int).Add(r, k); t.Cmp(N) == 0 {
				break
			}
		}
		rD := new(big.Int).Mul(priv.D, r)
		s = new(big.Int).Sub(k, rD)
		d1 := new(big.Int).Add(priv.D, new(big.Int).SetInt64(1))
		d1Inv := new(big.Int).ModInverse(d1, N)
		s.Mul(s, d1Inv)
		s.Mod(s, N)
		if s.Sign() != 0 {
			break
		}
	}
	return
}

func sm2_std_verify(pub *ecdsa.PublicKey, hash, uid []byte, r, s *big.Int) bool {

	var e *big.Int
	if uid == nil {
		if hash == nil || len(hash) != 32 {
			return false
		}
		e = new(big.Int).SetBytes(hash)
	} else {
		za, err := ZA(pub, uid)
		if err != nil {
			return false
		}

		e, err = msgHash(za, hash)
		if err != nil {
			return false
		}
	}

	c := pub.Curve
	N := c.Params().N

	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}

	t := new(big.Int).Add(r, s)
	t.Mod(t, N)
	if t.Sign() == 0 {
		return false
	}

	var x *big.Int
	x1, y1 := c.ScalarBaseMult(s.Bytes())
	x2, y2 := c.ScalarMult(pub.X, pub.Y, t.Bytes())
	x, _ = c.Add(x1, y1, x2, y2)

	x.Add(x, e)
	x.Mod(x, N)
	return x.Cmp(r) == 0
}

func intToBytes(x int) []byte {
	var buf = make([]byte, 4)

	binary.BigEndian.PutUint32(buf, uint32(x))
	return buf
}

func kdf(x, y []byte, length int) ([]byte, bool) {
	var c []byte

	ct := 1
	h := sm3.New()
	x = append(x, y...)
	for i, j := 0, (length+31)/32; i < j; i++ {
		h.Reset()
		h.Write(x)
		h.Write(intToBytes(ct))
		hash := h.Sum(nil)
		if i+1 == j && length%32 != 0 {
			c = append(c, hash[:length%32]...)
		} else {
			c = append(c, hash...)
		}
		ct++
	}
	for i := 0; i < length; i++ {
		if c[i] != 0 {
			return c, true
		}
	}
	return c, false
}

func sm2_std_encrypt(pub *ecdsa.PublicKey, data []byte) ([]byte, error) {
	length := len(data)
	for {
		c := []byte{}
		curve := pub.Curve
		k, err := randFieldElement(curve, rand.Reader)
		if err != nil {
			return nil, err
		}
		x1, y1 := curve.ScalarBaseMult(k.Bytes())
		x2, y2 := curve.ScalarMult(pub.X, pub.Y, k.Bytes())

		x1Buf := make([]byte, 32)
		y1Buf := make([]byte, 32)
		x2Buf := make([]byte, 32)
		y2Buf := make([]byte, 32)

		tmp := x1.Bytes()
		copy(x1Buf[32-len(tmp):], tmp)
		tmp = y1.Bytes()
		copy(y1Buf[32-len(tmp):], tmp)
		tmp = x2.Bytes()
		copy(x2Buf[32-len(tmp):], tmp)
		tmp = y2.Bytes()
		copy(y2Buf[32-len(tmp):], tmp)

		c = append(c, x1Buf...)
		c = append(c, y1Buf...)
		tm := []byte{}
		tm = append(tm, x2Buf...)
		tm = append(tm, data...)
		tm = append(tm, y2Buf...)
		h := sm3.Sm3Sum(tm)
		c = append(c, h...)
		ct, ok := kdf(x2Buf, y2Buf, length)
		if !ok {
			continue
		}
		c = append(c, ct...)
		for i := 0; i < length; i++ {
			c[96+i] ^= data[i]
		}
		return append([]byte{0x04}, c...), nil
	}
}

func sm2_std_decrypt(priv *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	data = data[1:]
	length := len(data) - 96
	curve := priv.Curve
	x := new(big.Int).SetBytes(data[:32])
	y := new(big.Int).SetBytes(data[32:64])
	x2, y2 := curve.ScalarMult(x, y, priv.D.Bytes())

	x2Buf := make([]byte, 32)
	y2Buf := make([]byte, 32)

	tmp := x2.Bytes()
	copy(x2Buf[32-len(tmp):], tmp)
	tmp = y2.Bytes()
	copy(y2Buf[32-len(tmp):], tmp)

	c, ok := kdf(x2Buf, y2Buf, length)
	if !ok {
		return nil, errors.New("Decrypt: failed to decrypt")
	}
	for i := 0; i < length; i++ {
		c[i] ^= data[i+96]
	}
	tm := []byte{}
	tm = append(tm, x2Buf...)
	tm = append(tm, c...)
	tm = append(tm, y2Buf...)
	h := sm3.Sm3Sum(tm)
	if bytes.Compare(h, data[64:96]) != 0 {
		return c, errors.New("Decrypt: failed to decrypt")
	}
	return c, nil
}

func ka_kdf(point *ecdsa.PublicKey, Zinitiator, Zresponder []byte, keyLengthbit uint16) (key []byte) {

	x := make([]byte, 32)
	y := make([]byte, 32)

	tmpBytes := point.X.Bytes()
	copy(x[32 - len(tmpBytes):], tmpBytes)
	tmpBytes = point.Y.Bytes()
	copy(y[32 - len(tmpBytes):], tmpBytes)

	generator := make([]byte, 4)

	var hlen1 uint32

	if keyLengthbit % 256 == 0 {
		hlen1 = uint32(keyLengthbit / 256)
	} else {
		hlen1 = uint32(keyLengthbit / 256) + 1
	}

	for i := uint32(1); i <= hlen1; i ++ {
		generator[0] = byte((i >> 24) & 0xff)
		generator[1] = byte((i >> 16) & 0xff)
		generator[2] = byte((i >> 8) & 0xff)
		generator[3] = byte(i & 0xff)

		h := sm3.New()
		h.Write(x)
		h.Write(y)
		h.Write(Zinitiator)
		h.Write(Zresponder)
		h.Write(generator)


		if keyLengthbit >= 256 {
			key = append(key, h.Sum(nil)...)
		} else {
			key = append(key, h.Sum(nil)[:keyLengthbit / 8]...)
		}

		keyLengthbit -= 256
	}

	return
}

func ka_check(value byte, Zinitiator, Zresponder, Rinitiator, Rresponder []byte, UV *ecdsa.PublicKey) []byte {
	x := make([]byte, 32)
	y := make([]byte, 32)

	tmpBytes := UV.X.Bytes()
	copy(x[32 - len(tmpBytes):], tmpBytes)
	tmpBytes = UV.Y.Bytes()
	copy(y[32 - len(tmpBytes):], tmpBytes)

	h := sm3.New()
	h.Write(x)
	h.Write(Zinitiator)
	h.Write(Zresponder)
	h.Write(Rinitiator)
	h.Write(Rresponder)
	tmp := h.Sum(nil)

	h.Reset()
	h.Write([]byte{value})
	h.Write(y)
	h.Write(tmp)
	return h.Sum(nil)

}


func sm2_std_ka_initiaor_step1() (tmpPrikeyInitiator, tmpPubkeyInitiator []byte) {
	tmpPrikeyInitiator = make([]byte, 32)

	random := make([]byte, 32)
	rand.Read(random)
	randbig := new(big.Int).SetBytes(random)
	randbig.Mod(randbig, sm2_std.N)
	random = randbig.Bytes()
	copy(tmpPrikeyInitiator[32-len(random):], random)
	tmpPubkeyInitiator, _ = genPublicKey(tmpPrikeyInitiator, "sm2_std")

	return
}

func sm2_std_ka_initiator_step2(IDinitiator []byte,
								IDresponder []byte,
								prikeyInitiator []byte,
								pubkeyInitiator []byte,
								pubkeyResponder []byte,
								tmpPrikeyInitiator []byte,
								tmpPubkeyInitiator []byte,
								tmpPubkeyResponder []byte,
								Sin []byte,
								keylen uint16,) (key, Sout []byte, err error){

	if tmpPubkeyResponder == nil || len(tmpPubkeyResponder) != 64 {
		err = errors.New("invalid responder's tmp public key")
		return
	}

	var x, y big.Int
	x.SetBytes(tmpPubkeyResponder[:32])
	y.SetBytes(tmpPubkeyResponder[32:])

	if !sm2_std.IsOnCurve(&x, &y) {
		err = errors.New("invalid responder's tmp public key")
		return
	}

	if tmpPubkeyInitiator == nil || len(tmpPubkeyInitiator) != 64 {
		err = errors.New("invalid initiator's tmp public key")
		return
	}
	tmp1Bytes := make([]byte, 16)
	copy(tmp1Bytes, tmpPubkeyInitiator[16:32])
	tmp1Bytes[0] |= 0x80

	if tmpPrikeyInitiator == nil || len(tmpPrikeyInitiator) != 32 {
		err = errors.New("invalid initiator's tmp private key")
		return
	}
	tmp1 := new(big.Int).SetBytes(tmp1Bytes)
	tmp2 := new(big.Int).Mul(tmp1, new(big.Int).SetBytes(tmpPrikeyInitiator))

	if prikeyInitiator == nil || len(prikeyInitiator) != 32 {
		err = errors.New("invalid initiator private key")
		return
	}
	tmp1 = tmp1.Add(new(big.Int).SetBytes(prikeyInitiator), tmp2)
	tmp1 = tmp1.Mod(tmp1, sm2_std.N)

	tmp2Bytes := make([]byte, 16)
	copy(tmp2Bytes, tmpPubkeyResponder[16:32])
	tmp2Bytes[0] |= 0x80

	point1 := new(ecdsa.PublicKey)
	point1.Curve = sm2_std
	point1.X, point1.Y = sm2_std.ScalarMult(new(big.Int).SetBytes(tmpPubkeyResponder[:32]), new(big.Int).SetBytes(tmpPubkeyResponder[32:]), tmp2Bytes)

	point2 := new(ecdsa.PublicKey)
	point2.Curve = sm2_std
	point2.X = new(big.Int).SetBytes(pubkeyResponder[:32])
	point2.Y = new(big.Int).SetBytes(pubkeyResponder[32:])

	point1.X, point1.Y = sm2_std.Add(point1.X, point1.Y, point2.X, point2.Y)
	point1.X, point1.Y = sm2_std.ScalarMult(point1.X, point1.Y, tmp1.Bytes())

	if pubkeyInitiator == nil || len(pubkeyInitiator) != 64 {
		err = errors.New("invalid initiator public key")
		return
	}
	pubInit := new(ecdsa.PublicKey)
	pubInit.X = new(big.Int).SetBytes(pubkeyInitiator[:32])
	pubInit.Y = new(big.Int).SetBytes(pubkeyInitiator[32:])
	if pubkeyResponder == nil || len(pubkeyResponder) != 64 {
		err = errors.New("invalid responder public key")
		return
	}
	pubResp := new(ecdsa.PublicKey)
	pubResp.X = new(big.Int).SetBytes(pubkeyResponder[:32])
	pubResp.Y = new(big.Int).SetBytes(pubkeyResponder[32:])

	if IDinitiator == nil || len(IDinitiator) == 0 {
		err = errors.New("invalid initiator ID")
		return
	}
	Zinitiator, err  := ZA(pubInit, IDinitiator)
	if err != nil {
		return nil, nil, err
	}
	if IDresponder == nil || len(IDresponder) == 0 {
		err = errors.New("invalid responder ID")
		return
	}
	Zresponder, err := ZA(pubResp, IDresponder)
	if err != nil {
		return nil, nil, err
	}

	key = ka_kdf(point1, Zinitiator, Zresponder, keylen * 8)

	s_check := ka_check(0x02, Zinitiator, Zresponder, tmpPubkeyInitiator, tmpPubkeyResponder, point1)

	if Sin == nil || len(Sin) != 32 || len(Sin) != len(s_check) {
		err = errors.New("check failed")
		return
	}

	for i := 0; i < 32; i ++ {
		if s_check[i] != Sin[i] {
			err = errors.New("check failed")
			return
		}
	}

	Sout = ka_check(0x03, Zinitiator, Zresponder, tmpPubkeyInitiator, tmpPubkeyResponder, point1)
	err = nil
	return
}

func sm2_std_ka_responder_step1(IDinitiator []byte,
								IDresponder []byte,
								prikeyResponder []byte,
								pubkeyResponder []byte,
								pubkeyInitiator []byte,
								tmpPubkeyInitiator []byte,
								random []byte,
								keylen uint16) (key, tmpPubkeyResponder, Sinner, Souter []byte, err error){
	if tmpPubkeyInitiator == nil || len(tmpPubkeyInitiator) != 64 {
		err = errors.New("invalid initiator's tmp public key")
		return
	}

	var x, y big.Int
	x.SetBytes(tmpPubkeyInitiator[:32])
	y.SetBytes(tmpPubkeyInitiator[32:])

	if !sm2_std.IsOnCurve(&x, &y) {
		err = errors.New("invalid initiator's tmp public key")
		return
	}

	tmpPriResponder := make([]byte, 32)

	if random == nil {
		tmp := make([]byte, 32)
		rand.Read(tmp)
		randbig := new(big.Int).SetBytes(tmp)
		randbig.Mod(randbig, sm2_std.N)
		tmp = randbig.Bytes()
		copy(tmpPriResponder[32-len(tmp):], tmp)
		} else {
		if len(random) != 32 {
			err = errors.New("invalid length of random")
			return
		}
		copy(tmpPriResponder, random)
	}

	tmpPubkeyResponder, err = genPublicKey(tmpPriResponder, "sm2_std")
	if err != nil {
		return
	}

	tmp1Bytes := make([]byte, 16)
	copy(tmp1Bytes, tmpPubkeyResponder[16:32])
	tmp1Bytes[0] |= 0x80

	if tmpPriResponder == nil || len(tmpPriResponder) != 32 {
		err = errors.New("invalid responder's tmp private key")
		return
	}
	tmp1 := new(big.Int).SetBytes(tmp1Bytes)
	tmp2 := new(big.Int).Mul(tmp1, new(big.Int).SetBytes(tmpPriResponder))

	if prikeyResponder == nil || len(prikeyResponder) != 32 {
		err = errors.New("invalid responder private key")
		return
	}
	tmp1 = tmp1.Add(new(big.Int).SetBytes(prikeyResponder), tmp2)
	tmp1 = tmp1.Mod(tmp1, sm2_std.N)

	tmp2Bytes := make([]byte, 16)
	copy(tmp2Bytes, tmpPubkeyInitiator[16:32])
	tmp2Bytes[0] |= 0x80

	point1 := new(ecdsa.PublicKey)
	point1.Curve = sm2_std
	point1.X, point1.Y = sm2_std.ScalarMult(new(big.Int).SetBytes(tmpPubkeyInitiator[:32]), new(big.Int).SetBytes(tmpPubkeyInitiator[32:]), tmp2Bytes)

	point2 := new(ecdsa.PublicKey)
	point2.Curve = sm2_std
	point2.X = new(big.Int).SetBytes(pubkeyInitiator[:32])
	point2.Y = new(big.Int).SetBytes(pubkeyInitiator[32:])

	point1.X, point1.Y = sm2_std.Add(point1.X, point1.Y, point2.X, point2.Y)
	point1.X, point1.Y = sm2_std.ScalarMult(point1.X, point1.Y, tmp1.Bytes())

	if pubkeyInitiator == nil || len(pubkeyInitiator) != 64 {
		err = errors.New("invalid initiator public key")
		return
	}
	pubInit := new(ecdsa.PublicKey)
	pubInit.X = new(big.Int).SetBytes(pubkeyInitiator[:32])
	pubInit.Y = new(big.Int).SetBytes(pubkeyInitiator[32:])
	if pubkeyResponder == nil || len(pubkeyResponder) != 64 {
		err = errors.New("invalid responder public key")
		return
	}
	pubResp := new(ecdsa.PublicKey)
	pubResp.X = new(big.Int).SetBytes(pubkeyResponder[:32])
	pubResp.Y = new(big.Int).SetBytes(pubkeyResponder[32:])

	if IDinitiator == nil || len(IDinitiator) == 0 {
		err = errors.New("invalid initiator ID")
		return
	}
	Zinitiator, err  := ZA(pubInit, IDinitiator)
	if err != nil {
		return
	}
	if IDresponder == nil || len(IDresponder) == 0 {
		err = errors.New("invalid responder ID")
		return
	}
	Zresponder, err := ZA(pubResp, IDresponder)
	if err != nil {
		return
	}

	key = ka_kdf(point1, Zinitiator, Zresponder, keylen * 8)

	Sinner = ka_check(0x03, Zinitiator, Zresponder, tmpPubkeyInitiator, tmpPubkeyResponder, point1)
	Souter = ka_check(0x02, Zinitiator, Zresponder, tmpPubkeyInitiator, tmpPubkeyResponder, point1)

	err = nil
	return
}

func sm2_std_ka_responder_step2(Sinitiator, Sresponder []byte) error {
	if Sinitiator == nil || len(Sinitiator) != 32 {
		return  errors.New("invalid check data of initiator")
	}

	if Sresponder == nil || len(Sresponder) != 32 {
		return errors.New("invalid check data of responder")
	}

	for i := 0; i < 32; i ++ {
		if Sinitiator[i] != Sresponder[i] {
			return errors.New("check failed")
		}
	}

	return nil
}

func getLastBit(a *big.Int) uint {
	return a.Bit(0)
}

func sm2_std_decompress(in []byte) ([]byte, error){
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

	c := sm2_std

	var y, x3b, xa big.Int
	x3b.Mul(x, x)
	x3b.Mul(&x3b, x)
	xa.SetBytes([]byte{0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFC})
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


func sm2_std_recover_public(sig, msg []byte) ([]byte, error) {

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

	curve := sm2_std

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

		buf1 := PointDecompress(buf2, ECC_CURVE_SM2_STANDARD)

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