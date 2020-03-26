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

package eddsa

import "crypto/sha256"

func CURVE25519_sha256_genPub(prikey []byte) ([]byte, error) {
	if prikey == nil || len(prikey) != 32 {
		return nil, ErrPrivateKeyIllegal
	}

	pubkey := make([]byte, 32)

	Keygen(pubkey, nil, prikey)

	return pubkey, nil
}

func CURVE25519_sha256_sign(prikey, message []byte) ([]byte, error) {
	if prikey == nil || len(prikey) != 32 {
		return nil, ErrPrivateKeyIllegal
	}

	pubkey := make([]byte, 32)
	s := make([]byte, 32)

	Keygen(pubkey, s, prikey)

	digest := sha256.New()
	digest.Write(message)
	m := digest.Sum(nil)

	digest.Reset()
	digest.Write(m)
	digest.Write(s)
	x := digest.Sum(nil)

	Y := make([]byte, 32)

	Keygen(Y, nil, x)

	digest.Reset()
	digest.Write(m)
	digest.Write(Y)
	h := digest.Sum(nil)
	v := make([]byte, 32)
	Sign(v, h, x, s)

	sig := make([]byte, 64)
	copy(sig[:32], v)
	copy(sig[32:], h)

	return sig, nil
}

func CURVE25519_sha256_verify(pubkey, message,signature []byte) bool {
	if signature == nil || len(signature) != 64 || pubkey == nil || len(pubkey) != 32 || message == nil || len(message) == 0 {
		return false
	}

	if !IsCanonicalSignature(signature) {
		return false
	}
	if !IsCanonicalPublicKey(pubkey) {
		return false
	}

	Y := make([]byte, 32)
	v := make([]byte, 32)
	copy(v, signature[:32])

	h := make([]byte, 32)
	copy(h, signature[32:])

	Verify(Y, v, h, pubkey)

	digest := sha256.New()
	_, _ = digest.Write(message)
	m := digest.Sum(nil)

	digest.Reset()
	_, _ = digest.Write(m)
	_, _ = digest.Write(Y)
	h2 := digest.Sum(nil)

	for i := range h {
		if h[i] != h2[i] {
			return false
		}
	}

	return true
}

const (
	keySize = 32

	p25 = 33554431
	p26 = 67108863
)

var prime = []byte{
	237, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
}

var order = []byte{
	237, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 16,
}

var orderTimes8 = []byte{
	104, 159, 174, 231, 210, 24, 147, 192, 178, 230, 188, 23, 245, 206, 247, 166, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 128,
}

var baseR2y = &long10{
	5744, 8160848, 4790893, 13779497, 35730846, 12541209, 49101323, 30047407, 40071253, 6226132,
}

var base2y = &long10{
	39999547, 18689728, 59995525, 1648697, 57546132, 24010086, 19059592, 5425144, 63499247, 16420658,
}

type long10 [10]int64

func clamp(k []byte) {
	k[31] &= 0x7F
	k[31] |= 0x40
	k[0] &= 0xF8
}

func Keygen(P, s, k []byte) {
	clamp(k)
	core(P, s, k, nil)
}

func mulaSmall(p, q []byte, m int, x []byte, n, z int) int {
	v := 0
	for i := 0; i < n; i++ {
		v += int(q[i+m]) + z*int(x[i])
		p[i+m] = byte(v)
		v >>= 8
	}
	return v
}

func mula32(p, x, y []byte, t, z int) {
	n := 31
	var w, i int
	for ; i < t; i++ {
		zy := z * int(y[i])
		w += mulaSmall(p, p, i, x, n, zy) + int(p[i+n]) + zy*int(x[n])
		p[i+n] = byte(w)
		w >>= 8
	}
	p[i+n] = byte(w + int(p[i+n]))
}

func divmod(q, r []byte, n int, d []byte, t int) {
	rn := 0
	dt := int(d[t-1]) << 8
	if t > 1 {
		dt |= int(d[t-2])
	}
	for n--; n >= t-1; n-- {
		z := (rn << 16) | (int(r[n]) << 8)
		if n > 0 {
			z |= int(r[n-1])
		}
		z /= dt
		rn += mulaSmall(r, r, n-t+1, d, t, -z)
		q[n-t+1] = byte(z + rn)
		mulaSmall(r, r, n-t+1, d, t, -rn)
		rn = int(r[n])
		r[n] = 0
	}
	r[t-1] = byte(rn)
}

func unpack(x *long10, m []byte) {
	x[0] = int64(m[0]) | (int64(m[1]) << 8) | (int64(m[2]) << 16) | ((int64(m[3]) & 3) << 24)
	x[1] = ((int64(m[3]) & ^3) >> 2) | (int64(m[4]) << 6) | (int64(m[5]) << 14) | (((int64(m[6]) & 0xFF) & 7) << 22)
	x[2] = ((int64(m[6]) & ^7) >> 3) | (int64(m[7]) << 5) | (int64(m[8]) << 13) | ((int64(m[9]) & 31) << 21)
	x[3] = ((int64(m[9]) & ^31) >> 5) | (int64(m[10]) << 3) | ((int64(m[11]) & 0xFF) << 11) | ((int64(m[12]) & 63) << 19)
	x[4] = (((int64(m[12]) & 0xFF) & ^63) >> 6) | (int64(m[13]) << 2) | (int64(m[14]) << 10) | (int64(m[15]) << 18)
	x[5] = int64(m[16]) | (int64(m[17]) << 8) | (int64(m[18]) << 16) | ((int64(m[19]) & 1) << 24)
	x[6] = (((int64(m[19]) & 0xFF) & ^1) >> 1) | (int64(m[20]) << 7) | (int64(m[21]) << 15) | ((int64(m[22]) & 7) << 23)
	x[7] = ((int64(m[22]) & ^7) >> 3) | (int64(m[23]) << 5) | (int64(m[24]) << 13) | ((int64(m[25]) & 15) << 21)
	x[8] = ((int64(m[25]) & ^15) >> 4) | (int64(m[26]) << 4) | (int64(m[27]) << 12) | ((int64(m[28]) & 63) << 20)
	x[9] = ((int64(m[28]) & ^63) >> 6) | (int64(m[29]) << 2) | (int64(m[30]) << 10) | (int64(m[31]) << 18)
}

func isOverflow(x *long10) bool {
	return ((x[0] > p26-19) && ((x[1] & x[3] & x[5] & x[7] & x[9]) == p25) && ((x[2] & x[4] & x[6] & x[8]) == p26)) || (x[9] > p25)
}

func pack(x *long10, m []byte) {
	var ld, ud int
	var t int64

	if isOverflow(x) {
		ld = 1
	}
	if x[9] < 0 {
		ld--
	}

	ud = ld * -(p25 + 1)
	ld *= 19
	t = int64(ld) + x[0] + (x[1] << 26)
	m[0] = byte(t)
	m[1] = byte(t >> 8)
	m[2] = byte(t >> 16)
	m[3] = byte(t >> 24)
	t = (t >> 32) + (x[2] << 19)
	m[4] = byte(t)
	m[5] = byte(t >> 8)
	m[6] = byte(t >> 16)
	m[7] = byte(t >> 24)
	t = (t >> 32) + (x[3] << 13)
	m[8] = byte(t)
	m[9] = byte(t >> 8)
	m[10] = byte(t >> 16)
	m[11] = byte(t >> 24)
	t = (t >> 32) + (x[4] << 6)
	m[12] = byte(t)
	m[13] = byte(t >> 8)
	m[14] = byte(t >> 16)
	m[15] = byte(t >> 24)
	t = (t >> 32) + x[5] + (x[6] << 25)
	m[16] = byte(t)
	m[17] = byte(t >> 8)
	m[18] = byte(t >> 16)
	m[19] = byte(t >> 24)
	t = (t >> 32) + (x[7] << 19)
	m[20] = byte(t)
	m[21] = byte(t >> 8)
	m[22] = byte(t >> 16)
	m[23] = byte(t >> 24)
	t = (t >> 32) + (x[8] << 12)
	m[24] = byte(t)
	m[25] = byte(t >> 8)
	m[26] = byte(t >> 16)
	m[27] = byte(t >> 24)
	t = (t >> 32) + ((x[9] + int64(ud)) << 6)
	m[28] = byte(t)
	m[29] = byte(t >> 8)
	m[30] = byte(t >> 16)
	m[31] = byte(t >> 24)
}

func cpy(out, in *long10) {
	out[0] = in[0]
	out[1] = in[1]
	out[2] = in[2]
	out[3] = in[3]
	out[4] = in[4]
	out[5] = in[5]
	out[6] = in[6]
	out[7] = in[7]
	out[8] = in[8]
	out[9] = in[9]
}

func set(out *long10, in int64) {
	out[0] = in
	out[1] = 0
	out[2] = 0
	out[3] = 0
	out[4] = 0
	out[5] = 0
	out[6] = 0
	out[7] = 0
	out[8] = 0
	out[9] = 0
}

func add(xy *long10, x *long10, y *long10) {
	xy[0] = x[0] + y[0]
	xy[1] = x[1] + y[1]
	xy[2] = x[2] + y[2]
	xy[3] = x[3] + y[3]
	xy[4] = x[4] + y[4]
	xy[5] = x[5] + y[5]
	xy[6] = x[6] + y[6]
	xy[7] = x[7] + y[7]
	xy[8] = x[8] + y[8]
	xy[9] = x[9] + y[9]
}

func sub(xy *long10, x *long10, y *long10) {
	xy[0] = x[0] - y[0]
	xy[1] = x[1] - y[1]
	xy[2] = x[2] - y[2]
	xy[3] = x[3] - y[3]
	xy[4] = x[4] - y[4]
	xy[5] = x[5] - y[5]
	xy[6] = x[6] - y[6]
	xy[7] = x[7] - y[7]
	xy[8] = x[8] - y[8]
	xy[9] = x[9] - y[9]
}

func mulSmall(xy *long10, x *long10, y int64) {
	t := (x[8] * y)
	xy[8] = (t & ((1 << 26) - 1))
	t = (t >> 26) + (x[9] * y)
	xy[9] = (t & ((1 << 25) - 1))
	t = 19*(t>>25) + (x[0] * y)
	xy[0] = (t & ((1 << 26) - 1))
	t = (t >> 26) + (x[1] * y)
	xy[1] = (t & ((1 << 25) - 1))
	t = (t >> 25) + (x[2] * y)
	xy[2] = (t & ((1 << 26) - 1))
	t = (t >> 26) + (x[3] * y)
	xy[3] = (t & ((1 << 25) - 1))
	t = (t >> 25) + (x[4] * y)
	xy[4] = (t & ((1 << 26) - 1))
	t = (t >> 26) + (x[5] * y)
	xy[5] = (t & ((1 << 25) - 1))
	t = (t >> 25) + (x[6] * y)
	xy[6] = (t & ((1 << 26) - 1))
	t = (t >> 26) + (x[7] * y)
	xy[7] = (t & ((1 << 25) - 1))
	t = (t >> 25) + xy[8]
	xy[8] = (t & ((1 << 26) - 1))
	xy[9] += (t >> 26)
}

func mul(xy *long10, x *long10, y *long10) {
	t := (x[0] * y[8]) + (x[2] * y[6]) + (x[4] * y[4]) + (x[6] * y[2]) + (x[8] * y[0]) + 2*((x[1]*y[7])+(x[3]*y[5])+(x[5]*y[3])+(x[7]*y[1])) + 38*(x[9]*y[9])
	xy[8] = (t & ((1 << 26) - 1))
	t = (t >> 26) + (x[0] * y[9]) + (x[1] * y[8]) + (x[2] * y[7]) + (x[3] * y[6]) + (x[4] * y[5]) + (x[5] * y[4]) + (x[6] * y[3]) + (x[7] * y[2]) + (x[8] * y[1]) + (x[9] * y[0])
	xy[9] = (t & ((1 << 25) - 1))
	t = (x[0] * y[0]) + 19*((t>>25)+(x[2]*y[8])+(x[4]*y[6])+(x[6]*y[4])+(x[8]*y[2])) + 38*((x[1]*y[9])+(x[3]*y[7])+(x[5]*y[5])+(x[7]*y[3])+(x[9]*y[1]))
	xy[0] = (t & ((1 << 26) - 1))
	t = (t >> 26) + (x[0] * y[1]) + (x[1] * y[0]) + 19*((x[2]*y[9])+(x[3]*y[8])+(x[4]*y[7])+(x[5]*y[6])+(x[6]*y[5])+(x[7]*y[4])+(x[8]*y[3])+(x[9]*y[2]))
	xy[1] = (t & ((1 << 25) - 1))
	t = (t >> 25) + (x[0] * y[2]) + (x[2] * y[0]) + 19*((x[4]*y[8])+(x[6]*y[6])+(x[8]*y[4])) + 2*(x[1]*y[1]) + 38*((x[3]*y[9])+(x[5]*y[7])+(x[7]*y[5])+(x[9]*y[3]))
	xy[2] = (t & ((1 << 26) - 1))
	t = (t >> 26) + (x[0] * y[3]) + (x[1] * y[2]) + (x[2] * y[1]) + (x[3] * y[0]) + 19*((x[4]*y[9])+(x[5]*y[8])+(x[6]*y[7])+(x[7]*y[6])+(x[8]*y[5])+(x[9]*y[4]))
	xy[3] = (t & ((1 << 25) - 1))
	t = (t >> 25) + (x[0] * y[4]) + (x[2] * y[2]) + (x[4] * y[0]) + 19*((x[6]*y[8])+(x[8]*y[6])) + 2*((x[1]*y[3])+(x[3]*y[1])) + 38*((x[5]*y[9])+(x[7]*y[7])+(x[9]*y[5]))
	xy[4] = (t & ((1 << 26) - 1))
	t = (t >> 26) + (x[0] * y[5]) + (x[1] * y[4]) + (x[2] * y[3]) + (x[3] * y[2]) + (x[4] * y[1]) + (x[5] * y[0]) + 19*((x[6]*y[9])+(x[7]*y[8])+(x[8]*y[7])+(x[9]*y[6]))
	xy[5] = (t & ((1 << 25) - 1))
	t = (t >> 25) + (x[0] * y[6]) + (x[2] * y[4]) + (x[4] * y[2]) + (x[6] * y[0]) + 19*(x[8]*y[8]) + 2*((x[1]*y[5])+(x[3]*y[3])+(x[5]*y[1])) + 38*((x[7]*y[9])+(x[9]*y[7]))
	xy[6] = (t & ((1 << 26) - 1))
	t = (t >> 26) + (x[0] * y[7]) + (x[1] * y[6]) + (x[2] * y[5]) + (x[3] * y[4]) + (x[4] * y[3]) + (x[5] * y[2]) + (x[6] * y[1]) + (x[7] * y[0]) + 19*((x[8]*y[9])+(x[9]*y[8]))
	xy[7] = (t & ((1 << 25) - 1))
	t = (t >> 25) + xy[8]
	xy[8] = (t & ((1 << 26) - 1))
	xy[9] += (t >> 26)
}

func sqr(x2 *long10, x *long10) {
	t := (x[4] * x[4]) + 2*((x[0]*x[8])+(x[2]*x[6])) + 38*(x[9]*x[9]) + 4*((x[1]*x[7])+(x[3]*x[5]))
	x2[8] = (t & ((1 << 26) - 1))
	t = (t >> 26) + 2*((x[0]*x[9])+(x[1]*x[8])+(x[2]*x[7])+(x[3]*x[6])+(x[4]*x[5]))
	x2[9] = (t & ((1 << 25) - 1))
	t = 19*(t>>25) + (x[0] * x[0]) + 38*((x[2]*x[8])+(x[4]*x[6])+(x[5]*x[5])) + 76*((x[1]*x[9])+(x[3]*x[7]))
	x2[0] = (t & ((1 << 26) - 1))
	t = (t >> 26) + 2*(x[0]*x[1]) + 38*((x[2]*x[9])+(x[3]*x[8])+(x[4]*x[7])+(x[5]*x[6]))
	x2[1] = (t & ((1 << 25) - 1))
	t = (t >> 25) + 19*(x[6]*x[6]) + 2*((x[0]*x[2])+(x[1]*x[1])) + 38*(x[4]*x[8]) + 76*((x[3]*x[9])+(x[5]*x[7]))
	x2[2] = (t & ((1 << 26) - 1))
	t = (t >> 26) + 2*((x[0]*x[3])+(x[1]*x[2])) + 38*((x[4]*x[9])+(x[5]*x[8])+(x[6]*x[7]))
	x2[3] = (t & ((1 << 25) - 1))
	t = (t >> 25) + (x[2] * x[2]) + 2*(x[0]*x[4]) + 38*((x[6]*x[8])+(x[7]*x[7])) + 4*(x[1]*x[3]) + 76*(x[5]*x[9])
	x2[4] = (t & ((1 << 26) - 1))
	t = (t >> 26) + 2*((x[0]*x[5])+(x[1]*x[4])+(x[2]*x[3])) + 38*((x[6]*x[9])+(x[7]*x[8]))
	x2[5] = (t & ((1 << 25) - 1))
	t = (t >> 25) + 19*(x[8]*x[8]) + 2*((x[0]*x[6])+(x[2]*x[4])+(x[3]*x[3])) + 4*(x[1]*x[5]) + 76*(x[7]*x[9])
	x2[6] = (t & ((1 << 26) - 1))
	t = (t >> 26) + 2*((x[0]*x[7])+(x[1]*x[6])+(x[2]*x[5])+(x[3]*x[4])) + 38*(x[8]*x[9])
	x2[7] = (t & ((1 << 25) - 1))
	t = (t >> 25) + x2[8]
	x2[8] = (t & ((1 << 26) - 1))
	x2[9] += (t >> 26)
}

func recip(y *long10, x *long10, sqrtassist int) {
	var t0, t1, t2, t3, t4 long10
	/* the chain for x^(2^255-21) is straight from djb's implementation */
	sqr(&t1, x)        /*  2 == 2 * 1  */
	sqr(&t2, &t1)      /*  4 == 2 * 2  */
	sqr(&t0, &t2)      /*  8 == 2 * 4  */
	mul(&t2, &t0, x)   /*  9 == 8 + 1  */
	mul(&t0, &t2, &t1) /* 11 == 9 + 2  */
	sqr(&t1, &t0)      /* 22 == 2 * 11 */
	mul(&t3, &t1, &t2) /* 31 == 22 + 9
	   == 2^5   - 2^0  */
	sqr(&t1, &t3)      /* 2^6   - 2^1  */
	sqr(&t2, &t1)      /* 2^7   - 2^2  */
	sqr(&t1, &t2)      /* 2^8   - 2^3  */
	sqr(&t2, &t1)      /* 2^9   - 2^4  */
	sqr(&t1, &t2)      /* 2^10  - 2^5  */
	mul(&t2, &t1, &t3) /* 2^10  - 2^0  */
	sqr(&t1, &t2)      /* 2^11  - 2^1  */
	sqr(&t3, &t1)      /* 2^12  - 2^2  */
	for i := 1; i < 5; i++ {
		sqr(&t1, &t3)
		sqr(&t3, &t1)
	} /* &t3 */ /* 2^20  - 2^10 */
	mul(&t1, &t3, &t2) /* 2^20  - 2^0  */
	sqr(&t3, &t1)      /* 2^21  - 2^1  */
	sqr(&t4, &t3)      /* 2^22  - 2^2  */
	for i := 1; i < 10; i++ {
		sqr(&t3, &t4)
		sqr(&t4, &t3)
	} /* &t4 */ /* 2^40  - 2^20 */
	mul(&t3, &t4, &t1) /* 2^40  - 2^0  */
	for i := 0; i < 5; i++ {
		sqr(&t1, &t3)
		sqr(&t3, &t1)
	} /* &t3 */ /* 2^50  - 2^10 */
	mul(&t1, &t3, &t2) /* 2^50  - 2^0  */
	sqr(&t2, &t1)      /* 2^51  - 2^1  */
	sqr(&t3, &t2)      /* 2^52  - 2^2  */
	for i := 1; i < 25; i++ {
		sqr(&t2, &t3)
		sqr(&t3, &t2)
	} /* &t3 */ /* 2^100 - 2^50 */
	mul(&t2, &t3, &t1) /* 2^100 - 2^0  */
	sqr(&t3, &t2)      /* 2^101 - 2^1  */
	sqr(&t4, &t3)      /* 2^102 - 2^2  */
	for i := 1; i < 50; i++ {
		sqr(&t3, &t4)
		sqr(&t4, &t3)
	} /* &t4 */ /* 2^200 - 2^100 */
	mul(&t3, &t4, &t2) /* 2^200 - 2^0  */
	for i := 0; i < 25; i++ {
		sqr(&t4, &t3)
		sqr(&t3, &t4)
	} /* &t3 */ /* 2^250 - 2^50 */
	mul(&t2, &t3, &t1) /* 2^250 - 2^0  */
	sqr(&t1, &t2)      /* 2^251 - 2^1  */
	sqr(&t2, &t1)      /* 2^252 - 2^2  */
	if sqrtassist != 0 {
		mul(y, x, &t2) /* 2^252 - 3 */
	} else {
		sqr(&t1, &t2)    /* 2^253 - 2^3  */
		sqr(&t2, &t1)    /* 2^254 - 2^4  */
		sqr(&t1, &t2)    /* 2^255 - 2^5  */
		mul(y, &t1, &t0) /* 2^255 - 21 */
	}
}

func isNegative(x *long10) int {
	var tmp int64
	if isOverflow(x) || x[9] < 0 {
		tmp = 1
	}
	return int(tmp ^ (x[0] & 1))
}

func sqrt(x *long10, u *long10) {
	var v, t1, t2 long10
	add(&t1, u, u)    /* t1 = 2u    */
	recip(&v, &t1, 1) /* v = (2u)^((p-5)/8) */
	sqr(x, &v)        /* x = v^2    */
	mul(&t2, &t1, x)  /* t2 = 2uv^2   */
	t2[0]--           /* t2 = 2uv^2-1   */
	mul(&t1, &v, &t2) /* t1 = v(2uv^2-1)  */
	mul(x, u, &t1)    /* x = uv(2uv^2-1)  */
}

func montPrep(t1 *long10, t2 *long10, ax *long10, az *long10) {
	add(t1, ax, az)
	sub(t2, ax, az)
}

func montAdd(t1 *long10, t2 *long10, t3 *long10, t4 *long10, ax *long10, az *long10, dx *long10) {
	mul(ax, t2, t3)
	mul(az, t1, t4)
	add(t1, ax, az)
	sub(t2, ax, az)
	sqr(ax, t1)
	sqr(t1, t2)
	mul(az, t1, dx)
}

func montDbl(t1 *long10, t2 *long10, t3 *long10, t4 *long10, bx *long10, bz *long10) {
	sqr(t1, t3)
	sqr(t2, t4)
	mul(bx, t1, t2)
	sub(t2, t1, t2)
	mulSmall(bz, t2, 121665)
	add(t1, t1, bz)
	mul(bz, t1, t2)
}

func xToY2(t *long10, y2 *long10, x *long10) {
	sqr(t, x)
	mulSmall(y2, x, 486662)
	add(t, t, y2)
	t[0]++
	mul(y2, t, x)
}

func core(Px, s, k, Gx []byte) {
	var dx, t1, t2, t3, t4 long10
	var x, z [2]*long10
	x[0] = &long10{}
	x[1] = &long10{}
	z[0] = &long10{}
	z[1] = &long10{}

	/* unpack the base */
	if Gx != nil {
		unpack(&dx, Gx)
	} else {
		set(&dx, 9)
	}

	/* 0G = point-at-infinity */
	set(x[0], 1)
	set(z[0], 0)

	/* 1G = G */
	cpy(x[1], &dx)
	set(z[1], 1)

	for i := 31; i >= 0; i-- {
		for j := 7; j >= 0; j-- {
			bit1 := uint(k[i]) >> uint(j) & 1
			bit0 := ^uint(k[i]) >> uint(j) & 1
			ax := x[bit0]
			az := z[bit0]
			bx := x[bit1]
			bz := z[bit1]

			/* a' = a + b */
			/* b' = 2 b */
			montPrep(&t1, &t2, ax, az)
			montPrep(&t3, &t4, bx, bz)
			montAdd(&t1, &t2, &t3, &t4, ax, az, &dx)
			montDbl(&t1, &t2, &t3, &t4, bx, bz)
		}
	}

	recip(&t1, z[0], 0)
	mul(&dx, x[0], &t1)
	pack(&dx, Px)

	/* calculate s such that s abs(P) = G  .. assumes G is std base point */
	if s != nil {
		xToY2(&t2, &t1, &dx)      /* t1 = Py^2  */
		recip(&t3, z[1], 0)       /* where Q=P+G ... */
		mul(&t2, x[1], &t3)       /* t2 = Qx  */
		add(&t2, &t2, &dx)        /* t2 = Qx + Px  */
		t2[0] += 9 + 486662       /* t2 = Qx + Px + Gx + 486662  */
		dx[0] -= 9                /* dx = Px - Gx  */
		sqr(&t3, &dx)             /* t3 = (Px - Gx)^2  */
		mul(&dx, &t2, &t3)        /* dx = t2 (Px - Gx)^2  */
		sub(&dx, &dx, &t1)        /* dx = t2 (Px - Gx)^2 - Py^2  */
		dx[0] -= 39420360         /* dx = t2 (Px - Gx)^2 - Py^2 - Gy^2  */
		mul(&t1, &dx, baseR2y)    /* t1 = -Py  */
		if isNegative(&t1) != 0 { /* sign is 1, so just copy  */
			copy(s, k)
		} else { /* sign is -1, so negate  */
			mulaSmall(s, orderTimes8, 0, k, 32, -1)
		}

		/* reduce s mod q
		 * (is this needed?  do it just in case, it's fast anyway) */
		//divmod((dstptr) t1, s, 32, order25519, 32);

		/* take reciprocal of s mod q */
		tmp1 := make([]byte, 32)
		tmp2 := make([]byte, 64)
		tmp3 := make([]byte, 64)
		copy(tmp1, order)
		copy(s, egcd32(tmp2, tmp3, s, tmp1))
		if (s[31] & 0x80) != 0 {
			mulaSmall(s, s, 0, order, 32, 1)
		}
	}
}

func Sign(v, h, x, s []byte) bool {
	var w int
	h1 := make([]byte, 32)
	x1 := make([]byte, 32)
	tmp3 := make([]byte, 32)
	tmp1 := make([]byte, 64)
	tmp2 := make([]byte, 64)

	copy(h1, h)
	copy(x1, x)

	divmod(tmp3, h1, 32, order, 32)
	divmod(tmp3, x1, 32, order, 32)

	mulaSmall(v, x1, 0, h1, 32, -1)
	mulaSmall(v, v, 0, order, 32, 1)

	mula32(tmp1, v, s, 32, 1)
	divmod(tmp2, tmp1, 64, order, 32)

	for i := 0; i < 32; i++ {
		v[i] = tmp1[i]
		w |= int(tmp1[i])
	}
	return w != 0
}

func Verify(Y, v, h, P []byte) {
	/* Y = v abs(P) + h G  */
	d := make([]byte, 32)
	p := [2]*long10{
		&long10{},
		&long10{},
	}
	s := [2]*long10{
		&long10{},
		&long10{},
	}
	yx := [3]*long10{
		&long10{},
		&long10{},
		&long10{},
	}
	yz := [3]*long10{
		&long10{},
		&long10{},
		&long10{},
	}
	t1 := [3]*long10{
		&long10{},
		&long10{},
		&long10{},
	}
	t2 := [3]*long10{
		&long10{},
		&long10{},
		&long10{},
	}

	var vi, hi, di, nvh, j, k int
	/* set p[0] to G and p[1] to P  */

	set(p[0], 9)
	unpack(p[1], P)

	/* set s[0] to P+G and s[1] to P-G  */

	/* s[0] = (Py^2 + Gy^2 - 2 Py Gy)/(Px - Gx)^2 - Px - Gx - 486662  */
	/* s[1] = (Py^2 + Gy^2 + 2 Py Gy)/(Px - Gx)^2 - Px - Gx - 486662  */

	xToY2(t1[0], t2[0], p[1])  /* t2[0] = Py^2  */
	sqrt(t1[0], t2[0])         /* t1[0] = Py or -Py  */
	j = isNegative(t1[0])      /*      ... check which  */
	t2[0][0] += 39420360       /* t2[0] = Py^2 + Gy^2  */
	mul(t2[1], base2y, t1[0])  /* t2[1] = 2 Py Gy or -2 Py Gy  */
	sub(t1[j], t2[0], t2[1])   /* t1[0] = Py^2 + Gy^2 - 2 Py Gy  */
	add(t1[1-j], t2[0], t2[1]) /* t1[1] = Py^2 + Gy^2 + 2 Py Gy  */
	cpy(t2[0], p[1])           /* t2[0] = Px  */
	t2[0][0] -= 9              /* t2[0] = Px - Gx  */
	sqr(t2[1], t2[0])          /* t2[1] = (Px - Gx)^2  */
	recip(t2[0], t2[1], 0)     /* t2[0] = 1/(Px - Gx)^2  */
	mul(s[0], t1[0], t2[0])    /* s[0] = t1[0]/(Px - Gx)^2  */
	sub(s[0], s[0], p[1])      /* s[0] = t1[0]/(Px - Gx)^2 - Px  */
	s[0][0] -= 9 + 486662      /* s[0] = X(P+G)  */
	mul(s[1], t1[1], t2[0])    /* s[1] = t1[1]/(Px - Gx)^2  */
	sub(s[1], s[1], p[1])      /* s[1] = t1[1]/(Px - Gx)^2 - Px  */
	s[1][0] -= 9 + 486662      /* s[1] = X(P-G)  */
	mulSmall(s[0], s[0], 1)    /* reduce s[0] */
	mulSmall(s[1], s[1], 1)    /* reduce s[1] */

	/* prepare the chain  */
	for i := 0; i < 32; i++ {
		vi = (vi >> 8) ^ int(v[i]) ^ (int(v[i]) << 1)
		hi = (hi >> 8) ^ int(h[i]) ^ (int(h[i]) << 1)
		nvh = ^(vi ^ hi)
		di = (nvh & ((di & 0x80) >> 7)) ^ vi
		di ^= nvh & ((di & 0x01) << 1)
		di ^= nvh & ((di & 0x02) << 1)
		di ^= nvh & ((di & 0x04) << 1)
		di ^= nvh & ((di & 0x08) << 1)
		di ^= nvh & ((di & 0x10) << 1)
		di ^= nvh & ((di & 0x20) << 1)
		di ^= nvh & ((di & 0x40) << 1)
		d[i] = byte(di)
	}

	di = ((nvh & ((di & 0x80) << 1)) ^ vi) >> 8

	/* initialize state */
	set(yx[0], 1)
	cpy(yx[1], p[di])
	cpy(yx[2], s[0])
	set(yz[0], 0)
	set(yz[1], 1)
	set(yz[2], 1)

	/* y[0] is (even)P + (even)G
	 * y[1] is (even)P + (odd)G  if current d-bit is 0
	 * y[1] is (odd)P + (even)G  if current d-bit is 1
	 * y[2] is (odd)P + (odd)G
	 */

	vi = 0
	hi = 0

	/* and go for it! */
	for i := 31; i >= 0; i-- {
		vi = (vi << 8) | int(v[i])
		hi = (hi << 8) | int(h[i])
		di = (di << 8) | int(d[i])

		for j := 7; j >= 0; j-- {
			montPrep(t1[0], t2[0], yx[0], yz[0])
			montPrep(t1[1], t2[1], yx[1], yz[1])
			montPrep(t1[2], t2[2], yx[2], yz[2])

			k = ((vi ^ vi>>1) >> uint(j) & 1) + ((hi ^ hi>>1) >> uint(j) & 1)
			montDbl(yx[2], yz[2], t1[k], t2[k], yx[0], yz[0])

			k = (di >> uint(j) & 2) ^ ((di >> uint(j) & 1) << 1)
			montAdd(t1[1], t2[1], t1[k], t2[k], yx[1], yz[1], p[di>>uint(j)&1])

			montAdd(t1[2], t2[2], t1[0], t2[0], yx[2], yz[2], s[((vi^hi)>>uint(j)&2)>>1])
		}
	}

	k = (vi & 1) + (hi & 1)
	recip(t1[0], yz[k], 0)
	mul(t1[1], yx[k], t1[0])

	pack(t1[1], Y)
}

func IsCanonicalSignature(v []byte) bool {
	vCopy := make([]byte, 32)
	copy(vCopy, v)
	tmp := make([]byte, 32)
	divmod(tmp, vCopy, 32, order, 32)
	for i := 0; i < 32; i++ {
		if v[i] != vCopy[i] {
			return false
		}
	}
	return true
}

func IsCanonicalPublicKey(publicKey []byte) bool {
	if len(publicKey) != 32 {
		return false
	}
	var publicKeyUnpacked long10
	unpack(&publicKeyUnpacked, publicKey)
	publicKeyCopy := make([]byte, 32)
	pack(&publicKeyUnpacked, publicKeyCopy)
	for i := 0; i < 32; i++ {
		if publicKeyCopy[i] != publicKey[i] {
			return false
		}
	}
	return true
}

func numsize(x []byte, n int) int {
	for i := n - 1; i != -1; i-- {
		if x[i] != 0 {
			return i + 1
		}
	}
	return 0
}

func egcd32(x, y, a, b []byte) []byte {
	var an, qn int
	bn := 32

	for i := 0; i < 32; i++ {
		x[i] = 0
		y[i] = 0
	}

	x[0] = 1
	an = numsize(a, 32)
	if an == 0 {
		return y
	}

	tmp := make([]byte, 32)
	for {
		qn = bn - an + 1
		divmod(tmp, b, bn, a, an)
		bn = numsize(b, bn)
		if bn == 0 {
			return x
		}
		mula32(y, x, tmp, qn, -1)

		qn = an - bn + 1
		divmod(tmp, a, an, b, bn)
		an = numsize(a, an)
		if an == 0 {
			return y
		}
		mula32(x, y, tmp, qn, -1)
	}
}

func Curve(Z, k, P []byte) {
	core(Z, nil, k, P)
}
