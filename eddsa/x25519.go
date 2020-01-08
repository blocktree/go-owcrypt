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

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"github.com/blocktree/go-owcrypt/eddsa/edwards25519"
)

func X25519_genPub(prikey []byte) ([]byte, error) {
	if prikey == nil || len(prikey) != 32 {
		return nil, ErrPrivateKeyIllegal
	}

	var A edwards25519.ExtendedGroupElement
	var hBytes [32]byte
	copy(hBytes[:], prikey[:])
	edwards25519.GeScalarMultBase(&A, &hBytes)

	var publicKeyBytes [32]byte
	A.ToBytes(&publicKeyBytes)

	publicKeyBytes, err := ConvertEdToX(publicKeyBytes)

	return publicKeyBytes[:], err
}

func load_3(in []byte) uint64 {
	tmp := make([]byte, 8)
	copy(tmp, in[:3])
	return binary.LittleEndian.Uint64(tmp)
}

func load_4(in []byte) uint64 {
	tmp := make([]byte, 8)
	copy(tmp, in[:4])
	return binary.LittleEndian.Uint64(tmp)
}

func x25519_sc_reduce(s []byte) [32]byte {

	var (
		s0 = int64(2097151 & load_3(s))
		s1 = int64(2097151 & (load_4(s[2:]) >> 5))
		s2 = int64(2097151 & (load_3(s[5:]) >> 2))
		s3 = int64(2097151 & (load_4(s[7:]) >> 7))
		s4 = int64(2097151 & (load_4(s[10:]) >> 4))
		s5 = int64(2097151 & (load_3(s[13:]) >> 1))
		s6 = int64(2097151 & (load_4(s[15:]) >> 6))
		s7 = int64(2097151 & (load_3(s[18:]) >> 3))
		s8 = int64(2097151 & load_3(s[21:]))
		s9 = int64(2097151 & (load_4(s[23:]) >> 5))
		s10 = int64(2097151 & (load_3(s[26:]) >> 2))
		s11 = int64(2097151 & (load_4(s[28:]) >> 7))
		s12 = int64(2097151 & (load_4(s[31:]) >> 4))
		s13 = int64(2097151 & (load_3(s[34:]) >> 1))
		s14 = int64(2097151 & (load_4(s[36:]) >> 6))
		s15 = int64(2097151 & (load_3(s[39:]) >> 3))
		s16 = int64(2097151 & load_3(s[42:]))
		s17 = int64(2097151 & (load_4(s[44:]) >> 5))
		s18 = int64(2097151 & (load_3(s[47:]) >> 2))
		s19 = int64(2097151 & (load_4(s[49:]) >> 7))
		s20 = int64(2097151 & (load_4(s[52:]) >> 4))
		s21 = int64(2097151 & (load_3(s[55:]) >> 1))
		s22 = int64(2097151 & (load_4(s[57:]) >> 6))
		s23 = int64((load_4(s[60:]) >> 3))
		carry0 = int64(0)
		carry1 = int64(0)
		carry2 = int64(0)
		carry3 = int64(0)
		carry4 = int64(0)
		carry5 = int64(0)
		carry6 = int64(0)
		carry7 = int64(0)
		carry8 = int64(0)
		carry9 = int64(0)
		carry10 = int64(0)
		carry11 = int64(0)
		carry12 = int64(0)
		carry13 = int64(0)
		carry14 = int64(0)
		carry15 = int64(0)
		carry16 = int64(0)
	)

	s11 += s23 * 666643
	s12 += s23 * 470296
	s13 += s23 * 654183
	s14 -= s23 * 997805
	s15 += s23 * 136657
	s16 -= s23 * 683901
	s23 = 0

	s10 += s22 * 666643
	s11 += s22 * 470296
	s12 += s22 * 654183
	s13 -= s22 * 997805
	s14 += s22 * 136657
	s15 -= s22 * 683901
	s22 = 0

	s9 += s21 * 666643
	s10 += s21 * 470296
	s11 += s21 * 654183
	s12 -= s21 * 997805
	s13 += s21 * 136657
	s14 -= s21 * 683901
	s21 = 0

	s8 += s20 * 666643
	s9 += s20 * 470296
	s10 += s20 * 654183
	s11 -= s20 * 997805
	s12 += s20 * 136657
	s13 -= s20 * 683901
	s20 = 0

	s7 += s19 * 666643
	s8 += s19 * 470296
	s9 += s19 * 654183
	s10 -= s19 * 997805
	s11 += s19 * 136657
	s12 -= s19 * 683901
	s19 = 0

	s6 += s18 * 666643
	s7 += s18 * 470296
	s8 += s18 * 654183
	s9 -= s18 * 997805
	s10 += s18 * 136657
	s11 -= s18 * 683901
	s18 = 0

	carry6 = (s6 + (1 << 20)) >> 21
	s7 += carry6
	s6 -= carry6 * (1 << 21)
	carry8 = (s8 + (1 << 20)) >> 21
	s9 += carry8
	s8 -= carry8 * (1 << 21)
	carry10 = (s10 + (1 << 20)) >> 21
	s11 += carry10
	s10 -= carry10 * (1 << 21)
	carry12 = (s12 + (1 << 20)) >> 21
	s13 += carry12
	s12 -= carry12 * (1 << 21)
	carry14 = (s14 + (1 << 20)) >> 21
	s15 += carry14
	s14 -= carry14 * (1 << 21)
	carry16 = (s16 + (1 << 20)) >> 21
	s17 += carry16
	s16 -= carry16 * (1 << 21)

	carry7 = (s7 + (1 << 20)) >> 21
	s8 += carry7
	s7 -= carry7 * (1 << 21)
	carry9 = (s9 + (1 << 20)) >> 21
	s10 += carry9
	s9 -= carry9 * (1 << 21)
	carry11 = (s11 + (1 << 20)) >> 21
	s12 += carry11
	s11 -= carry11 * (1 << 21)
	carry13 = (s13 + (1 << 20)) >> 21
	s14 += carry13
	s13 -= carry13 * (1 << 21)
	carry15 = (s15 + (1 << 20)) >> 21
	s16 += carry15
	s15 -= carry15 * (1 << 21)

	s5 += s17 * 666643
	s6 += s17 * 470296
	s7 += s17 * 654183
	s8 -= s17 * 997805
	s9 += s17 * 136657
	s10 -= s17 * 683901
	s17 = 0

	s4 += s16 * 666643
	s5 += s16 * 470296
	s6 += s16 * 654183
	s7 -= s16 * 997805
	s8 += s16 * 136657
	s9 -= s16 * 683901
	s16 = 0

	s3 += s15 * 666643
	s4 += s15 * 470296
	s5 += s15 * 654183
	s6 -= s15 * 997805
	s7 += s15 * 136657
	s8 -= s15 * 683901
	s15 = 0

	s2 += s14 * 666643
	s3 += s14 * 470296
	s4 += s14 * 654183
	s5 -= s14 * 997805
	s6 += s14 * 136657
	s7 -= s14 * 683901
	s14 = 0

	s1 += s13 * 666643
	s2 += s13 * 470296
	s3 += s13 * 654183
	s4 -= s13 * 997805
	s5 += s13 * 136657
	s6 -= s13 * 683901
	s13 = 0

	s0 += s12 * 666643
	s1 += s12 * 470296
	s2 += s12 * 654183
	s3 -= s12 * 997805
	s4 += s12 * 136657
	s5 -= s12 * 683901
	s12 = 0

	carry0 = (s0 + (1 << 20)) >> 21
	s1 += carry0
	s0 -= carry0 * (1 << 21)
	carry2 = (s2 + (1 << 20)) >> 21
	s3 += carry2
	s2 -= carry2 * (1 << 21)
	carry4 = (s4 + (1 << 20)) >> 21
	s5 += carry4
	s4 -= carry4 * (1 << 21)
	carry6 = (s6 + (1 << 20)) >> 21
	s7 += carry6
	s6 -= carry6 * (1 << 21)
	carry8 = (s8 + (1 << 20)) >> 21
	s9 += carry8
	s8 -= carry8 * (1 << 21)
	carry10 = (s10 + (1 << 20)) >> 21
	s11 += carry10
	s10 -= carry10 * (1 << 21)

	carry1 = (s1 + (1 << 20)) >> 21
	s2 += carry1
	s1 -= carry1 * (1 << 21)
	carry3 = (s3 + (1 << 20)) >> 21
	s4 += carry3
	s3 -= carry3 * (1 << 21)
	carry5 = (s5 + (1 << 20)) >> 21
	s6 += carry5
	s5 -= carry5 * (1 << 21)
	carry7 = (s7 + (1 << 20)) >> 21
	s8 += carry7
	s7 -= carry7 * (1 << 21)
	carry9 = (s9 + (1 << 20)) >> 21
	s10 += carry9
	s9 -= carry9 * (1 << 21)
	carry11 = (s11 + (1 << 20)) >> 21
	s12 += carry11
	s11 -= carry11 * (1 << 21)

	s0 += s12 * 666643
	s1 += s12 * 470296
	s2 += s12 * 654183
	s3 -= s12 * 997805
	s4 += s12 * 136657
	s5 -= s12 * 683901
	s12 = 0

	carry0 = s0 >> 21
	s1 += carry0
	s0 -= carry0 * (1 << 21)
	carry1 = s1 >> 21
	s2 += carry1
	s1 -= carry1 * (1 << 21)
	carry2 = s2 >> 21
	s3 += carry2
	s2 -= carry2 * (1 << 21)
	carry3 = s3 >> 21
	s4 += carry3
	s3 -= carry3 * (1 << 21)
	carry4 = s4 >> 21
	s5 += carry4
	s4 -= carry4 * (1 << 21)
	carry5 = s5 >> 21
	s6 += carry5
	s5 -= carry5 * (1 << 21)
	carry6 = s6 >> 21
	s7 += carry6
	s6 -= carry6 * (1 << 21)
	carry7 = s7 >> 21
	s8 += carry7
	s7 -= carry7 * (1 << 21)
	carry8 = s8 >> 21
	s9 += carry8
	s8 -= carry8 * (1 << 21)
	carry9 = s9 >> 21
	s10 += carry9
	s9 -= carry9 * (1 << 21)
	carry10 = s10 >> 21
	s11 += carry10
	s10 -= carry10 * (1 << 21)
	carry11 = s11 >> 21
	s12 += carry11
	s11 -= carry11 * (1 << 21)

	s0 += s12 * 666643
	s1 += s12 * 470296
	s2 += s12 * 654183
	s3 -= s12 * 997805
	s4 += s12 * 136657
	s5 -= s12 * 683901
	s12 = 0

	carry0 = s0 >> 21
	s1 += carry0
	s0 -= carry0 * (1 << 21)
	carry1 = s1 >> 21
	s2 += carry1
	s1 -= carry1 * (1 << 21)
	carry2 = s2 >> 21
	s3 += carry2
	s2 -= carry2 * (1 << 21)
	carry3 = s3 >> 21
	s4 += carry3
	s3 -= carry3 * (1 << 21)
	carry4 = s4 >> 21
	s5 += carry4
	s4 -= carry4 * (1 << 21)
	carry5 = s5 >> 21
	s6 += carry5
	s5 -= carry5 * (1 << 21)
	carry6 = s6 >> 21
	s7 += carry6
	s6 -= carry6 * (1 << 21)
	carry7 = s7 >> 21
	s8 += carry7
	s7 -= carry7 * (1 << 21)
	carry8 = s8 >> 21
	s9 += carry8
	s8 -= carry8 * (1 << 21)
	carry9 = s9 >> 21
	s10 += carry9
	s9 -= carry9 * (1 << 21)
	carry10 = s10 >> 21
	s11 += carry10
	s10 -= carry10 * (1 << 21)

	var ret [32]byte

	ret[0] = byte(s0 >> 0)
	ret[1] = byte(s0 >> 8)
	ret[2] = byte((s0 >> 16) | (s1 << 5))
	ret[3] = byte(s1 >> 3)
	ret[4] = byte(s1 >> 11)
	ret[5] = byte((s1 >> 19) | (s2 << 2))
	ret[6] = byte(s2 >> 6)
	ret[7] = byte((s2 >> 14) | (s3 << 7))
	ret[8] = byte(s3 >> 1)
	ret[9] = byte(s3 >> 9)
	ret[10] = byte((s3 >> 17) | (s4 << 4))
	ret[11] = byte(s4 >> 4)
	ret[12] = byte(s4 >> 12)
	ret[13] = byte((s4 >> 20) | (s5 << 1))
	ret[14] = byte(s5 >> 7)
	ret[15] = byte((s5 >> 15) | (s6 << 6))
	ret[16] = byte(s6 >> 2)
	ret[17] = byte(s6 >> 10)
	ret[18] = byte((s6 >> 18) | (s7 << 3))
	ret[19] = byte(s7 >> 5)
	ret[20] = byte(s7 >> 13)
	ret[21] = byte(s8 >> 0)
	ret[22] = byte(s8 >> 8)
	ret[23] = byte((s8 >> 16) | (s9 << 5))
	ret[24] = byte(s9 >> 3)
	ret[25] = byte(s9 >> 11)
	ret[26] = byte((s9 >> 19) | (s10 << 2))
	ret[27] = byte(s10 >> 6)
	ret[28] = byte((s10 >> 14) | (s11 << 7))
	ret[29] = byte(s11 >> 1)
	ret[30] = byte(s11 >> 9)
	ret[31] = byte(s11 >> 17)

	return ret
}

func sign_modify(sm, message, prikey, ed_pubkey, random []byte) []byte {
	copy(sm[64:], message)
	copy(sm[32:], prikey)

	sm[0] = 0xFE
	for i := 1; i < 32; i ++ {
		sm[i] = 0xFF
	}

	copy(sm[len(message) + 64 :], random)
	h := sha512.New()
	h.Write(sm)
	digest := h.Sum(nil)

	copy(sm[32:], ed_pubkey)

	nonce := x25519_sc_reduce(digest)

	var R edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&R, &nonce)
	var Rbytes [32]byte
	R.ToBytes(&Rbytes)
	copy(sm, Rbytes[:])

	h.Reset()
	h.Write(sm[:len(message) + 64])
	digest = h.Sum(nil)

	hram := x25519_sc_reduce(digest)
	var Sbytes [32]byte
	var pribytes [32]byte
	copy(pribytes[:], prikey)
	edwards25519.ScMulAdd(&Sbytes, &hram, &pribytes, &nonce)

	copy(sm[32:], Sbytes[:])

	return sm[:64]
}

func X25519_sign(prikey, message []byte) ([]byte, error) {
	if prikey == nil || len(prikey) != 32 {
		return nil, ErrPrivateKeyIllegal
	}

	ed_pubkey, err := ED25519_genPub(prikey)
	if err != nil {
		return nil, err
	}

	signbit := ed_pubkey[31] & 0x80
	sm := make([]byte, len(message) + 128)
	random := make([]byte, 64)
	rand.Read(random)

	signature := sign_modify(sm, message, prikey, ed_pubkey, random)

	signature[63] &= 0x7F
	signature[63] |= signbit

	return signature, nil
}

var d = edwards25519.FieldElement{
	-10913610, 13857413, -15372611, 6949391, 114729, -8787816, -6275908, -3247719, -18696448, -12055116,
}

func fePow22523(out, z *edwards25519.FieldElement) {
	var t0, t1, t2 edwards25519.FieldElement
	var i int

	edwards25519.FeSquare(&t0, z)
	for i = 1; i < 1; i++ {
		edwards25519.FeSquare(&t0, &t0)
	}
	edwards25519.FeSquare(&t1, &t0)
	for i = 1; i < 2; i++ {
		edwards25519.FeSquare(&t1, &t1)
	}
	edwards25519.FeMul(&t1, z, &t1)
	edwards25519.FeMul(&t0, &t0, &t1)
	edwards25519.FeSquare(&t0, &t0)
	for i = 1; i < 1; i++ {
		edwards25519.FeSquare(&t0, &t0)
	}
	edwards25519.FeMul(&t0, &t1, &t0)
	edwards25519.FeSquare(&t1, &t0)
	for i = 1; i < 5; i++ {
		edwards25519.FeSquare(&t1, &t1)
	}
	edwards25519.FeMul(&t0, &t1, &t0)
	edwards25519.FeSquare(&t1, &t0)
	for i = 1; i < 10; i++ {
		edwards25519.FeSquare(&t1, &t1)
	}
	edwards25519.FeMul(&t1, &t1, &t0)
	edwards25519.FeSquare(&t2, &t1)
	for i = 1; i < 20; i++ {
		edwards25519.FeSquare(&t2, &t2)
	}
	edwards25519.FeMul(&t1, &t2, &t1)
	edwards25519.FeSquare(&t1, &t1)
	for i = 1; i < 10; i++ {
		edwards25519.FeSquare(&t1, &t1)
	}
	edwards25519.FeMul(&t0, &t1, &t0)
	edwards25519.FeSquare(&t1, &t0)
	for i = 1; i < 50; i++ {
		edwards25519.FeSquare(&t1, &t1)
	}
	edwards25519.FeMul(&t1, &t1, &t0)
	edwards25519.FeSquare(&t2, &t1)
	for i = 1; i < 100; i++ {
		edwards25519.FeSquare(&t2, &t2)
	}
	edwards25519.FeMul(&t1, &t2, &t1)
	edwards25519.FeSquare(&t1, &t1)
	for i = 1; i < 50; i++ {
		edwards25519.FeSquare(&t1, &t1)
	}
	edwards25519.FeMul(&t0, &t1, &t0)
	edwards25519.FeSquare(&t0, &t0)
	for i = 1; i < 2; i++ {
		edwards25519.FeSquare(&t0, &t0)
	}
	edwards25519.FeMul(out, &t0, z)
}

func geFromBytesNegateVartime(h *edwards25519.ExtendedGroupElement, s *[32]byte) bool{
	var u, v, v3, vxx, check edwards25519.FieldElement

	edwards25519.FeFromBytes(&h.Y, s)
	edwards25519.FeOne(&h.Z)
	edwards25519.FeSquare(&u, &h.Y)
	edwards25519.FeMul(&v, &u, &d)
	edwards25519.FeSub(&u, &u, &h.Z)
	edwards25519.FeAdd(&v, &v, &h.Z)

	edwards25519.FeSquare(&v3, &v)
	edwards25519.FeMul(&v3, &v3, &v)
	edwards25519.FeSquare(&h.X, &v3)
	edwards25519.FeMul(&h.X, &h.X, &v)
	edwards25519.FeMul(&h.X, &h.X, &u)

	fePow22523(&h.X, &h.X)
	edwards25519.FeMul(&h.X, &h.X, &v3)
	edwards25519.FeMul(&h.X, &h.X, &u)

	edwards25519.FeSquare(&vxx, &h.X)
	edwards25519.FeMul(&vxx, &vxx, &v)
	edwards25519.FeSub(&check, &vxx, &u)
	if edwards25519.FeIsNonZero(&check) != 0 {
		edwards25519.FeAdd(&check, &vxx, &u)
		if edwards25519.FeIsNonZero(&check) != 0 {
			return false
		}
		edwards25519.FeMul(&h.X, &h.X, &edwards25519.SqrtM1)
	}

	if edwards25519.FeIsNegative(&h.X) == (s[31] >> 7) {
		edwards25519.FeNeg(&h.X, &h.X)
	}

	edwards25519.FeMul(&h.T, &h.X, &h.Y)

	return true
}

func cryptoVerify32Ref(x, y *[32]byte) int {
	var differentbits int
	for i := 0; i < 32; i ++ {
		differentbits |= int(x[i] ^ y[i])
	}

	return (1 & ((differentbits - 1) >> 8)) - 1
}

func verify_modify(message, sm, pubkey []byte) bool {
	var pkcopy, rcopy, scopy, rcheck [32]byte
	var A edwards25519.ExtendedGroupElement
	var R edwards25519.ProjectiveGroupElement

	if sm[63] & 224 != 0 {
		return false
	}
	var pk [32]byte
	copy(pk[:], pubkey)

	if !geFromBytesNegateVartime(&A, &pk) {
		return false
	}

	copy(pkcopy[:], pk[:])
	copy(rcopy[:], sm[:32])
	copy(scopy[:], sm[32:64])
	copy(message, sm)
	copy(message[32:], pkcopy[:])

	h := sha512.New()
	h.Write(message[:len(sm)])
	digest := h.Sum(nil)

	hash := x25519_sc_reduce(digest)
	edwards25519.GeDoubleScalarMultVartime(&R, &hash, &A, &scopy)
	R.ToBytes(&rcheck)

	if cryptoVerify32Ref(&rcheck, &rcopy) == 0 {
		return true
	}

	return false
}

func X25519_verify(pubkey, message,signature []byte) bool {

	if signature == nil || len(signature) != 64 || pubkey == nil || len(pubkey) != 32 || message == nil || len(message) == 0 {
		return false
	}

	verifybuf := make([]byte, len(message) + 64)
	verifbuf2 := make([]byte, len(message) + 64)

	var u edwards25519.FieldElement
	var x25519_pubkey, ed_pubkey [32]byte
	copy(x25519_pubkey[:], pubkey)
	edwards25519.FeFromBytes(&u, &x25519_pubkey)
	y := montToEdy(u)
	edwards25519.FeToBytes(&ed_pubkey, &y)

	ed_pubkey[31] &= 0x7F
	ed_pubkey[31] |= signature[63] & 0x80

	copy(verifybuf, signature)
	verifybuf[63] &= 0x7F

	copy(verifybuf[64:], message)

	return verify_modify(verifbuf2, verifybuf, ed_pubkey[:])
}
