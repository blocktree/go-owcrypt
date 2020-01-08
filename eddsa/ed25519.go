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
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"github.com/blocktree/go-owcrypt/eddsa/edwards25519"
)

var (
	ErrPrivateKeyIllegal = errors.New("Invalid private key data!")
)

func ED25519_genPub(prikey []byte) ([]byte, error) {
	if prikey == nil || len(prikey) != 32 {
		return nil, ErrPrivateKeyIllegal
	}

	var A edwards25519.ExtendedGroupElement
	var hBytes [32]byte
	copy(hBytes[:], prikey[:])
	edwards25519.GeScalarMultBase(&A, &hBytes)

	var publicKeyBytes [32]byte
	A.ToBytes(&publicKeyBytes)

	return publicKeyBytes[:], nil
}


func ED25519_sign(prikey, message []byte) ([]byte, error) {

	if prikey == nil || len(prikey) != 32 {
		return nil, ErrPrivateKeyIllegal
	}

	pubkey, err := ED25519_genPub(prikey)
	if err != nil {
		return nil, ErrPrivateKeyIllegal
	}
	var expandedSecretKey, digest1 [32]byte
	var messageDigest, hramDigest [64]byte

	copy(expandedSecretKey[:], prikey[:])
	expandedSecretKey[0] &= 248
	expandedSecretKey[31] &= 63
	expandedSecretKey[31] |= 64

	h := sha512.New()
	h.Write(digest1[32:])
	h.Write(message)
	h.Sum(messageDigest[:0])

	var messageDigestReduced [32]byte
	edwards25519.ScReduce(&messageDigestReduced, &messageDigest)
	var R edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&R, &messageDigestReduced)

	var encodedR [32]byte
	R.ToBytes(&encodedR)

	h.Reset()
	h.Write(encodedR[:])
	h.Write(pubkey)
	h.Write(message)
	h.Sum(hramDigest[:0])
	var hramDigestReduced [32]byte
	edwards25519.ScReduce(&hramDigestReduced, &hramDigest)

	var s [32]byte
	edwards25519.ScMulAdd(&s, &hramDigestReduced, &expandedSecretKey, &messageDigestReduced)

	signature := make([]byte, 64)
	copy(signature[:], encodedR[:])
	copy(signature[32:], s[:])

	return signature, nil
}

func ED25519_verify(pubkey, message, sig []byte) bool {
	publicKey := make([]byte, 32)

	if len(pubkey) != 32 {
		return false
	}

	if len(sig) != 64 || sig[63]&224 != 0 {
		return false
	}

	copy(publicKey, pubkey)
	var A edwards25519.ExtendedGroupElement
	var publicKeyBytes [32]byte
	copy(publicKeyBytes[:], publicKey)
	if !A.FromBytes(&publicKeyBytes) {
		return false
	}
	edwards25519.FeNeg(&A.X, &A.X)
	edwards25519.FeNeg(&A.T, &A.T)

	h := sha512.New()
	h.Write(sig[:32])
	h.Write(publicKey[:])
	h.Write(message)
	var digest [64]byte
	h.Sum(digest[:0])

	var hReduced [32]byte
	edwards25519.ScReduce(&hReduced, &digest)

	var R edwards25519.ProjectiveGroupElement
	var b [32]byte
	copy(b[:], sig[32:])
	edwards25519.GeDoubleScalarMultVartime(&R, &hReduced, &A, &b)

	var checkR [32]byte
	R.ToBytes(&checkR)
	return subtle.ConstantTimeCompare(sig[:32], checkR[:]) == 1
}

func feIsZero(f edwards25519.FieldElement) bool {
	zero := [32]byte{0}
	var s [32]byte

	edwards25519.FeToBytes(&s, &f)
	if cryptoVerify32(s, zero) != 0 {
		return false
	}
	return true
}

func feIsOne(f edwards25519.FieldElement) bool {
	one := [32]byte{0}
	var s [32]byte

	one[0] = 1
	edwards25519.FeToBytes(&s, &f)
	if cryptoVerify32(s, one) != 0 {
		return false
	}
	return true
}

func ScalarMultBaseAdd(point1, scalar, point2 *[32]byte) bool {
	var (
		P1    edwards25519.ExtendedGroupElement   //p3
		R     edwards25519.ProjectiveGroupElement //p2
		recip edwards25519.FieldElement
		x     edwards25519.FieldElement
		y     edwards25519.FieldElement
		one   [32]byte
	)
	P1.FromBytes(point1)
	one[0] = 1
	edwards25519.GeDoubleScalarMultVartime(&R, &one, &P1, scalar)

	edwards25519.FeInvert(&recip, &R.Z)
	edwards25519.FeMul(&x, &R.X, &recip)
	edwards25519.FeMul(&y, &R.Y, &recip)

	if feIsZero(x) && feIsOne(y) {
		return false
	}
	edwards25519.FeToBytes(point2, &y)
	point2[31] ^= (edwards25519.FeIsNegative(&x) << 7)

	return true
}