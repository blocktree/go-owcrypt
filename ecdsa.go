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
	"crypto/rand"
	"errors"
	"math/big"
	"sync"
)

type curveParam struct {
	elliptic.CurveParams
}

var (
	ErrPrivateKeyIllegal = errors.New("Invalid private key data!")
	ErrUnknownCurve      = errors.New("Unknown curve type!")
	ErrMessageIllegal    = errors.New("Invalid message data!")
	ErrPublicKeyIllegal  = errors.New("Invalid public key data!")
)

var (
	initonce sync.Once
	three    = new(big.Int).SetUint64(3)
)

func genPublicKey(privateKey []byte, name string) ([]byte, error) {
	if privateKey == nil || len(privateKey) != 32 {
		return nil, ErrPrivateKeyIllegal
	}

	var curve *curveParam
	var k1curve *secp256k1Curve
	var sm2Curve *sm2_stdCurve
	privateKeyBig := new(big.Int).SetBytes(privateKey)
	priv := new(ecdsa.PrivateKey)

	if privateKeyBig.Cmp(big.NewInt(0)) == 0 {
		return nil, ErrPrivateKeyIllegal
	}
	priv.D = privateKeyBig
	if name == "secp256k1" {
		k1curve = secp256k1

		if privateKeyBig.Cmp(k1curve.Params().N) >= 0 {
			return nil, ErrPrivateKeyIllegal
		}

		priv.PublicKey.Curve = k1curve

		priv.PublicKey.X, priv.PublicKey.Y = k1curve.ScalarBaseMult(privateKey)

	} else if name == "sm2_std" {

		sm2Curve = sm2_std

		if privateKeyBig.Cmp(sm2Curve.Params().N) >= 0 {
			return nil, ErrPrivateKeyIllegal
		}

		priv.PublicKey.Curve = sm2Curve

		priv.PublicKey.X, priv.PublicKey.Y = sm2Curve.ScalarBaseMult(privateKey)

	} else { // ecdsa
		if name == "secp256r1" {
			curve = secp256r1
		} else {
			return nil, ErrUnknownCurve
		}

		if privateKeyBig.Cmp(curve.Params().N) >= 0 {
			return nil, ErrPrivateKeyIllegal
		}

		priv.PublicKey.Curve = curve
		priv.D = privateKeyBig
		priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(privateKey)

	}

	x := priv.PublicKey.X.Bytes()

	for len(x) < 32 {
		x = append([]byte{0x00}, x...)
	}

	y := priv.PublicKey.Y.Bytes()

	for len(y) < 32 {
		y = append([]byte{0x00}, y...)
	}
	return append(x, y...), nil
}

func sign(privateKey, ID, hash []byte, name string) ([]byte, byte, error) {

	if privateKey == nil || len(privateKey) != 32 {
		return nil, 0, ErrPrivateKeyIllegal
	}

	if hash == nil || len(hash) != 32 {
		return nil, 0, ErrMessageIllegal
	}

	var curve *curveParam
	var k1curve *secp256k1Curve
	var sm2Curve *sm2_stdCurve
	privateKeyBig := new(big.Int).SetBytes(privateKey)
	priv := new(ecdsa.PrivateKey)

	if privateKeyBig.Cmp(big.NewInt(0)) == 0 {
		return nil, 0, ErrPrivateKeyIllegal
	}
	priv.D = privateKeyBig
	if name == "secp256k1" {
		k1curve = secp256k1

		if privateKeyBig.Cmp(k1curve.Params().N) >= 0 {
			return nil, 0, ErrPrivateKeyIllegal
		}

		priv.PublicKey.Curve = k1curve

		priv.PublicKey.X, priv.PublicKey.Y = k1curve.ScalarBaseMult(privateKey)

	} else if name == "secp256r1" {
		curve = secp256r1
		if privateKeyBig.Cmp(curve.Params().N) >= 0 {
			return nil, 0, ErrPrivateKeyIllegal
		}

		priv.PublicKey.Curve = curve
		priv.D = privateKeyBig
		priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(privateKey)
	} else if name == "sm2_std" {
		sm2Curve = sm2_std

		if privateKeyBig.Cmp(sm2Curve.Params().N) >= 0 {
			return nil, 0, ErrPrivateKeyIllegal
		}

		priv.PublicKey.Curve = sm2Curve
		priv.D = privateKeyBig
		priv.PublicKey.X, priv.PublicKey.Y = sm2Curve.ScalarBaseMult(privateKey)

		signature := make([]byte, 64)

		r, s, v, err := sm2_std_sign(priv, hash, ID)
		if err != nil {
			return nil, 0, err
		}

		rBytes := r.Bytes()
		sBytes := s.Bytes()

		copy(signature[32-len(rBytes):32], rBytes)
		copy(signature[64-len(sBytes):64], sBytes)

		return signature, v, nil
	} else {
		return nil, 0, ErrUnknownCurve
	}

	signature := make([]byte, 64)

	r, s, v, err := signecdsa(rand.Reader, priv, hash)
	if err != nil {
		return nil, 0, err
	}

	rBytes := r.Bytes()
	sBytes := s.Bytes()

	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):64], sBytes)

	return signature, v, nil
}

func verify(publicKey, ID, hash, signature []byte, name string) bool {
	if publicKey == nil || len(publicKey) != 64 {
		return false
	}
	if signature == nil || len(signature) != 64 {
		return false
	}
	if hash == nil || len(hash) != 32 {
		return false
	}

	pubk := new(ecdsa.PublicKey)

	if name == "secp256k1" {
		pubk.Curve = secp256k1
	} else {
		if name == "secp256r1" {
			pubk.Curve = secp256r1
		} else if name == "sm2_std" {
			pubk.Curve = sm2_std
			pubk.X = new(big.Int).SetBytes(publicKey[:32])
			pubk.Y = new(big.Int).SetBytes(publicKey[32:])

			r := new(big.Int).SetBytes(signature[:32])
			s := new(big.Int).SetBytes(signature[32:])

			return sm2_std_verify(pubk, hash, ID, r, s)
		} else {
			return false
		}
	}
	pubk.X = new(big.Int).SetBytes(publicKey[:32])
	pubk.Y = new(big.Int).SetBytes(publicKey[32:])

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	return verifyesdsa(pubk, hash, r, s)
}

func encrypt(pubkey []byte, plain []byte, name string) ([]byte, error) {
	if name != "sm2_std" {
		return nil, ErrUnknownCurve
	}

	if pubkey == nil || len(pubkey) != 64 {
		return nil, ErrPublicKeyIllegal
	}

	if plain == nil || len(plain) == 0 {
		return nil, ErrMessageIllegal
	}

	pubk := new(ecdsa.PublicKey)
	pubk.Curve = sm2_std
	pubk.X = new(big.Int).SetBytes(pubkey[:32])
	pubk.Y = new(big.Int).SetBytes(pubkey[32:])

	return sm2_std_encrypt(pubk, plain)
}

func decrypt(prikey, cipher []byte, name string) ([]byte, error) {

	if name != "sm2_std" {
		return nil, ErrUnknownCurve
	}

	if prikey == nil || len(prikey) != 32 {
		return nil, ErrPrivateKeyIllegal
	}

	if cipher == nil || len(cipher) == 0 {
		return nil, ErrMessageIllegal
	}

	var sm2Curve *sm2_stdCurve
	privateKeyBig := new(big.Int).SetBytes(prikey)
	priv := new(ecdsa.PrivateKey)

	priv.D = privateKeyBig
	sm2Curve = sm2_std

	if privateKeyBig.Cmp(sm2Curve.Params().N) >= 0 {
		return nil, ErrPrivateKeyIllegal
	}

	priv.PublicKey.Curve = sm2Curve
	priv.D = privateKeyBig
	priv.PublicKey.X, priv.PublicKey.Y = sm2Curve.ScalarBaseMult(prikey)

	return sm2_std_decrypt(priv, cipher)
}

func MulBaseG_Add(pointin, scalar []byte, name string) (point []byte, isinfinity bool) {

	var curve *curveParam
	var k1curve *secp256k1Curve
	var sm2Curve *sm2_stdCurve
	privateKeyBig := new(big.Int).SetBytes(scalar)
	priv := new(ecdsa.PrivateKey)
	p := new(ecdsa.PublicKey)
	p.X = new(big.Int).SetBytes(pointin[:32])
	p.Y = new(big.Int).SetBytes(pointin[32:])

	priv.D = privateKeyBig
	if name == "secp256k1" {
		k1curve = secp256k1

		priv.PublicKey.Curve = k1curve
		p.Curve = k1curve

		priv.PublicKey.X, priv.PublicKey.Y = k1curve.ScalarBaseMult(scalar)

		priv.PublicKey.X, priv.PublicKey.Y = k1curve.Add(priv.PublicKey.X, priv.PublicKey.Y, p.X, p.Y)

	} else if name == "sm2_std" {

		sm2Curve = sm2_std

		priv.PublicKey.Curve = sm2Curve
		p.Curve = sm2Curve

		priv.PublicKey.X, priv.PublicKey.Y = sm2Curve.ScalarBaseMult(scalar)

		priv.PublicKey.X, priv.PublicKey.Y = sm2Curve.Add(priv.PublicKey.X, priv.PublicKey.Y, p.X, p.Y)

	} else { // ecdsa
		if name == "secp256r1" {
			curve = secp256r1
		} else {
			return nil, false
		}

		priv.PublicKey.Curve = curve
		p.Curve = curve
		priv.D = privateKeyBig
		priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(scalar)
		priv.PublicKey.X, priv.PublicKey.Y = curve.Add(priv.PublicKey.X, priv.PublicKey.Y, p.X, p.Y)

	}

	if priv.PublicKey.X.Cmp(big.NewInt(0)) == 0 && priv.PublicKey.Y.Cmp(big.NewInt(0)) == 0 {
		return nil, true
	}

	x := priv.PublicKey.X.Bytes()

	for len(x) < 32 {
		x = append([]byte{0x00}, x...)
	}

	y := priv.PublicKey.Y.Bytes()

	for len(y) < 32 {
		y = append([]byte{0x00}, y...)
	}
	return append(x, y...), false
}

func Add(point1, point2 []byte, name string) (point []byte, isinfinity bool) {
	var curve *curveParam
	var k1curve *secp256k1Curve
	var sm2Curve *sm2_stdCurve

	var x_big, y_big *big.Int

	p1 := new(ecdsa.PublicKey)
	p1.X = new(big.Int).SetBytes(point1[:32])
	p1.Y = new(big.Int).SetBytes(point1[32:])

	p2 := new(ecdsa.PublicKey)
	p2.X = new(big.Int).SetBytes(point2[:32])
	p2.Y = new(big.Int).SetBytes(point2[32:])

	if name == "secp256k1" {
		k1curve = secp256k1
		x_big, y_big = k1curve.Add(p1.X, p1.Y, p2.X, p2.Y)
	} else if name == "sm2_std" {
		sm2Curve = sm2_std
		x_big, y_big = sm2Curve.Add(p1.X, p1.Y, p2.X, p2.Y)
	} else if name == "secp256r1"{ // ecdsa
		curve = secp256r1
		x_big, y_big = curve.Add(p1.X, p1.Y, p2.X, p2.Y)
	} else {
		return nil, false
	}

	if x_big.Cmp(big.NewInt(0)) == 0 && x_big.Cmp(big.NewInt(0)) == 0 {
		return nil, true
	}

	x := x_big.Bytes()

	for len(x) < 32 {
		x = append([]byte{0x00}, x...)
	}

	y := y_big.Bytes()

	for len(y) < 32 {
		y = append([]byte{0x00}, y...)
	}
	return append(x, y...), false
}

func Mul(pointin, scalar []byte, name string) (point []byte, isinfinity bool) {

	var curve *curveParam
	var k1curve *secp256k1Curve
	var sm2Curve *sm2_stdCurve
	privateKeyBig := new(big.Int).SetBytes(scalar)
	priv := new(ecdsa.PrivateKey)
	p := new(ecdsa.PublicKey)
	p.X = new(big.Int).SetBytes(pointin[:32])
	p.Y = new(big.Int).SetBytes(pointin[32:])

	priv.D = privateKeyBig
	if name == "secp256k1" {
		k1curve = secp256k1
		priv.PublicKey.Curve = k1curve
		p.Curve = k1curve
		priv.PublicKey.X, priv.PublicKey.Y = k1curve.ScalarMult(p.X, p.Y, scalar)
	} else if name == "sm2_std" {
		sm2Curve = sm2_std
		priv.PublicKey.Curve = sm2Curve
		p.Curve = sm2Curve
		priv.PublicKey.X, priv.PublicKey.Y = sm2Curve.ScalarMult(p.X, p.Y, scalar)
	} else if name == "secp256r1"{ // ecdsa
		curve = secp256r1
		priv.PublicKey.Curve = curve
		p.Curve = curve
		priv.D = privateKeyBig
		priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarMult(p.X, p.Y, scalar)
	} else {
		return nil, false
	}

	if priv.PublicKey.X.Cmp(big.NewInt(0)) == 0 && priv.PublicKey.Y.Cmp(big.NewInt(0)) == 0 {
		return nil, true
	}

	x := priv.PublicKey.X.Bytes()

	for len(x) < 32 {
		x = append([]byte{0x00}, x...)
	}

	y := priv.PublicKey.Y.Bytes()

	for len(y) < 32 {
		y = append([]byte{0x00}, y...)
	}
	return append(x, y...), false
}