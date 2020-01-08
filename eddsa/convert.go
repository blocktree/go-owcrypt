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
	"errors"
	"github.com/blocktree/go-owcrypt/eddsa/edwards25519"
)

func arrayToFixedLength(in []byte) (out [32]byte) {
	copy(out[:], in[:32])
	return out
}

func montToEdy(u edwards25519.FieldElement) edwards25519.FieldElement {
	var (
		one edwards25519.FieldElement
		um1 edwards25519.FieldElement
		up1 edwards25519.FieldElement
		y   edwards25519.FieldElement
	)

	edwards25519.FeOne(&one)
	edwards25519.FeSub(&um1, &u, &one)
	edwards25519.FeAdd(&up1, &u, &one)
	edwards25519.FeInvert(&up1, &up1)
	edwards25519.FeMul(&y, &um1, &up1)

	return y
}

func montFromEdy(y edwards25519.FieldElement) edwards25519.FieldElement {
	var (
		one edwards25519.FieldElement
		um1 edwards25519.FieldElement
		up1 edwards25519.FieldElement
		u   edwards25519.FieldElement
	)

	edwards25519.FeOne(&one)
	edwards25519.FeSub(&um1, &one, &y)
	edwards25519.FeInvert(&um1, &um1)
	edwards25519.FeAdd(&up1, &y, &one)
	edwards25519.FeMul(&u, &um1, &up1)

	return u
}

func cryptoVerify32(x, y [32]byte) uint32 {
	differentbits := uint32(0)
	for index := 0; index < 32; index++ {
		differentbits |= uint32(x[index] ^ y[index])
	}
	return differentbits
}

func feIsReduced(s [32]byte) bool {
	var (
		strict [32]byte
		f      edwards25519.FieldElement
	)

	edwards25519.FeFromBytes(&f, &s)
	edwards25519.FeToBytes(&strict, &f)
	if cryptoVerify32(s, strict) != 0 {
		return true
	}
	return false
}


func ConvertXToEd(x25519PubkeyBytes [32]byte) ([32]byte, error) {
	var (
		ed25519PubkeyBytes [32]byte
		u                  edwards25519.FieldElement
	)

	if feIsReduced(x25519PubkeyBytes) {
		return [32]byte{}, errors.New("The x25519 public key inputed is reduced!")
	}
	edwards25519.FeFromBytes(&u, &x25519PubkeyBytes)
	y := montToEdy(u)
	edwards25519.FeToBytes(&ed25519PubkeyBytes, &y)
	return ed25519PubkeyBytes, nil
}

func ConvertEdToX(ed25519PubkeyBytes [32]byte) ([32]byte, error) {
	var (
		x25519PubkeyBytes [32]byte
		y                 edwards25519.FieldElement
	)

	edwards25519.FeFromBytes(&y, &ed25519PubkeyBytes)
	u := montFromEdy(y)
	edwards25519.FeToBytes(&x25519PubkeyBytes, &u)
	if feIsReduced(x25519PubkeyBytes) {
		return [32]byte{}, errors.New("The x25519 public key inputed is reduced!")
	}
	return x25519PubkeyBytes, nil
}