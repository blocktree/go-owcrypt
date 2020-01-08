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
package sm3

import (
	"encoding/binary"
	"hash"
)

type SM3 struct {
	digest      [8]uint32
	length      uint64
	unhandleMsg []byte
}

func (sm3 *SM3) ff0(x, y, z uint32) uint32 { return x ^ y ^ z }

func (sm3 *SM3) ff1(x, y, z uint32) uint32 { return (x & y) | (x & z) | (y & z) }

func (sm3 *SM3) gg0(x, y, z uint32) uint32 { return x ^ y ^ z }

func (sm3 *SM3) gg1(x, y, z uint32) uint32 { return (x & y) | (^x & z) }

func (sm3 *SM3) p0(x uint32) uint32 { return x ^ sm3.leftRotate(x, 9) ^ sm3.leftRotate(x, 17) }

func (sm3 *SM3) p1(x uint32) uint32 { return x ^ sm3.leftRotate(x, 15) ^ sm3.leftRotate(x, 23) }

func (sm3 *SM3) leftRotate(x uint32, i uint32) uint32 { return (x<<(i%32) | x>>(32-i%32)) }

func (sm3 *SM3) pad() []byte {
	msg := sm3.unhandleMsg
	msg = append(msg, 0x80)
	blockSize := 64
	for len(msg)%blockSize != 56 {
		msg = append(msg, 0x00)
	}

	msg = append(msg, uint8(sm3.length>>56&0xff))
	msg = append(msg, uint8(sm3.length>>48&0xff))
	msg = append(msg, uint8(sm3.length>>40&0xff))
	msg = append(msg, uint8(sm3.length>>32&0xff))
	msg = append(msg, uint8(sm3.length>>24&0xff))
	msg = append(msg, uint8(sm3.length>>16&0xff))
	msg = append(msg, uint8(sm3.length>>8&0xff))
	msg = append(msg, uint8(sm3.length>>0&0xff))

	if len(msg)%64 != 0 {
		panic("------SM3 Pad: error msgLen =")
	}
	return msg
}

func (sm3 *SM3) update(msg []byte, nblocks int) {
	var w [68]uint32
	var w1 [64]uint32

	a, b, c, d, e, f, g, h := sm3.digest[0], sm3.digest[1], sm3.digest[2], sm3.digest[3], sm3.digest[4], sm3.digest[5], sm3.digest[6], sm3.digest[7]
	for len(msg) >= 64 {
		for i := 0; i < 16; i++ {
			w[i] = binary.BigEndian.Uint32(msg[4*i : 4*(i+1)])
		}
		for i := 16; i < 68; i++ {
			w[i] = sm3.p1(w[i-16]^w[i-9]^sm3.leftRotate(w[i-3], 15)) ^ sm3.leftRotate(w[i-13], 7) ^ w[i-6]
		}
		for i := 0; i < 64; i++ {
			w1[i] = w[i] ^ w[i+4]
		}
		A, B, C, D, E, F, G, H := a, b, c, d, e, f, g, h
		for i := 0; i < 16; i++ {
			SS1 := sm3.leftRotate(sm3.leftRotate(A, 12)+E+sm3.leftRotate(0x79cc4519, uint32(i)), 7)
			SS2 := SS1 ^ sm3.leftRotate(A, 12)
			TT1 := sm3.ff0(A, B, C) + D + SS2 + w1[i]
			TT2 := sm3.gg0(E, F, G) + H + SS1 + w[i]
			D = C
			C = sm3.leftRotate(B, 9)
			B = A
			A = TT1
			H = G
			G = sm3.leftRotate(F, 19)
			F = E
			E = sm3.p0(TT2)
		}
		for i := 16; i < 64; i++ {
			SS1 := sm3.leftRotate(sm3.leftRotate(A, 12)+E+sm3.leftRotate(0x7a879d8a, uint32(i)), 7)
			SS2 := SS1 ^ sm3.leftRotate(A, 12)
			TT1 := sm3.ff1(A, B, C) + D + SS2 + w1[i]
			TT2 := sm3.gg1(E, F, G) + H + SS1 + w[i]
			D = C
			C = sm3.leftRotate(B, 9)
			B = A
			A = TT1
			H = G
			G = sm3.leftRotate(F, 19)
			F = E
			E = sm3.p0(TT2)
		}
		a ^= A
		b ^= B
		c ^= C
		d ^= D
		e ^= E
		f ^= F
		g ^= G
		h ^= H
		msg = msg[64:]
	}
	sm3.digest[0], sm3.digest[1], sm3.digest[2], sm3.digest[3], sm3.digest[4], sm3.digest[5], sm3.digest[6], sm3.digest[7] = a, b, c, d, e, f, g, h
}

func New() hash.Hash {
	var sm3 SM3

	sm3.Reset()
	return &sm3
}

func (sm3 *SM3) BlockSize() int { return 64 }

func (sm3 *SM3) Size() int { return 32 }

func (sm3 *SM3) Reset() {
	// Reset digest
	sm3.digest[0] = 0x7380166f
	sm3.digest[1] = 0x4914b2b9
	sm3.digest[2] = 0x172442d7
	sm3.digest[3] = 0xda8a0600
	sm3.digest[4] = 0xa96f30bc
	sm3.digest[5] = 0x163138aa
	sm3.digest[6] = 0xe38dee4d
	sm3.digest[7] = 0xb0fb0e4e

	sm3.length = 0
	sm3.unhandleMsg = []byte{}
}

func (sm3 *SM3) Write(p []byte) (int, error) {
	toWrite := len(p)
	sm3.length += uint64(len(p) * 8)

	msg := append(sm3.unhandleMsg, p...)
	nblocks := len(msg) / sm3.BlockSize()
	sm3.update(msg, nblocks)

	sm3.unhandleMsg = msg[nblocks*sm3.BlockSize():]

	return toWrite, nil
}

func (sm3 *SM3) Sum(in []byte) []byte {
	sm3.Write(in)
	msg := sm3.pad()

	sm3.update(msg, len(msg)/sm3.BlockSize())

	needed := sm3.Size()
	if cap(in)-len(in) < needed {
		newIn := make([]byte, len(in), len(in)+needed)
		copy(newIn, in)
		in = newIn
	}
	out := in[len(in) : len(in)+needed]

	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint32(out[i*4:], sm3.digest[i])
	}
	return out

}

func Sm3Sum(data []byte) []byte {
	var sm3 SM3

	sm3.Reset()
	sm3.Write(data)
	return sm3.Sum(nil)
}
