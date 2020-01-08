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
package blake256

import "hash"

const BlockSize = 64
const Size = 32
const Size224 = 28

type digest struct {
	hashSize int
	h        [8]uint32
	s        [4]uint32
	t        uint64
	nullt    bool
	x        [BlockSize]byte
	nx       int
}

var (
	iv256 = [8]uint32{
		0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
		0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19}

	iv224 = [8]uint32{
		0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
		0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4}

	pad = [64]byte{0x80}
)

func (d *digest) Reset() {
	if d.hashSize == 224 {
		d.h = iv224
	} else {
		d.h = iv256
	}
	d.t = 0
	d.nx = 0
	d.nullt = false
}

func (d *digest) Size() int { return d.hashSize >> 3 }

func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	if d.nx > 0 {
		n := len(p)
		if n > BlockSize-d.nx {
			n = BlockSize - d.nx
		}
		d.nx += copy(d.x[d.nx:], p)
		if d.nx == BlockSize {
			block(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= BlockSize {
		n := len(p) &^ (BlockSize - 1)
		block(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d0 *digest) Sum(in []byte) []byte {
	d := *d0

	nx := uint64(d.nx)
	l := d.t + nx<<3
	len := make([]byte, 8)
	len[0] = byte(l >> 56)
	len[1] = byte(l >> 48)
	len[2] = byte(l >> 40)
	len[3] = byte(l >> 32)
	len[4] = byte(l >> 24)
	len[5] = byte(l >> 16)
	len[6] = byte(l >> 8)
	len[7] = byte(l)

	if nx == 55 {
		d.t -= 8
		if d.hashSize == 224 {
			d.Write([]byte{0x80})
		} else {
			d.Write([]byte{0x81})
		}
	} else {
		if nx < 55 {
			if nx == 0 {
				d.nullt = true
			}
			d.t -= 440 - nx<<3
			d.Write(pad[0 : 55-nx])
		} else {
			d.t -= 512 - nx<<3
			d.Write(pad[0 : 64-nx])
			d.t -= 440
			d.Write(pad[1:56])
			d.nullt = true
		}
		if d.hashSize == 224 {
			d.Write([]byte{0x00})
		} else {
			d.Write([]byte{0x01})
		}
		d.t -= 8
	}
	d.t -= 64
	d.Write(len)

	out := make([]byte, d.Size())
	j := 0
	for _, s := range d.h[:d.hashSize>>5] {
		out[j+0] = byte(s >> 24)
		out[j+1] = byte(s >> 16)
		out[j+2] = byte(s >> 8)
		out[j+3] = byte(s >> 0)
		j += 4
	}
	return append(in, out...)
}

func (d *digest) setSalt(s []byte) {
	if len(s) != 16 {
		panic("salt length must be 16 bytes")
	}
	d.s[0] = uint32(s[0])<<24 | uint32(s[1])<<16 | uint32(s[2])<<8 | uint32(s[3])
	d.s[1] = uint32(s[4])<<24 | uint32(s[5])<<16 | uint32(s[6])<<8 | uint32(s[7])
	d.s[2] = uint32(s[8])<<24 | uint32(s[9])<<16 | uint32(s[10])<<8 | uint32(s[11])
	d.s[3] = uint32(s[12])<<24 | uint32(s[13])<<16 | uint32(s[14])<<8 | uint32(s[15])
}

func New() hash.Hash {
	return &digest{
		hashSize: 256,
		h:        iv256,
	}
}

func NewSalt(salt []byte) hash.Hash {
	d := &digest{
		hashSize: 256,
		h:        iv256,
	}
	d.setSalt(salt)
	return d
}

func New224() hash.Hash {
	return &digest{
		hashSize: 224,
		h:        iv224,
	}
}

func New224Salt(salt []byte) hash.Hash {
	d := &digest{
		hashSize: 224,
		h:        iv224,
	}
	d.setSalt(salt)
	return d
}
