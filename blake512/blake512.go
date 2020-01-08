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
package blake512

import "hash"

const BlockSize = 128
const Size = 64
const Size384 = 48

type digest struct {
	hashSize int
	h        [8]uint64
	s        [4]uint64
	t        uint64
	nullt    bool
	x        [BlockSize]byte
	nx       int
}

var (
	iv512 = [8]uint64{
		0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
		0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
		0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
		0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179}

	iv384 = [8]uint64{
		0xCBBB9D5DC1059ED8, 0x629A292A367CD507,
		0x9159015A3070DD17, 0x152FECD8F70E5939,
		0x67332667FFC00B31, 0x8EB44A8768581511,
		0xDB0C2E0D64F98FA7, 0x47B5481DBEFA4FA4}
)

func (d *digest) Reset() {
	if d.hashSize == 384 {
		d.h = iv384
	} else {
		d.h = iv512
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
	len := make([]byte, 16)

	len[8] = byte(l >> 56)
	len[9] = byte(l >> 48)
	len[10] = byte(l >> 40)
	len[11] = byte(l >> 32)
	len[12] = byte(l >> 24)
	len[13] = byte(l >> 16)
	len[14] = byte(l >> 8)
	len[15] = byte(l)

	if nx == 111 {
		d.t -= 8
		if d.hashSize == 384 {
			d.Write([]byte{0x80})
		} else {
			d.Write([]byte{0x81})
		}
	} else {
		pad := [129]byte{0x80}
		if nx < 111 {
			if nx == 0 {
				d.nullt = true
			}
			d.t -= 888 - nx<<3
			d.Write(pad[0 : 111-nx])
		} else {
			d.t -= 1024 - nx<<3
			d.Write(pad[0 : 128-nx])
			d.t -= 888
			d.Write(pad[1:112])
			d.nullt = true
		}
		if d.hashSize == 384 {
			d.Write([]byte{0x00})
		} else {
			d.Write([]byte{0x01})
		}
		d.t -= 8
	}
	d.t -= 128
	d.Write(len)

	out := make([]byte, d.Size())
	j := 0
	for _, s := range d.h[:d.hashSize>>6] {
		out[j+0] = byte(s >> 56)
		out[j+1] = byte(s >> 48)
		out[j+2] = byte(s >> 40)
		out[j+3] = byte(s >> 32)
		out[j+4] = byte(s >> 24)
		out[j+5] = byte(s >> 16)
		out[j+6] = byte(s >> 8)
		out[j+7] = byte(s >> 0)
		j += 8
	}
	return append(in, out...)
}

func (d *digest) setSalt(s []byte) {
	if len(s) != 32 {
		panic("salt length must be 32 bytes")
	}
	j := 0
	for i := 0; i < 4; i++ {
		d.s[i] = uint64(s[j])<<56 | uint64(s[j+1])<<48 | uint64(s[j+2])<<40 |
			uint64(s[j+3])<<32 | uint64(s[j+4])<<24 | uint64(s[j+5])<<16 |
			uint64(s[j+6])<<8 | uint64(s[j+7])
		j += 8
	}
}

func New() hash.Hash {
	return &digest{
		hashSize: 512,
		h:        iv512,
	}
}

func NewSalt(salt []byte) hash.Hash {
	d := &digest{
		hashSize: 512,
		h:        iv512,
	}
	d.setSalt(salt)
	return d
}

func New384() hash.Hash {
	return &digest{
		hashSize: 384,
		h:        iv384,
	}
}

func New384Salt(salt []byte) hash.Hash {
	d := &digest{
		hashSize: 384,
		h:        iv384,
	}
	d.setSalt(salt)
	return d
}
