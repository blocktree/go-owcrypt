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
package blake2s

import (
	"encoding/binary"
	"errors"
	"hash"
)

const (
	BlockSize  = 64
	Size       = 32
	SaltSize   = 8
	PersonSize = 8
	KeySize    = 32
)

type digest struct {
	h  [8]uint32
	t  [2]uint32
	f  [2]uint32
	x  [BlockSize]byte
	nx int

	ih         [8]uint32
	paddedKey  [BlockSize]byte
	isKeyed    bool
	size       uint8
	isLastNode bool
}

var iv = [8]uint32{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

type Config struct {
	Size   uint8
	Key    []byte
	Salt   []byte
	Person []byte
	Tree   *Tree
}

type Tree struct {
	Fanout        uint8
	MaxDepth      uint8
	LeafSize      uint32
	NodeOffset    uint64
	NodeDepth     uint8
	InnerHashSize uint8
	IsLastNode    bool
}

var defaultConfig = &Config{Size: Size}

func verifyConfig(c *Config) error {
	if c.Size > Size {
		return errors.New("digest size is too large")
	}
	if len(c.Key) > KeySize {
		return errors.New("key is too large")
	}
	if len(c.Salt) > SaltSize {
		return errors.New("salt is too large")
	}
	if len(c.Person) > PersonSize {
		return errors.New("personalization is too large")
	}
	if c.Tree != nil {
		if c.Tree.InnerHashSize > Size {
			return errors.New("incorrect tree inner hash size")
		}
		if c.Tree.NodeOffset > (1<<48)-1 {
			return errors.New("tree node offset is too large")
		}
	}
	return nil
}

func New(c *Config) (hash.Hash, error) {
	if c == nil {
		c = defaultConfig
	} else {
		if c.Size == 0 {
			c.Size = Size
		}
		if err := verifyConfig(c); err != nil {
			return nil, err
		}
	}
	d := new(digest)
	d.initialize(c)
	return d, nil
}

func (d *digest) initialize(c *Config) {
	var p [BlockSize]byte
	p[0] = c.Size
	p[1] = uint8(len(c.Key))
	if c.Salt != nil {
		copy(p[16:], c.Salt)
	}
	if c.Person != nil {
		copy(p[24:], c.Person)
	}
	if c.Tree != nil {
		p[2] = c.Tree.Fanout
		p[3] = c.Tree.MaxDepth
		binary.LittleEndian.PutUint32(p[4:], c.Tree.LeafSize)
		p[8] = byte(c.Tree.NodeOffset)
		p[9] = byte(c.Tree.NodeOffset >> 8)
		p[10] = byte(c.Tree.NodeOffset >> 16)
		p[11] = byte(c.Tree.NodeOffset >> 24)
		p[12] = byte(c.Tree.NodeOffset >> 32)
		p[13] = byte(c.Tree.NodeOffset >> 40)
		p[14] = c.Tree.NodeDepth
		p[15] = c.Tree.InnerHashSize
	} else {
		p[2] = 1
		p[3] = 1
	}

	d.size = c.Size
	for i := 0; i < 8; i++ {
		d.h[i] = iv[i] ^ binary.LittleEndian.Uint32(p[i*4:])
	}
	if c.Tree != nil && c.Tree.IsLastNode {
		d.isLastNode = true
	}

	if len(c.Key) > 0 {
		copy(d.paddedKey[:], c.Key)
		d.Write(d.paddedKey[:])
		d.isKeyed = true
	}

	copy(d.ih[:], d.h[:])
}

func New256() hash.Hash {
	d := new(digest)
	d.initialize(defaultConfig)
	return d
}

func NewMAC(outBytes uint8, key []byte) hash.Hash {
	d, err := New(&Config{Size: outBytes, Key: key})
	if err != nil {
		panic(err.Error())
	}
	return d
}

func (d *digest) Reset() {
	copy(d.h[:], d.ih[:])
	d.t[0] = 0
	d.t[1] = 0
	d.f[0] = 0
	d.f[1] = 0
	d.nx = 0
	if d.isKeyed {
		d.Write(d.paddedKey[:])
	}
}

func (d *digest) Size() int { return int(d.size) }

func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	left := BlockSize - d.nx
	if len(p) > left {
		copy(d.x[d.nx:], p[:left])
		p = p[left:]
		blocks(d, d.x[:])
		d.nx = 0
	}

	if len(p) > BlockSize {
		n := len(p) &^ (BlockSize - 1)
		if n == len(p) {
			n -= BlockSize
		}
		blocks(d, p[:n])
		p = p[n:]
	}

	d.nx += copy(d.x[d.nx:], p)
	return
}

func (d0 *digest) Sum(in []byte) []byte {
	d := *d0
	hash := d.checkSum()
	return append(in, hash[:d.size]...)
}

func (d *digest) checkSum() [Size]byte {
	if d.isKeyed {
		for i := 0; i < len(d.paddedKey); i++ {
			d.paddedKey[i] = 0
		}
	}

	dec := BlockSize - uint32(d.nx)
	if d.t[0] < dec {
		d.t[1]--
	}
	d.t[0] -= dec

	for i := d.nx; i < len(d.x); i++ {
		d.x[i] = 0
	}
	d.f[0] = 0xffffffff
	if d.isLastNode {
		d.f[1] = 0xffffffff
	}
	blocks(d, d.x[:])

	var out [Size]byte
	j := 0
	for _, s := range d.h[:(d.size-1)/4+1] {
		out[j+0] = byte(s >> 0)
		out[j+1] = byte(s >> 8)
		out[j+2] = byte(s >> 16)
		out[j+3] = byte(s >> 24)
		j += 4
	}
	return out
}

func Sum256(data []byte) [Size]byte {
	var d digest
	d.initialize(defaultConfig)
	d.Write(data)
	return d.checkSum()
}
