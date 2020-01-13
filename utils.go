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
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"errors"
	"io"
	"math/big"
)

func zForAffine(x, y *big.Int) *big.Int {
	z := new(big.Int)
	if x.Sign() != 0 || y.Sign() != 0 {
		z.SetInt64(1)
	}
	return z
}

func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, new(big.Int).SetInt64(1))
	k.Mod(k, n)
	k.Add(k, new(big.Int).SetInt64(1))
	return
}

type invertible interface {
	Inverse(k *big.Int) *big.Int
}

func fermatInverse(k, N *big.Int) *big.Int {
	two := big.NewInt(2)
	nMinus2 := new(big.Int).Sub(N, two)
	return new(big.Int).Exp(k, nMinus2, N)
}

func signGeneric(priv *ecdsa.PrivateKey, csprng *cipher.StreamReader, c elliptic.Curve, e *big.Int) (r, s *big.Int, v byte,  err error) {
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, nil, 0, errors.New("Invalid param!")
	}

	var k, kInv, ry *big.Int
	for {
		for {
			k, err = randFieldElement(c, *csprng)
			if err != nil {
				r = nil
				return
			}

			if in, ok := priv.Curve.(invertible); ok {
				kInv = in.Inverse(k)
			} else {
				kInv = fermatInverse(k, N) // N != 0
			}

			r, ry = priv.Curve.ScalarBaseMult(k.Bytes())
			r.Mod(r, N)
			if r.Sign() != 0 {
				rBytes := r.Bytes()
				for len(rBytes) < 32  {
					rBytes = append([]byte{0x00}, rBytes...)
				}
				if !((rBytes[0] & 0x80 == 0) && !(rBytes[0] == 0  && (rBytes[1] & 0x80 == 0))) {
					continue
				}
				if ry.Mod(ry, big.NewInt(2)).Cmp(big.NewInt(1)) == 0 {
					v = 0x01
				} else {
					v = 0x00
				}
				break
			}
		}
		s = new(big.Int).Mul(priv.D, r)
		s.Add(s, e)
		s.Mul(s, kInv)
		s.Mod(s, N) // N != 0
		if s.Sign() != 0 {
			halfCurveOrder := new(big.Int).Div(priv.Curve.Params().N, big.NewInt(2))
			if s.Cmp(halfCurveOrder) > 0{
				s.Sub(priv.Curve.Params().N, s)
				v ^= 1
			}
			sBytes := s.Bytes()
			for len(sBytes) < 32  {
				sBytes = append([]byte{0x00}, sBytes...)
			}
			if !((sBytes[0] & 0x80 == 0) && !(sBytes[0] == 0  && (sBytes[1] & 0x80 == 0))) {
				continue
			}
			break
		}
	}
	return
}

func signecdsa(rand io.Reader, priv *ecdsa.PrivateKey, hash []byte) (r, s *big.Int,v byte, err error) {

	//randutil.MaybeReadByte(rand)

	// Get min(log2(q) / 2, 256) bits of entropy from rand.
	entropylen := (priv.Curve.Params().BitSize + 7) / 16
	if entropylen > 32 {
		entropylen = 32
	}
	entropy := make([]byte, entropylen)
	_, err = io.ReadFull(rand, entropy)
	if err != nil {
		return
	}

	// Initialize an SHA-512 hash context; digest ...
	md := sha512.New()
	md.Write(priv.D.Bytes()) // the private key,
	md.Write(entropy)        // the entropy,
	md.Write(hash)           // and the input hash;
	key := md.Sum(nil)[:32]  // and compute ChopMD-256(SHA-512),
	// which is an indifferentiable MAC.

	// Create an AES-CTR instance to use as a CSPRNG.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil,0, err
	}

	// Create a CSPRNG that xors a stream of zeros with
	// the output of the AES-CTR instance.
	csprng := cipher.StreamReader{
		R: zeroReader,
		S: cipher.NewCTR(block, []byte(aesIV)),
	}

	// See [NSA] 3.4.1
	c := priv.PublicKey.Curve
	e := hashToInt(hash, c)
	r, s,v, err = signGeneric(priv, &csprng, c, e)
	return
}

func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

const (
	aesIV = "IV for ECDSA CTR"
)


func verifyesdsa(pub *ecdsa.PublicKey, hash []byte, r, s *big.Int) bool {
	// See [NSA] 3.4.2
	c := pub.Curve
	N := c.Params().N

	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}
	e := hashToInt(hash, c)
	return verifyGeneric(pub, c, e, r, s)
}

func verifyGeneric(pub *ecdsa.PublicKey, c elliptic.Curve, e, r, s *big.Int) bool {
	var w *big.Int
	N := c.Params().N
	if in, ok := c.(invertible); ok {
		w = in.Inverse(s)
	} else {
		w = new(big.Int).ModInverse(s, N)
	}

	u1 := e.Mul(e, w)
	u1.Mod(u1, N)
	u2 := w.Mul(r, w)
	u2.Mod(u2, N)

	// Check if implements S1*g + S2*p
	var x, y *big.Int
	if opt, ok := c.(combinedMult); ok {
		x, y = opt.CombinedMult(pub.X, pub.Y, u1.Bytes(), u2.Bytes())
	} else {
		x1, y1 := c.ScalarBaseMult(u1.Bytes())
		x2, y2 := c.ScalarMult(pub.X, pub.Y, u2.Bytes())
		x, y = c.Add(x1, y1, x2, y2)
	}

	if x.Sign() == 0 && y.Sign() == 0 {
		return false
	}
	x.Mod(x, N)
	return x.Cmp(r) == 0
}

type combinedMult interface {
	CombinedMult(bigX, bigY *big.Int, baseScalar, scalar []byte) (x, y *big.Int)
}

type zr struct {
	io.Reader
}

// Read replaces the contents of dst with zeros.
func (z *zr) Read(dst []byte) (n int, err error) {
	for i := range dst {
		dst[i] = 0
	}
	return len(dst), nil
}

var zeroReader = &zr{}
