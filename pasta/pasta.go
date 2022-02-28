package pasta

import (
	"crypto/rand"
	"errors"
)

// privateKey : big endian
// publicKey  : big endian X || Y
// all data is in big int field
func GenPublicKey(privateKey []byte) ([]byte, error) {
	if privateKey == nil || len(privateKey) != 32 || privateKey[0]&0xC0 != 0 {
		return nil, errors.New("invalid private key")
	}

	var publicKey Affine
	GeneratePubkey(&publicKey, BigEndianBytesToFqMontgomeryArray(privateKey))
	return publicKey.ToBigEndianBytes(), nil
}

func Sign(privateKey, msg []byte) ([]byte, error) {
	pubBytes, err := GenPublicKey(privateKey)
	if err != nil {
		return nil, err
	}
	var kBytes [32]byte

	var k Scalar
	for {
		rand.Read(kBytes[:])
		kBytes[0] &= 0x03

		k.Set(BigEndianBytesToFqMontgomeryArray(kBytes[:]))
		var k_nonzero uint64
		FiatPastaFqNonZero(&k_nonzero, k.ToU64Array())
		if k_nonzero == 0 {
			continue
		} else {
			break
		}
	}

	var r Affine
	AffineScalarMul(&r, k, AffineOne)

	rBytes := r.ToBigEndianBytes()[:32]

	if FieldIsOdd(r.Y) {
		var tmp [4]uint64
		FiatPastaFqCopy(&tmp, k.ToU64Array())
		ScalarNegate(&k, tmp)
	}

	mm, err := NewMinaMessage(msg)
	if err != nil {
		return nil, err
	}

	hash := MessageHash(pubBytes, r.X, *mm)

	var e_priv Scalar
	ScalarMul(&e_priv, BigEndianBytesToFqMontgomeryArray(hash), BigEndianBytesToFqMontgomeryArray(privateKey))

	var s Scalar
	ScalarAdd(&s, k, e_priv)
	sBytes := FqMontgomeryArrayToBigEndianBytes(s.ToU64Array())
	return append(rBytes, sBytes...), nil
}

func Verify(publicKey, msg, sig []byte) bool {
	if publicKey == nil || msg == nil || sig == nil || len(sig) != 64 {
		return false
	}
	var pub Affine
	err := pub.FromBigEndianBytes(publicKey)
	if err != nil {
		return false
	}

	var r_mont, s_mont Scalar
	r_mont.Set(BigEndianBytesToFpMontgomeryArray(sig[:32]))
	s_mont.Set(BigEndianBytesToFqMontgomeryArray(sig[32:]))

	mm, err := NewMinaMessage(msg)
	if err != nil {
		return false
	}
	hash := MessageHash(publicKey, r_mont, *mm)
	var e Scalar

	e.Set(BigEndianBytesToFqMontgomeryArray(hash))

	var g Group
	AffineToGroup(&g, AffineOne)

	var sg Group
	GroupScalarMul(&sg, s_mont, g)

	var pub_proj Group
	AffineToGroup(&pub_proj, pub)
	var epub Group
	GroupScalarMul(&epub, e, pub_proj)

	var neg_epub Group
	neg_epub.X.Set(epub.X)
	var opp_y [4]uint64
	FiatPastaFpOpp(&opp_y, epub.Y)
	neg_epub.Y.Set(opp_y)
	neg_epub.Z.Set(epub.Z)

	var r Group
	GroupAdd(&r, sg, neg_epub)

	var raff Affine
	AffineFromGroup(&raff, r)

	var ry_bigint [4]uint64
	FiatPastaFpFromMontgomery(&ry_bigint, raff.Y)

	ry_even := ry_bigint[0]&1 == 0

	return ry_even && FiatPastaFpEquals(raff.X, r_mont)
}

func PointMulBaseGAdd(pointin, scalar []byte) ([]byte, error) {
	if pointin == nil || scalar == nil || len(scalar) != 32 {
		return nil, errors.New("invalid input data")
	}
	pointTmp, err := GenPublicKey(scalar)
	if err != nil {
		return nil, err
	}

	return PointAdd(pointTmp, pointin)
}

func PointAdd(point1, point2 []byte) ([]byte, error) {
	if point1 == nil || point2 == nil {
		return nil, errors.New("invalid input, missing data")
	}
	var r, p, q Affine
	var err error
	err = p.FromBigEndianBytes(point1)
	if err != nil {
		return nil, err
	}
	err = q.FromBigEndianBytes(point2)
	if err != nil {
		return nil, err
	}
	AffineAdd(&r, p, q)
	return r.ToBigEndianBytes(), nil
}

func PointMul(pointin, scalar []byte) ([]byte, error) {
	if pointin == nil || scalar == nil || len(scalar) != 32 {
		return nil, errors.New("invalid input data")
	}

	var r, p Affine
	var err error
	err = p.FromBigEndianBytes(pointin)
	if err != nil {
		return nil, err
	}
	AffineScalarMul(&r, BigEndianBytesToFqMontgomeryArray(scalar), p)

	return r.ToBigEndianBytes(), nil
}

func PointDecompress(point []byte) ([]byte, error) {
	var a Affine
	err := a.FromBigEndianBytes(point)
	if err != nil {
		return nil, err
	}
	return append([]byte{0x04}, a.ToBigEndianBytes()...), nil
}
