package pasta

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
)

const LimbsPerField = 4

type Field [LimbsPerField]uint64
type Scalar [LimbsPerField]uint64

func (f Field) ToU64Array() (out [4]uint64) {
	out[0] = f[0]
	out[1] = f[1]
	out[2] = f[2]
	out[3] = f[3]
	return
}
func (f *Field) Set(in [4]uint64) {
	f[0] = in[0]
	f[1] = in[1]
	f[2] = in[2]
	f[3] = in[3]
}

func (f Field) ToBigEndianBytes() []byte {
	var out [32]byte
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(out[i*8:(i+1)*8], f.ToU64Array()[i])
	}
	return reverseBytes(out[:])
}

func (s Scalar) ToU64Array() (out [4]uint64) {
	out[0] = s[0]
	out[1] = s[1]
	out[2] = s[2]
	out[3] = s[3]
	return
}
func (s *Scalar) Set(in [4]uint64) {
	s[0] = in[0]
	s[1] = in[1]
	s[2] = in[2]
	s[3] = in[3]
}

type Group struct {
	X Field
	Y Field
	Z Field
}

type Affine struct {
	X Field
	Y Field
}

func (a Affine) ToBigEndianBytes() []byte {
	var out []byte
	var tmp [4]uint64
	FiatPastaFpFromMontgomery(&tmp, a.X.ToU64Array())
	a.X.Set(tmp)
	FiatPastaFpFromMontgomery(&tmp, a.Y.ToU64Array())
	a.Y.Set(tmp)
	out = append(out, a.X.ToBigEndianBytes()...)
	return append(out, a.Y.ToBigEndianBytes()...)
}

func (a *Affine) FromBigEndianBytes(p []byte) error {
	if p == nil || (len(p) != 33 && len(p) != 64 && len(p) != 65) {
		return errors.New("invalid input length p")
	}
	if len(p) == 33 {
		var compressed Compressed
		err := compressed.FromBigEndianBytes(p)
		if err != nil {
			return err
		}
		Decompress(a, compressed)
	} else {
		var x_mont, y_mont [4]uint64
		var tmp [32]byte
		if len(p) == 65 {
			if p[0] != 0x04 {
				return errors.New("invalid input data p, first byte is not 0x04")
			}
			p = p[1:]
		} else {
			copy(tmp[:], reverseBytes(p[:32]))
			FiatPastaFpToMontgomery(&x_mont, BytesArrayToU64Array(tmp))
			copy(tmp[:], reverseBytes(p[32:]))
			FiatPastaFpToMontgomery(&y_mont, BytesArrayToU64Array(tmp))
		}
		a.X.Set(x_mont)
		a.Y.Set(y_mont)
	}

	return nil
}

func (a Affine) ToBigEndianMontgomeryBytes() []byte {
	var out []byte
	out = append(out, a.X.ToBigEndianBytes()...)
	return append(out, a.Y.ToBigEndianBytes()...)
}

type Compressed struct {
	X     Field
	IsOdd bool
}

func (c Compressed) ToBigEndianBytes() []byte {
	var out []byte
	if c.IsOdd {
		out = append(out, 0x02)
	} else {
		out = append(out, 0x03)
	}

	return append(out, c.X.ToBigEndianBytes()...)
}

func (c *Compressed) FromBigEndianBytes(p []byte) error {
	if p == nil || len(p) != 33 {
		return errors.New("invalid input length p")
	}
	if p[0] == 0x02 {
		c.IsOdd = true
	} else if p[0] == 0x03 {
		c.IsOdd = false
	} else {
		errors.New("invalid input data p, first byte is not 0x02 or 0x03")
	}

	var tmp [32]byte
	copy(tmp[:], reverseBytes(p[1:]))
	var x_mont [4]uint64
	FiatPastaFpToMontgomery(&x_mont, BytesArrayToU64Array(tmp))
	c.X.Set(x_mont)
	return nil
}

type Signature struct {
	R Field
	S Scalar
}

type Keypair struct {
	Pub  Affine
	Priv Scalar
}

func FieldFromHex(b *Field, hexStr string) bool {

	bytes, err := hex.DecodeString(hexStr)

	if err != nil || len(bytes) != 32 || (bytes[31]&0xC0 != 0) {
		return false
	}

	var out [4]uint64
	FiatPastaFpToMontgomery(&out, BytesArrayToU64Array(BytesArrayTo32LengthBytesArray(bytes)))

	b.Set(out)
	return true
}

func FieldCopy(c *Field, a Field) {
	var out [4]uint64
	FiatPastaFpCopy(&out, a)
	c.Set(out)
}

func FieldIsOdd(y Field) bool {
	var tmp [4]uint64
	FiatPastaFpFromMontgomery(&tmp, y)
	if tmp[0]&1 == 1 {
		return true
	}
	return false
}

func FieldAdd(c *Field, a, b Field) {
	var out [4]uint64
	FiatPastaFpAdd(&out, a.ToU64Array(), b.ToU64Array())
	c.Set(out)
}

func FieldSub(c *Field, a, b Field) {
	var out [4]uint64
	FiatPastaFpSub(&out, a.ToU64Array(), b.ToU64Array())
	c.Set(out)
}

func FieldMul(c *Field, a, b Field) {
	var out [4]uint64
	FiatPastaFpMul(&out, a.ToU64Array(), b.ToU64Array())
	c.Set(out)
}

func FieldSq(c *Field, a Field) {
	var out [4]uint64
	FiatPastaFpSquare(&out, a.ToU64Array())
	c.Set(out)
}

func FieldPow(c *Field, a Field, b uint8) {
	FieldCopy(c, FieldOne)
	if b == 0 {
		return
	}
	var tmp Field
	for i := int(math.Log2(float64(b))) + 1; i > 0; i-- {
		FieldCopy(&tmp, *c)
		FieldSq(c, tmp)
		if b&(1<<(i-1)) != 0 {
			FieldCopy(&tmp, *c)
			FieldMul(c, tmp, a)
		}

	}
}

func FieldInv(c *Field, a Field) {
	var out [4]uint64
	FiatPastaFpInv(&out, a)
	c.Set(out)
}

func FieldNegate(c *Field, a Field) {
	var out [4]uint64
	FiatPastaFpOpp(&out, a.ToU64Array())
	c.Set(out)
}

func FieldEq(a, b Field) uint {
	if FiatPastaFpEquals(a.ToU64Array(), b.ToU64Array()) {
		return 1
	}
	return 0
}

func ScalarFromHex(b *Scalar, hexStr string) bool {
	bytes, err := hex.DecodeString(hexStr)

	if err != nil || len(bytes) != 32 || (bytes[31]&0xC0 != 0) {
		return false
	}

	var out [4]uint64
	FiatPastaFqToMontgomery(&out, BytesArrayToU64Array(BytesArrayTo32LengthBytesArray(bytes)))

	b.Set(out)
	return true
}

func ScalarFromWords(b *Scalar, words [4]uint64) {
	var tmp [4]uint64
	copy(tmp[:], words[:])
	tmp[3] &= (uint64(1) << 62) - 1
	var out [4]uint64
	FiatPastaFqToMontgomery(&out, tmp)
	b.Set(out)
}

func ScalarCopy(b *Scalar, a Scalar) {
	var out [4]uint64
	FiatPastaFqCopy(&out, a)
	b.Set(out)
}

func ScalarAdd(c *Scalar, a, b Scalar) {
	var out [4]uint64
	FiatPastaFqAdd(&out, a.ToU64Array(), b.ToU64Array())
	c.Set(out)
}

func ScalarSub(c *Scalar, a, b Scalar) {
	var out [4]uint64
	FiatPastaFqSub(&out, a.ToU64Array(), b.ToU64Array())
	c.Set(out)
}

func ScalarMul(c *Scalar, a, b Scalar) {
	var out [4]uint64
	FiatPastaFqMul(&out, a.ToU64Array(), b.ToU64Array())
	c.Set(out)
}

func ScalarSq(c *Scalar, a Scalar) {
	var out [4]uint64
	FiatPastaFqSquare(&out, a.ToU64Array())
	c.Set(out)
}

func ScalarNegate(c *Scalar, a Scalar) {
	var out [4]uint64
	FiatPastaFqOpp(&out, a.ToU64Array())
	c.Set(out)
}

func ScalarEq(a, b Scalar) bool {
	return FiatPastaFqEquals(a.ToU64Array(), b.ToU64Array())
}

func IsZero(p Group) uint {
	return FieldEq(p.Z, FieldZero)
}

func AffineIsZero(p Affine) uint {
	if FieldEq(p.X, FieldZero) == 1 && FieldEq(p.Y, FieldZero) == 1 {
		return 1
	}
	return 0
}

func GroupIsOnCurve(p Group) uint {
	if IsZero(p) == 1 {
		return 1
	}

	var lhs, rhs Field
	if FieldEq(p.Z, FieldOne) == 1 {
		FieldSq(&lhs, p.Y)
		FieldSq(&rhs, p.X)
		FieldMul(&rhs, rhs, p.X)
		FieldAdd(&rhs, rhs, GroupCoeffB)
	} else {
		var x3, z6 Field
		FieldSq(&x3, p.X)
		FieldMul(&x3, x3, p.X)
		FieldSq(&lhs, p.Y)
		FieldSq(&z6, p.Z)
		FieldSq(&z6, z6)
		FieldMul(&z6, z6, p.Z)
		FieldMul(&z6, z6, p.Z)

		FieldMul(&rhs, z6, GroupCoeffB)
		FieldAdd(&rhs, x3, rhs)
	}
	return FieldEq(lhs, rhs)
}

func AffineToGroup(r *Group, p Affine) {
	if FieldEq(p.X, FieldZero) == 1 && FieldEq(p.Y, FieldZero) == 1 {
		r.X.Set(FieldZero)
		r.Y.Set(FieldOne)
		r.Z.Set(FieldZero)
	} else {
		r.X.Set(p.X)
		r.Y.Set(p.Y)
		r.Z.Set(FieldOne)
	}
}

func AffineFromGroup(r *Affine, p Group) {
	if FieldEq(p.Z, FieldZero) == 1 {
		r.X.Set(FieldZero)
		r.Y.Set(FieldZero)
	} else {
		var zi, zi2, zi3 Field
		FieldInv(&zi, p.Z)
		FieldMul(&zi2, zi, zi)
		FieldMul(&zi3, zi2, zi)
		FieldMul(&r.X, p.X, zi2)
		FieldMul(&r.Y, p.Y, zi3)
	}
}

func GroupOne(a *Group) {
	AffineToGroup(a, AffineOne)
}

func GroupDbl(r *Group, p Group) {
	if IsZero(p) == 1 {
		r.X.Set(p.X)
		r.Y.Set(p.Y)
		r.Z.Set(p.Z)
	} else {
		var a, b, c Field
		FieldSq(&a, p.X)
		FieldSq(&b, p.Y)
		FieldSq(&c, b)

		var d, e, f Field
		FieldAdd(&r.X, p.X, b)
		FieldSq(&r.Y, r.X)
		FieldSub(&r.Z, r.Y, a)
		FieldSub(&r.X, r.Z, c)
		FieldAdd(&d, r.X, r.X)
		FieldMul(&e, FieldThree, a)
		FieldSq(&f, e)

		FieldAdd(&r.Y, d, d)
		FieldSub(&r.X, f, r.Y)

		FieldSub(&r.Y, d, r.X)
		FieldMul(&f, FieldEight, c)
		FieldMul(&r.Z, e, r.Y)
		FieldSub(&r.Y, r.Z, f)

		FieldMul(&f, p.Y, p.Z)
		FieldAdd(&r.Z, f, f)
	}
}

func GroupAdd(r *Group, p, q Group) {
	if IsZero(p) == 1 {
		r.X.Set(q.X)
		r.Y.Set(q.Y)
		r.Z.Set(q.Z)
		return
	}

	if IsZero(q) == 1 {
		r.X.Set(p.X)
		r.Y.Set(p.Y)
		r.Z.Set(p.Z)
		return
	}

	if FieldEq(p.X, q.X) == 1 && FieldEq(p.Y, q.Y) == 1 && FieldEq(p.Z, q.Z) == 1 {
		GroupDbl(r, p)
		return
	}

	var z1z1, z2z2 Field
	FieldSq(&z1z1, p.Z)
	FieldSq(&z2z2, q.Z)

	var u1, u2, s1, s2 Field
	FieldMul(&u1, p.X, z2z2)
	FieldMul(&u2, q.X, z1z1)
	FieldMul(&r.X, q.Z, z2z2)
	FieldMul(&s1, p.Y, r.X)
	FieldMul(&r.Y, p.Z, z1z1)
	FieldMul(&s2, q.Y, r.Y)

	var h, i, j, w, v Field
	FieldSub(&h, u2, u1)
	FieldAdd(&r.Z, h, h)
	FieldSq(&i, r.Z)
	FieldMul(&j, h, i)
	FieldSub(&r.X, s2, s1)
	FieldAdd(&w, r.X, r.X)
	FieldMul(&v, u1, i)

	FieldSq(&r.X, w)
	FieldAdd(&r.Y, v, v)
	FieldSub(&r.Z, r.X, j)
	FieldSub(&r.X, r.Z, r.Y)

	FieldSub(&r.Y, v, r.X)
	FieldMul(&r.Z, s1, j)
	FieldAdd(&s1, r.Z, r.Z)
	FieldMul(&r.Z, w, r.Y)
	FieldSub(&r.Y, r.Z, s1)

	FieldAdd(&r.Z, p.Z, q.Z)
	FieldSq(&s1, r.Z)
	FieldSub(&r.Z, s1, z1z1)
	FieldSub(&j, r.Z, z2z2)
	FieldMul(&r.Z, j, h)
}

func GroupScalarMul(r *Group, k Scalar, p Group) {
	r.X.Set(GroupZero.X)
	r.Y.Set(GroupZero.Y)
	r.Z.Set(GroupZero.Z)

	if IsZero(p) == 1 {
		return
	}
	if ScalarEq(k, ScalarZero) {
		return
	}

	var tmp Group
	var k_bits [4]uint64
	FiatPastaFqFromMontgomery(&k_bits, k.ToU64Array())

	for i := 0; i < FieldSizeInBits; i++ {
		j := FieldSizeInBits - 1 - i
		limb_idx := j / 64
		in_limb_idx := j % 64
		di := (k_bits[limb_idx]>>in_limb_idx)&1 == 1

		GroupDbl(&tmp, *r)
		if di {
			GroupAdd(r, tmp, p)
		} else {
			FieldCopy(&r.X, tmp.X)
			FieldCopy(&r.Y, tmp.Y)
			FieldCopy(&r.Z, tmp.Z)
		}
	}
}

func GroupNegate(q *Group, p Group) {
	FieldCopy(&q.X, p.X)
	FieldCopy(&q.Y, p.Y)
	FieldCopy(&q.Z, p.Z)
}

func AffineScalarMul(r *Affine, k Scalar, p Affine) {
	var pp, pr Group
	AffineToGroup(&pp, p)
	GroupScalarMul(&pr, k, pp)
	AffineFromGroup(r, pr)
}

func AffineEq(p, q Affine) bool {
	return FieldEq(p.X, q.X) == 1 && FieldEq(p.Y, q.Y) == 1
}

func AffineAdd(r *Affine, p, q Affine) {
	var gr, gp, gq Group
	AffineToGroup(&gp, p)
	AffineToGroup(&gq, q)
	GroupAdd(&gr, gp, gq)
	AffineFromGroup(r, gr)
}

func AffineNegate(q *Affine, p Affine) {
	var gq, gp Group
	AffineToGroup(&gp, p)
	GroupNegate(&gq, gp)
	AffineFromGroup(q, gq)
}

func AffineIsOnCurve(p Affine) bool {
	var gp Group
	AffineToGroup(&gp, p)
	return GroupIsOnCurve(gp) == 1
}

//////////////////////////////

func GeneratePubkey(pub_key *Affine, priv_key Scalar) {
	AffineScalarMul(pub_key, priv_key, AffineOne)
}

func Compress(compressed *Compressed, pt Affine) {
	var out, y_bigint [4]uint64
	FiatPastaFpFromMontgomery(&out, pt.X.ToU64Array())
	FiatPastaFpFromMontgomery(&y_bigint, pt.Y.ToU64Array())
	compressed.X.Set(out)
	if y_bigint[0]&0x01 == 1 {
		compressed.IsOdd = true
	} else {
		compressed.IsOdd = false
	}
}

func Decompress(pt *Affine, compressed Compressed) bool {
	pt.X.Set(compressed.X.ToU64Array())

	var x2, x3, y2 [4]uint64
	FiatPastaFpSquare(&x2, pt.X)
	FiatPastaFpMul(&x3, x2, pt.X)
	FiatPastaFpAdd(&y2, x3, GroupCoeffB)

	var y_pre [4]uint64
	if !FiatPastaFpSqrt(&y_pre, y2) {
		return false
	}

	var y_pre_bigint [4]uint64
	FiatPastaFpFromMontgomery(&y_pre_bigint, y_pre)
	var y_pre_odd = y_pre_bigint[0]&1 == 1
	if y_pre_odd == compressed.IsOdd {
		pt.Y.Set(y_pre)
	} else {
		var opp [4]uint64
		FiatPastaFpOpp(&opp, y_pre)
		pt.Y.Set(opp)
	}
	return true
}
