package bls12_381

import (
	"crypto/cipher"
	"encoding/hex"
	"github.com/blocktree/go-owcrypt/bls12_381/bls"

	"io"

	"github.com/drand/kyber"
	"github.com/drand/kyber/group/mod"
)

type OwcryptG1 struct {
	p *bls.PointG1
}

func NullOwcryptG1() *OwcryptG1 {
	var p bls.PointG1
	return newOwcryptG1(&p)
}
func newOwcryptG1(p *bls.PointG1) *OwcryptG1 {
	return &OwcryptG1{p: p}
}

func (k *OwcryptG1) Equal(k2 kyber.Point) bool {
	return bls.NewG1().Equal(k.p, k2.(*OwcryptG1).p)
}

func (k *OwcryptG1) Null() kyber.Point {
	return newOwcryptG1(bls.NewG1().Zero())
}

func (k *OwcryptG1) Base() kyber.Point {
	return newOwcryptG1(bls.NewG1().One())
}

func (k *OwcryptG1) Pick(rand cipher.Stream) kyber.Point {
	var dst, src [32]byte
	rand.XORKeyStream(dst[:], src[:])
	return k.Hash(dst[:])
}

func (k *OwcryptG1) Set(q kyber.Point) kyber.Point {
	k.p.Set(q.(*OwcryptG1).p)
	return k
}

func (k *OwcryptG1) Clone() kyber.Point {
	var p bls.PointG1
	p.Set(k.p)
	return newOwcryptG1(&p)
}

func (k *OwcryptG1) EmbedLen() int {
	panic("bls12-381: unsupported operation")
}

func (k *OwcryptG1) Embed(data []byte, rand cipher.Stream) kyber.Point {
	panic("bls12-381: unsupported operation")
}

func (k *OwcryptG1) Data() ([]byte, error) {
	panic("bls12-381: unsupported operation")
}

func (k *OwcryptG1) Add(a, b kyber.Point) kyber.Point {
	aa := a.(*OwcryptG1)
	bb := b.(*OwcryptG1)
	bls.NewG1().Add(k.p, aa.p, bb.p)
	return k
}

func (k *OwcryptG1) Sub(a, b kyber.Point) kyber.Point {
	aa := a.(*OwcryptG1)
	bb := b.(*OwcryptG1)
	bls.NewG1().Sub(k.p, aa.p, bb.p)
	return k
}

func (k *OwcryptG1) Neg(a kyber.Point) kyber.Point {
	aa := a.(*OwcryptG1)
	bls.NewG1().Neg(k.p, aa.p)
	return k
}

func (k *OwcryptG1) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	if q == nil {
		q = NullOwcryptG1().Base()
	}
	bls.NewG1().MulScalar(k.p, q.(*OwcryptG1).p, &s.(*mod.Int).V)
	return k
}

func (k *OwcryptG1) MarshalBinary() ([]byte, error) {
	return bls.NewG1().ToCompressed(k.p), nil
}

func (k *OwcryptG1) UnmarshalBinary(buff []byte) error {
	var err error
	k.p, err = bls.NewG1().FromCompressed(buff)
	return err
}

func (k *OwcryptG1) MarshalTo(w io.Writer) (int, error) {
	buf, err := k.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

func (k *OwcryptG1) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, k.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, k.UnmarshalBinary(buf)
}

func (k *OwcryptG1) MarshalSize() int {
	return 48
}

func (k *OwcryptG1) String() string {
	b, _ := k.MarshalBinary()
	return "bls12-381.G1: " + hex.EncodeToString(b)
}

func (k *OwcryptG1) Hash(m []byte) kyber.Point {
	p, _ := bls.NewG1().HashToCurve(m, Domain)
	k.p = p
	return k

}

func (k *OwcryptG1) IsInCorrectGroup() bool {
	return bls.NewG1().InCorrectSubgroup(k.p)
}
