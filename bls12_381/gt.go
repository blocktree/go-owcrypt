package bls12_381

import (
	"crypto/cipher"
	"encoding/hex"
	"github.com/blocktree/go-owcrypt/bls12_381/bls"
	"io"

	"github.com/drand/kyber"
)

type OwcryptGT struct {
	f *bls.E
}

func newEmptyGT() *OwcryptGT {
	return newOwcryptGT(bls.NewGT().New())
}
func newOwcryptGT(f *bls.E) *OwcryptGT {
	return &OwcryptGT{
		f: f,
	}
}

func (k *OwcryptGT) Equal(kk kyber.Point) bool {
	return k.f.Equal(kk.(*OwcryptGT).f)
}

const gtLength = 576

func (k *OwcryptGT) Null() kyber.Point {
	var zero [gtLength]byte
	k.f, _ = bls.NewGT().FromBytes(zero[:])
	return k
}

func (k *OwcryptGT) Base() kyber.Point {
	panic("not yet available")
}

func (k *OwcryptGT) Pick(rand cipher.Stream) kyber.Point {
	panic("TODO: bls12-381.GT.Pick()")
}

func (k *OwcryptGT) Set(q kyber.Point) kyber.Point {
	k.f.Set(q.(*OwcryptGT).f)
	return k
}

func (k *OwcryptGT) Clone() kyber.Point {
	kk := newEmptyGT()
	kk.Set(k)
	return kk
}

func (k *OwcryptGT) Add(a, b kyber.Point) kyber.Point {
	aa := a.(*OwcryptGT)
	bb := b.(*OwcryptGT)
	bls.NewGT().Mul(k.f, aa.f, bb.f)
	return k
}

func (k *OwcryptGT) Sub(a, b kyber.Point) kyber.Point {
	aa := a.(*OwcryptGT)
	bb := b.(*OwcryptGT)
	bls.NewGT().Sub(k.f, aa.f, bb.f)
	return k
}

func (k *OwcryptGT) Neg(q kyber.Point) kyber.Point {
	panic("bls12-381: GT is not a full kyber.Point implementation")
}

func (k *OwcryptGT) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	panic("bls12-381: GT is not a full kyber.Point implementation")
}

func (k *OwcryptGT) MarshalBinary() ([]byte, error) {
	return bls.NewGT().ToBytes(k.f), nil
}

func (k *OwcryptGT) MarshalTo(w io.Writer) (int, error) {
	buf, err := k.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

func (k *OwcryptGT) UnmarshalBinary(buf []byte) error {
	fe12, err := bls.NewGT().FromBytes(buf)
	k.f = fe12
	return err
}

func (k *OwcryptGT) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, k.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, k.UnmarshalBinary(buf)
}

func (k *OwcryptGT) MarshalSize() int {
	return 576
}

func (k *OwcryptGT) String() string {
	b, _ := k.MarshalBinary()
	return "bls12-381.GT: " + hex.EncodeToString(b)
}

func (k *OwcryptGT) EmbedLen() int {
	panic("bls12-381.GT.EmbedLen(): unsupported operation")
}

func (k *OwcryptGT) Embed(data []byte, rand cipher.Stream) kyber.Point {
	panic("bls12-381.GT.Embed(): unsupported operation")
}

func (k *OwcryptGT) Data() ([]byte, error) {
	panic("bls12-381.GT.Data(): unsupported operation")
}
