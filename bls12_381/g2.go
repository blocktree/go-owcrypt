package bls12_381

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"github.com/blocktree/go-owcrypt/bls12_381/bls"
	"io"
	"strings"

	"github.com/drand/kyber"
	"github.com/drand/kyber/group/mod"
)

// Domain comes from the ciphersuite used by the RFC of this name compatible
// with the paired library > v18
var Domain = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_")

type OwcryptG2 struct {
	p *bls.PointG2
}

func NullOwcryptG2() *OwcryptG2 {
	var p bls.PointG2
	return newOwcryptG2(&p)
}

func newOwcryptG2(p *bls.PointG2) *OwcryptG2 {
	return &OwcryptG2{p: p}
}

func (k *OwcryptG2) Equal(k2 kyber.Point) bool {
	return bls.NewG2(nil).Equal(k.p, k2.(*OwcryptG2).p)
}

func (k *OwcryptG2) Null() kyber.Point {
	return newOwcryptG2(bls.NewG2(nil).Zero())
}

func (k *OwcryptG2) Base() kyber.Point {
	return newOwcryptG2(bls.NewG2(nil).One())
}

func (k *OwcryptG2) Pick(rand cipher.Stream) kyber.Point {
	var dst, src [32]byte
	rand.XORKeyStream(dst[:], src[:])
	return k.Hash(dst[:])
}

func (k *OwcryptG2) Set(q kyber.Point) kyber.Point {
	k.p.Set(q.(*OwcryptG2).p)
	return k
}

func (k *OwcryptG2) Clone() kyber.Point {
	var p bls.PointG2
	p.Set(k.p)
	return newOwcryptG2(&p)
}

func (k *OwcryptG2) EmbedLen() int {
	panic("bls12-381: unsupported operation")
}

func (k *OwcryptG2) Embed(data []byte, rand cipher.Stream) kyber.Point {
	panic("bls12-381: unsupported operation")
}

func (k *OwcryptG2) Data() ([]byte, error) {
	panic("bls12-381: unsupported operation")
}

func (k *OwcryptG2) Add(a, b kyber.Point) kyber.Point {
	aa := a.(*OwcryptG2)
	bb := b.(*OwcryptG2)
	bls.NewG2(nil).Add(k.p, aa.p, bb.p)
	return k
}

func (k *OwcryptG2) Sub(a, b kyber.Point) kyber.Point {
	aa := a.(*OwcryptG2)
	bb := b.(*OwcryptG2)
	bls.NewG2(nil).Sub(k.p, aa.p, bb.p)
	return k
}

func (k *OwcryptG2) Neg(a kyber.Point) kyber.Point {
	aa := a.(*OwcryptG2)
	bls.NewG2(nil).Neg(k.p, aa.p)
	return k
}

func (k *OwcryptG2) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	if q == nil {
		q = NullOwcryptG2().Base()
	}
	bls.NewG2(nil).MulScalar(k.p, q.(*OwcryptG2).p, &s.(*mod.Int).V)
	return k
}

func (k *OwcryptG2) MarshalBinary() ([]byte, error) {
	return bls.NewG2(nil).ToCompressed(k.p), nil
}

func (k *OwcryptG2) UnmarshalBinary(buff []byte) error {
	var err error
	k.p, err = bls.NewG2(nil).FromCompressed(buff)
	return err
}

func (k *OwcryptG2) MarshalTo(w io.Writer) (int, error) {
	buf, err := k.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

func (k *OwcryptG2) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, k.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, k.UnmarshalBinary(buf)
}

func (k *OwcryptG2) MarshalSize() int {
	return 96
}

func (k *OwcryptG2) String() string {
	b, _ := k.MarshalBinary()
	return "bls12-381.G1: " + hex.EncodeToString(b)
}

const (
	basic_scheme_dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
	aug_scheme_dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_"
)

func (k *OwcryptG2) Hash(m []byte) kyber.Point {
	if strings.Index(string(m), basic_scheme_dst) == 0 {
		pg2, _ := bls.NewG2(nil).HashToCurve(m[len(basic_scheme_dst):], m[:len(basic_scheme_dst)])
		k.p = pg2
	} else if strings.Index(string(m), aug_scheme_dst) == 0 {
		pg2, _ := bls.NewG2(nil).HashToCurve(m[len(aug_scheme_dst):], m[:len(aug_scheme_dst)])
		k.p = pg2
	}

	return k
}

func sha256Hash(in []byte) []byte {
	h := sha256.New()
	h.Write(in)
	return h.Sum(nil)
}

func (k *OwcryptG2) IsInCorrectGroup() bool {
	return bls.NewG2(nil).InCorrectSubgroup(k.p)
}
