package bls12_381

import (
	"crypto/cipher"
	"crypto/sha256"
	"github.com/blocktree/go-owcrypt/bls12_381/bls"
	"hash"
	"io"
	"reflect"

	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing"
	"github.com/drand/kyber/util/random"
	"github.com/drand/kyber/xof/blake2xb"
)

type GroupChecker interface {
	kyber.Point
	IsInCorrectGroup() bool
}

type groupBls struct {
	str      string
	newPoint func() kyber.Point
	isPrime  bool
}

func (g *groupBls) String() string {
	return g.str
}

func (g *groupBls) Scalar() kyber.Scalar {
	return NewOwcryptScalar()
}

func (g *groupBls) ScalarLen() int {
	return g.Scalar().MarshalSize()
}

func (g *groupBls) PointLen() int {
	return g.Point().MarshalSize()
}

func (g *groupBls) Point() kyber.Point {
	return g.newPoint()
}

func (g *groupBls) IsPrimeOrder() bool {
	return g.isPrime
}

func (g *groupBls) Hash() hash.Hash {
	return sha256.New()
}

func (g *groupBls) XOF(seed []byte) kyber.XOF {
	return blake2xb.New(seed)
}

func (g *groupBls) RandomStream() cipher.Stream {
	return random.New()
}

func NewGroupG1() kyber.Group {
	return &groupBls{
		str:      "bls12-381.G1",
		newPoint: func() kyber.Point { return NullOwcryptG1() },
		isPrime:  true,
	}
}

func NewGroupG2() kyber.Group {
	return &groupBls{
		str:      "bls12-381.G2",
		newPoint: func() kyber.Point { return NullOwcryptG2() },
		isPrime:  false,
	}
}

func NewGroupGT() kyber.Group {
	return &groupBls{
		str:      "bls12-381.GT",
		newPoint: func() kyber.Point { return newEmptyGT() },
		isPrime:  false,
	}
}

type Suite struct{}

func NewBLS12381Suite() pairing.Suite {
	return &Suite{}
}

func (s *Suite) G1() kyber.Group {
	return NewGroupG1()
}

func (s *Suite) G2() kyber.Group {
	return NewGroupG2()
}

func (s *Suite) GT() kyber.Group {
	return NewGroupGT()
}

func (s *Suite) ValidatePairing(p1, p2, p3, p4 kyber.Point) bool {
	e := bls.NewEngine()
	e.AddPair(p1.(*OwcryptG1).p, p2.(*OwcryptG2).p)
	e.AddPairInv(p3.(*OwcryptG1).p, p4.(*OwcryptG2).p)
	return e.Check()
}

func (s *Suite) Pair(p1, p2 kyber.Point) kyber.Point {
	e := bls.NewEngine()
	g1point := p1.(*OwcryptG1).p
	g2point := p2.(*OwcryptG2).p
	return newOwcryptGT(e.AddPair(g1point, g2point).Result())
}

func (s *Suite) New(t reflect.Type) interface{} {
	panic("Suite.Encoding: deprecated in drand")
}

func (s *Suite) Read(r io.Reader, objs ...interface{}) error {
	panic("Suite.Read(): deprecated in drand")
}

func (s *Suite) Write(w io.Writer, objs ...interface{}) error {
	panic("Suite.Write(): deprecated in drand")
}

func (s *Suite) Hash() hash.Hash {
	return sha256.New()
}

func (s *Suite) XOF(seed []byte) kyber.XOF {
	return blake2xb.New(seed)
}

func (s *Suite) RandomStream() cipher.Stream {
	return random.New()
}
