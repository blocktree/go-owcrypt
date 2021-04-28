package bls12_381

import (
	"errors"
	"github.com/phoreproject/bls/g1pubs"
	"math/big"
)

const BLS12_381_ORDER = "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"

func isScalarLegal(scalar []byte) bool {
	curveOrder, _ := new(big.Int).SetString(BLS12_381_ORDER, 16)
	scalarBig := new(big.Int).SetBytes(scalar)
	if scalarBig.Cmp(curveOrder) >= 0 {
		return false
	}
	return true
}

func GenPublicKey(privateKey []byte) ([]byte, error) {
	if len(privateKey) != 32 {
		return nil, errors.New("invalid private key length")
	}
	if !isScalarLegal(privateKey) {
		return nil, errors.New("invalid private key data")
	}
	publicKey := g1pubs.PrivToPub(newSK(privateKey))
	pubBytes := publicKey.Serialize()

	return pubBytes[:], nil
}

func newSK(skBytes []byte) *g1pubs.SecretKey {
	sk := [32]byte{}
	copy(sk[:], skBytes)
	return g1pubs.DeserializeSecretKey(sk)
}

func Sign(privateKey, message []byte) ([]byte, error) {
	if len(privateKey) != 32 {
		return nil, errors.New("invalid private key lenth!")
	}

	sig := g1pubs.Sign(message, newSK(privateKey))
	sigBytes := sig.Serialize()
	return sigBytes[:], nil
}

func Verify(publicKey, message, signature []byte) bool {
	if len(publicKey) != 48 || len(message) == 0 || len(signature) != 96 {
		return false
	}
	pk, err := newPK(publicKey)
	if err != nil {
		return false
	}
	sig, err := newSig(signature)
	if err != nil {
		return false
	}

	return g1pubs.Verify(message, pk, sig)
}

func newPK(pkBytes []byte) (*g1pubs.PublicKey, error){
	pk := [48]byte{}
	copy(pk[:], pkBytes)
	return g1pubs.DeserializePublicKey(pk)
}

func newSig(signature []byte) (*g1pubs.Signature, error) {
	sig := [96]byte{}
	copy(sig[:], signature)
	return g1pubs.DeserializeSignature(sig)
}

func scalarMulG(scalar []byte) (*g1pubs.PublicKey, error) {
	if len(scalar) != 32 {
		return nil, errors.New("invalid private key length")
	}
	if !isScalarLegal(scalar) {
		return nil, errors.New("invalid private key data")
	}
	publicKey := g1pubs.PrivToPub(newSK(scalar))

	return publicKey, nil
}

func ScalarMultBaseAdd(pointin, scalar []byte) ([]byte, bool) {

	pin, _ := newPK(pointin)

	pScalar, _ := scalarMulG(scalar)

	pout := g1pubs.NewPublicKeyFromG1(pin.GetPoint().Add(pScalar.GetPoint()).ToAffine())

	poutBytes := pout.Serialize()

	if new(big.Int).SetBytes(poutBytes[:]).Cmp(big.NewInt(0)) == 0 {
		return nil, true
	}
	return poutBytes[:], false
}