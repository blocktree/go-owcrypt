package pasta

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

func printBigInt(in []byte) {
	bn := new(big.Int).SetBytes(in)
	fmt.Println(bn)
}

func TestGenPublicKey(t *testing.T) {
	prikey := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	pubkey, err := GenPublicKey(prikey)

	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("public key : ", hex.EncodeToString(pubkey))

	var a Affine
	err = a.FromBigEndianBytes(pubkey)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("pubkey in mont : ", a)
	fmt.Println("point g        : ", AffineOne)

	var compressed Compressed
	Compress(&compressed, a)
	cBytes := compressed.ToBigEndianBytes()
	fmt.Println("compressed pub : ", hex.EncodeToString(cBytes))

	err = a.FromBigEndianBytes(cBytes)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("pubkey in mont : ", a)
	fmt.Println("point g        : ", AffineOne)
}

func TestSign(t *testing.T) {
	prikey, _ := hex.DecodeString("3d082fcfdd540532351b84ba15dbef5bd2a60fe95e850f1e28f8eb53f71284d6")
	pubkey, _ := GenPublicKey(prikey)
	hash, _ := hex.DecodeString("2b846f815ac61ab4140fc9a3d3a683a5e08651290de2476bdd5a5e8f0f6a9bbc")

	sig, err := Sign(prikey, hash)
	fmt.Println(err)
	fmt.Println(hex.EncodeToString(sig))
	fmt.Print("r : ")
	printBigInt(sig[:32])
	fmt.Print("s : ")
	printBigInt(sig[32:])

	pass := Verify(pubkey, hash, sig)
	fmt.Println(pass)
}

func TestPointMulBaseGAdd(t *testing.T) {
	pointin, _ := hex.DecodeString("00000000000000000000000000000000000000000000000000000000000000011b74b5a30a12937c53dfa9f06378ee548f655bd4333d477119cf7a23caed2abb")
	scalar := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

	pointout, err := PointMulBaseGAdd(pointin, scalar)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println(hex.EncodeToString(pointout))

}

func TestPointAdd(t *testing.T) {
	pri1 := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	pub1, err := GenPublicKey(pri1)
	fmt.Println(err)
	fmt.Println("pub1 : ", hex.EncodeToString(pub1))
	pri2 := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	pub2, err := GenPublicKey(pri2)
	fmt.Println(err)
	fmt.Println("pub2 : ", hex.EncodeToString(pub2))
	pri3 := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	pub3, err := GenPublicKey(pri3)
	fmt.Println(err)
	fmt.Println("pub3 : ", hex.EncodeToString(pub3))

	chk, err := PointAdd(pub1, pub2)
	fmt.Println(err)
	fmt.Println("chk  : ", hex.EncodeToString(chk))
}

func TestPointMul(t *testing.T) {
	pointin, _ := hex.DecodeString("00000000000000000000000000000000000000000000000000000000000000011b74b5a30a12937c53dfa9f06378ee548f655bd4333d477119cf7a23caed2abb")
	scalar := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}

	pointout, err := PointMul(pointin, scalar)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println(hex.EncodeToString(pointout))
}
