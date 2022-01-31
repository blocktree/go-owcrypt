package pasta

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

func Test_Field(t *testing.T) {
	in := "1f7a89dd176479535790be58c050df13c68de1279dc601eb6119a3dd8e1a6f1f"
	var out Field
	FieldFromHex(&out, in)

	fmt.Println(out)

	var dst Field
	FieldCopy(&dst, out)
	fmt.Println(out)

	fmt.Println(FieldIsOdd(dst))

	var addret Field
	FieldAdd(&addret, out, dst)
	fmt.Println(addret)

	var subret Field
	FieldSub(&subret, addret, dst)
	fmt.Println(subret)

	var mulret Field
	FieldMul(&mulret, out, dst)
	fmt.Println(mulret)

	var sqret Field
	FieldSq(&sqret, out)
	fmt.Println(sqret)

	var powret Field
	FieldPow(&powret, out, 17)
	fmt.Println(powret)

	var invret Field
	FieldInv(&invret, out)
	fmt.Println(invret)

	var negateret Field
	FieldNegate(&negateret, out)
	fmt.Println(negateret)

	fmt.Println(FieldEq(out, dst))
	fmt.Println(FieldEq(out, sqret))
}

func Test_Scalar(t *testing.T) {
	in := "1f7a89dd176479535790be58c050df13c68de1279dc601eb6119a3dd8e1a6f1f"
	var out Scalar
	ScalarFromHex(&out, in)
	fmt.Println(out)

	var out1 [4]uint64
	FiatPastaFpFromMontgomery(&out1, FieldOne)
	fmt.Println(out1)

	var chk [4]uint64
	FiatPastaFpToMontgomery(&chk, out1)
	fmt.Println(chk)
	fmt.Println(FieldOne)
	//var tmp = [32]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	//tmpo := BytesArrayToU64Array(tmp)
	//fmt.Println(tmpo)

}

func Test_Key(t *testing.T) {
	//priHex := "3d082fcfdd540532351b84ba15dbef5bd2a60fe95e850f1e28f8eb53f71284d6"
	//var pri Scalar
	//ScalarFromHex(&pri, priHex)

	//var pri = Scalar{0xca14d6eed923f6e3, 0x61185a1b5e29e6b2, 0xe26d38de9c30753b, 0x3fdf0efb0a5714}
	//var pub Affine
	//GeneratePubkey(&pub, pri)
	//
	//fmt.Println(pub)

	pri1 := [32]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	pri2 := [32]byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	var p1, p2 [4]uint64
	FiatPastaFqToMontgomery(&p1, BytesArrayToU64Array(pri1))
	FiatPastaFqToMontgomery(&p2, BytesArrayToU64Array(pri2))

	var sp1 Scalar
	sp1.Set(p1)
	fmt.Println(sp1)
	var pub1 Affine
	GeneratePubkey(&pub1, sp1)
	fmt.Println("pub1    : ", pub1)
	fmt.Println("affine1 : ", AffineOne)

	var addret Affine
	AffineAdd(&addret, pub1, pub1)
	fmt.Println("pub1 + pub1 : ", addret)

	var sp2 Scalar
	sp2.Set(p2)
	var pub2 Affine
	GeneratePubkey(&pub2, sp2)
	fmt.Println("pub1 * 2    : ", pub2)
}

//func reverseBytes(s []byte) []byte {
//	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
//		s[i], s[j] = s[j], s[i]
//	}
//	return s
//}
func Test_tmp(t *testing.T) {
	priHex := "3d082fcfdd540532351b84ba15dbef5bd2a60fe95e850f1e28f8eb53f71284d6"
	priBytes, _ := hex.DecodeString(priHex)
	priBytes = reverseBytes(priBytes)
	fmt.Println(hex.EncodeToString(priBytes))
	var pri Scalar
	ScalarFromHex(&pri, hex.EncodeToString(priBytes))
	fmt.Println(pri)

	var chk = Scalar{0xca14d6eed923f6e3, 0x61185a1b5e29e6b2, 0xe26d38de9c30753b, 0x3fdf0efb0a5714}
	fmt.Println(chk)

	bnbytes, _ := hex.DecodeString("1b74b5a30a12937c53dfa9f06378ee548f655bd4333d477119cf7a23caed2abb")
	bn := new(big.Int).SetBytes(bnbytes)
	fmt.Println(bn)
}
