package owcrypt

import (
	"encoding/hex"
	"fmt"
	"github.com/blocktree/go-owcrypt/pasta"
	"math/big"
	"testing"
)

func TestMina(t *testing.T) {
	var ivForTest = [3]pasta.Field{
		{0x67097c15f1a46d64, 0xc76fd61db3c20173, 0xbdf9f393b220a17, 0x10c0e352378ab1fd},
		{0x57dbbe3a20c2a32, 0x486f1b93a41e04c7, 0xa21341e97da1bdc1, 0x24a095608e4bf2e9},
		{0xd4559679d839ff92, 0x577371d495f4d71b, 0x3227c7db607b3ded, 0x2ca212648a12291e},
	}

	var transForTest = []pasta.Field{
		{0x67097c15f1a46d64, 0xc76fd61db3c20173, 0xbdf9f393b220a17, 0x10c0e352378ab1fd},
		{0x57dbbe3a20c2a32, 0x486f1b93a41e04c7, 0xa21341e97da1bdc1, 0x24a095608e4bf2e9},
		{0xd4559679d839ff92, 0x577371d495f4d71b, 0x3227c7db607b3ded, 0x2ca212648a12291e},
	}

	var mm = pasta.MinaMessage{
		TransactionPrefix: transForTest,
		TransactionSuffix: transForTest,
		SpongeIV:          ivForTest,
	}

	message := mm.ToBytes()
	fmt.Println(string(message))

	priKey, _ := hex.DecodeString("3d082fcfdd540532351b84ba15dbef5bd2a60fe95e850f1e28f8eb53f71284d6")
	pubKey, _ := GenPubkey(priKey, ECC_CURVE_PASTA)

	fmt.Println(hex.EncodeToString(pubKey))

	sig, _, retCode := Signature(priKey, nil, message, ECC_CURVE_PASTA)
	if retCode != SUCCESS {
		t.Error("sign failed with return code : ", retCode)
		return
	}
	fmt.Println(hex.EncodeToString(sig))
	pass := Verify(pubKey, nil, message, sig, ECC_CURVE_PASTA)
	if pass != SUCCESS {
		t.Error("verify failed")
		return
	}
	fmt.Println("success")

}

func Test_example(t *testing.T) {
	data := []string{
		"04d5806fee539e9190827496c9c07dd249f775785e0baf8155d9ba9ab0466f2b",
		"04d5806fee539e9190827496c9c07dd249f775785e0baf8155d9ba9ab0466f2b",
		"ea8ce5d00cdce54ae0f60ee845ee3804e77806af78bd1751a55000ceb54ac03b",
		"04d5806fee539e9190827496c9c07dd249f775785e0baf8155d9ba9ab0466f2b",
		"6201606c19b1325469dccd3242efad08c75ab38f0de3401955efb150172f6f1f",
		"77ff28fef125f2fc9e6e2d705f23b3cfc47e81d0beb756a9f820eff45c33fb32",
		"40420f0000000000010000000000000000000000204e0000021ce8d0d2e64012",
		"9b030903692b6b7b030000000000000000000000000000000000000100000000",
		"000000005a620200000000000000000000000000000000000000000000000000",
	}
	mainnetIV3W := [3]pasta.Field{
		{0xc21e7c13c81e894, 0x710189d783717f27, 0x7825ac132f04e050, 0x6fd140c96a52f28},
		{0x25611817aeec99d8, 0x24e1697f7e63d4b4, 0x13dabc79c3b8bba9, 0x232c7b1c778fbd08},
		{0x70bff575f3c9723c, 0x96818a1c2ae2e7ef, 0x2eec149ee0aacb0c, 0xecf6e7248a576ad},
	}

	privateKey, _ := hex.DecodeString("3ca187a58f09da346844964310c7e0dd948a9105702b716f4d732e042e0c172e")

	var prefix, suffix []pasta.Field

	//prefix message
	for i := 0; i < 3; i++ {
		var tmp pasta.Field
		pasta.FieldFromHex(&tmp, data[i])
		prefix = append(prefix, tmp)
	}
	//suffix message
	for i := 6; i < 9; i++ {
		var tmp pasta.Field
		pasta.FieldFromHex(&tmp, data[i])
		suffix = append(suffix, tmp)
	}

	//message struct
	message := pasta.MinaMessage{
		TransactionPrefix: prefix,
		TransactionSuffix: suffix,
		SpongeIV:          mainnetIV3W,
	}

	signature, _, retCode := Signature(privateKey, nil, message.ToBytes(), ECC_CURVE_PASTA)

	if retCode != SUCCESS {
		t.Error(retCode)
		return
	}
	fmt.Println("r in base 16 : ", hex.EncodeToString(signature[:32]))
	fmt.Println("s in base 16 : ", hex.EncodeToString(signature[32:]))

	rBigInt := new(big.Int).SetBytes(signature[:32])
	sBigInt := new(big.Int).SetBytes(signature[32:])

	fmt.Println("r in base 10 : ", rBigInt)
	fmt.Println("s in base 10 : ", sBigInt)

}
