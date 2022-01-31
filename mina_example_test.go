package owcrypt

import (
	"encoding/hex"
	"fmt"
	"github.com/blocktree/go-owcrypt/pasta"
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
		Transaction: transForTest,
		SpongeIV:    ivForTest,
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
