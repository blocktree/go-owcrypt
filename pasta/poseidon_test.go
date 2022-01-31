package pasta

import "testing"

func TestPoseidon(t *testing.T) {
	var input = Field{0x34786d38fffffffd, 0x992c350be41914ad, 0xffffffffffffffff, 0x3fffffffffffffff}
	var iv_test = [3]Field{
		{0x67097c15f1a46d64, 0xc76fd61db3c20173, 0xbdf9f393b220a17, 0x10c0e352378ab1fd},
		{0x57dbbe3a20c2a32, 0x486f1b93a41e04c7, 0xa21341e97da1bdc1, 0x24a095608e4bf2e9},
		{0xd4559679d839ff92, 0x577371d495f4d71b, 0x3227c7db607b3ded, 0x2ca212648a12291e},
	}
	ctx := Poseidon3WInit(iv_test[:])
	PoseidonUpdate(&ctx, []Field{input})
	PoseidonDigest(&ctx)
}
