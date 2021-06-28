package owcrypt

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

func Test_BLS_12381_basic(t *testing.T) {
	prikey, _ := hex.DecodeString("1078e74b73ca24796808f4d856c0bdf8a40483f41e52765640968b89fc73700d")
	msg, _ := hex.DecodeString("d396bc63594bff4dab6d91b59efa8491eacbd8003f6fff9b2594a058ca0844156348539d4a324732b0dad6f2f4c3cbb11f596552c6f1e088543031e7085174c4ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb")
	except_pub := "8eaee6cd97fc5b2f4aede9f257d61aa48768180561cf470eabba8ffbf8a356035e5b0993cf238096b1dc16603088f84f"
	except_sig  := "a80bceb6e5ea9e8bfd1fca8318e9170af4941ed232336c4ed56430b645683290ca4e936aacd4d2b1a4abfef9045e034f00c22d5ede8b15b7bf30f431727a51d30a27eaab47e223fbd1b8ab60ff0023f93d7c1dc3b0aa3ca9919c4dcba7219c48"
	pubkey, err := GenPubkey(prikey, ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_NUL)
	if err != SUCCESS {
		t.Error("gen key failed")
		return
	}
	if hex.EncodeToString(pubkey) != except_pub {
		t.Error("public key wrong")
	}

	sig, _, err := Signature(prikey,nil, msg, ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_NUL)
	if err != SUCCESS {
		t.Error("sign failed")
		return
	}
	if hex.EncodeToString(sig) != except_sig {
		t.Error("signature wrong")
		return
	}

	pass := Verify(pubkey, nil, msg, sig, ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_NUL)
	if pass != SUCCESS {
		t.Error("verify failed")
		return
	}

	fmt.Println("=====SUCCESS=====")


}




func Test_BLS_12381_aug(t *testing.T) {
	prikey, _ := hex.DecodeString("1078e74b73ca24796808f4d856c0bdf8a40483f41e52765640968b89fc73700d")
	msg, _ := hex.DecodeString("d396bc63594bff4dab6d91b59efa8491eacbd8003f6fff9b2594a058ca0844156348539d4a324732b0dad6f2f4c3cbb11f596552c6f1e088543031e7085174c4ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb")
	except_pub := "8eaee6cd97fc5b2f4aede9f257d61aa48768180561cf470eabba8ffbf8a356035e5b0993cf238096b1dc16603088f84f"
	except_sig  := "809f00c133e64d4929de228292a80307b8f5195fc74b7824e73c04b008e21d8c6ff9c4701f5f659ae1c11320e3cc6b4b03a2cd3260987add74fa2aec4ba1da19d40824b4c1c175c94e1926961ff800ff9f4e4ee50260434173c458ece65f7c35"
	pubkey, err := GenPubkey(prikey, ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_AUG)
	if err != SUCCESS {
		t.Error("failed")
		return
	}
	if hex.EncodeToString(pubkey) != except_pub {
		t.Error("public key wrong")
	}

	sig, _, err := Signature(prikey,nil, msg, ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_AUG)
	if err != SUCCESS {
		t.Error("failed")
		return
	}
	if hex.EncodeToString(sig) != except_sig {
		t.Error("public key wrong")
		return
	}

	pass := Verify(pubkey, nil, msg, sig, ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_AUG)
	if pass != SUCCESS {
		t.Error("verify failed")
		return
	}
	fmt.Println("=====SUCCESS=====")
}

func TestAggregateSignatures(t *testing.T) {
	sig1, _ := hex.DecodeString("809f00c133e64d4929de228292a80307b8f5195fc74b7824e73c04b008e21d8c6ff9c4701f5f659ae1c11320e3cc6b4b03a2cd3260987add74fa2aec4ba1da19d40824b4c1c175c94e1926961ff800ff9f4e4ee50260434173c458ece65f7c35")
	sig2, _ := hex.DecodeString("8717efd4477d434669bd29133827047fc2ed657847e42d7aa6670416c7bfcad1fe43d9676de39d2e31bc4cba2e7c16ff12d2e386fcca5f9accae7012b84abbf1a48a0af65b0705d4b22cd7b0f8b20a5384279f3cf7dcf2513e43be5dcc4d079c")
	except := "b9d54c3041c10956472a163ba61d64e0aeba97c91f6ff319dbb758770311d42928369097c88685e3fe16524a3abf25cf095e9cbf5f3953396cacc97c8ac1b26a6bdec7993474a542b86adea5e91c7f63c329632a371ef19f524b184c82f2ed73"

	aggregate, ret := AggregateSignatures(ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_NUL, sig1, sig2)
	if ret != SUCCESS {
		t.Error("aggregate failed")
		return
	}
	if hex.EncodeToString(aggregate) != except {
		t.Error("result error")
		return
	}

	aggregate, ret = AggregateSignatures(ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_AUG, sig1, sig2)
	if ret != SUCCESS {
		t.Error("aggregate failed")
		return
	}
	if hex.EncodeToString(aggregate) != except {
		t.Error("result error")
		return
	}
	fmt.Println("=====SUCCESS=====")
}

const CHIA_GROUP_ORDER = "73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001"
const CHIA_DEFAULT_HIDDEN_PUZZLE_HASH = "711d6c4e32c92e53179b199484cf8c897542bc57f2b22582799f9d657eec4699"

func chia_complement_bytes_to_bigint(data []byte) *big.Int {
	if data[0] & 0x80 == 0 {
		return new(big.Int).SetBytes(data)
	}
	data[0] &= 0x7F
	data_big := new(big.Int).SetBytes(data)
	data_big = data_big.Sub(data_big, big.NewInt(1))
	data_bytes := data_big.Bytes()
	data_bytes_len := len(data_bytes)
	if data_bytes_len < 32 {
		for i := 0; i < 32 -data_bytes_len; i ++ {
			data_bytes = append([]byte{0}, data_bytes...)
		}
	}
	for i, _ := range data_bytes {
		data_bytes[i] ^= 0xFF
	}
	data_bytes[0] &= 0x7F
	data_big = new(big.Int).SetBytes(data_bytes)
	return data_big.Neg(data_big)
}


func chia_calculate_synthetic_offset(public_key, hidden_puzzle_hash []byte) *big.Int {
	offset := chia_complement_bytes_to_bigint(Hash(append(public_key, hidden_puzzle_hash...), 0, HASH_ALG_SHA256))
	fmt.Println("offset :  ", offset.Text(10))
	groupOrderBytes, _ := hex.DecodeString(CHIA_GROUP_ORDER)
	groupOrder := new(big.Int).SetBytes(groupOrderBytes)
	offset = offset.Mod(offset, groupOrder)
	return offset
}


func chia_calculate_synthetic_secret_key(prikey []byte) []byte {
	default_hidden_puzzle_hash, _ := hex.DecodeString(CHIA_DEFAULT_HIDDEN_PUZZLE_HASH)
	secret_exponent := new(big.Int).SetBytes(prikey)
	public_key, _ := GenPubkey(prikey, ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_AUG)
	synthetic_offset := chia_calculate_synthetic_offset(public_key, default_hidden_puzzle_hash)
	fmt.Println("test : ", synthetic_offset.Text(10))
	synthetic_secret_exponent := new(big.Int).Add(secret_exponent, synthetic_offset)
	groupOrderBytes, _ := hex.DecodeString(CHIA_GROUP_ORDER)
	groupOrder := new(big.Int).SetBytes(groupOrderBytes)
	synthetic_secret_exponent = synthetic_secret_exponent.Mod(synthetic_secret_exponent, groupOrder)

	return synthetic_secret_exponent.Bytes()
}

func Test_BLS_12381_aug_tmp(t *testing.T) {
	prikey, _ := hex.DecodeString("0f2ce66096fe2aee7354ec6df069ceba6635dbf0c3064d969dfaa025eab0abbe")
	pub, _ := GenPubkey(prikey, ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_AUG)
	fmt.Println(hex.EncodeToString(pub))

	synthetic_secret_key := chia_calculate_synthetic_secret_key(prikey)
	fmt.Println("synthetic_secret_key : ", hex.EncodeToString(synthetic_secret_key))
	pub, _ = GenPubkey(synthetic_secret_key, ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_AUG)
	fmt.Println("true pub : ", hex.EncodeToString(pub))

	synthetic_secret_key, _ = hex.DecodeString("505edad01152517ab5b43e0d8e349304dee143626b2553021ae588bb6a946f7c")
	msg, _ := hex.DecodeString("8daca921cf806da7c4ae31fa388340326681c32cb43e64f456399d6b572d8676f216bda1dff44181f125d0bd994cf6c8dd4fa0124aeb1929f64dcc263bbed481ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb ")
	sig,_, ret := Signature(synthetic_secret_key, nil, msg, ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_AUG)

	fmt.Println(ret)
	fmt.Println(hex.EncodeToString(sig))

	pass := Verify(pub,nil,msg,sig,ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_AUG)

	fmt.Println(pass)
	//if hex.EncodeToString(pubkey) != except_pub {
	//	t.Error("public key wrong")
	//}

	//sig, _, err := Signature(prikey,nil, msg, ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_AUG)
	//if err != SUCCESS {
	//	t.Error("failed")
	//	return
	//}
	//if hex.EncodeToString(sig) != except_sig {
	//	t.Error("public key wrong")
	//	return
	//}
	//
	//pass := Verify(pubkey, nil, msg, sig, ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_AUG)
	//if pass != SUCCESS {
	//	t.Error("verify failed")
	//	return
	//}
	//fmt.Println("=====SUCCESS=====")
}


func Test_puzzle_hash(t *testing.T) {
	public_key, _ := hex.DecodeString("ae1cc8cb032229ff92261067e5136e003fff0a468c490b073926c32744196c7931bb29d83b9788f61da5eed5ad394c5a")
	hidden_puzzle_hash, _ := hex.DecodeString(CHIA_DEFAULT_HIDDEN_PUZZLE_HASH)
	offset := chia_calculate_synthetic_offset(public_key,hidden_puzzle_hash)

	pubkey_for_exp, _ := GenPubkey(offset.Bytes(), ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_AUG)

	fmt.Println(hex.EncodeToString(pubkey_for_exp))

	ret,_ := Point_mulBaseG_add(public_key,offset.Bytes(),ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_AUG)
	fmt.Println(hex.EncodeToString(ret))
}


func Test_tmp(t *testing.T) {
	pri0, _ := hex.DecodeString("4622543fac0ab44cb84a9d40e69ced1431afdfd08b80af1314b5d604c4d08410")
	pub, _ := GenPubkey(pri0, ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_AUG)
	fmt.Println(hex.EncodeToString(pub))
	fmt.Println("priiiii : ", hex.EncodeToString(chia_calculate_synthetic_secret_key(pri0)))
	sig0, _ := hex.DecodeString("9298dfe538bca2c2f2cac376c204f75189a7d50e56a6cafa4fce41f0212bb505de0a0bca33c455ec0bde111adea83feb03f7150a9ec889ab27bb23fbf21af49284613e746cfa1ff30bb59ed5eac55cce9c4e1e57e08fc649439966fee8e52d8c")
	msg0, _ := hex.DecodeString("c50435475642f2b2b1f33f21f372cf672881b735f5e0391bdea7e408a88054eba834772c7e4863562d5f8fa285b0f712fbc18f5109f30881973d38d92185cad9ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb")

	chk0, _, ret := Signature(chia_calculate_synthetic_secret_key(pri0), nil, msg0, ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_AUG)
	fmt.Println("ret : ", ret)
	fmt.Println("chk0 : ", hex.EncodeToString(chk0))

	pri1, _ := hex.DecodeString("4622543fac0ab44cb84a9d40e69ced1431afdfd08b80af1314b5d604c4d08410")
	sig1, _ := hex.DecodeString("abe59e45ea216e569e6b31861e3b97516aacda7ea8712cc9fd797dc15479df49b750391b8f248066008fb1ea8b8106dc028eb71bcc90015059cd8cfbd014b180e5e44b2b1f929848d783a294996ee0dbeb443725a23f223ce5d2948e2fe0741a")
	msg1, _ := hex.DecodeString("6495ba7315b746762e0d9d516f8d620fdd68c67f1c810621ee8d4d432c51fd8ac8a6b8e536db98ee2ce2616c37eabd9d8cd79688d8e45f8ebb551fcca086cc32ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb")
	chk1, _, ret := Signature(chia_calculate_synthetic_secret_key(pri1), nil, msg1, ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_AUG)
	fmt.Println("ret : ", ret)
	fmt.Println("chk1 : ", hex.EncodeToString(chk1))

	pri2, _ := hex.DecodeString("4622543fac0ab44cb84a9d40e69ced1431afdfd08b80af1314b5d604c4d08410")
	sig2, _ := hex.DecodeString("9095c1721482b0b96228652b81998f90351f6dd3e8df8650ab11ef2cb4583dcbb5ff5f42c4c58800a8dbe82a2b74cce3144f4ae0013fe1ff089a9a9cc1a836dba421cec027261194c1a73d2e4bd1789fe3a3c9ad02125bf7b3f5d6fd4289c754")
	msg2, _ := hex.DecodeString("6495ba7315b746762e0d9d516f8d620fdd68c67f1c810621ee8d4d432c51fd8a3f5b1ff7e909deb8722c2876181ffed748fa3dcea1410dba7bde36515b0fa3dbccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb")
	chk2, _, ret := Signature(chia_calculate_synthetic_secret_key(pri2), nil, msg2, ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_AUG)
	fmt.Println("ret : ", ret)
	fmt.Println("chk2 : ", hex.EncodeToString(chk2))

	sig, _ := AggregateSignatures(ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_AUG,sig0, sig1, sig2)

	fmt.Println(hex.EncodeToString(sig))
}

func Test_conv(t *testing.T) {
	in, _ := hex.DecodeString("80b67b0974e07dc0930a72b2c67bd02de00fb75ea1c3b142bec22ac2f7996aae")
	ret := chia_complement_bytes_to_bigint(in)

	fmt.Println(ret.Text(10))
}

func Test_ed25519_add(t *testing.T) {
	point1,_ := hex.DecodeString("302c3707dace5e5191c481bb6e9467833a2ce8890d5de5ba57e85916ac841316")
	point2, _ := hex.DecodeString("f8fb0656c56f55545b6c306a617a46bc77928f9a8c2b2f656fa2942e047381fd")
	//fb6e804d8178e2c407eac41a2a36df76e83547c63a7d202270bd32bceb038e7a
	point,retcode := Point_add(point1, point2, ECC_CURVE_ED25519)

	fmt.Println(retcode)
	fmt.Println(hex.EncodeToString(point))
}

func Test_ed(t *testing.T) {
	prikey,_ := hex.DecodeString("186fdc45db17672d005622038f4c9e1c424acee661108fc70adee9fb7871a556")

	fmt.Println(hex.EncodeToString(prikey))

	pubkey, _ := GenPubkey(prikey, ECC_CURVE_ED25519)
	fmt.Println(hex.EncodeToString(pubkey))

	msg := []byte{1,2,3}

	sig, _, _ := Signature(prikey, nil, msg, ECC_CURVE_ED25519)

	fmt.Println(hex.EncodeToString(sig))

	pass := Verify(pubkey, nil, msg, sig, ECC_CURVE_ED25519_NORMAL)

	fmt.Println(pass)
}


