package owcrypt

import (
	"encoding/hex"
	"fmt"
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