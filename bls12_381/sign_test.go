package bls12_381

import (
	"encoding/hex"
	"fmt"
	sig "github.com/drand/kyber/sign/bls"
	"github.com/drand/kyber/util/random"
	"testing"
)


func Test_sig(t *testing.T) {
	pairing := NewBLS12381Suite()
	scheme := sig.NewSchemeOnG2(pairing)
	_, pubkey:=scheme.NewKeyPair(random.New())
	pribytes, _ := hex.DecodeString("1078e74b73ca24796808f4d856c0bdf8a40483f41e52765640968b89fc73700d")
	prikey := NewScalar(pribytes)

	pubkey = NullKyberG1().Mul(prikey, nil)
	pub_bytes, _ := pubkey.MarshalBinary()
	fmt.Println("pub  :: ",hex.EncodeToString(pub_bytes))
	fmt.Println(pubkey.String())
	pb, _ := hex.DecodeString("8eaee6cd97fc5b2f4aede9f257d61aa48768180561cf470eabba8ffbf8a356035e5b0993cf238096b1dc16603088f84f")
	chk := NullKyberG1()
	chk.UnmarshalBinary(pb)
	fmt.Println("chk : ", chk.String())
	//msg, _ := hex.DecodeString("d396bc63594bff4dab6d91b59efa8491eacbd8003f6fff9b2594a058ca0844156348539d4a324732b0dad6f2f4c3cbb11f596552c6f1e088543031e7085174c4ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb")
	msg, _ := hex.DecodeString("8eaee6cd97fc5b2f4aede9f257d61aa48768180561cf470eabba8ffbf8a356035e5b0993cf238096b1dc16603088f84fd396bc63594bff4dab6d91b59efa8491eacbd8003f6fff9b2594a058ca0844156348539d4a324732b0dad6f2f4c3cbb11f596552c6f1e088543031e7085174c4ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb")
	signature, err := scheme.Sign(prikey, msg)

fmt.Println(hex.EncodeToString(signature))
fmt.Println(err)



}

func Test_add_sig(t *testing.T) {
	sig1, _ := hex.DecodeString("809f00c133e64d4929de228292a80307b8f5195fc74b7824e73c04b008e21d8c6ff9c4701f5f659ae1c11320e3cc6b4b03a2cd3260987add74fa2aec4ba1da19d40824b4c1c175c94e1926961ff800ff9f4e4ee50260434173c458ece65f7c35")
	sig2, _ := hex.DecodeString("8717efd4477d434669bd29133827047fc2ed657847e42d7aa6670416c7bfcad1fe43d9676de39d2e31bc4cba2e7c16ff12d2e386fcca5f9accae7012b84abbf1a48a0af65b0705d4b22cd7b0f8b20a5384279f3cf7dcf2513e43be5dcc4d079c")
	pairing := NewBLS12381Suite()
	scheme := sig.NewSchemeOnG2(pairing)

	ret, err := scheme.AggregateSignatures(sig1, sig2)
	fmt.Println(err)
	fmt.Println(hex.EncodeToString(ret))

}