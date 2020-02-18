package owcrypt

import (
	"bytes"
	"encoding/hex"
	"flag"
	"os"
	"testing"
)

var (
	testCurve   *curveCfg
	testPrivHex = "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032"
	testmsgStr  = "77015816143ee627f4fa410b6dad2bdb9fcbdf1e061a452a686b8711a484c5d7"
)

type curveCfg struct {
	curve uint32
	name  string
}

func TestMain(m *testing.M) {
	flag.Parse()

	curvs := []*curveCfg{
		{
			ECC_CURVE_SECP256K1, "ECC_CURVE_SECP256K1",
		},
		{
			ECC_CURVE_SECP256R1, "ECC_CURVE_SECP256R1",
		},
		{
			ECC_CURVE_PRIMEV1, "ECC_CURVE_PRIMEV1",
		},
		{
			ECC_CURVE_NIST_P256, "ECC_CURVE_NIST_P256",
		},
		{
			ECC_CURVE_SM2_STANDARD, "ECC_CURVE_SM2_STANDARD",
		},
	}

	for _, curve := range curvs {
		testCurve = curve
		m.Run()
	}
	os.Exit(0)
}
func TestRecoverPubkey(t *testing.T) {
	testmsg, _ := hex.DecodeString(testmsgStr)
	d, _ := hex.DecodeString(testPrivHex)
	pubkey, err := GenPubkey(d, testCurve.curve)
	if err != SUCCESS {
		t.Fatalf("%x", err)
	}
	t.Logf("pub: %x", pubkey)

	sig, v, err := Signature(d, nil, testmsg, testCurve.curve)
	if err != SUCCESS {
		t.Fatalf("%x", err)
	}
	t.Logf("_v_: %x", v)
	t.Logf("sig: %x", sig)
	sig = append(sig, v)

	t.Logf("sig: %x", sig)
	rPubkey, err := RecoverPubkey(sig, testmsg, testCurve.curve)
	if err != SUCCESS {
		t.Fatalf("recover error: %d", err)
	}
	if !bytes.Equal(rPubkey, pubkey) {
		t.Fatalf("pubkey mismatch: \nwant: %x \nhave: %x\ncurve(%v)", pubkey, rPubkey, testCurve)
	}
}
