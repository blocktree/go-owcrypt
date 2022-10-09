/*
 * Copyright 2020 The openwallet Authors
 * This file is part of the openwallet library.
 *
 * The openwallet library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The openwallet library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 */
package owcrypt

import (
	"encoding/hex"
	"errors"
	"github.com/blocktree/go-owcrypt/bls12_381"
	"github.com/blocktree/go-owcrypt/eddsa"
	"github.com/blocktree/go-owcrypt/pasta"
)

func GenPubkey(prikey []byte, typeChoose uint32) (pubkey []byte, ret uint16) {
	var err error
	switch typeChoose {
	case ECC_CURVE_ED25519_NORMAL:
		pubkey, err = eddsa.CURVE25519_genPub(prikey)
		break
	case ECC_CURVE_ED25519:
		pubkey, err = eddsa.ED25519_genPub(prikey)
		break
	case ECC_CURVE_X25519:
		pubkey, err = eddsa.X25519_genPub(prikey)
		break
	case ECC_CURVE_CURVE25519_SHA256:
		pubkey, err = eddsa.CURVE25519_sha256_genPub(prikey)
		break
	case ECC_CURVE_SECP256K1:
		pubkey, err = genPublicKey(prikey, "secp256k1")
		break
	case ECC_CURVE_SECP256R1:
		pubkey, err = genPublicKey(prikey, "secp256r1")
		break
	case ECC_CURVE_SM2_STANDARD:
		pubkey, err = genPublicKey(prikey, "sm2_std")
		break
	case ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_AUG, ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_NUL:
		pubkey, err = bls12_381.GenPublicKey(prikey)
		break
	case ECC_CURVE_PASTA:
		pubkey, err = pasta.GenPublicKey(prikey)
		break
	default:
		return nil, ECC_WRONG_TYPE
	}

	if err != nil {
		if err == ErrPrivateKeyIllegal {
			return nil, ECC_PRIKEY_ILLEGAL
		}
		if err == ErrUnknownCurve {
			return nil, ECC_WRONG_TYPE
		}
		return nil, FAILURE
	}
	ret = SUCCESS
	return
}

func Signature(prikey []byte, ID []byte, message []byte, typeChoose uint32) (signature []byte, v byte, ret uint16) {
	var err error
	switch typeChoose {
	case ECC_CURVE_ED25519_NORMAL:
		signature, err = eddsa.CURVE25519_sign(prikey, message)
		break
	case ECC_CURVE_ED25519:
		signature, err = eddsa.ED25519_sign(prikey, message)
		break
	case ECC_CURVE_X25519:
		signature, err = eddsa.X25519_sign(prikey, message)
		break
	case ECC_CURVE_CURVE25519_SHA256:
		signature, err = eddsa.CURVE25519_sha256_sign(prikey, message)
		break
	case ECC_CURVE_SECP256K1:
		signature, v, err = sign(prikey, nil, message, "secp256k1")
		break
	case ECC_CURVE_SECP256R1:
		signature, v, err = sign(prikey, nil, message, "secp256r1")
		break
	case ECC_CURVE_SM2_STANDARD:
		signature, v, err = sign(prikey, ID, message, "sm2_std")
		break
	case ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_NUL:
		message = append([]byte(BASIC_SCHEME_DST), message...)
		signature, err = bls12_381.Sign(prikey, message)
		break
	case ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_AUG:
		pubkey, _ := GenPubkey(prikey, typeChoose)
		message = append(pubkey, message...)
		message = append([]byte(AUG_SCHEME_DST), message...)
		signature, err = bls12_381.Sign(prikey, message)
		break
	case ECC_CURVE_PASTA:
		signature, err = pasta.Sign(prikey, message)
		break
	default:
		return nil, 0, ECC_WRONG_TYPE
	}

	if err != nil {
		if err == ErrPrivateKeyIllegal {
			return nil, 0, ECC_PRIKEY_ILLEGAL
		}
		if err == ErrUnknownCurve {
			return nil, 0, ECC_WRONG_TYPE
		}
		if err == ErrMessageIllegal {
			return nil, 0, MESSAGE_ILLEGAL
		}
		return nil, 0, FAILURE
	}

	ret = SUCCESS
	return
}

func AggregateSignatures(typeChoose uint32, sigs ...[]byte) ([]byte, uint16) {
	if len(sigs) == 0 {
		return nil, FAILURE
	}

	aggregate := make([]byte, 0)
	var err error
	switch typeChoose {
	case ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_NUL, ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_AUG:
		aggregate, err = bls12_381.AggregateSignatures(sigs...)
		if err != nil {
			return nil, FAILURE
		}
		break
	default:
		return nil, ECC_WRONG_TYPE
		break
	}

	return aggregate, SUCCESS
}

func Verify(pubkey []byte, ID []byte, message []byte, signature []byte, typeChoose uint32) uint16 {
	var pass bool
	switch typeChoose {
	case ECC_CURVE_ED25519_NORMAL:
		pass = eddsa.CURVE25519_verify(pubkey, message, signature)
		break
	case ECC_CURVE_ED25519:
		pass = eddsa.ED25519_verify(pubkey, message, signature)
		break
	case ECC_CURVE_X25519:
		pass = eddsa.X25519_verify(pubkey, message, signature)
		break
	case ECC_CURVE_CURVE25519_SHA256:
		pass = eddsa.CURVE25519_sha256_verify(pubkey, message, signature)
		break
	case ECC_CURVE_SECP256K1:
		pass = verify(pubkey, nil, message, signature, "secp256k1")
		break
	case ECC_CURVE_SECP256R1:
		pass = verify(pubkey, nil, message, signature, "secp256r1")
		break
	case ECC_CURVE_SM2_STANDARD:
		pass = verify(pubkey, ID, message, signature, "sm2_std")
		break
	case ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_NUL:
		message = append([]byte(BASIC_SCHEME_DST), message...)
		pass = bls12_381.Verify(pubkey, message, signature)
		break
	case ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_AUG:
		message = append(pubkey, message...)
		message = append([]byte(AUG_SCHEME_DST), message...)
		pass = bls12_381.Verify(pubkey, message, signature)
		break
	case ECC_CURVE_PASTA:
		pass = pasta.Verify(pubkey, message, signature)
		break
	default:
		return ECC_WRONG_TYPE
	}
	if pass {
		return SUCCESS
	}

	return FAILURE
}

func Encryption(pubkey []byte, plain []byte, typeChoose uint32) (cipher []byte, ret uint16) {

	var err error

	switch typeChoose {
	case ECC_CURVE_SM2_STANDARD:
		cipher, err = encrypt(pubkey, plain, "sm2_std")
		break
	default:
		return nil, ECC_WRONG_TYPE
	}

	switch err {
	case ErrPublicKeyIllegal:
		return nil, ECC_PUBKEY_ILLEGAL
		break
	case ErrMessageIllegal:
		return nil, MESSAGE_ILLEGAL
		break
	case ErrUnknownCurve:
		return nil, ECC_WRONG_TYPE
		break
	}

	ret = SUCCESS
	return
}

func Decryption(prikey []byte, cipher []byte, typeChoose uint32) (plain []byte, ret uint16) {
	var err error

	switch typeChoose {
	case ECC_CURVE_SM2_STANDARD:
		plain, err = decrypt(prikey, cipher, "sm2_std")
		break
	default:
		return nil, ECC_WRONG_TYPE
	}

	switch err {
	case ErrPrivateKeyIllegal:
		return nil, ECC_PRIKEY_ILLEGAL
		break
	case ErrMessageIllegal:
		return nil, MESSAGE_ILLEGAL
		break
	case ErrUnknownCurve:
		return nil, ECC_WRONG_TYPE
		break
	}

	ret = SUCCESS
	return
}

///////////////////////////////////////////////////////////密钥协商////////////////////////////////////////////////////////
func KeyAgreement_initiator_step1(typeChoose uint32) (tmpPrikeyInitiator, tmpPubkeyInitiator []byte) {
	tmpPrikeyInitiator, tmpPubkeyInitiator = sm2_std_ka_initiaor_step1()
	return
}

func KeyAgreement_initiator_step2(IDinitiator []byte,
	IDresponder []byte,
	prikeyInitiator []byte,
	pubkeyInitiator []byte,
	pubkeyResponder []byte,
	tmpPrikeyInitiator []byte,
	tmpPubkeyInitiator []byte,
	tmpPubkeyResponder []byte,
	Sin []byte,
	keylen uint16,
	typeChoose uint32) (key, Sout []byte, ret uint16) {

	if typeChoose != ECC_CURVE_SM2_STANDARD {
		return nil, nil, ECC_WRONG_TYPE
	}

	var err error
	key, Sout, err = sm2_std_ka_initiator_step2(IDinitiator, IDresponder, prikeyInitiator, pubkeyInitiator, pubkeyResponder, tmpPrikeyInitiator, tmpPubkeyInitiator, tmpPubkeyResponder, Sin, keylen)
	if err != nil {
		ret = FAILURE
		return
	}

	ret = SUCCESS
	return
}

func KeyAgreement_responder_step1(IDinitiator []byte,
	IDresponder []byte,
	prikeyResponder []byte,
	pubkeyResponder []byte,
	pubkeyInitiator []byte,
	tmpPubkeyInitiator []byte,
	keylen uint16,
	typeChoose uint32) (key, tmpPubkeyResponder, Sinner, Souter []byte, ret uint16) {

	if typeChoose != ECC_CURVE_SM2_STANDARD {
		ret = ECC_WRONG_TYPE
		return
	}

	var err error

	key, tmpPubkeyResponder, Sinner, Souter, err = sm2_std_ka_responder_step1(IDinitiator, IDresponder, prikeyResponder, pubkeyResponder, pubkeyInitiator, tmpPubkeyInitiator, nil, keylen)

	if err != nil {
		ret = FAILURE
		return
	}

	ret = SUCCESS
	return
}

func KeyAgreement_responder_ElGamal_step1(IDinitiator []byte,
	IDresponder []byte,
	prikeyResponder []byte,
	pubkeyResponder []byte,
	pubkeyInitiator []byte,
	tmpPubkeyInitiator []byte,
	keylen uint16,
	random []byte,
	typeChoose uint32) (key, tmpPubkeyResponder, Sinner, Souter []byte, ret uint16) {

	if typeChoose != ECC_CURVE_SM2_STANDARD {
		ret = ECC_WRONG_TYPE
		return
	}

	var err error

	key, tmpPubkeyResponder, Sinner, Souter, err = sm2_std_ka_responder_step1(IDinitiator, IDresponder, prikeyResponder, pubkeyResponder, pubkeyInitiator, tmpPubkeyInitiator, random, keylen)

	if err != nil {
		ret = FAILURE
		return
	}

	ret = SUCCESS
	return
}

func KeyAgreement_responder_step2(Sinitiator []byte, Sresponder []byte, typeChoose uint32) uint16 {
	if typeChoose != ECC_CURVE_SM2_STANDARD {
		return ECC_WRONG_TYPE
	}

	err := sm2_std_ka_responder_step2(Sinitiator, Sresponder)

	if err != nil {
		return FAILURE
	}

	return SUCCESS
}

func Point_mulBaseG(scalar []byte, typeChoose uint32) []byte {
	if scalar == nil || len(scalar) != 32 {
		return nil
	}
	switch typeChoose {
	case ECC_CURVE_SECP256K1:
		ret, _ := genPublicKey(scalar, "secp256k1")
		return PointCompress(ret, typeChoose)
		break
	case ECC_CURVE_SECP256R1:
		ret, _ := genPublicKey(scalar, "secp256r1")
		return PointCompress(ret, typeChoose)
		break
	case ECC_CURVE_SM2_STANDARD:
		ret, _ := genPublicKey(scalar, "sm2_std")
		return PointCompress(ret, typeChoose)
		break
	case ECC_CURVE_ED25519:
		ret, _ := eddsa.ED25519_genPub(scalar)
		return ret
		break
	case ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_NUL, ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_AUG:
		ret, _ := bls12_381.GenPublicKey(scalar)
		return ret
		break
	case ECC_CURVE_PASTA:
		ret, _ := pasta.GenPublicKey(scalar)
		return PointCompress(ret, typeChoose)
		break
	default:
		return nil
	}
	return nil
}

func Point_mulBaseG_add(pointin, scalar []byte, typeChoose uint32) (point []byte, isinfinity bool) {
	if scalar == nil || len(scalar) != 32 {
		return nil, false
	}

	switch typeChoose {
	case ECC_CURVE_SECP256K1:
		return MulBaseG_Add(pointin, scalar, "secp256k1")
		break
	case ECC_CURVE_SECP256R1:
		return MulBaseG_Add(pointin, scalar, "secp256r1")
		break
	case ECC_CURVE_SM2_STANDARD:
		return MulBaseG_Add(pointin, scalar, "sm2_std")
		break
	case ECC_CURVE_ED25519:
		var point1, s, point2 [32]byte
		copy(point1[:], pointin)
		copy(s[:], scalar)
		infinity := eddsa.ScalarMultBaseAdd(&point1, &s, &point2)
		if infinity {
			return nil, true
		}
		return point2[:], false
		break
	case ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_NUL, ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_AUG:
		return bls12_381.ScalarMultBaseAdd(pointin, scalar)
		break
	case ECC_CURVE_PASTA:
		pointout, _ := pasta.PointMulBaseGAdd(pointin, scalar)
		return pointout, false
	default:
		return nil, false
	}
	return nil, false
}

func Point_add(point1, point2 []byte, typeChoose uint32) ([]byte, uint16) {
	if typeChoose == ECC_CURVE_ED25519 {
		if len(point1) != 32 || len(point2) != 32 {
			return nil, FAILURE
		}
	} else {
		if len(point1) == 33 {
			point1 = PointDecompress(point1, typeChoose)[1:]
		} else if len(point1) == 65 {
			point1 = point1[1:]
		} else if len(point1) != 64 {
			return nil, FAILURE
		}

		if len(point2) == 33 {
			point2 = PointDecompress(point2, typeChoose)[1:]
		} else if len(point2) == 65 {
			point2 = point2[1:]
		} else if len(point2) != 64 {
			return nil, FAILURE
		}
	}
	switch typeChoose {
	case ECC_CURVE_SECP256K1:
		point, is_infinity := Add(point1, point2, "secp256k1")
		if is_infinity {
			return nil, FAILURE
		}
		return point, SUCCESS
		break
	case ECC_CURVE_SECP256R1:
		point, is_infinity := Add(point1, point2, "secp256r1")
		if is_infinity {
			return nil, FAILURE
		}
		return point, SUCCESS
		break
	case ECC_CURVE_SM2_STANDARD:
		point, is_infinity := Add(point1, point2, "sm2_std")
		if is_infinity {
			return nil, FAILURE
		}
		return point, SUCCESS
		break
	case ECC_CURVE_ED25519:
		var P1, P2, P [32]byte
		copy(P1[:], point1)
		copy(P2[:], point2)
		infinity := eddsa.Point_add(&P1, &P2, &P)
		if infinity {
			return nil, FAILURE
		}
		return P[:], SUCCESS
		break
	case ECC_CURVE_PASTA:
		pout, _ := pasta.PointAdd(point1, point2)
		return pout, SUCCESS
		break
	default:
		return nil, FAILURE
	}
	return nil, FAILURE
}

func Point_mul(pointin, scalar []byte, typeChoose uint32) ([]byte, uint16) {
	if typeChoose == ECC_CURVE_ED25519 {
		if len(pointin) != 32 || len(scalar) != 32 {
			return nil, FAILURE
		}
	} else {
		if len(pointin) == 33 {
			pointin = PointDecompress(pointin, typeChoose)[1:]
		} else if len(pointin) == 65 {
			pointin = pointin[1:]
		} else if len(pointin) != 64 {
			return nil, FAILURE
		}

		if len(scalar) != 32 {
			return nil, FAILURE
		}
	}
	switch typeChoose {
	case ECC_CURVE_SECP256K1:
		point, is_infinity := Mul(pointin, scalar, "secp256k1")
		if is_infinity {
			return nil, FAILURE
		}
		return point, SUCCESS
		break
	case ECC_CURVE_SECP256R1:
		point, is_infinity := Mul(pointin, scalar, "secp256r1")
		if is_infinity {
			return nil, FAILURE
		}
		return point, SUCCESS
		break
	case ECC_CURVE_SM2_STANDARD:
		point, is_infinity := Mul(pointin, scalar, "sm2_std")
		if is_infinity {
			return nil, FAILURE
		}
		return point, SUCCESS
		break
	//case ECC_CURVE_ED25519:
	//	var P1, P2, P [32]byte
	//	copy(P1[:], pointin)
	//	copy(P2[:], scalar)
	//	infinity := eddsa.Point_add(&P1, &P2, &P)
	//	if infinity {
	//		return nil, FAILURE
	//	}
	//	return P[:], SUCCESS
	//	break
	case ECC_CURVE_PASTA:
		pout, _ := pasta.PointMul(pointin, scalar)
		return pout, SUCCESS
		break
	default:
		return nil, FAILURE
	}
	return nil, FAILURE
}

func GetCurveOrder(typeChoose uint32) []byte {
	switch typeChoose {
	case ECC_CURVE_SECP256K1:
		order, _ := hex.DecodeString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
		return order
		break
	case ECC_CURVE_SECP256R1:
		order, _ := hex.DecodeString("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
		return order
		break
	case ECC_CURVE_SM2_STANDARD:
		order, _ := hex.DecodeString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123")
		return order
		break
	case ECC_CURVE_ED25519:
		order, _ := hex.DecodeString("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed")
		return order
		break
	case ECC_CURVE_PASTA:
		order, _ := hex.DecodeString("40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001")
		return order
		break
	default:
		return nil
	}

	return nil
}

func PointCompress(point []byte, typeChoose uint32) []byte {
	if typeChoose != ECC_CURVE_SECP256K1 && typeChoose != ECC_CURVE_SECP256R1 && typeChoose != ECC_CURVE_SM2_STANDARD && typeChoose != ECC_CURVE_PASTA {
		return nil
	}

	if point == nil {
		return nil
	}

	if len(point) == 65 && point[0] == 0x04 {
		point = point[1:]
	}

	if len(point) != 64 {
		return nil
	}

	if point[63]%2 == 0 {
		return append([]byte{0x02}, point[:32]...)
	} else {
		return append([]byte{0x03}, point[:32]...)
	}
}

func PointDecompress(point []byte, typeChoose uint32) []byte {
	if point == nil || len(point) != 33 {
		return nil
	}
	switch typeChoose {
	case ECC_CURVE_SECP256K1:
		ret, err := secp256k1_decompress(point)
		if err != nil {
			return nil
		}
		return ret
		break
	case ECC_CURVE_SECP256R1:
		ret, err := secp256r1_decompress(point)
		if err != nil {
			return nil
		}
		return ret
		break
	case ECC_CURVE_SM2_STANDARD:
		ret, err := sm2_std_decompress(point)
		if err != nil {
			return nil
		}
		return ret
		break
	case ECC_CURVE_PASTA:
		ret, err := pasta.PointDecompress(point)
		if err != nil {
			return nil
		}
		return ret
		break
	default:
		return nil
	}
	return nil
}

func RecoverPubkey(sig []byte, msg []byte, typeChoose uint32) ([]byte, uint16) {
	switch typeChoose {
	case ECC_CURVE_SECP256K1:
		pubkey, err := secp256k1_recover_public(sig, msg)
		if err != nil {
			return nil, FAILURE
		}
		return pubkey, SUCCESS
		break
	case ECC_CURVE_SECP256R1:
		pubkey, err := secp256r1_recover_public(sig, msg)
		if err != nil {
			return nil, FAILURE
		}
		return pubkey, SUCCESS
		break
	case ECC_CURVE_SM2_STANDARD:
		pubkey, err := sm2_std_recover_public(sig, msg)
		if err != nil {
			return nil, FAILURE
		}
		return pubkey, SUCCESS
		break
	default:
		return nil, ECC_WRONG_TYPE
		break
	}

	return nil, FAILURE
}

func CURVE25519_convert_X_to_Ed(x []byte) ([]byte, error) {
	if x == nil || len(x) != 32 {
		return nil, errors.New("invalid point")
	}

	var in [32]byte
	copy(in[:], x)
	out, err := eddsa.ConvertXToEd(in)
	if err != nil {
		return nil, err
	}
	return out[:], nil
}

func CURVE25519_convert_Ed_to_X(ed []byte) ([]byte, error) {
	if ed == nil || len(ed) != 32 {
		return nil, errors.New("invalid point")
	}
	var in [32]byte
	copy(in[:], ed)
	out, err := eddsa.ConvertEdToX(in)
	if err != nil {
		return nil, err
	}
	return out[:], nil
}
