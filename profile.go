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

const (
	HASH_ALG_SHA1                = uint32(0xA0000000)
	HASH_ALG_SHA3_256            = uint32(0xA0000001)
	HASH_ALG_SHA256              = uint32(0xA0000002)
	HASH_ALG_SHA512              = uint32(0xA0000003)
	HASH_ALG_MD4                 = uint32(0xA0000004)
	HASH_ALG_MD5                 = uint32(0xA0000005)
	HASH_ALG_RIPEMD160           = uint32(0xA0000006)
	HASH_ALG_BLAKE2B             = uint32(0xA0000007)
	HASH_ALG_BLAKE2S             = uint32(0xA0000008)
	HASH_ALG_SM3                 = uint32(0xA0000009)
	HASH_ALG_DOUBLE_SHA256       = uint32(0xA000000A)
	HASH_ALG_HASH160             = uint32(0xA000000B)
	HASH_ALG_BLAKE256            = uint32(0xA000000C)
	HASH_ALG_BLAKE512            = uint32(0xA000000D)
	HASH_ALG_KECCAK256           = uint32(0xA000000E)
	HASH_ALG_KECCAK256_RIPEMD160 = uint32(0xA000000F)
	HASH_ALG_SHA3_256_RIPEMD160  = uint32(0xA0000010)
	HASH_ALG_KECCAK512           = uint32(0xA0000011)
	HASH_ALG_SHA3_512            = uint32(0xA0000012)

	HMAC_SHA256_ALG = uint32(0x50505050)
	HMAC_SHA512_ALG = uint32(0x50505051)
	HMAC_SM3_ALG    = uint32(0x50505052)

	ECC_CURVE_SECP256K1                           = uint32(0xECC00000)
	ECC_CURVE_SECP256R1                           = uint32(0xECC00001)
	ECC_CURVE_PRIMEV1                             = ECC_CURVE_SECP256R1
	ECC_CURVE_NIST_P256                           = ECC_CURVE_SECP256R1
	ECC_CURVE_SM2_STANDARD                        = uint32(0xECC00002)
	ECC_CURVE_ED25519_NORMAL                      = uint32(0xECC00003)
	ECC_CURVE_ED25519                             = uint32(0xECC00004)
	ECC_CURVE_X25519                              = uint32(0xECC00005)
	ECC_CURVE_CURVE25519_SHA256                   = uint32(0xECC00006)
	ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_NUL = uint32(0xECC00007)
	ECC_CURVE_BLS12381_G2_XMD_SHA_256_SSWU_RO_AUG = uint32(0xECC00008)
	ECC_CURVE_PASTA                               = uint32(0xECC00009)

	BASIC_SCHEME_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
	AUG_SCHEME_DST   = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_"

	//签名流程中的随机数是外部传入的标志位置
	NOUNCE_OUTSIDE_FLAG = uint32(1 << 8)
	//外部已经计算消息的哈希值的标识位置
	HASH_OUTSIDE_FLAG = uint32(1 << 9)

	SUCCESS            = uint16(0x0001)
	FAILURE            = uint16(0x0000)
	ECC_PRIKEY_ILLEGAL = uint16(0xE000)
	ECC_PUBKEY_ILLEGAL = uint16(0xE001)
	ECC_WRONG_TYPE     = uint16(0xE002)
	ECC_MISS_ID        = uint16(0xE003)
	RAND_IS_NULL       = uint16(0xE004)
	LENGTH_ERROR       = uint16(0xE005)
	POINT_AT_INFINITY  = uint16(0xE006)
	MESSAGE_ILLEGAL    = uint16(0xE007)
)
