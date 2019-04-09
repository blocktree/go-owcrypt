/*
 * Copyright 2018 The OpenWallet Authors
 * This file is part of the OpenWallet library.
 *
 * The OpenWallet library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The OpenWallet library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 */

#include "hash_set.h"



/*
 @function:hash operation
 @paramter[in]:msg pointer to the message to do hash
 @paramter[in]:msg_len denotes the byte length of msg
 @paramter[in]:type,hash algorithm flag.
 HASH_ALG_SHA1: sha1
 HASH_ALG_SHA256: sha256
 HASH_ALG_SHA512: sha512
 HASH_ALG_SM3: sm3
 HASH_ALG_MD5: md5
 HASH_ALG_RIPEMD160: ripemd160
 HASH_ALG_BLAKE2B: blake2b
 HASH_ALG_BLAKE2S: blake2s
 HASh_ALG_DOUBLE_SHA256: do sha256 for twice;
 HASH_ALG_HASH160: hash160
 HASH_ALG_BLKKE256: blake256
 HASH_ALG_BLKKE512: blake512
 HASH_ALG_KECCAK256:keccak256
 HASH_ALG_KECCAK256_RIPEMD160:first do sha3_256,then do ripemd160
 HASH_ALG_KECCAK512:keccak512
 HASH_ALG_SHA3_256:sha3_256
 HASH_ALG_SHA3_512:sha3_512
 
 OTHERWISE:not support.
 @paramter[out]:digest pointer to hash result(make sure the space size is enough)
 @paramter[in]:digest_len,the byte length of digest.It is useful if and only if blake2b and blake2s algorithm.Because the digest length of other hash algorithms is fix.
 */
void hash(uint8_ow *msg,uint32_ow msg_len,uint8_ow *digest,uint16_ow digest_len,uint32_ow type)
{
    switch (type)
    {
        case HASH_ALG_SHA1:
            sha1_hash(msg, msg_len, digest);
            break;
        case HASH_ALG_SHA3_256:
            sha3_256_hash(msg, msg_len, digest);
            break;
        case HASH_ALG_SHA3_512:
            sha3_512_hash(msg, msg_len, digest);
            break;
        case HASH_ALG_SHA256:
            sha256_hash(msg, msg_len, digest);
            break;
        case HASH_ALG_SHA512:
            sha512_hash(msg, msg_len, digest);
            break;
        case HASH_ALG_SM3:
            sm3_hash(msg, msg_len, digest);
            break;
        case HASH_ALG_MD4:
            md4_hash(msg,msg_len,digest);
            break;
        case HASH_ALG_MD5:
            md5_hash(msg,msg_len,digest);
            break;
        case HASH_ALG_RIPEMD160:
            ripemd160_hash(msg,msg_len,digest);
            break;
        case HASH_ALG_BLAKE2B:
            blake2b(msg, msg_len,NULL,0, digest_len, digest);
            break;
        case HASH_ALG_BLAKE2S:
            blake2s(msg, msg_len,NULL,0, digest_len, digest);
            break;
        case HASh_ALG_DOUBLE_SHA256:
            sha256_hash(msg, msg_len, digest);
            sha256_hash(digest, 32, digest);
            break;
        case HASH_ALG_HASH160:
            sha256_hash(msg, msg_len, digest);
            ripemd160_hash(digest,32,digest);
            break;

        case HASH_ALG_BLAKE256:
            blake256_hash(msg,  msg_len, digest);
            break;
        case HASH_ALG_BLAKE512:
             blake512_hash(msg,  msg_len, digest);
            break;
        case HASH_ALG_KECCAK256:
            keccak256_hash(msg, msg_len,digest);
            break;
        case HASH_ALG_KECCAK512:
            keccak512_hash(msg, msg_len, digest);
            break;
        case HASH_ALG_KECCAK256_RIPEMD160:
            keccak256_hash(msg, msg_len,digest);
            ripemd160_hash(digest,32,digest);
            break;
            case HASH_ALG_SHA3_256_RIPEMD160:
            sha3_256_hash(msg, msg_len,digest);
            ripemd160_hash(digest,32,digest);
            break;
        default:
            break;
    }
}
