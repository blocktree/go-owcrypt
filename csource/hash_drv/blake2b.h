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

#ifndef blake2b_h
#define blake2b_h

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "type.h"

#define BLAKE2B_BLOCKBYTES    128
#define BLAKE2B_OUTBYTES      64
#define BLAKE2B_KEYBYTES      64
#define BLAKE2B_SALTBYTES     16
#define BLAKE2B_PERSONALBYTES 16
#define BLAKE2B_DIGEST_LENGTH 64


struct blake2b_ctx_st {
    uint64_ow h[8];//store hash intermidiate state
    uint64_ow t[2];//counter
    uint64_ow f[2]; //finalization flags
    uint8_ow  buf[BLAKE2B_BLOCKBYTES];//store block message to deal with
    size_t   buflen;//the message length left
};
typedef struct blake2b_ctx_st BLAKE2B_CTX;


struct blake2b_param_st
{
    uint8_ow  digest_length;//(1 byte)digest length,an integer in [1,64]
    uint8_ow  key_length;//(1 byte)key length,an integer in [0,64]
    uint8_ow  fanout;//(1 byte)an integer in[0,255](set to 0 if unlimited,and to 1 only in sequential mode)
    uint8_ow  depth; //(1 byte) an integer in [1,255](set to 255 if unlimited,and to 1 only in sequential mode)
    uint8_ow  leaf_length[4];//(4 bytes)an integer in[0,2^32-1]
    uint8_ow  node_offset[8];//(8 byte):an integer in [0,2^64-1]
    uint8_ow  node_depth;//(1 byte):an integer in [0,255](set to 0 for the leaves)
    uint8_ow  inner_length; //(1 byte)an integer in [0,64]
    uint8_ow  reserved[14];//(14 byte)
    uint8_ow  salt[BLAKE2B_SALTBYTES];//(16 bytes)an arbitary string of 16 bytes
    uint8_ow  personal[BLAKE2B_PERSONALBYTES];//(16 bytes)an arbitary string of 16 bytes(set to all-NULL by default)
};

typedef struct blake2b_param_st BLAKE2B_PARAM;

/*
 @function:init BLAKE2B_CTX,writing a new message
 @paramter[in]:ctx pointer to BLAKE2B_CTX structure
 @paramter[in]:key pointer to the key(if dosen't need key,please input NULL)
 @paramter[in]:key_bytelen denotes the byte length of key.(if dosen't need key,please set key_bytelen to zero)
 @paramter[in]:digest_length denotes the expected hash result length
 */
void blake2b_init(BLAKE2B_CTX *ctx, uint8_ow *key,uint8_ow key_len,uint8_ow digest_len);

/*
 @function:update message Continues an blake2b message-digest operation,
 processing another message block, and updating the context.
 @paramter[in]:ctx pointer to BLAKE2B_CTX structure
 @paramter[in]:data pointer to the message to do hash
 @paramter[in]:datalen denotes the byte length of data.
 */
void blake2b_update(BLAKE2B_CTX *ctx, uint8_ow *msg, uint32_ow msg_len);
/*
 @function: end an ripemd160 message-digest operation, writing the message digest and zeroizing the context
 @paramter[in]:md pointer to hash intermidate intermidiate result
 @paramter[in]:md_bytelen denotes the byte length of md
 @paramter[in]:c pointer to BLAKE2B_CTX structure
 */
void blake2b_final(BLAKE2B_CTX *ctx,uint8_ow *msg, uint8_ow msg_len);


/*
 @function:BLAKE2b hash
 @paramter[in]:msg pointer to the data to do hash
 @paramter[in]:msg_len denotes the byte length of msg
 @paramter[in]:key pointer to the key(if dosen't need key,please input NULL)
 @paramter[in]:key_len denotes the byte length of key.(if dosen't need key,please set key_len to zero)
 @paramter[in]:digest_len denotes the expected hash result length(rang in[1,64])
 @paramter[out]:digest pointer to hash result
 */
void blake2b(uint8_ow *msg, uint16_ow msg_len,uint8_ow *key,uint16_ow key_len, uint8_ow digest_len, uint8_ow *digest);


#endif /* blake2b_h */
