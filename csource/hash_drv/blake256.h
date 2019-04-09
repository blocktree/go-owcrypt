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
#ifndef blake256_h
#define blake256_h
#include "type.h"
#include "string.h"

#define BLAKE256_DIGEST_LENGTH 32
#define BLAKE256_BLOCK_LENGTH  64

typedef struct {
    uint32_ow h[8], s[4], t[2];
    int buflen;
    uint8_ow nullt;
    uint8_ow buf[64];
} BLAKE256_CTX;

/*
 @function:init BLAKE256_CTX,writing a new message
 @paramter[in]:ctx pointer to BLAKE256_CTX
 @return: NULL
 @notice: none
 */
void blake256_Init(BLAKE256_CTX *);

/*
 @function:update message Continues an blake256 message-digest operation,
 processing another message block, and updating the context.
 @paramter[in]:ctx pointer to BLAKE256_CTX
 @paramter[in]:msg pointer to the message to do blake2556
 @paramter[in]:msg_len,the byte length of input
 @return:NULL
 @notoce:none
 */
void blake256_update( BLAKE256_CTX *ctx, const uint8_ow *msg, uint16_ow msg_len);

/*
 @function:finalization blake256 operation ends an sha1 message-digest operation, writing the message digest and zeroizing the context
 @paramter[in]:ctx pointer to BLAKE256_CTX
 @paramter[out]:digest pointer to blake256 hash result
 @return:NULL
 @notice:nothing
 */
void blake256_final(BLAKE256_CTX *, uint8_ow *);

/*
 @function: blake256 hash
 @parameter[in]:msg pointer to the message to do hash
 @parameter[in]:msg_len,the byte length of msg
 @parameter[in]:digest pointer to hash result
 @return: none
 @notice:nothing
 */
void blake256_hash(const uint8_ow *msg, uint16_ow msg_len, uint8_ow *digest);

#endif /* blake256_h */
