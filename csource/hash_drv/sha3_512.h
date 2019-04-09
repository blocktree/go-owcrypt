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

#ifndef sha3_512_h
#define sha3_512_h
#include "type.h"

#ifdef __cplusplus
extern "C" {
#endif
    

#define sha3_512_hash_size  64
#define sha3_512_max_permutation_size 25
#define sha3_512_max_rate_in_qwords 24
/**
 * SHA3 Algorithm context.
 */
typedef struct
{
    /* 1600 bits algorithm hashing state */
    uint64_ow hash[sha3_512_max_permutation_size];
    /* 1536-bit buffer for leftovers */
    uint64_ow message[sha3_512_max_rate_in_qwords];
    /* count of bytes in the message[] buffer */
    uint32_ow rest;
    /* size of a message block processed at once */
    uint32_ow block_size;
} SHA3_512_CTX;
    
/**
 * Initialize context before calculating hash.
 *
 * @param ctx context to initialize
 */
void sha3_512_init(SHA3_512_CTX *ctx);
    
/**
 * Calculate message hash.
 * Can be called repeatedly with chunks of the message to be hashed.
 *
 * @param ctx the algorithm context containing current hashing state
 * @param msg message chunk
 * @param msg_len length of the message chunk
 */
void sha3_512_update(SHA3_512_CTX *ctx, const uint8_ow *msg, uint32_ow msg_len);
    
/**
 * Store calculated hash into the given array.
 *
 * @param ctx the algorithm context containing current hashing state
 * @param digest calculated hash in binary form
 */
void sha3_512_final(SHA3_512_CTX *ctx, uint8_ow* digest);
    
/**
 * Store calculated hash into the given array.
 *
 * @param msg message chunk
 * @param msg_len length of the message chunk
 * @param digest calculated hash in binary form
 */
void sha3_512_hash(const uint8_ow *msg, uint16_ow msg_len, uint8_ow *digest);
#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */
#endif /* sha3_512_h */
