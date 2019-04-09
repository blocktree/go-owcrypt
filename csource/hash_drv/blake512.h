
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

#ifndef _BLAKE512_H_
#define _BLAKE512_H_

#include "type.h"
typedef struct {
    uint64_ow h[8], s[4], t[2];
    int buflen, nullt;
    uint8_ow buf[128];
} BLAKE512_CTX;

/**
 * Initialize context before calculating hash.
 *
 * @param ctx context to initialize
 */
void blake512_init(BLAKE512_CTX *ctx);

/**
 * Calculate message hash.
 * Can be called repeatedly with chunks of the message to be hashed.
 *
 * @param ctx the algorithm context containing current hashing state
 * @param msg message chunk
 * @param msg_len length of the message chunk
 */
void blake512_update(BLAKE512_CTX *ctx, const uint8_ow *msg, uint32_ow msg_len);

/**
 * Store calculated hash into the given array.
 *
 * @param ctx the algorithm context containing current hashing state
 * @param digest calculated hash in binary form
 */
void blake512_final(BLAKE512_CTX *ctx, uint8_ow *digest);


/**
 * blake512 hash.
 *
 * @param msg the message to do hash
 * @param msg_len the length of message
 * @param digest hash result
 */
void blake512_hash(const uint8_ow *msg, uint32_ow msg_len,uint8_ow *digest);
#endif /* _BLAKE512_H_ */

