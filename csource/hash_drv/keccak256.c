
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
#include "keccak256.h"

/* constants and macro definition */
#define KECCAK256_NumberOfRounds 24
#define KECCAK256_FINALIZED 0x80000000
#define KECCAK256_ROTL64(qword, n) ((qword) << (n) ^ ((qword) >> (64 - (n))))
#define KECCAK256_IS_ALIGNED_64(p) (0 == (7 & ((const char*)(p) - (const char*)0)))
#define keccak256_me64_to_le_str(to, from, length) memcpy((to), (from), (length))
# define keccak256_le2me_64(x) (x)
/* SHA3 (Keccak) constants for 24 rounds */
static uint64_ow keccak256_round_constants[KECCAK256_NumberOfRounds] = {
    (0x0000000000000001), (0x0000000000008082), (0x800000000000808A), (0x8000000080008000),
    (0x000000000000808B), (0x0000000080000001), (0x8000000080008081), (0x8000000000008009),
    (0x000000000000008A), (0x0000000000000088), (0x0000000080008009), (0x000000008000000A),
    (0x000000008000808B), (0x800000000000008B), (0x8000000000008089), (0x8000000000008003),
    (0x8000000000008002), (0x8000000000000080), (0x000000000000800A), (0x800000008000000A),
    (0x8000000080008081), (0x8000000000008080), (0x0000000080000001), (0x8000000080008008)
};


/**
 * Initialize context before calculating hash.
 *
 * @param ctx context to initialize
 */
void keccak256_init(KECCAK256_CTX *ctx)
{
    /* NB: The Keccak capacity parameter = bits * 2 */
    unsigned rate = 1600 - 256 * 2;
    memset(ctx, 0, sizeof(KECCAK256_CTX));
    ctx->block_size = rate / 8;
    assert(rate <= 1600 && (rate % 64) == 0);
}

#define KECCAK256_XORED_A(i) A[(i)] ^ A[(i) + 5] ^ A[(i) + 10] ^ A[(i) + 15] ^ A[(i) + 20]
#define KECCAK256_THETA_STEP(i) \
A[(i)]      ^= D[(i)]; \
A[(i) + 5]  ^= D[(i)]; \
A[(i) + 10] ^= D[(i)]; \
A[(i) + 15] ^= D[(i)]; \
A[(i) + 20] ^= D[(i)] \

/* Keccak theta() transformation */
static void keccak256_theta(uint64_ow *A)
{
    uint64_ow D[5];
    D[0] = KECCAK256_ROTL64(KECCAK256_XORED_A(1), 1) ^ KECCAK256_XORED_A(4);
    D[1] = KECCAK256_ROTL64(KECCAK256_XORED_A(2), 1) ^ KECCAK256_XORED_A(0);
    D[2] = KECCAK256_ROTL64(KECCAK256_XORED_A(3), 1) ^ KECCAK256_XORED_A(1);
    D[3] = KECCAK256_ROTL64(KECCAK256_XORED_A(4), 1) ^ KECCAK256_XORED_A(2);
    D[4] = KECCAK256_ROTL64(KECCAK256_XORED_A(0), 1) ^ KECCAK256_XORED_A(3);
    KECCAK256_THETA_STEP(0);
    KECCAK256_THETA_STEP(1);
    KECCAK256_THETA_STEP(2);
    KECCAK256_THETA_STEP(3);
    KECCAK256_THETA_STEP(4);
}

/* Keccak pi() transformation */
static void keccak256_pi(uint64_ow *A)
{
    uint64_ow A1;
    A1 = A[1];
    A[ 1] = A[ 6];
    A[ 6] = A[ 9];
    A[ 9] = A[22];
    A[22] = A[14];
    A[14] = A[20];
    A[20] = A[ 2];
    A[ 2] = A[12];
    A[12] = A[13];
    A[13] = A[19];
    A[19] = A[23];
    A[23] = A[15];
    A[15] = A[ 4];
    A[ 4] = A[24];
    A[24] = A[21];
    A[21] = A[ 8];
    A[ 8] = A[16];
    A[16] = A[ 5];
    A[ 5] = A[ 3];
    A[ 3] = A[18];
    A[18] = A[17];
    A[17] = A[11];
    A[11] = A[ 7];
    A[ 7] = A[10];
    A[10] = A1;
    /* note: A[ 0] is left as is */
}
#define KECCAK256_CHI_STEP(i) \
A0 = A[0 + (i)]; \
A1 = A[1 + (i)]; \
A[0 + (i)] ^= ~A1 & A[2 + (i)]; \
A[1 + (i)] ^= ~A[2 + (i)] & A[3 + (i)]; \
A[2 + (i)] ^= ~A[3 + (i)] & A[4 + (i)]; \
A[3 + (i)] ^= ~A[4 + (i)] & A0; \
A[4 + (i)] ^= ~A0 & A1 \

/* Keccak chi() transformation */
static void keccak256_chi(uint64_ow *A)
{
    uint64_ow A0, A1;
    KECCAK256_CHI_STEP(0);
    KECCAK256_CHI_STEP(5);
    KECCAK256_CHI_STEP(10);
    KECCAK256_CHI_STEP(15);
    KECCAK256_CHI_STEP(20);
}

static void keccak256_permutation(uint64_ow *state)
{
    int round;
    for (round = 0; round < KECCAK256_NumberOfRounds; round++)
    {
        keccak256_theta(state);
        
        /* apply Keccak rho() transformation */
        state[ 1] = KECCAK256_ROTL64(state[ 1],  1);
        state[ 2] = KECCAK256_ROTL64(state[ 2], 62);
        state[ 3] = KECCAK256_ROTL64(state[ 3], 28);
        state[ 4] = KECCAK256_ROTL64(state[ 4], 27);
        state[ 5] = KECCAK256_ROTL64(state[ 5], 36);
        state[ 6] = KECCAK256_ROTL64(state[ 6], 44);
        state[ 7] = KECCAK256_ROTL64(state[ 7],  6);
        state[ 8] = KECCAK256_ROTL64(state[ 8], 55);
        state[ 9] = KECCAK256_ROTL64(state[ 9], 20);
        state[10] = KECCAK256_ROTL64(state[10],  3);
        state[11] = KECCAK256_ROTL64(state[11], 10);
        state[12] = KECCAK256_ROTL64(state[12], 43);
        state[13] = KECCAK256_ROTL64(state[13], 25);
        state[14] = KECCAK256_ROTL64(state[14], 39);
        state[15] = KECCAK256_ROTL64(state[15], 41);
        state[16] = KECCAK256_ROTL64(state[16], 45);
        state[17] = KECCAK256_ROTL64(state[17], 15);
        state[18] = KECCAK256_ROTL64(state[18], 21);
        state[19] = KECCAK256_ROTL64(state[19],  8);
        state[20] = KECCAK256_ROTL64(state[20], 18);
        state[21] = KECCAK256_ROTL64(state[21],  2);
        state[22] = KECCAK256_ROTL64(state[22], 61);
        state[23] = KECCAK256_ROTL64(state[23], 56);
        state[24] = KECCAK256_ROTL64(state[24], 14);
        keccak256_pi(state);
        keccak256_chi(state);
        /* apply iota(state, round) */
        *state ^= keccak256_round_constants[round];
    }
}

/**
 * The core transformation. Process the specified block of data.
 *
 * @param hash the algorithm state
 * @param block the message block to process
 * @param block_size the size of the processed block in bytes
 */
static void keccak256_process_block(uint64_ow hash[25], const uint64_ow *block, uint32_ow block_size)
{
    /* expanded loop */
    hash[ 0] ^= keccak256_le2me_64(block[ 0]);
    hash[ 1] ^= keccak256_le2me_64(block[ 1]);
    hash[ 2] ^= keccak256_le2me_64(block[ 2]);
    hash[ 3] ^= keccak256_le2me_64(block[ 3]);
    hash[ 4] ^= keccak256_le2me_64(block[ 4]);
    hash[ 5] ^= keccak256_le2me_64(block[ 5]);
    hash[ 6] ^= keccak256_le2me_64(block[ 6]);
    hash[ 7] ^= keccak256_le2me_64(block[ 7]);
    hash[ 8] ^= keccak256_le2me_64(block[ 8]);
    /* if not sha3-512 */
    if (block_size > 72)
    {
        hash[ 9] ^= keccak256_le2me_64(block[ 9]);
        hash[10] ^= keccak256_le2me_64(block[10]);
        hash[11] ^= keccak256_le2me_64(block[11]);
        hash[12] ^= keccak256_le2me_64(block[12]);
        /* if not sha3-384 */
        if (block_size > 104)
        {
            hash[13] ^= keccak256_le2me_64(block[13]);
            hash[14] ^= keccak256_le2me_64(block[14]);
            hash[15] ^= keccak256_le2me_64(block[15]);
            hash[16] ^= keccak256_le2me_64(block[16]);
            /* if not sha3-256 */
            if (block_size > 136)
            {
                hash[17] ^= keccak256_le2me_64(block[17]);
            }
        }
    }
    /* make a permutation of the hash */
    keccak256_permutation(hash);
}

/**
 * Calculate message hash.
 * Can be called repeatedly with chunks of the message to be hashed.
 *
 * @param ctx the algorithm context containing current hashing state
 * @param msg message chunk
 * @param msg_len length of the message chunk
 */
void keccak256_update(KECCAK256_CTX *ctx, const uint8_ow *msg, uint32_ow msg_len)
{
    uint32_ow index = (uint32_ow)ctx->rest;
    uint32_ow block_size = (uint32_ow)ctx->block_size;
    if (ctx->rest & KECCAK256_FINALIZED) /* too late for additional input */
        return;
    ctx->rest = (unsigned)((ctx->rest + msg_len) % block_size);
    
    /* fill partial block */
    if (index)
    {
        int left = block_size - index;
        memcpy((uint8_ow*)ctx->message + index, msg, (msg_len < left ? msg_len : left));
        if (msg_len < left)
            return;
        /* process partial block */
        keccak256_process_block(ctx->hash, ctx->message, (uint32_ow)block_size);
        msg  += left;
        msg_len -= left;
    }
    while (msg_len >= block_size)
    {
        uint64_ow* aligned_message_block;
        if (KECCAK256_IS_ALIGNED_64(msg))
        {
            /* the most common case is processing of an already aligned message
             without copying it */
            aligned_message_block = (uint64_ow*)msg;
        }
        else
        {
            memcpy(ctx->message, msg, block_size);
            aligned_message_block = ctx->message;
        }
        keccak256_process_block(ctx->hash, aligned_message_block, (uint32_ow)block_size);
        msg  += block_size;
        msg_len -= block_size;
    }
    if (msg_len)
    {
        memcpy(ctx->message, msg, msg_len); /* save leftovers */
    }
}

/**
 * Store calculated hash into the given array.
 *
 * @param ctx the algorithm context containing current hashing state
 * @param digest calculated hash in binary form
 */
void keccak256_final(KECCAK256_CTX *ctx, uint8_ow* digest)
{
    int digest_length = 100 - ctx->block_size / 2;
    const uint32_ow block_size = ctx->block_size;
    if (!(ctx->rest & KECCAK256_FINALIZED))
    {
        /* clear the rest of the data queue */
        memset((uint8_ow*)ctx->message + ctx->rest, 0, block_size - ctx->rest);
        ((uint8_ow*)ctx->message)[ctx->rest] |= 0x01;
        ((uint8_ow*)ctx->message)[block_size - 1] |= 0x80;
        /* process final block */
        keccak256_process_block(ctx->hash, ctx->message, (uint32_ow)block_size);
        ctx->rest = KECCAK256_FINALIZED; /* mark context as finalized */
    }
    assert(block_size > digest_length);
    if (digest) keccak256_me64_to_le_str(digest, ctx->hash, digest_length);
}

/**
 * keccak256 hash.
 *
 * @param msg the message to do hash
 * @param msg_len the length of message
 * @param digest hash result
 */
void keccak256_hash(const uint8_ow *msg,uint32_ow msg_len,uint8_ow *digest)
{
    KECCAK256_CTX ctx;
    keccak256_init(&ctx);
    keccak256_update(&ctx, msg, msg_len);
    keccak256_final(&ctx, digest);
}
