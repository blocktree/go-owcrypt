
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

#include <string.h>
#include "blake512.h"
#define BLAKE512_U8TO32(p) \
(((uint32_ow)((p)[0]) << 24) | ((uint32_ow)((p)[1]) << 16) | \
((uint32_ow)((p)[2]) <<  8) | ((uint32_ow)((p)[3])      ))

#define BLAKE512_U8TO64(p) \
(((uint64_ow)BLAKE512_U8TO32(p) << 32) | (uint64_ow)BLAKE512_U8TO32((p) + 4))

#define BLAKE512_U32TO8(p, v) \
(p)[0] = (uint8_ow)((v) >> 24); (p)[1] = (uint8_ow)((v) >> 16); \
(p)[2] = (uint8_ow)((v) >>  8); (p)[3] = (uint8_ow)((v)      );

#define BLAKE512_U64TO8(p, v) \
BLAKE512_U32TO8((p),     (uint32_ow)((v) >> 32)); \
BLAKE512_U32TO8((p) + 4, (uint32_ow)((v)      ));

const uint8_ow blake512_sigma[][16] =
{
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3},
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4},
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8},
    { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13},
    { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9},
    {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11},
    {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10},
    { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0},
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3},
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4},
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8},
    { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13},
    { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9}
};

const uint64_ow blake512_cst[16] =
{
    0x243F6A8885A308D3ULL, 0x13198A2E03707344ULL, 0xA4093822299F31D0ULL, 0x082EFA98EC4E6C89ULL,
    0x452821E638D01377ULL, 0xBE5466CF34E90C6CULL, 0xC0AC29B7C97C50DDULL, 0x3F84D5B5B5470917ULL,
    0x9216D5D98979FB1BULL, 0xD1310BA698DFB5ACULL, 0x2FFD72DBD01ADFB7ULL, 0xB8E1AFED6A267E96ULL,
    0xBA7C9045F12C7F99ULL, 0x24A19947B3916CF7ULL, 0x0801F2E2858EFC16ULL, 0x636920D871574E69ULL
};

static const uint8_ow blake512_padding[129] =
{
    0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};


void static blake512_compress(BLAKE512_CTX *ctx, const uint8_ow *block)
{
    uint64_ow v[16], m[16], i;
    #define ROT(x,n) (((x)<<(64-n))|((x)>>(n)))
    #define G(a,b,c,d,e)                                                             \
    v[a] += (m[blake512_sigma[i][e]] ^ blake512_cst[blake512_sigma[i][e+1]]) + v[b]; \
    v[d] = ROT(v[d] ^ v[a],32);                                                      \
    v[c] += v[d];                                                                    \
    v[b] = ROT(v[b] ^ v[c],25);                                                      \
    v[a] += (m[blake512_sigma[i][e+1]] ^ blake512_cst[blake512_sigma[i][e]])+v[b];   \
    v[d] = ROT(v[d] ^ v[a],16);                                                      \
    v[c] += v[d];                                                                    \
    v[b] = ROT(v[b] ^ v[c],11);
    for (i = 0; i < 16; ++i)
    {
        m[i] = BLAKE512_U8TO64(block + i * 8);
    }
    for (i = 0; i < 8;  ++i)
    {
       v[i] = ctx->h[i];
    }
    v[ 8] = ctx->s[0] ^ 0x243F6A8885A308D3ULL;
    v[ 9] = ctx->s[1] ^ 0x13198A2E03707344ULL;
    v[10] = ctx->s[2] ^ 0xA4093822299F31D0ULL;
    v[11] = ctx->s[3] ^ 0x082EFA98EC4E6C89ULL;
    v[12] = 0x452821E638D01377ULL;
    v[13] = 0xBE5466CF34E90C6CULL;
    v[14] = 0xC0AC29B7C97C50DDULL;
    v[15] = 0x3F84D5B5B5470917ULL;
    if (ctx->nullt == 0)
    {
        v[12] ^= ctx->t[0];
        v[13] ^= ctx->t[0];
        v[14] ^= ctx->t[1];
        v[15] ^= ctx->t[1];
    }
    for (i = 0; i < 16; ++i)
    {
        G(0, 4,  8, 12,  0);
        G(1, 5,  9, 13,  2);
        G(2, 6, 10, 14,  4);
        G(3, 7, 11, 15,  6);
        G(3, 4,  9, 14, 14);
        G(2, 7,  8, 13, 12);
        G(0, 5, 10, 15,  8);
        G(1, 6, 11, 12, 10);
    }
    for (i = 0; i < 16; ++i)
    {
       ctx->h[i % 8] ^= v[i];
    }
    for (i = 0; i < 8;  ++i)
    {
      ctx->h[i] ^= ctx->s[i % 4];
    }
}


// datalen = number of bits
void static blake512_update_inner(BLAKE512_CTX *ctx, const uint8_ow *data, uint64_ow datalen)
{
    int left = (ctx->buflen >> 3);
    int fill = 128 - left;
    if (left && (((datalen >> 3) & 0x7F) >= (unsigned) fill))
    {
        memcpy((void *) (ctx->buf + left), (void *) data, fill);
        ctx->t[0] += 1024;
        blake512_compress(ctx, ctx->buf);
        data += fill;
        datalen -= (fill << 3);
        left = 0;
    }
    while (datalen >= 1024)
    {
        ctx->t[0] += 1024;
        blake512_compress(ctx, data);
        data += 128;
        datalen -= 1024;
    }
    if (datalen > 0)
    {
        memcpy((void *) (ctx->buf + left), (void *) data, (datalen >> 3) & 0x7F);
        ctx->buflen = (left << 3) + (int)datalen;
    }
    else
    {
        ctx->buflen = 0;
    }
}

void static blake512_final_h(BLAKE512_CTX *ctx, uint8_ow *digest, uint8_ow pa, uint8_ow pb)
{
    uint8_ow msglen[16];
    uint64_ow lo = ctx->t[0] + ctx->buflen, hi = ctx->t[1];
    if (lo < (unsigned)ctx->buflen)
    {
         hi++;
    }
    BLAKE512_U64TO8(msglen + 0, hi);
    BLAKE512_U64TO8(msglen + 8, lo);
    if (ctx->buflen == 888)
    { /* one padding byte */
        ctx->t[0] -= 8;
        blake512_update_inner(ctx, &pa, 8);
    }
    else
    {
        if (ctx->buflen < 888)
        { /* enough space to fill the block */
            if (ctx->buflen == 0)
            {
              ctx->nullt = 1;
            }
            ctx->t[0] -= 888 - ctx->buflen;
            blake512_update_inner(ctx, blake512_padding, 888 - ctx->buflen);
        }
        else
        { /* NOT enough space, need 2 compressions */
            ctx->t[0] -= 1024 - ctx->buflen;
            blake512_update_inner(ctx, blake512_padding, 1024 - ctx->buflen);
            ctx->t[0] -= 888;
            blake512_update_inner(ctx, blake512_padding + 1, 888);
            ctx->nullt = 1;
        }
        blake512_update_inner(ctx, &pb, 8);
        ctx->t[0] -= 8;
    }
    ctx->t[0] -= 128;
    blake512_update_inner(ctx, msglen, 128);
    BLAKE512_U64TO8(digest +  0, ctx->h[0]);
    BLAKE512_U64TO8(digest +  8, ctx->h[1]);
    BLAKE512_U64TO8(digest + 16, ctx->h[2]);
    BLAKE512_U64TO8(digest + 24, ctx->h[3]);
    BLAKE512_U64TO8(digest + 32, ctx->h[4]);
    BLAKE512_U64TO8(digest + 40, ctx->h[5]);
    BLAKE512_U64TO8(digest + 48, ctx->h[6]);
    BLAKE512_U64TO8(digest + 56, ctx->h[7]);
}

/**
 * Initialize context before calculating hash.
 *
 * @param ctx context to initialize
 */
void blake512_init(BLAKE512_CTX *ctx)
{
    ctx->h[0] = 0x6A09E667F3BCC908ULL;
    ctx->h[1] = 0xBB67AE8584CAA73BULL;
    ctx->h[2] = 0x3C6EF372FE94F82BULL;
    ctx->h[3] = 0xA54FF53A5F1D36F1ULL;
    ctx->h[4] = 0x510E527FADE682D1ULL;
    ctx->h[5] = 0x9B05688C2B3E6C1FULL;
    ctx->h[6] = 0x1F83D9ABFB41BD6BULL;
    ctx->h[7] = 0x5BE0CD19137E2179ULL;
    ctx->t[0] = ctx->t[1] = ctx->buflen = ctx->nullt = 0;
    ctx->s[0] = ctx->s[1] = ctx->s[2] = ctx->s[3] = 0;
}

/**
 * Calculate message hash.
 * Can be called repeatedly with chunks of the message to be hashed.
 *
 * @param ctx the algorithm context containing current hashing state
 * @param msg message chunk
 * @param msg_len length of the message chunk
 */
void blake512_update(BLAKE512_CTX *ctx, const uint8_ow *msg, uint32_ow msg_len)
{
    blake512_update_inner(ctx, msg,  msg_len*8);
}

/**
 * Store calculated hash into the given array.
 *
 * @param ctx the algorithm context containing current hashing state
 * @param digest calculated hash in binary form
 */
void blake512_final(BLAKE512_CTX *ctx, uint8_ow *digest)
{
    blake512_final_h(ctx, digest, 0x81, 0x01);
}

/**
 * keccak256 hash.
 *
 * @param msg the message to do hash
 * @param msg_len the length of message
 * @param digest hash result
 */
void blake512_hash(const uint8_ow *msg, uint32_ow msg_len,uint8_ow *digest)
{
    BLAKE512_CTX ctx;
    blake512_init(&ctx);
    blake512_update(&ctx, msg, msg_len);
    blake512_final(&ctx, digest);
}
