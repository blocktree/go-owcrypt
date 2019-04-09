
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

#include "sha1.h"

#define sha1_rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))
#define sha1_blk0(i) (block->l[i] = (sha1_rol(block->l[i],24)&0xFF00FF00) |(sha1_rol(block->l[i],8)&0x00FF00FF))
#define sha1_blk(i) (block->l[i&15] = sha1_rol(block->l[(i+13)&15]^block->l[(i+8)&15]^block->l[(i+2)&15]^block->l[i&15],1))
/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define sha1_R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+sha1_blk0(i)+0x5A827999+sha1_rol(v,5);w=sha1_rol(w,30);
#define sha1_R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+sha1_blk(i)+0x5A827999+sha1_rol(v,5);w=sha1_rol(w,30);
#define sha1_R2(v,w,x,y,z,i) z+=(w^x^y)+sha1_blk(i)+0x6ED9EBA1+sha1_rol(v,5);w=sha1_rol(w,30);
#define sha1_R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+sha1_blk(i)+0x8F1BBCDC+sha1_rol(v,5);w=sha1_rol(w,30);
#define sha1_R4(v,w,x,y,z,i) z+=(w^x^y)+sha1_blk(i)+0xCA62C1D6+sha1_rol(v,5);w=sha1_rol(w,30);


/* Hash a single 512-bit block. This is the core of the algorithm. */

static void SHA1Transform(uint32_ow state[5],const uint8_ow buffer[64])
{
  uint32_ow a, b, c, d, e;
  typedef union
    {
        unsigned char c[64];
        uint32_ow l[16];
    } CHAR64LONG16;
    CHAR64LONG16 block[1];   /* use array to appear as a pointer */
    memcpy(block, buffer, 64);
    /* The following had better never be used because it causes the
     * pointer-to-const buffer to be cast into a pointer to non-const.
     * And the result is written through.  I threw a "const" in, hoping
     * this will cause a diagnostic.
     */
    
    // CHAR64LONG16 *block = (const CHAR64LONG16 *) buffer;
    /* Copy context->state[] to working vars */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    /* 4 rounds of 20 operations each. Loop unrolled. */
    sha1_R0(a, b, c, d, e, 0);
    sha1_R0(e, a, b, c, d, 1);
    sha1_R0(d, e, a, b, c, 2);
    sha1_R0(c, d, e, a, b, 3);
    sha1_R0(b, c, d, e, a, 4);
    sha1_R0(a, b, c, d, e, 5);
    sha1_R0(e, a, b, c, d, 6);
    sha1_R0(d, e, a, b, c, 7);
    sha1_R0(c, d, e, a, b, 8);
    sha1_R0(b, c, d, e, a, 9);
    sha1_R0(a, b, c, d, e, 10);
    sha1_R0(e, a, b, c, d, 11);
    sha1_R0(d, e, a, b, c, 12);
    sha1_R0(c, d, e, a, b, 13);
    sha1_R0(b, c, d, e, a, 14);
    sha1_R0(a, b, c, d, e, 15);
    sha1_R1(e, a, b, c, d, 16);
    sha1_R1(d, e, a, b, c, 17);
    sha1_R1(c, d, e, a, b, 18);
    sha1_R1(b, c, d, e, a, 19);
    sha1_R2(a, b, c, d, e, 20);
    sha1_R2(e, a, b, c, d, 21);
    sha1_R2(d, e, a, b, c, 22);
    sha1_R2(c, d, e, a, b, 23);
    sha1_R2(b, c, d, e, a, 24);
    sha1_R2(a, b, c, d, e, 25);
    sha1_R2(e, a, b, c, d, 26);
    sha1_R2(d, e, a, b, c, 27);
    sha1_R2(c, d, e, a, b, 28);
    sha1_R2(b, c, d, e, a, 29);
    sha1_R2(a, b, c, d, e, 30);
    sha1_R2(e, a, b, c, d, 31);
    sha1_R2(d, e, a, b, c, 32);
    sha1_R2(c, d, e, a, b, 33);
    sha1_R2(b, c, d, e, a, 34);
    sha1_R2(a, b, c, d, e, 35);
    sha1_R2(e, a, b, c, d, 36);
    sha1_R2(d, e, a, b, c, 37);
    sha1_R2(c, d, e, a, b, 38);
    sha1_R2(b, c, d, e, a, 39);
    sha1_R3(a, b, c, d, e, 40);
    sha1_R3(e, a, b, c, d, 41);
    sha1_R3(d, e, a, b, c, 42);
    sha1_R3(c, d, e, a, b, 43);
    sha1_R3(b, c, d, e, a, 44);
    sha1_R3(a, b, c, d, e, 45);
    sha1_R3(e, a, b, c, d, 46);
    sha1_R3(d, e, a, b, c, 47);
    sha1_R3(c, d, e, a, b, 48);
    sha1_R3(b, c, d, e, a, 49);
    sha1_R3(a, b, c, d, e, 50);
    sha1_R3(e, a, b, c, d, 51);
    sha1_R3(d, e, a, b, c, 52);
    sha1_R3(c, d, e, a, b, 53);
    sha1_R3(b, c, d, e, a, 54);
    sha1_R3(a, b, c, d, e, 55);
    sha1_R3(e, a, b, c, d, 56);
    sha1_R3(d, e, a, b, c, 57);
    sha1_R3(c, d, e, a, b, 58);
    sha1_R3(b, c, d, e, a, 59);
    sha1_R4(a, b, c, d, e, 60);
    sha1_R4(e, a, b, c, d, 61);
    sha1_R4(d, e, a, b, c, 62);
    sha1_R4(c, d, e, a, b, 63);
    sha1_R4(b, c, d, e, a, 64);
    sha1_R4(a, b, c, d, e, 65);
    sha1_R4(e, a, b, c, d, 66);
    sha1_R4(d, e, a, b, c, 67);
    sha1_R4(c, d, e, a, b, 68);
    sha1_R4(b, c, d, e, a, 69);
    sha1_R4(a, b, c, d, e, 70);
    sha1_R4(e, a, b, c, d, 71);
    sha1_R4(d, e, a, b, c, 72);
    sha1_R4(c, d, e, a, b, 73);
    sha1_R4(b, c, d, e, a, 74);
    sha1_R4(a, b, c, d, e, 75);
    sha1_R4(e, a, b, c, d, 76);
    sha1_R4(d, e, a, b, c, 77);
    sha1_R4(c, d, e, a, b, 78);
    sha1_R4(b, c, d, e, a, 79);
    /* Add the working vars back into context.state[] */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    /* Wipe variables */
    a = b = c = d = e = 0;
    memset(block, 0, sizeof(block));
}


/*
 @function:init SHA1_CTX,writing a new message
 @paramter[in]:ctx pointer to SHA1_CTX
 @return: NULL
 @notice: none
 */
void sha1_init(SHA1_CTX * ctx)
{
    /* SHA1 initialization constants */
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count[0] = ctx->count[1] = 0;
}


/*
 @function:update message Continues an sha1 message-digest operation,
 processing another message block, and updating the context.
 @paramter[in]:ctx pointer to SHA1_CTX
 @paramter[in]:msg pointer to the message to do sha1
 @paramter[in]:msg_len,the byte length of input
 @return:NULL
 @notoce:none
 */

void sha1_update(SHA1_CTX * ctx,const uint8_ow *msg,uint32_ow msg_len)
{
    uint32_ow i;
    uint32_ow j;
    j = ctx->count[0];
    if ((ctx->count[0] += msg_len << 3) < j)
        ctx->count[1]++;
    ctx->count[1] += (msg_len >> 29);
    j = (j >> 3) & 63;
    if ((j + msg_len) > 63)
    {
        memcpy(&ctx->buffer[j], msg, (i = 64 - j));
        SHA1Transform(ctx->state, ctx->buffer);
        for (; i + 63 < msg_len; i += 64)
        {
            SHA1Transform(ctx->state, &msg[i]);
        }
        j = 0;
    }
    else
        i = 0;
    memcpy(&ctx->buffer[j], &msg[i], msg_len - i);
}

/*
 @function:finalization sha1 operation ends an sha1 message-digest operation, writing the message digest and zeroizing the context
 @paramter[in]:ctx pointer to SHA1_CTX
 @paramter[out]:digest pointer to sha1 hash result
 @return:NULL
 @notice:nothing
 */
void sha1_final(SHA1_CTX * ctx,uint8_ow digest[20])
{
    uint32_ow i;
    uint8_ow finalcount[8];
    uint8_ow c;
    for (i = 0; i < 8; i++)
    {
        finalcount[i] = (uint8_ow) ((ctx->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);      /* Endian independent */
    }
    c = 0200;
    sha1_update(ctx, &c, 1);
    
    while ((ctx->count[0] & 504) != 448)
    {
        c = 0000;
        sha1_update(ctx, &c, 1);
    }
    sha1_update(ctx, finalcount, 8); /* Should cause a SHA1Transform() */
    for (i = 0; i < 20; i++)
    {
        digest[i] = (unsigned char)
        ((ctx->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
    }
    /* Wipe variables */
    memset(ctx, 0, sizeof(*ctx));
    memset(&finalcount, 0, sizeof(finalcount));
}

/*
 @function: sha1 hash
 @parameter[in]:msg pointer to the message to do hash
 @parameter[in]:msg_len,the byte length of msg
 @parameter[in]:digest pointer to hash result
 @return: none
 @notice:nothing
 */
void sha1_hash(const uint8_ow *msg,uint32_ow msg_len,uint8_ow *digest)
{
    SHA1_CTX ctx;
    uint32_ow i;
    sha1_init(&ctx);
    for (i=0; i<msg_len; i+=1)
    sha1_update(&ctx, msg + i, 1);
    sha1_final(&ctx,digest);
}

