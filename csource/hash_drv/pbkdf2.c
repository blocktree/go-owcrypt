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

#include "pbkdf2.h"
#define PBKDF2_SHA512_DIGEST_LENGTH 64
static void pbkdf2_XOR(uint8_ow *a,uint8_ow *b,uint32_ow len,uint8_ow *c)
{
    uint32_ow i;
    for(i=0;i<len;i++)
    {
        c[i]=a[i]^b[i];
    }
}

static void prf_hmac_sha512(uint8_ow *pw,uint32_ow pw_len,uint8_ow *salt,uint32_ow salt_len,uint32_ow iterations,uint32_ow block_index,uint8_ow *out)
{
    uint32_ow i;
    uint8_ow *index_buf=NULL,*saltAndsuffix=NULL,*tempout=NULL;
    index_buf=calloc(4,sizeof(uint8_ow));
    saltAndsuffix=calloc(salt_len + 4,sizeof(uint8_ow));
    tempout=calloc(PBKDF2_SHA512_DIGEST_LENGTH,sizeof(uint8_ow));
    
    //-------for the first iteration--------
    //transform integer block_index into four byte according to big endian
    index_buf[0]=(block_index >> 24)&0xff;
    index_buf[1]=(block_index >> 16)&0xff;
    index_buf[2]=(block_index>>8)&0xff;
    index_buf[3]=block_index&0xff;
    memcpy(saltAndsuffix,salt,salt_len);
    memcpy(saltAndsuffix+salt_len,index_buf,4);
    
    HMAC(pw, pw_len,saltAndsuffix,salt_len + 4, tempout, HMAC_SHA512_ALG);
    //HMAC(saltAndsuffix, salt_len + 4,pw,pw_len, tempout, HMAC_SHA512_ALG);
    memcpy(out, tempout, PBKDF2_SHA512_DIGEST_LENGTH);
    for(i=1;i<iterations;i++)
    {
        HMAC(pw, pw_len,tempout,PBKDF2_SHA512_DIGEST_LENGTH, tempout, HMAC_SHA512_ALG);
        //HMAC(tempout, PBKDF2_SHA512_DIGEST_LENGTH,pw,pw_len, tempout, HMAC_SHA512_ALG);
        pbkdf2_XOR(out,tempout,PBKDF2_SHA512_DIGEST_LENGTH,out);
    }
    free(index_buf);
    free(saltAndsuffix);
    free(tempout);
}

/*
 @function:Apply a pseudorandom function to derive keys
 @paramter[in] pw pointer to pass words
 @paramter[in] pw_len denotes the byte length of pw
 @paramter[in] salt pointer to the salt
 @paramter[in]salt_len denotes the byte length of salt
 @paramter[in]iterations denotes the iteration times
 @paramter[out]out pointer to the derived key
 @paramter[in]out_len denotes byte length of derived key
 */
void pbkdf2_hamc_sha512(uint8_ow *pw,uint32_ow pw_len,uint8_ow *salt,uint32_ow salt_len,uint32_ow iterations,uint8_ow *out,uint32_ow out_len)
{
    uint32_ow offset; //偏移变量
    uint32_ow block_index=1;  //循环变量,注意这里要求从1开始计数
    uint32_ow last_block_size=out_len % PBKDF2_SHA512_DIGEST_LENGTH; //最后一个block的大小
    uint32_ow blocks_count = out_len/PBKDF2_SHA512_DIGEST_LENGTH;  //block的数量
    uint8_ow *digest=NULL;
    digest=calloc(PBKDF2_SHA512_DIGEST_LENGTH,sizeof(uint8_ow));
    if(last_block_size)
    {
        blocks_count++;
    }
    else
    {
        last_block_size =PBKDF2_SHA512_DIGEST_LENGTH;
    }
    for(block_index=1;block_index<=blocks_count;block_index++)
    {
        prf_hmac_sha512( pw, pw_len,salt, salt_len, iterations, block_index, digest);
        offset=(block_index-1)*PBKDF2_SHA512_DIGEST_LENGTH;
        if(block_index < blocks_count)
        {
            memcpy(out+offset,digest,PBKDF2_SHA512_DIGEST_LENGTH);
        }
        else
        {
            memcpy(out+offset,digest,last_block_size);
        }
    }
}
