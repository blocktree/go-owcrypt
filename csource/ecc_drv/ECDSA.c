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

#include "ECDSA.h"

uint16_ow ECDSA_genPubkey(ECC_CURVE_PARAM *curveParam, uint8_ow *prikey, ECC_POINT *pubkey)
{
    ECC_POINT *point_g = NULL;
    
    if(!is_prikey_legal(curveParam, prikey))
        return ECC_PRIKEY_ILLEGAL;
    
    point_g = calloc(1, sizeof(ECC_POINT));
    
    memcpy(point_g -> x, curveParam -> x, ECC_LEN);
    memcpy(point_g -> y, curveParam -> y, ECC_LEN);
    
    if(point_mul(curveParam, point_g, prikey, pubkey))
    {
        free(point_g);
        return ECC_PRIKEY_ILLEGAL;
    }
    
    free(point_g);
    return SUCCESS;
}



uint16_ow ECDSA_sign(ECC_CURVE_PARAM *curveParam, uint8_ow *prikey, uint8_ow *message, uint16_ow message_len,uint8_ow *rand, uint8_ow hash_flag, uint8_ow *sig)
{
    uint8_ow *k = NULL, *tmp = NULL;
    ECC_POINT *point = NULL;
    if(!is_prikey_legal(curveParam, prikey))
        return ECC_PRIKEY_ILLEGAL;
    k = calloc(ECC_LEN, sizeof(uint8_ow));
    tmp = calloc(ECC_LEN, sizeof(uint8_ow));
    point = calloc(1, sizeof(ECC_POINT));
    while(1)
    {
        memcpy(point -> x, curveParam -> x, ECC_LEN);
        memcpy(point -> y, curveParam -> y, ECC_LEN);
        
        if(rand==NULL)
        {
            bigrand_get_rand_range(k, curveParam -> n, prikey, ECC_LEN, message, message_len);
        }
        else
        {
            memcpy(k,rand,ECC_LEN);
        }
        point_mul(curveParam, point, k, point);
        bignum_mod(point -> x, curveParam -> n, sig);
        if(is_all_zero(sig, ECC_LEN))
            continue;
        if(!hash_flag)//传入的是消息
        {
            sha256_hash(message, message_len, tmp);
        }
        else//传入的是哈希值
        {
            if(message_len != ECC_LEN)
            {
                return LENGTH_ERROR;
            }
            else
            {
                 memcpy(tmp, message, message_len);
            }
        }
        bignum_mod_mul(prikey, sig, curveParam -> n, sig + ECC_LEN);
        bignum_mod_add(tmp, sig + ECC_LEN, curveParam -> n, tmp);
        bignum_mod_inv(k, curveParam -> n, k);
        bignum_mod_mul(k, tmp, curveParam -> n, sig + ECC_LEN);
        if(is_all_zero(sig + ECC_LEN, ECC_LEN))
            continue;
        else
            break;
    }
    free(k);
    free(tmp);
    free(point);
    return SUCCESS;
}

uint16_ow ECDSA_verify(ECC_CURVE_PARAM *curveParam, ECC_POINT *pubkey, uint8_ow *message, uint16_ow message_len,uint8_ow hash_flag, uint8_ow *sig)
{
    uint8_ow *tmp1 = NULL, *tmp2 = NULL;
    ECC_POINT *point1 = NULL, *point2 = NULL;
    if(!is_pubkey_legal(curveParam, pubkey))
        return ECC_PUBKEY_ILLEGAL;
    
    if(is_all_zero(sig, ECC_LEN) || memcmp(sig, curveParam -> n, ECC_LEN) >= 0 || is_all_zero(sig + ECC_LEN, ECC_LEN) || memcmp(sig + ECC_LEN, curveParam -> n, ECC_LEN) >= 0)
        return FAILURE;
    
    tmp1 = calloc(ECC_LEN, sizeof(uint8_ow));
    tmp2 = calloc(ECC_LEN, sizeof(uint8_ow));
    point1 = calloc(1, sizeof(ECC_POINT));
    point2 = calloc(1, sizeof(ECC_POINT));
    if(!hash_flag) //需要内部计算哈希值
    {
        sha256_hash(message, message_len, tmp1);
    }
    else//外部已经计算哈希值
    {
        if(message_len != ECC_LEN)
        {
            return LENGTH_ERROR;
        }
        memcpy(tmp1,message,message_len);
    }
    
    bignum_mod_inv(sig + ECC_LEN, curveParam -> n, tmp2);
    bignum_mod_mul(tmp1, tmp2, curveParam -> n, tmp1);
    bignum_mod_mul(sig, tmp2, curveParam -> n, tmp2);
    
    memcpy(point2 -> x, curveParam -> x, ECC_LEN);
    memcpy(point2 -> y, curveParam -> y, ECC_LEN);
    
    point_mul(curveParam, point2, tmp1, point1);
    point_mul(curveParam, pubkey, tmp2, point2);
    
    if(point_add(curveParam, point1, point2, point1))
    {
        free(tmp1);
        free(tmp2);
        free(point1);
        free(point2);
        return FAILURE;
    }
    
    bignum_mod(point1 -> x, curveParam -> n, tmp1);
    
    if(memcmp(tmp1, sig, ECC_LEN))
    {
        free(tmp1);
        free(tmp2);
        free(point1);
        free(point2);
        return FAILURE;
    }
    free(tmp1);
    free(tmp2);
    free(point1);
    free(point2);
    return SUCCESS;
}

uint16_ow ECDSA_recover_public(ECC_CURVE_PARAM *curveParam,uint8_ow *sig,uint32_ow sig_len,uint8_ow *msg,uint32_ow msg_len,uint8_ow hash_flag,uint8_ow *pubkey)
{
    int k=0;
    uint16_ow ret=0x5a5a;
    uint8_ow *buf1=NULL,*buf2=NULL,*r_inv=NULL,*hash=NULL,*s=NULL;
    ECC_POINT *point1,*point2,*R,*G;
    if(!curveParam || !sig || !msg)
    {
        return FAILURE;
    }
    buf1=calloc(65,sizeof(uint8_ow));
    buf2=calloc(33,sizeof(uint8_ow));
    r_inv=calloc(32,sizeof(uint8_ow));
    hash=calloc(32,sizeof(uint8_ow));
    s=calloc(32,sizeof(uint8_ow));
    point1=calloc(1,sizeof(ECC_POINT));
    point2=calloc(1,sizeof(ECC_POINT));
    R=calloc(1,sizeof(ECC_POINT));
    G=calloc(1,sizeof(ECC_POINT));
    if(!hash_flag)
    {
        sha256_hash(msg, msg_len, hash);
    }
    else
    {
        if(msg_len !=32)
        {
            return LENGTH_ERROR;
        }
        else
        {
            memcpy(hash,msg,32);
        }
    }
    memcpy(buf2+1,sig,ECC_LEN);
    bignum_mod_inv(sig, curveParam->n,  r_inv);
    //get point G
    memcpy(G->x,curveParam->x,ECC_LEN);
    memcpy(G->y,curveParam->y,ECC_LEN);
    for(k=0;k<2;k++)
    {
        if(k == 0) //设置R->y为偶数
        {
            buf2[0]=0x02;
        }
        if(k == 1) //设置R->y为奇数
        {
            buf2[0]=0x03;
        }
        if(k == 0)
        {
            if(sig[64]==1) //进行curveParam->n - s的操作，需要将s还原
            {
                bignum_sub(curveParam->n, sig+ECC_LEN, ECC_LEN ,s);
            }
        }
        if(k==1)
        {
            if(sig[64] == 0)//进行curveParam->n - s的操作，需要将s还原
            {
                bignum_sub(curveParam->n, sig+ECC_LEN, ECC_LEN ,s);
            }
        }
        point_decompress(curveParam,  buf2,33, buf1);
        //get point R
        memcpy(R->x,buf1+1,ECC_LEN);
        memcpy(R->y,buf1+1+ECC_LEN,ECC_LEN);
        //point1=s*R
        point_mul(curveParam, R, s,  point1);
        //point2=e*G
        point_mul(curveParam, G, hash, point2);
        //计算 [-1]point2
        bignum_sub(curveParam->p, point2->y, ECC_LEN ,  point2->y);
        point_add(curveParam, point1,  point2,  point1);
        point_mul(curveParam, point1, r_inv,  point2);
        ret=ECDSA_verify(curveParam,  point2, hash,  32, 1,  sig);
        if(ret==SUCCESS)
        {
            memcpy(pubkey,point2->x,ECC_LEN);
            memcpy(pubkey+ECC_LEN,point2->y,ECC_LEN);
            break;
        }
    }
    free(buf1);
    free(buf2);
    free(r_inv);
    free(hash);
    free(point1);
    free(point2);
    free(R);
    free(G);
    free(s);
    return ret;
}

