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

#include "ecc_set.h"
#include "secp256k1.h"
#include "secp256r1.h"
#include "sm2.h"
#include "CURVE25519.h"

static uint8_ow randNum[32]={0};
uint16_ow ECC_preprocess_randomnum(uint8_ow *rand)
{
    if(rand==NULL)
    {
        return RAND_IS_NULL;
    }
    memcpy(randNum,rand,32);
    return SUCCESS;
}
uint16_ow ECC_genPubkey(uint8_ow *prikey, uint8_ow *pubkey, uint32_ow type)
{
    uint16_ow ret = 0;
    
    switch (type)
    {
        case ECC_CURVE_SECP256K1:
        {
            ret = secp256k1_genPubkey(prikey, pubkey);
        }
            break;
        case ECC_CURVE_SECP256R1:
        {
            ret = secp256r1_genPubkey(prikey, pubkey);
        }
            break;
        case ECC_CURVE_SM2_STANDARD:
        {
            ret = sm2_std_genPubkey(prikey, pubkey);
        }
            break;
        case ECC_CURVE_CURVE25519:
        {
            CURVE25519_genPubkey(prikey, pubkey);
            ret = SUCCESS;
        }
            break;
        case ECC_CURVE_ED25519:
        {
            ED25519_genPubkey(prikey, pubkey);
            ret = SUCCESS;
        }
            break;
        case ECC_CURVE_X25519:
        {
            X25519_genPubkey(pubkey, prikey);
            ret = SUCCESS;
        }
            break;
        default:
        {
            ret = ECC_WRONG_TYPE;
        }
            break;
    }
    
    return ret;
}

uint16_ow ECC_sign(uint8_ow *prikey, uint8_ow *ID, uint16_ow IDlen, uint8_ow *message, uint16_ow message_len, uint8_ow *sig, uint32_ow type)
{
    uint16_ow ret = 0;
    uint32_ow mask1=1<<8,mask2=1<<9,mask3=0xECC000FF;
    //外部传入随机数
    switch (type & mask3)
    {
        case ECC_CURVE_SECP256K1:
        {
            if(type&mask1) //外部传入随机数
            {
                //判断传入的随机数是否为全0
                if(is_all_zero(randNum, ECC_LEN))
                {
                    return RAND_IS_NULL;
                }
                ret = secp256k1_sign(prikey, message, message_len,randNum,1,sig);
                /*
                if(type&mask2)//外部已经计算哈希值
                {
                    ret = secp256k1_sign(prikey, message, message_len,randNum,1,sig);
                }
                else//需要内部计算哈希值
                {
                    ret = secp256k1_sign(prikey, message, message_len,randNum,0,sig);
                }
                */
            }
            else //需要内部产生随机数
            {
                ret = secp256k1_sign(prikey, message, message_len,NULL,1,sig);
            /*
               if(type &mask2)
               {
                   ret = secp256k1_sign(prikey, message, message_len,NULL,1,sig);
               }
                else
                {
                    ret = secp256k1_sign(prikey, message, message_len,NULL,0,sig);
                }
            */
            }
        }
            break;
        case ECC_CURVE_SECP256R1:
        {
            if(type & mask1)//外部传入随机数
            {
                //判断随机数是否为全0
                if(is_all_zero(randNum, ECC_LEN))
                {
                    return RAND_IS_NULL;
                }
                ret = secp256r1_sign(prikey, message, message_len,randNum,1,sig);
            /*
                if(type & mask2)//外部已经计算哈希值
                {
                    ret = secp256r1_sign(prikey, message, message_len,randNum,1,sig);
                }
                else//需要内部计算哈希值
                {
                    ret = secp256r1_sign(prikey, message, message_len,randNum,0,sig);
                }
            */
            }
            else //需要内部产生随机数
            {
                ret = secp256r1_sign(prikey, message, message_len,NULL,1,sig);
            /*
                if(type & mask2)//外部已经计算哈希值
                {
                    ret = secp256r1_sign(prikey, message, message_len,NULL,1,sig);
                }
                else //需要内部计算哈希值
                {
                    ret = secp256r1_sign(prikey, message, message_len,NULL,0,sig);
                }
            */
            }
        }
            break;
        case ECC_CURVE_SM2_STANDARD:
        {
            if(ID == NULL || IDlen == 0)
                return ECC_MISS_ID;
            if(type&mask1)//外部传入随机数
            {
                //判断随机数是否为全0
                if(is_all_zero(randNum, ECC_LEN))
                {
                    return RAND_IS_NULL;
                }
                if(type&mask2) //外部已经计算哈希值
                {
                    ret = sm2_std_sign(prikey, ID, IDlen, message, message_len,randNum,1,sig);
                }
                else//需要内部计算哈希值
                {
                    ret = sm2_std_sign(prikey, ID, IDlen, message, message_len,randNum,0,sig);
                }
            }
            else//需要内部计算随机数
            {
                if(type&mask2)//外部已经计算哈希值
                {
                    ret = sm2_std_sign(prikey, ID, IDlen, message, message_len,NULL,1,sig);
                }
                else//需要内部计算哈希值
                {
                    ret = sm2_std_sign(prikey, ID, IDlen, message, message_len,NULL,0,sig);
                }
            }
            
        }
            break;
        case ECC_CURVE_CURVE25519:
        {
            CURVE25519_Sign(prikey, message, message_len, sig, 0);
            ret = SUCCESS;
        }
            break;
        case  ECC_CURVE_ED25519:
        {
            ED25519_Sign(prikey, message, message_len, sig, ECC_CURVE_ED25519);
            ret = SUCCESS;
        }
            break;
        case ECC_CURVE_X25519:
        {
            /*int REF10_curve25519_sign(unsigned char* signature_out,
             const unsigned char* curve25519_privkey,
             const unsigned char* msg, const unsigned long msg_len,
             const unsigned char* random)*/
            SHA512_CTX sha512;
            uint32_ow hashTime = (uint32_ow)time(NULL);
            uint8_ow *random = NULL;
            random = calloc(1, 64);
            sha512_init(&sha512);
            sha512_update(&sha512, (uint8_ow*)&hashTime, 4);
            sha512_update(&sha512, prikey, 32);
            sha512_update(&sha512, message, message_len);
            sha512_final(&sha512, random);
            if(0 != X25519_Sign(sig, prikey, message, message_len, random))
            {
                free(random);
                ret = FAILURE;
            }else{
                free(random);
                ret = SUCCESS;
            }
        }
            break;
        default:
        {
            ret = ECC_WRONG_TYPE;
        }
            break;
    }
    return  ret;
}

uint16_ow ECC_verify(uint8_ow *pubkey, uint8_ow *ID, uint16_ow IDlen, uint8_ow *message, uint16_ow message_len, uint8_ow *sig, uint32_ow type)
{
    uint16_ow ret = 0;
    uint32_ow mask1=1<<9,mask2=0xECC000FF;
    
    switch (type & mask2)
    {
        case ECC_CURVE_SECP256K1:
        {
            ret = secp256k1_verify(pubkey, message, message_len, 1,sig);
            /*
            if(type & mask1)//外部已经计算哈希值
            {
                ret = secp256k1_verify(pubkey, message, message_len, 1,sig);
            }
            else//需要内部计算哈希值
            {
                ret = secp256k1_verify(pubkey, message, message_len, 0,sig);
            }
             */
            
        }
          break;
        case ECC_CURVE_SECP256R1:
        {
             ret = secp256r1_verify(pubkey, message, message_len,1,sig);
            /*
            if(type & mask1)//外部已经计算哈希值
            {
                 ret = secp256r1_verify(pubkey, message, message_len,1,sig);
            }
            else
            {
                ret = secp256r1_verify(pubkey, message, message_len,0,sig);
            }
             */
        }
            break;
        case ECC_CURVE_SM2_STANDARD:
        {
            if(ID == NULL || IDlen == 0)
                return ECC_MISS_ID;
            if(type & mask1)//外部已经计算哈希值
            {
                ret = sm2_std_verify(pubkey, ID, IDlen, message, message_len,1, sig);
            }
            else//需要内部计算哈希值
            {
                 ret = sm2_std_verify(pubkey, ID, IDlen, message, message_len,0, sig);
            }
            
        }
            break;
        case ECC_CURVE_CURVE25519:
        case ECC_CURVE_ED25519:
        {
            ret = ED25519_Verify(pubkey, message, message_len, sig);
        }
            break;
        case ECC_CURVE_X25519:
        {
            /*
             int REF10_curve25519_verify(const unsigned char* signature,
             const unsigned char* curve25519_pubkey,
             const unsigned char* msg, const unsigned long msg_len)
             */
            if(0 != X25519_Verify(sig, pubkey, message, message_len))
            {
                ret = FAILURE;
            }else{
                ret = SUCCESS;
            }
        }
            break;
        default:
        {
            ret = ECC_WRONG_TYPE;
        }
            break;
    }
    return  ret;
}

uint16_ow ECC_enc(uint8_ow *pubkey, uint8_ow *plain, uint16_ow plain_len, uint8_ow *cipher, uint16_ow *cipher_len, uint32_ow type)
{
    uint16_ow ret = 0;
    
    switch (type)
    {
        case ECC_CURVE_SM2_STANDARD:
        {
            ret = sm2_std_enc(pubkey, plain, plain_len, cipher, cipher_len);
        }
            break;
        default:
        {
            ret = ECC_WRONG_TYPE;
        }
            break;
    }
    
    return  ret;
}

uint16_ow ECC_dec(uint8_ow *prikey, uint8_ow *cipher, uint16_ow cipher_len, uint8_ow *plain, uint16_ow *plain_len, uint32_ow type)
{
    uint16_ow ret = 0;
    
    switch (type)
    {
        case ECC_CURVE_SM2_STANDARD:
        {
            ret = sm2_std_dec(prikey, cipher, cipher_len, plain, plain_len);
        }
            break;
        default:
        {
            ret = ECC_WRONG_TYPE;
        }
            break;
    }
    
    return  ret;
}


//////////////////////////////////////////////////////协商////////////////////////////////////////////////
uint16_ow ECC_key_exchange_initiator_step1(uint8_ow *tmpPriInitiator, uint8_ow *tmpPubInitiator, uint32_ow type)
{
    uint16_ow ret = 0;
    
    switch (type)
    {
        case ECC_CURVE_SM2_STANDARD:
        {
            sm2_std_ka_initiator_step1(tmpPriInitiator, tmpPubInitiator);
            ret = SUCCESS;
        }
            break;
        default:
        {
            ret = ECC_WRONG_TYPE;
        }
            break;
    }
    
    return ret;
}

uint16_ow ECC_key_exchange_initiator_step2(uint8_ow *IDinitiator,         \
                                          uint16_ow IDinitiator_len,     \
                                          uint8_ow *IDresponder,         \
                                          uint16_ow IDresponder_len,     \
                                          uint8_ow *priInitiator,        \
                                          uint8_ow *pubInitiator,        \
                                          uint8_ow *pubResponder,        \
                                          uint8_ow *tmpPriInitiator,     \
                                          uint8_ow *tmpPubInitiator,     \
                                          uint8_ow *tmpPubResponder,     \
                                          uint8_ow *Sin,                 \
                                          uint8_ow *Sout,                \
                                          uint16_ow keylen,              \
                                          uint8_ow *key,                 \
                                          uint32_ow type)
{
    uint16_ow ret = 0;
    
    switch (type)
    {
        case ECC_CURVE_SM2_STANDARD:
        {
            ret = sm2_std_ka_initiator_step2(IDinitiator, IDinitiator_len,     \
                                             IDresponder, IDresponder_len,     \
                                             priInitiator, pubInitiator,       \
                                             pubResponder, tmpPriInitiator,    \
                                             tmpPubInitiator, tmpPubResponder, \
                                             Sin, Sout,                        \
                                             keylen, key);
        }
            break;
        default:
        {
            ret = ECC_WRONG_TYPE;
        }
            break;
    }
    
    return ret;
}

uint16_ow ECC_key_exchange_responder_step1(uint8_ow *IDinitiator,         \
                                          uint16_ow IDinitiator_len,     \
                                          uint8_ow *IDresponder,         \
                                          uint16_ow IDresponder_len,     \
                                          uint8_ow *priResponder,        \
                                          uint8_ow *pubResponder,        \
                                          uint8_ow *pubInitiator,        \
                                          uint8_ow *tmpPubResponder,     \
                                          uint8_ow *tmpPubInitiator,     \
                                          uint8_ow *Sin,                 \
                                          uint8_ow *Sout,                \
                                          uint16_ow keylen,              \
                                          uint8_ow *key,                 \
                                          uint32_ow type)
{
    uint16_ow ret = 0;
    
    switch (type)
    {
        case ECC_CURVE_SM2_STANDARD:
        {
            ret = sm2_std_ka_responder_step1(IDinitiator, IDinitiator_len, IDresponder, IDresponder_len, priResponder, pubResponder, pubInitiator, tmpPubResponder, tmpPubInitiator, Sin, Sout, keylen, key, 0, 0);
        }
            break;
        default:
        {
            ret = ECC_WRONG_TYPE;
        }
            break;
    }
    
    return ret;
}

uint16_ow ECC_key_exchange_responder_ElGamal_step1(uint8_ow *IDinitiator,     \
                                               uint16_ow IDinitiator_len,     \
                                               uint8_ow *IDresponder,         \
                                               uint16_ow IDresponder_len,     \
                                               uint8_ow *priResponder,        \
                                               uint8_ow *pubResponder,        \
                                               uint8_ow *pubInitiator,        \
                                               uint8_ow *tmpPubResponder,     \
                                               uint8_ow *tmpPubInitiator,     \
                                               uint8_ow *Sin,                 \
                                               uint8_ow *Sout,                \
                                               uint16_ow keylen,              \
                                               uint8_ow *key,                 \
                                               uint8_ow *random,              \
                                               uint32_ow type)
{
    uint16_ow ret = 0;
    
    switch (type)
    {
        case ECC_CURVE_SM2_STANDARD:
        {
            ret = sm2_std_ka_responder_step1(IDinitiator, IDinitiator_len, IDresponder, IDresponder_len, priResponder, pubResponder, pubInitiator, tmpPubResponder, tmpPubInitiator, Sin, Sout, keylen, key, random, 1);
        }
            break;
        default:
        {
            ret = ECC_WRONG_TYPE;
        }
            break;
    }
    
    return ret;
}

uint16_ow ECC_key_exchange_responder_step2(uint8_ow *Sinitiator, uint8_ow *Sresponder, uint32_ow type)
{
    uint16_ow ret = 0;
    
    switch (type)
    {
        case ECC_CURVE_SM2_STANDARD:
        {
            ret = sm2_std_ka_responder_step2(Sinitiator, Sresponder);
            break;
        }
        default:
        {
            ret = ECC_WRONG_TYPE;
        }
            break;
    }
    
    return ret;
}



/*
 @function:(Point)outpoint_buf = (Point)inputpoint1_buf+[k](Point)inputpoint2_buf
 @paramter[in]:inputpoint1_buf pointer to one point(stored by byte string) on the curve elliptic
 @paramter[in]:inputpoint2_buf pointer to another point(stored by byte string) on the curve elliptic
 @paramter[in]:k pointer to the multiplicator
 @paramter[out]:outpoint_buf pointer to the result(stored by byte string)
 @paramter[in]:type denotes ECC_CURVE_PARAM type.ECC_CURVE_SECP256K1:choose secp256k1 paramters;ECC_CURVE_SECP256R1:choose
 secp256r1 paramters; ECC_CURVE_SM2_STANDARD;choose sm2 paramters.others:not support.
 @return:0表示运算失败；1表示运算成功.
 */

//uint16_ow ECC_point_mul_add(ECC_POINT *P,ECC_POINT *Q,uint8_ow *k,ECC_POINT *T,uint32_ow Type)
uint16_ow ECC_point_mul_add(uint8_ow *inputpoint1_buf,uint8_ow *inputpoint2_buf,uint8_ow *k,uint8_ow *outpoint_buf,uint32_ow type)
{
    if(type == ECC_CURVE_SECP256K1)
    {
        return secp256k1_point_mul_add(inputpoint1_buf,inputpoint2_buf,k,outpoint_buf);
    }
    else if(type == ECC_CURVE_SECP256R1)
    {
        return secp256r1_point_mul_add(inputpoint1_buf,inputpoint2_buf,k,outpoint_buf);
    }
    else if(type == ECC_CURVE_SM2_STANDARD)
    {
        return sm2_point_mul_add(inputpoint1_buf,inputpoint2_buf,k,outpoint_buf);
    }
    else
    {
        return 0;
    }
}

/*
 @function:(Point)outpoint_buf = (Point)inputpoint_buf+[k]G(G is the base point of curve elliptic)
 @paramter[in]:inputpoint_buf pointer to one point(stored by byte string) on the curve elliptic
 @paramter[in]:k pointer to the multiplicator
 @paramter[out]:outpoint_buf pointer to the result(stored by byte string)
 @paramter[in]:type denotes ECC_CURVE_PARAM type.ECC_CURVE_SECP256K1:choose secp256k1 paramters;ECC_CURVE_SECP256R1:choose
 secp256r1 paramters; ECC_CURVE_SM2_STANDARD;choose sm2 paramters.others:not support.
 @return:0 表示运算失败；1 表示运算成功.
 ed25519 data is in little endian
 */

uint16_ow ECC_point_mul_baseG_add(uint8_ow *inputpoint_buf,uint8_ow *k,uint8_ow *outpoint_buf,uint32_ow type)
{
    
    if(type==ECC_CURVE_SECP256K1)
    {
        return secp256k1_point_mul_baseG_add(inputpoint_buf,k,outpoint_buf);
    }
    else if(type == ECC_CURVE_SECP256R1)
    {
        return secp256r1_point_mul_base_G_add(inputpoint_buf,k,outpoint_buf);
    }
    else if(type == ECC_CURVE_SM2_STANDARD)
    {
        return sm2_point_mul_baseG_add(inputpoint_buf,k,outpoint_buf);
    }
    else if(type == ECC_CURVE_ED25519)
    {
        return ED25519_point_add_mul_base(inputpoint_buf, k, outpoint_buf);
    }
    else
    {
        return 0;
    }
    
}


uint16_ow ECC_point_mul_baseG(uint8_ow *scalar, uint8_ow *point, uint32_ow type)
{
    switch (type) {
        case ECC_CURVE_SECP256K1:
            return secp256k1_genPubkey(scalar, point);
            break;
        case ECC_CURVE_SECP256R1:
            return secp256r1_genPubkey(scalar, point);
            break;
        case ECC_CURVE_SM2_STANDARD:
            return sm2_std_genPubkey(scalar, point);
            break;
        case ECC_CURVE_ED25519:
            ED25519_point_mul_base(scalar, point);
            return SUCCESS;
            break;
        case ECC_CURVE_X25519:
            X25519_genPubkey(point, scalar);
            return SUCCESS;
        default:
            return ECC_WRONG_TYPE;
            break;
    }
}

/*
 @function:椭圆曲线上点的压缩
 @paramter[in]:pubKey,待压缩的公钥
 @paramter[in]:pubKey_len表示公钥的字节长度
 @paramter[out]:x,公钥压缩后的横坐标（长度为ECC_LEN+1 字节）
 @paramter[in]:TYpe denotes ECC_CURVE_PARAM type.ECC_CURVE_SECP256K1:choose secp256k1 paramters;ECC_CURVE_SECP256R1:choose
 secp256r1 paramters; ECC_CURVE_SM2_STANDARD;choose sm2 paramters.others:not support.
 @return：0 表示压缩失败；1 表示压缩成功
 @note:secp256k1/secp256r1/sm2三种形式的参数，点的压缩都是一样的处理流程.此处之所以通过Type做区别，只是为了在形式上与解压缩函数保持一致.
 */

uint16_ow ECC_point_compress(uint8_ow *pubKey,uint16_ow pubKey_len,uint8_ow *x,uint32_ow type)
{
    if(type == ECC_CURVE_SECP256K1)
    {
        return secp256k1_point_compress(pubKey, pubKey_len,x);
    }
    else if(type == ECC_CURVE_SECP256R1)
    {
        return secp256r1_point_compress(pubKey, pubKey_len,x);
    }
    else if(type == ECC_CURVE_SM2_STANDARD)
    {
        return sm2_point_compress(pubKey, pubKey_len,x);
    }
    else
    {
        return 1;
    }
}

/*
 @function:椭圆曲线上点的解压缩
 @paramter[in]:curveParam pointer to curve elliptic paramters
 @paramter[in]:x pointer to the x-coordiate of the point on curve elliptic
 @paramter[in]:x_len denotes the byte length of x(x_len=ECC_LEN=1)
 @paramter[out]:y pointer to the y-coordiate of the point on curve elliptic
 @paramter[in]:Type denotes ECC_CURVE_PARAM type.ECC_CURVE_SECP256K1:choose secp256k1 paramters;ECC_CURVE_SECP256R1:choose
 secp256r1 paramters; ECC_CURVE_SM2_STANDARD;choose sm2 paramters.others:not support.
 @return:1 表示解压缩失败；0 表示解压缩成功
*/
uint16_ow ECC_point_decompress(uint8_ow *x,uint16_ow x_len,uint8_ow *y,uint32_ow type)
{
    if(type == ECC_CURVE_SECP256K1)
    {
        return secp256k1_point_decompress(x,x_len,y);
    }
    else if(type == ECC_CURVE_SECP256R1)
    {
        return secp256r1_point_decompress(x,x_len,y);
    }
    else if(type == ECC_CURVE_SM2_STANDARD)
    {
        return sm2_point_decompress(x,x_len,y);
    }
    else
    {
        return 1;
    }
}

uint16_ow ECC_get_curve_order(uint8_ow *order, uint32_ow type)
{
    uint16_ow ret = SUCCESS;
    
    switch (type)
    {
        case ECC_CURVE_SECP256K1:
        {
            secp256k1_get_order(order);
        }
            break;
        case ECC_CURVE_SECP256R1:
        {
            secp256r1_get_order(order);
        }
            break;
        case ECC_CURVE_SM2_STANDARD:
        {
            sm2_std_get_order(order);
        }
            break;
        case ECC_CURVE_CURVE25519:
        case ECC_CURVE_ED25519:
        {
            ED25519_get_order(order);
        }
            break;
        default:
        {
            ret = ECC_WRONG_TYPE;
        }
            break;
    }
    
    return  ret;
}

/*
 @function:recover the the public key of the signer.
 @paramter[in]sig pointer to signature(r||s||v)
 @paramter[in]sig_len denotes the length of sig (must be 65 byte)
 @paramter[in]msg pointer to message(or hash value)
 @paramter[in]msg_len denotes the length of msg
 @paramter[in]type denotes the ECC ALG type choose
 @paramter[out]pubkey pointer to the recover public key
 */
uint16_ow ECC_recover_pubkey(uint8_ow *sig,uint32_ow sig_len,uint8_ow *msg,uint32_ow msg_len,uint8_ow *pubkey,uint32_ow type)
{
    uint16_ow ret = SUCCESS;
    //uint32_ow mask1=1<<9;
    uint32_ow mask2=0xECC000FF;
    if(sig_len !=65)
    {
        ret=LENGTH_ERROR;
    }
    switch(type & mask2)
    {
        case ECC_CURVE_SECP256K1:
        {
             secp256k1_recover_pubkey(sig,sig_len,msg,msg_len,1,pubkey);
            /*
            if(type & mask1)//外部已经计算哈希
            {
                secp256k1_recover_pubkey(sig,sig_len,msg,msg_len,1,pubkey);
            }
            else
            {
                secp256k1_recover_pubkey(sig,sig_len,msg,msg_len,0,pubkey);
            }
             */
            break;
        }
        case ECC_CURVE_SECP256R1:
        {
            secp256r1_recover_pubkey(sig,sig_len,msg,msg_len,1,pubkey);
           /*
            if(type & mask1)
            {
                secp256r1_recover_pubkey(sig,sig_len,msg,msg_len,1,pubkey);
            }
            else
            {
                secp256r1_recover_pubkey(sig,sig_len,msg,msg_len,0,pubkey);
            }
            */
            
            break;
        }
        default:
        {
            ret=ECC_WRONG_TYPE;
            break;
        }
    }
    return ret;
}



/*
 @functions: convert between x25519 point and ed25519 point
 */
uint16_ow CURVE25519_convert_X_to_Ed(uint8_ow *ed, uint8_ow *x)
{
    if(convert_X_to_Ed(ed, x) != 0)
        return FAILURE;
    return SUCCESS;
}

uint16_ow CURVE25519_convert_Ed_to_X(uint8_ow *x, uint8_ow *ed)
{
    if(convert_Ed_to_X(x, ed) != 0)
        return FAILURE;
    return SUCCESS;
}


uint16_ow MultiSig_key_exchange_step1(uint8_ow *pubkey, uint8_ow *tmp_rand, uint8_ow *tmp_point, uint32_ow curve_type)
{
    switch (curve_type) {
        case ECC_CURVE_SECP256K1:
            return secp256k1_multisig_keyexchange_step1(pubkey, tmp_rand, tmp_point);
            break;
            
        default:
            return ECC_WRONG_TYPE;
            break;
    }
}

uint16_ow MultiSig_key_exchange_step2(uint8_ow *prikey, uint8_ow *tmp_rand, uint8_ow *tmp_point, uint8_ow *result, uint32_ow curve_type)
{
    switch (curve_type) {
        case ECC_CURVE_SECP256K1:
            return secp256k1_multisig_keyexchange_step2(prikey, tmp_rand, tmp_point, result);
            break;
            
        default:
            return ECC_WRONG_TYPE;
            break;
    }
}

uint16_ow ECC_point_add(uint8_ow *point1, uint8_ow *point2, uint8_ow *point, uint32_ow curve_type)
{
    switch (curve_type) {
        case ECC_CURVE_SECP256K1:
            return secp256k1_point_add(point1, point2, point);
            break;
            
        default:
            return ECC_WRONG_TYPE;
            break;
    }
}

uint16_ow ECC_point_mul(uint8_ow *point_in, uint8_ow *scalar, uint8_ow *point_out, uint32_ow curve_type)
{
    switch (curve_type) {
        case ECC_CURVE_SECP256K1:
            return secp256k1_point_mul(point_in, scalar, point_out);
            break;
            
        default:
            return ECC_WRONG_TYPE;
            break;
    }
}
