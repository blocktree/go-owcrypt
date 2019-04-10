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

#ifndef ecc_set_h
#define ecc_set_h

#include <stdio.h>
#include "ecc_drv.h"
#include "type.h"

/*
 note：定义的type为0xECCXXXXX，其中低8bit(bit 0~7）为曲线类型，具体参考下面宏定义；
 bit 8 为随机数生成方式的标志位，1:外部传入随机数；0:内部产生随机数；
 bit 9 为传入消息形式的标志位，1:传入消息的哈希值；0；传入消息本身.
 */
#define  ECC_CURVE_SECP256K1        0xECC00000
#define  ECC_CURVE_SECP256R1        0xECC00001
#define  ECC_CURVE_PRIMEV1          ECC_CURVE_SECP256R1
#define  ECC_CURVE_NIST_P256        ECC_CURVE_SECP256R1
#define  ECC_CURVE_SM2_STANDARD     0xECC00002
#define  ECC_CURVE_CURVE25519       0xECC00003
#define  ECC_CURVE_ED25519          0xECC00004
#define  ECC_CURVE_X25519           0xECC00005

#define SUCCESS              0x0001
#define FAILURE              0x0000
#define ECC_PRIKEY_ILLEGAL   0xE000
#define ECC_PUBKEY_ILLEGAL   0xE001
#define ECC_WRONG_TYPE       0xE002
#define ECC_MISS_ID          0xE003
#define RAND_IS_NULL         0xE004
#define LENGTH_ERROR    0xE005

/*
 @function:preprocess the random number in ECC signeture
 @paramter[in]rand pointer to the random number used in ECC signature
 @return:SUCCESS,operation success;others:operation fail
 @note:if you want to incomming random number from outside in ECC signature,this function muse be recalled before start signature.
*/
uint16_ow ECC_preprocess_randomnum(uint8_ow *rand);
uint16_ow ECC_genPubkey(uint8_ow *prikey, uint8_ow *pubkey, uint32_ow type);
uint16_ow ECC_sign(uint8_ow *prikey, uint8_ow *ID, uint16_ow IDlen, uint8_ow *message, uint16_ow message_len, uint8_ow *sig, uint32_ow type);
uint16_ow ECC_verify(uint8_ow *pubkey, uint8_ow *ID, uint16_ow IDlen, uint8_ow *message, uint16_ow message_len, uint8_ow *sig, uint32_ow type);
uint16_ow ECC_enc(uint8_ow *pubkey, uint8_ow *plain, uint16_ow plain_len, uint8_ow *cipher, uint16_ow *cipher_len, uint32_ow type);
uint16_ow ECC_dec(uint8_ow *prikey, uint8_ow *cipher, uint16_ow cipher_len, uint8_ow *plain, uint16_ow *plain_len, uint32_ow type);

//////////////////////////////////////////////////////协商/////////////////////////////////////////////////
uint16_ow ECC_key_exchange_initiator_step1(uint8_ow *tmpPriInitiator, uint8_ow *tmpPubInitiator, uint32_ow type);
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
                                          uint32_ow type);
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
                                          uint32_ow type);
uint16_ow ECC_key_exchange_responder_ElGamal_step1(uint8_ow *IDinitiator,         \
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
                                           uint32_ow type);
uint16_ow ECC_key_exchange_responder_step2(uint8_ow *Sinitiator, uint8_ow *Sresponder, uint32_ow type);
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
uint16_ow ECC_point_mul_add(uint8_ow *inputpoint1_buf,uint8_ow *inputpoint2_buf,uint8_ow *k,uint8_ow *outpoint_buf,uint32_ow type);

/*
 @function:(Point)outpoint_buf = (Point)inputpoint_buf+[k]G(G is the base point of curve elliptic)
 @paramter[in]:inputpoint_buf pointer to one point(stored by byte string) on the curve elliptic
 @paramter[in]:k pointer to the multiplicator
 @paramter[out]:outpoint_buf pointer to the result(stored by byte string)
 @paramter[in]:type denotes ECC_CURVE_PARAM type.ECC_CURVE_SECP256K1:choose secp256k1 paramters;ECC_CURVE_SECP256R1:choose
 secp256r1 paramters; ECC_CURVE_SM2_STANDARD;choose sm2 paramters.others:not support.
 @return:0 表示运算失败；1 表示运算成功.
 */

uint16_ow ECC_point_mul_baseG_add(uint8_ow *inputpoint_buf,uint8_ow *k,uint8_ow *outpoint_buf,uint32_ow type);

uint16_ow ECC_point_mul_baseG(uint8_ow *scalar, uint8_ow *point, uint32_ow type);

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

uint16_ow ECC_point_compress(uint8_ow *pubKey,uint16_ow pubKey_len,uint8_ow *x,uint32_ow type);


/*
 @function:椭圆曲线上点的解压缩
 @paramter[in]:curveParam pointer to curve elliptic paramters
 @paramter[in]:x pointer to the x-coordiate of the point on curve elliptic
 @paramter[in]:x_len denotes the byte length of x(x_len=ECC_LEN=1)
 @paramter[out]:y pointer to the y-coordiate of the point on curve elliptic
 @paramter[in]:Type denotes ECC_CURVE_PARAM type.ECC_CURVE_SECP256K1:choose secp256k1 paramters;ECC_CURVE_SECP256R1:choose
 secp256r1 paramters; ECC_CURVE_SM2_STANDARD;choose sm2 paramters.others:not support.
 @return:0 表示解压缩失败；1 表示解压缩成功
 */
uint16_ow ECC_point_decompress(uint8_ow *x,uint16_ow x_len,uint8_ow *y,uint32_ow type);

/*
 @function:获取椭圆曲线的阶
 @paramter[in]:Type denotes ECC_CURVE_PARAM type.ECC_CURVE_SECP256K1:choose secp256k1 paramters;ECC_CURVE_SECP256R1:choose
 @paramter[out]:order the order of the curve
 @return: SUCCESS/ECC_WRONG_TYPE
 */
uint16_ow ECC_get_curve_order(uint8_ow *order, uint32_ow type);

/*
 @function:recover the the public key of the signer.
 @paramter[in]sig pointer to signature(r||s||v)
 @paramter[in]sig_len denotes the length of sig (must be 65 byte)
 @paramter[in]msg pointer to message(or hash value)
 @paramter[in]msg_len denotes the length of msg
 @paramter[in]type denotes the ECC ALG type choose
 @paramter[out]pubkey pointer to the recover public key
 */
uint16_ow ECC_recover_pubkey(uint8_ow *sig,uint32_ow sig_len,uint8_ow *msg,uint32_ow msg_len,uint8_ow *pubkey,uint32_ow type);


/*
 @functions: convert between x25519 point and ed25519 point
 */
uint16_ow CURVE25519_convert_X_to_Ed(uint8_ow *ed, uint8_ow *x);
uint16_ow CURVE25519_convert_Ed_to_X(uint8_ow *x, uint8_ow *ed);

#endif /* ecc_set_h */
