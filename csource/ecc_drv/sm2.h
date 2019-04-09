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

#ifndef sm2_h
#define sm2_h

#include <stdio.h>
#include "ecc_set.h"
#include "ecc_drv.h"
#include "sm3.h"
#include "bigrand.h"
#include "bignum.h"
#include "type.h"

void sm2_std_get_order(uint8_ow *order);

uint16_ow sm2_std_genPubkey(uint8_ow *prikey, uint8_ow *pubkey);
//uint16_ow sm2_std_sign(uint8_ow *prikey, uint8_ow *ID, uint16_ow IDlen, uint8_ow *message, uint16_ow message_len, uint8_ow *sig);
uint16_ow sm2_std_sign(uint8_ow *prikey, uint8_ow *ID, uint16_ow IDlen, uint8_ow *message, uint16_ow message_len,uint8_ow *rand,uint8_ow hash_flag, uint8_ow *sig);
//uint16_ow sm2_std_verify(uint8_ow *pubkey, uint8_ow *ID, uint16_ow IDlen, uint8_ow *message, uint16_ow message_len, uint8_ow *sig);
uint16_ow sm2_std_verify(uint8_ow *pubkey, uint8_ow *ID, uint16_ow IDlen, uint8_ow *message, uint16_ow message_len, uint8_ow hash_flag,uint8_ow *sig);
uint16_ow sm2_std_enc(uint8_ow *pubkey, uint8_ow *plain, uint16_ow plain_len, uint8_ow *cipher, uint16_ow *cipher_len);
uint16_ow sm2_std_dec(uint8_ow *prikey, uint8_ow *cipher, uint16_ow cipher_len, uint8_ow *plain, uint16_ow *plain_len);


/////////////////////////////////////////////////////////////////////密钥协商///////////////////////////////////////////////////////////////
void sm2_ka_get_Z(uint8_ow *ID, uint16_ow IDlen, uint8_ow *pubkey, uint8_ow *Z);
void  sm2_std_ka_initiator_step1(uint8_ow *tmpPriInitiator, uint8_ow *tmpPubInitiator);
uint16_ow sm2_std_ka_initiator_step2(uint8_ow *IDinitiator,         \
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
                                    uint8_ow *key);
uint16_ow sm2_std_ka_responder_step1(uint8_ow *IDinitiator,         \
                                    uint16_ow IDinitiator_len,     \
                                    uint8_ow *IDresponder,         \
                                    uint16_ow IDresponder_len,     \
                                    uint8_ow *priResponder,        \
                                    uint8_ow *pubResponder,        \
                                    uint8_ow *pubInitiator,        \
                                    uint8_ow *tmpPubResponder,     \
                                    uint8_ow *tmpPubInitiator,     \
                                    uint8_ow *Sinner,              \
                                    uint8_ow *Souter,              \
                                    uint16_ow keylen,              \
                                    uint8_ow *key,                 \
                                    uint8_ow *random,              \
                                    uint8_ow isElGamal);
uint16_ow sm2_std_ka_responder_step2(uint8_ow *Sinitiator, uint8_ow *Sresponder);
/*
 @function:(Point)outpointbuf = (Point)inputpoint1_buf+[k](Point)inputpoint2_buf
 @paramter[in]:inputpoint1_buf pointer to one point(stored by byte string) on the elliptic
 @paramter[in]:inputpoint2_buf pointer to another point(stored by byte string) on the elliptic
 @paramter[in]:k pointer to the multiplicator
 @paramter[out]:outpointbuf pointer to the result(stored by byte string)
 @return:0表示运算失败；1表示运算成功.
 */
uint16_ow sm2_point_mul_add(uint8_ow *inputpoint1_buf,uint8_ow *inputpoint2_buf,uint8_ow *k,uint8_ow *outpointbuf);

/*
 @function:(Point)outpoint_buf = (Point)inputpoint_buf+[k]G(G is the base point of curve elliptic)
 @paramter[in]:P pointer to one point(stored by byte string) on the elliptic
 @paramter[in]:k pointer to the multiplicator
 @paramter[out]:outpoint_buf pointer to the result(stored by byte string)
 @return:0表示运算失败；1表示运算成功.
 */
uint16_ow sm2_point_mul_baseG_add(uint8_ow *inputpoint_buf,uint8_ow *k,uint8_ow *outpoint_buf);

/*
 @function:椭圆曲线（sm2）上点的压缩
 @paramter[in]:point_buf,待压缩的点（stored by byte string）
 @paramter[in]:point_buf_len表示point_buf的字节长度
 @paramter[out]:x,点压缩后的横坐标（长度为ECC_LEN+1 字节）
 @return：0 表示压缩失败；1 表示压缩成功
 */
uint16_ow sm2_point_compress(uint8_ow *point_buf,uint16_ow point_buf_len,uint8_ow *x);

/*
 @function:椭圆曲线(sm2)点的解压缩
 @paramter[in]:x pointer to the x-coordiate of the point on curve elliptic
 @paramter[in]:x_len denotes the byte length of x(x_len=ECC_LEN=1)
 @paramter[out]:point_buf pointer to the xy-coordiate(with 0x04) of the point on curve elliptic
 @return：0 表示解压缩失败；1 表示解压缩成功
 */
uint16_ow sm2_point_decompress(uint8_ow *x,uint16_ow x_len,uint8_ow *point_buf);
#endif /* sm2_h */
