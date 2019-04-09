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

#ifndef secp256k1_h
#define secp256k1_h

#include <stdio.h>
#include "ECDSA.h"
#include "ecc_set.h"
#include "type.h"

void secp256k1_get_order(uint8_ow *order);

uint16_ow secp256k1_genPubkey(uint8_ow *prikey, uint8_ow *pubkey);
//uint16_ow secp256k1_sign(uint8_ow *prikey, uint8_ow *message, uint16_ow message_len, uint8_ow *sig);
uint16_ow secp256k1_sign(uint8_ow *prikey, uint8_ow *message, uint16_ow message_len,uint8_ow *rand,uint8_ow hash_flag, uint8_ow *sig);
//uint16_ow secp256k1_verify(uint8_ow *pubkey, uint8_ow *message, uint16_ow message_len, uint8_ow *sig);
uint16_ow secp256k1_verify(uint8_ow *pubkey, uint8_ow *message, uint16_ow message_len, uint8_ow hash_flag,uint8_ow *sig);

/*
 @function:(Point) outpoint_buf= (Point)inputpoint1_buf+[k](Point)inputpoint2_buf
 @paramter[in]:inputpoint1_buf pointer to one point (stored by byte string)on the curve elliptic
 @paramter[in]:Q pointer to another point(stored by byte string) on the curve elliptic
 @paramter[in]:k pointer to the multiplicator
 @paramter[in]:outpoint_buf pointer to the result(stored by byte string)
 @return:0表示运算失败；1表示运算成功.
 */
uint16_ow secp256k1_point_mul_add(uint8_ow *inputpoint1_buf,uint8_ow *inputpoint2_buf,uint8_ow *k,uint8_ow *outpoint_buf);

/*
 @function:(Point)outpoint_buf = (Point)inputpoint_buf+[k]G(G is the base point of curve elliptic)
 @paramter[in]:inputpoint_buf pointer to one point on the curve elliptic(stored by byte string)
 @paramter[in]:k pointer to the multiplicator
 @paramter[out]:outpoint_buf pointer to the result(stored by byte string)
 @return:0表示运算失败；1表示运算成功.
 */
uint16_ow secp256k1_point_mul_baseG_add(uint8_ow *inputpoint_buf,uint8_ow *k,uint8_ow *outpoint_buf);

/*
 @function:椭圆曲线（参数为secp256k1）上点的压缩
 @paramter[in]:point_buf,待压缩的点
 @paramter[in]:point_buf_len表示point_buf的字节长度
 @paramter[out]:x,点压缩后的横坐标（长度为ECC_LEN+1 字节）
 @return：0表示压缩失败；1表示压缩成功
 */
uint16_ow secp256k1_point_compress(uint8_ow *point_buf,uint16_ow point_buf_len,uint8_ow *x);
/*
 @function:椭圆曲线(参数为secp256k1)点的解压缩
 @paramter[in]:x pointer to the x-coordiate of the point on curve elliptic
 @paramter[in]:x_len denotes the byte length of x(x_len=ECC_LEN=1)
 @paramter[out]:point_buf pointer to xy-coordiate(with 0x04) of the point on curve elliptic
 @return:1 表示解压缩失败；0 表示解压缩成功.
 */
uint16_ow secp256k1_point_decompress(uint8_ow *x,uint16_ow x_len,uint8_ow *point_buf);

/*
 @function:recover the the public key of the signer.
 @paramter[in]sig pointer to signature(r||s||v)
 @paramter[in]sig_len denotes the length of sig(65 bytes)
 @paramter[in]msg pointer to message(or hash value)
 @paramter[in]msg_len denotes the length of msg
 @paramter[in]hash_flag denotes the message type.1:hash(msg);0:just msg
 @paramter[out]pubkey pointer to the recovery public
 */
uint16_ow secp256k1_recover_pubkey(uint8_ow *sig,uint32_ow sig_len,uint8_ow *msg,uint32_ow msg_len,uint8_ow hash_flag,uint8_ow *pubkey);
#endif /* secp256k1_h */
