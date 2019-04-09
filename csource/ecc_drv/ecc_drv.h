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

#ifndef ecc_drv_h
#define ecc_drv_h

#include <stdio.h>
#include "bignum.h"
#include <stdlib.h>
#include <string.h>
#include "type.h"

#define ECC_LEN 32

typedef struct
{
    uint8_ow *p;
    uint8_ow *a;
    uint8_ow *b;
    uint8_ow *x;
    uint8_ow *y;
    uint8_ow *n;
}ECC_CURVE_PARAM;

typedef struct
{
    uint8_ow x[ECC_LEN];
    uint8_ow y[ECC_LEN];
    uint8_ow infinity;//判断点是否为无穷远点的标志位.1:无穷远点；0:不是无穷远点.
}ECC_POINT;

uint8_ow is_prikey_legal(ECC_CURVE_PARAM *curveParam, uint8_ow *prikey); //1 for legal //0 for illegal
uint8_ow point_add(ECC_CURVE_PARAM *curveParam, ECC_POINT *point1, ECC_POINT *point2, ECC_POINT *point);//point = point1 + point2//return 1 : infinity point
uint8_ow point_mul(ECC_CURVE_PARAM *curveParam, ECC_POINT *point_in, uint8_ow *k, ECC_POINT *point_out);//point_out= [k]point_in//return 1 : infinity point//二进制展开
uint8_ow is_pubkey_legal(ECC_CURVE_PARAM *curveParam, ECC_POINT *point);//1 for legal//0 for illegal

/*
 @function:(Point)outpoint_buf = (Point)inputpoint1_buf +[k](Point)inputpoint2_buf
 @paramter[in]:curveParam pointer to curve elliptic paremters
 @paramter[in]:inputpoint1_buf pointer to one point on the curve elliptic(stroreed by byte string)
 @paramter[in]:Q pointer to another point on the elliptic(stored by byte string)
 @paramter[in]:k pointer to the multiplicator
 @paramter[out]:outpoint_buf pointer to the result((Point)outpoint_buf:=(Point)inputpoint1_buf +[k](Point)inputpoint2_buf)
 */
uint8_ow point_mul_add(ECC_CURVE_PARAM *curveParam,uint8_ow *inputpoint1_buf,uint8_ow *inputpoint2_buf,uint8_ow *k,uint8_ow *outpoint_buf);

/*
 @function:点的压缩
 @paramter[in]:point_buf,待压缩的点
 @paramter[in]:point_buf_len表示point_buf的字节长度
 @paramter[in]:x,点压缩后的横坐标（长度为ECC_LEN+1 字节）
 @return：1，压缩失败；0:压缩成功
 */
uint8_ow point_compress(uint8_ow *point_buf,uint16_ow point_buf_len,uint8_ow *x);

/*
 @function:点的解压缩：根据曲线参数curveParam和x坐标，求解y坐标(满足曲线方程y^2=x^3+a*x+b)
 @paramter[in]:curveParam,椭圆曲线方程参数
 @paramter[in]:compresspoint,曲线上点的横坐标（第一个字节为0x02或0x03.0x02表示y为偶数；0x03表示y为奇数）
 @paramter[in]:compresspoint_len表示x的字节长度（一个字节的表示符 + ECC_LEN 字节的私钥）
 @paramter[out]:decompresspoint,待求解的曲线上的点（含0x04）
 @return:1,表示输入的数据格式错误或者求解y时，平方根不存在;0:表示解压缩成功
 @note：(1)输入的x坐标一定带有标示字节（第一个字节）0x02:表示y为偶数；0x03表示y为奇数.(2)目前支持（p =3(mod4)和p=5(mod8)两种情况）
 */

uint8_ow point_decompress(ECC_CURVE_PARAM *curveParam, uint8_ow *compresspoint,uint16_ow compresspoint_len,uint8_ow *decompresspoint);

#endif /* ecc_drv_h */
