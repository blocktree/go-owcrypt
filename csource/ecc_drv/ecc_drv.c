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

#include "ecc_drv.h"
#include "owcrypt_core.h"

/** 1 for legal;0 for illegal **/

/*
 @function:transfer byte string to point
 @paramter[in]:src pointer to source address(byte string)
 @paramter[out]:dst pointer to destination address(point)
 @return: 1 denotes success; 0 denotes fail
 */
static uint8_ow byte_to_point(uint8_ow *src,ECC_POINT *dst)
{
    if(!src || !dst)
    {
        return 0;
    }
    memcpy(dst->x,src,ECC_LEN);
    memcpy(dst->y,src+ECC_LEN,ECC_LEN);
    //make sure the input point is not infinity
    dst->infinity = 0;
    return 1;
}
/*
 @function:transfer point to byte string
 @paramter[in]:src pointer to source address(point)
 @paramter[out]:dst pointer to destination address(byte string)
 @return: 1 denotes success; 0 denotes fail
 */
static uint8_ow point_to_byte(ECC_POINT *src,uint8_ow *dst)
{
    if(!dst || !src)
    {
        return 0;
    }
    memcpy(dst,src->x,ECC_LEN);
    memcpy(dst + ECC_LEN,src->y,ECC_LEN);
    return 1;
}
uint8_ow is_prikey_legal(ECC_CURVE_PARAM *curveParam, uint8_ow *prikey)
{
    if(is_all_zero(prikey, ECC_LEN) || memcmp(prikey, curveParam -> n, ECC_LEN) >= 0)
        return 0;
    else
        return 1;
}

uint8_ow is_neg_y(uint8_ow *y1, uint8_ow *y2, uint8_ow *p)
{
    uint8_ow *tmp = NULL;
    tmp = calloc(ECC_LEN, sizeof(uint8_ow));
    
    bignum_mod_add(y1, y2, p, tmp);
    
    if(is_all_zero(tmp, ECC_LEN))
    {
        free(tmp);
        return 1;
    }
    else
    {
        free(tmp);
        return 0;
    }
}


//point = point1 + point2
//return 1 : infinity point
uint8_ow point_add(ECC_CURVE_PARAM *curveParam, ECC_POINT *point1, ECC_POINT *point2, ECC_POINT *point)
{
    owcrypt owc;
    
    owcrypt *pr_owc = &owc;
    
    OWC_BN p1x,p1y,p2x,p2y,p,a,b;
    owc_point *p1,*p2;
    
    owcsys_init(pr_owc);
    
    p1x = bignum_init(pr_owc);
    p1y = bignum_init(pr_owc);
    p2x = bignum_init(pr_owc);
    p2y = bignum_init(pr_owc);
    p   = bignum_init(pr_owc);
    a   = bignum_init(pr_owc);
    b   = bignum_init(pr_owc);
    
    bytes_to_big(pr_owc, ECC_LEN, (char *)point1->x, p1x);
    bytes_to_big(pr_owc, ECC_LEN, (char *)point1->y, p1y);
    bytes_to_big(pr_owc, ECC_LEN, (char *)point2->x, p2x);
    bytes_to_big(pr_owc, ECC_LEN, (char *)point2->y, p2y);
    bytes_to_big(pr_owc, ECC_LEN, (char *)curveParam ->p, p);
    bytes_to_big(pr_owc, ECC_LEN, (char *)curveParam ->a, a);
    bytes_to_big(pr_owc, ECC_LEN, (char *)curveParam ->b, b);
    
    p1 = epoint_init(pr_owc);
    p2 = epoint_init(pr_owc);
    
    ecurve_init(pr_owc, a, b, p);
    
    epoint_set(pr_owc, p1x, p1y, p1);
    epoint_set(pr_owc, p2x, p2y, p2);
    
    ecurve_add(pr_owc, p1, p2);
    
    epoint_get(pr_owc, p2, p2x, p2y);
    
    big_to_bytes(pr_owc, ECC_LEN, p2x, (char *)point->x, 1);
    big_to_bytes(pr_owc, ECC_LEN, p2y, (char *)point->y, 1);
    
    point->infinity =   point_at_infinity(p2);
    
    epoint_free(p1);
    epoint_free(p2);
    
    bignum_clear(p1x);
    bignum_clear(p1y);
    bignum_clear(p2x);
    bignum_clear(p2y);
    bignum_clear(p);
    bignum_clear(a);
    bignum_clear(b);
    
    memkill(pr_owc, pr_owc->tmp_alloc, 26);
    
    return point->infinity;
}

//point_out= [k]point_in
//return 1 : infinity point
//二进制展开
uint8_ow point_mul(ECC_CURVE_PARAM *curveParam, ECC_POINT *point_in, uint8_ow *k, ECC_POINT *point_out)
{
    owcrypt owc;
    
    owcrypt *pr_owc = &owc;
    
    OWC_BN pinx,piny,poutx,pouty,p,a,b,scalar;
    owc_point *pin,*pout;
    
    owcsys_init(pr_owc);
    
    pinx   = bignum_init(pr_owc);
    piny   = bignum_init(pr_owc);
    poutx  = bignum_init(pr_owc);
    pouty  = bignum_init(pr_owc);
    p      = bignum_init(pr_owc);
    a      = bignum_init(pr_owc);
    b      = bignum_init(pr_owc);
    scalar = bignum_init(pr_owc);
    
    bytes_to_big(pr_owc, ECC_LEN, (char *)point_in->x, pinx);
    bytes_to_big(pr_owc, ECC_LEN, (char *)point_in->y, piny);
    bytes_to_big(pr_owc, ECC_LEN, (char *)curveParam ->p, p);
    bytes_to_big(pr_owc, ECC_LEN, (char *)curveParam ->a, a);
    bytes_to_big(pr_owc, ECC_LEN, (char *)curveParam ->b, b);
    bytes_to_big(pr_owc, ECC_LEN, (char *)k, scalar);
    
    pin = epoint_init(pr_owc);
    pout = epoint_init(pr_owc);
    
    ecurve_init(pr_owc, a, b, p);
    
    epoint_set(pr_owc, pinx, piny, pin);
    
    ecurve_mult(pr_owc, scalar, pin, pout);
    
    epoint_get(pr_owc, pout, poutx, pouty);
    
    big_to_bytes(pr_owc, ECC_LEN, poutx, (char *)point_out->x, 1);
    big_to_bytes(pr_owc, ECC_LEN, pouty, (char *)point_out->y, 1);
    
    point_out->infinity =  point_at_infinity(pout);
    
    epoint_free(pin);
    epoint_free(pout);
    
    bignum_clear(pinx);
    bignum_clear(piny);
    bignum_clear(poutx);
    bignum_clear(pouty);
    bignum_clear(p);
    bignum_clear(a);
    bignum_clear(b);
    bignum_clear(scalar);
    
    memkill(pr_owc, pr_owc->tmp_alloc, 26);
    
    return point_out->infinity;
}

//1 for legal
//0 for illegal
uint8_ow is_pubkey_legal(ECC_CURVE_PARAM *curveParam, ECC_POINT *point)
{
    uint8_ow *tmp1 = NULL, *tmp2 = NULL;
    ECC_POINT *point_tmp = NULL;
    
    if(memcmp(point -> x, curveParam -> p, ECC_LEN) >= 0 || memcmp(point -> y, curveParam -> p, ECC_LEN) >= 0)
        return 0;
    
    tmp1 = calloc(ECC_LEN, sizeof(uint8_ow));
    tmp2 = calloc(ECC_LEN, sizeof(uint8_ow));
    
    bignum_mod_mul(point -> x, point -> x, curveParam -> p, tmp1);
    bignum_mod_mul(point -> x, tmp1, curveParam -> p, tmp2);
    bignum_mod_mul(curveParam -> a, point -> x, curveParam -> p, tmp1);
    bignum_mod_add(tmp1, tmp2, curveParam -> p, tmp1);
    bignum_mod_add(tmp1, curveParam -> b, curveParam -> p, tmp1);
    
    bignum_mod_mul(point -> y, point -> y, curveParam -> p, tmp2);
    
    if(memcmp(tmp1, tmp2, ECC_LEN))
    {
        free(tmp1);
        free(tmp2);
        return 0;
    }
    
    point_tmp = calloc(1, sizeof(ECC_POINT));
    
    if(!point_mul(curveParam, point, curveParam -> n, point_tmp))
    {
        free(tmp1);
        free(tmp2);
        free(point_tmp);
        return 0;
    }
    
    free(tmp1);
    free(tmp2);
    free(point_tmp);
    
    return 1;
}
/*
 @function:(Point)outpoint_buf = (Point)inputpoint1_buf +[k](Point)inputpoint2_buf
 @paramter[in]:curveParam pointer to curve elliptic paremters
 @paramter[in]:inputpoint1_buf pointer to one point on the curve elliptic(stroreed by byte string)
 @paramter[in]:Q pointer to another point on the elliptic(stored by byte string)
 @paramter[in]:k pointer to the multiplicator
 @paramter[out]:outpoint_buf pointer to the result((Point)outpoint_buf:=(Point)inputpoint1_buf +[k](Point)inputpoint2_buf)
 */
uint8_ow point_mul_add(ECC_CURVE_PARAM *curveParam,uint8_ow *inputpoint1_buf,uint8_ow *inputpoint2_buf,uint8_ow *k,uint8_ow *outpoint_buf)
{
    uint16_ow ret;
    ECC_POINT *P=NULL,*Q=NULL,*T=NULL;
    P = calloc(1,sizeof(ECC_POINT));
    Q = calloc(1,sizeof(ECC_POINT));
    T = calloc(1,sizeof(ECC_POINT));
    byte_to_point(inputpoint2_buf,Q);
    ret=point_mul(curveParam, Q, k, T);
    if(ret)
    {
        return ret;
    }
    byte_to_point(inputpoint1_buf,P);
    ret=point_add(curveParam, P, T, Q);
    if(ret)
    {
        return ret;
    }
    point_to_byte(Q,outpoint_buf);
    free(P);
    free(Q);
    free(T);
    return 0;
}


/*
 @function:点的压缩
 @paramter[in]:point_buf,待压缩的点
 @paramter[in]:point_buf_len表示point_buf的字节长度
 @paramter[in]:x,点压缩后的横坐标（长度为ECC_LEN+1 字节）
 @return：1，压缩失败；0:压缩成功
 */
uint8_ow point_compress(uint8_ow *point_buf,uint16_ow point_buf_len,uint8_ow *x)
{
    if(point_buf_len ==((ECC_LEN<<1) + 1))
    {
        if(point_buf[0]!=0x04)
            return 0;
    }
    else if(point_buf_len == (ECC_LEN<<1))
    {
        ;
    }
    else
    {
        return 0;
    }
    if(point_buf_len == ((ECC_LEN<<1)+1))
    {
        if(point_buf[(ECC_LEN << 1)]&0x01)
        {
            x[0]=0x03;
            memcpy(x + 1,point_buf+1,(point_buf_len-1)>>1);
        }
        else
        {
            x[0]=0x02;
            memcpy(x+1,point_buf + 1,(point_buf_len-1)>>1);
        }
    }
    else
    {
        if(point_buf[(ECC_LEN << 1)-1]&0x01)
        {
            x[0]=0x03;
            memcpy(x + 1,point_buf,point_buf_len>>1);
        }
        else
        {
            x[0]=0x02;
            memcpy(x+1,point_buf,point_buf_len>>1);
        }
    }
    return 1;
}

/*
 @function:点的解压缩：根据曲线参数curveParam和x坐标，求解y坐标(满足曲线方程y^2=x^3+a*x+b)
 @paramter[in]:curveParam,椭圆曲线方程参数
 @paramter[in]:compresspoint,曲线上点的横坐标（第一个字节为0x02或0x03.0x02表示y为偶数；0x03表示y为奇数）
 @paramter[in]:compresspoint_len表示x的字节长度（一个字节的表示符 + ECC_LEN 字节的私钥）
 @paramter[out]:decompresspoint,待求解的曲线上的点（含0x04）
 @return:1,表示输入的数据格式错误或者求解y时，平方根不存在;0:表示解压缩成功
 @note：(1)输入的x坐标一定带有标示字节（第一个字节）0x02:表示y为偶数；0x03表示y为奇数.(2)目前支持（p =3(mod4)和p=5(mod8)两种情况）
 */
uint8_ow point_decompress(ECC_CURVE_PARAM *curveParam, uint8_ow *compresspoint,uint16_ow compresspoint_len,uint8_ow *decompresspoint)
{
    uint8_ow *tmp1 = NULL, *tmp2 = NULL,*tmp3=NULL,*tmp4=NULL;
    ECC_POINT *point=NULL;
    tmp1 = calloc(ECC_LEN, sizeof(uint8_ow));
    tmp2 = calloc(ECC_LEN, sizeof(uint8_ow));
    tmp3 = calloc(ECC_LEN, sizeof(uint8_ow));
    tmp4 = calloc(ECC_LEN, sizeof(uint8_ow));
    point=calloc(1,sizeof(ECC_POINT));
    if(compresspoint_len != (ECC_LEN + 1))
    {
        free(point);
        free(tmp1);
        free(tmp2);
        free(tmp3);
        free(tmp4);
        return 0;
    }
    if((compresspoint[0] != 0x02)&&(compresspoint[0] != 0x03))
    {
        free(point);
        free(tmp1);
        free(tmp2);
        free(tmp3);
        free(tmp4);
        return 0;
    }
    //求解tmp1 = x^2
    bignum_mod_mul(compresspoint+1, compresspoint+1, curveParam -> p, tmp1);
    //求解tmp2 = x^3
    bignum_mod_mul(compresspoint+1, tmp1, curveParam -> p, tmp2);
    //求解 tmp1 = a*x (mod q)
    bignum_mod_mul(curveParam -> a, compresspoint + 1, curveParam -> p, tmp1);
    //求解 tmp1 = x^3 + a*x
    bignum_mod_add(tmp1, tmp2, curveParam -> p, tmp1);
    //求解 tmp1 = x^3 + a*x +b
    bignum_mod_add(tmp1, curveParam -> b, curveParam -> p, tmp1);
    //下面求解tmp1的平方根
    
    //curveParam->p =3(mod 4)
    if((curveParam->p[ECC_LEN-1]&0x03)==3)
    {
        memset(tmp2,0,ECC_LEN);
        tmp2[ECC_LEN-1]=0x03;
        //tmp3=(p-3)/4
        bignum_sub(curveParam->p, tmp2, ECC_LEN,tmp3);
        bignum_shr_1bit(tmp3, ECC_LEN);
        bignum_shr_1bit(tmp3, ECC_LEN);
         memset(tmp2,0,ECC_LEN);
        tmp2[ECC_LEN-1]=0x01;
        //计算tmp3 = tmp3 + 1
        bignum_add(tmp3, tmp2, ECC_LEN, tmp3);
        //计算tmp2=tmp1^(tmp3)
        bignum_mod_exp(tmp1, tmp3, curveParam->p, tmp2);
        //计算 tmp3 = tmp2^2
        bignum_mod_mul(tmp2, tmp2, curveParam->p, tmp3);
        //check whether tmp1 is equal to tmp3.if it is,tmp3 is the result we need;otherwise,there is no square root.
        if(bignum_cmp(tmp1, ECC_LEN,tmp3,ECC_LEN)==0)
        {
            if(compresspoint[0]==0x02)
            {
                if(tmp2[ECC_LEN-1]&0x01)
                {
                    bignum_sub(curveParam->p, tmp2, ECC_LEN, decompresspoint + ECC_LEN + 1);
                }
                else
                {
                    memcpy(decompresspoint + ECC_LEN + 1,tmp2,ECC_LEN);
                    
                }
            }
           else if(compresspoint[0]==0x03)
            {
                if(tmp2[ECC_LEN-1]&0x01)
                {
                  memcpy(decompresspoint + ECC_LEN + 1,tmp2,ECC_LEN);
                }
                else
                {
                    bignum_sub(curveParam->p, tmp2, ECC_LEN, decompresspoint + ECC_LEN + 1);
                }
            }
            else
            {
                return 0;
            }
        }
        else
        {
            free(point);
            free(tmp1);
            free(tmp2);
            free(tmp3);
            free(tmp4);
            return 0;
        }
    }
    //curveParam->p = 5(mod 8)
    else if((curveParam->p[ECC_LEN-1]&7)==5)
    {
        memset(tmp2,0,ECC_LEN);
        //tmp4 = (p-5)/8
        tmp2[ECC_LEN-1]=0x05;
        bignum_sub(curveParam->p, tmp2, ECC_LEN,tmp4);
        bignum_shr_1bit(tmp4, ECC_LEN);
        bignum_shr_1bit(tmp4, ECC_LEN);
        bignum_shr_1bit(tmp4, ECC_LEN);
        //tmp3=2*tmp4
        bignum_add(tmp4, tmp4, ECC_LEN, tmp3);
        //tmp3 = tmp3 + 1
        memset(tmp2,0,ECC_LEN);
        tmp2[ECC_LEN]=0x01;
        bignum_add(tmp3, tmp2, ECC_LEN, tmp3);
        //tmp2=tmp1^tmp3
        bignum_mod_exp(tmp1, tmp3, curveParam->p, tmp2);
        bignum_mod(tmp2, curveParam->p, tmp3);
        
        memset(tmp2, 0, ECC_LEN);
        tmp2[ECC_LEN-1]=0x01;
        if( bignum_cmp(tmp3, ECC_LEN,tmp2,ECC_LEN)==0)
        {
            memset(tmp2,0,ECC_LEN);
            tmp2[ECC_LEN-1]=0x01;
            bignum_add(tmp4, tmp2, ECC_LEN, tmp4);
            bignum_mod_exp(tmp1, tmp4, curveParam->p, tmp2);
            if(compresspoint[0]==0x02)
            {
                if(tmp2[ECC_LEN-1]&0x01)
                {
                    bignum_sub(curveParam->p, tmp2, ECC_LEN, decompresspoint + ECC_LEN + 1);
                }
                else
                {
                    memcpy(decompresspoint + ECC_LEN + 1,tmp2,ECC_LEN);
                }
            }
            else if(compresspoint[0]==0x03)
            {
                if(tmp2[ECC_LEN-1]&0x01)
                {
                    memcpy(decompresspoint + ECC_LEN + 1,tmp2,ECC_LEN);
                }
                else
                {
                    bignum_sub(curveParam->p, tmp2, ECC_LEN, decompresspoint + ECC_LEN + 1);
                }
            }
            else
            {
                free(point);
                free(tmp1);
                free(tmp2);
                free(tmp3);
                free(tmp4);
                return 0;
            }
        }
        else
        {
            bignum_sub(curveParam->p, tmp2, ECC_LEN, tmp2);
            if(bignum_cmp(tmp3, ECC_LEN,tmp2,ECC_LEN)==0)
            {
                memset(tmp2,0,ECC_LEN);
                tmp2[ECC_LEN-1]=0x04;
                bignum_mod_mul(tmp1,tmp2,curveParam ->p, tmp3);
                bignum_mod_exp(tmp3, tmp4, curveParam->p, tmp2);
                memset(tmp3,0,ECC_LEN);
                tmp3[ECC_LEN] = 0x02;
                bignum_mod_mul(tmp1,tmp3,curveParam ->p, tmp4);
                bignum_mod_mul(tmp4,tmp2,curveParam ->p, tmp3);
                if(compresspoint[0]==0x02)
                {
                    if(tmp3[ECC_LEN-1]&0x01)
                    {
                       bignum_sub(curveParam->p, tmp3, ECC_LEN, decompresspoint + ECC_LEN + 1);
                    }
                    else
                    {
                        memcpy(decompresspoint + ECC_LEN + 1,tmp3,ECC_LEN);
                    }
                }
                else if(compresspoint[0]==0x03)
                {
                    if(tmp3[ECC_LEN-1]&0x01)
                    {
                        memcpy(decompresspoint + ECC_LEN + 1,tmp3,ECC_LEN);
                    }
                    else
                    {
                        bignum_sub(curveParam->p, tmp3, ECC_LEN, decompresspoint + ECC_LEN + 1);
                    }
                }
            }
            else
            {
                return 0;
            }
        }
    }
    //暂时不支持这种模式
    else if((curveParam->p[ECC_LEN-1]&7)==1)
    {
        ;
    }
    else
    {
        free(point);
        free(tmp1);
        free(tmp2);
        free(tmp3);
        free(tmp4);
        return 0;
    }
    decompresspoint[0]=0x04;
    memcpy(decompresspoint + 1,compresspoint+1,ECC_LEN);
    memcpy(point->x,decompresspoint+1,32);
    memcpy(point->y,decompresspoint+33,32);
    if(!is_pubkey_legal(curveParam, point))
    {
        free(point);
        free(tmp1);
        free(tmp2);
        free(tmp3);
        free(tmp4);
        return 0;
    }
    free(point);
    free(tmp1);
    free(tmp2);
    free(tmp3);
    free(tmp4);
    return 1;
}


