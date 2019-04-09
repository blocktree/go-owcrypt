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

#include "bigrand.h"


void bigrand_get_rand_range_normal(uint8_ow *bigrand, uint8_ow *range, uint16_ow len)
{
    uint32_ow tmp = 0;
    uint16_ow i = 0;
    
    srand((uint32_ow)time(NULL));
    
    for(i = 0; i < len / 4; i ++)
    {
        tmp = rand();
        memcpy(bigrand + i * 4, (uint8_ow *)&tmp, 4);
    }
    
    if((len - i * 4) % 4)
    {
        tmp = rand();
        memcpy(bigrand + i * 4, (uint8_ow *)&tmp, (len - i * 4) % 4);
    }
    
    while(*bigrand >= *range)
        *bigrand -= *range;
}

void bigrand_get_rand_range(uint8_ow *bigrand, uint8_ow *range, uint8_ow *key, uint16_ow keyLen, uint8_ow *data, uint16_ow dataLen)
{
    if(key == 0)
    {
        bigrand_get_rand_range_normal(bigrand, range, ECC_LEN);
        return;
    }
    
    uint8_ow hashSrc[ECC_LEN * 2] = {0};
    
    uint32_ow hashTime = (uint32_ow)time(NULL);
    
    switch (hashTime & 0x03) {
        case 0:
        {
            SHA512_CTX sha512;
            sha512_init(&sha512);
            sha512_update(&sha512, (uint8_ow*)&hashTime, 4);
            sha512_update(&sha512, key, keyLen);
            sha512_update(&sha512, data, dataLen);
            sha512_final(&sha512, hashSrc);
        }
            break;
        case 1:
        {
            SHA3_512_CTX sha3_512;
            sha3_512_init(&sha3_512);
            sha3_512_update(&sha3_512, (uint8_ow*)&hashTime, 4);
            sha3_512_update(&sha3_512, key, keyLen);
            sha3_512_update(&sha3_512, data, dataLen);
            sha3_512_final(&sha3_512, hashSrc);
        }
            break;
        case 2:
        {
            KECCAK512_CTX keccak512;
            keccak512_init(&keccak512);
            keccak512_update(&keccak512, (uint8_ow*)&hashTime, 4);
            keccak512_update(&keccak512, key, keyLen);
            keccak512_update(&keccak512, data, dataLen);
            keccak512_final(&keccak512, hashSrc);
        }
            break;
        default:
        {
            BLAKE512_CTX blake512;
            blake512_init(&blake512);
            blake512_update(&blake512, (uint8_ow*)&hashTime, 4);
            blake512_update(&blake512, key, keyLen);
            blake512_update(&blake512, data, dataLen);
            blake512_final(&blake512, hashSrc);
        }
            break;
    }
    BLAKE2B_CTX blake2b;
    blake2b_init(&blake2b, hashSrc, ECC_LEN, ECC_LEN);
    blake2b_update(&blake2b, hashSrc + ECC_LEN, ECC_LEN);
    blake2b_final(&blake2b, bigrand, ECC_LEN);
    
    while(*bigrand >= *range)
        *bigrand -= *range;
}

