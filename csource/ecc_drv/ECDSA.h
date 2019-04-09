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

#ifndef ECDSA_h
#define ECDSA_h

#include <stdio.h>
#include "ecc_drv.h"
#include "ecc_set.h"
#include "bigrand.h"
#include "sha256.h"
#include "type.h"

uint16_ow ECDSA_genPubkey(ECC_CURVE_PARAM *curveParam, uint8_ow *prikey, ECC_POINT *pubkey);
//uint16_ow ECDSA_sign(ECC_CURVE_PARAM *curveParam, uint8_ow *prikey, uint8_ow *message, uint16_ow message_len, uint8_ow *sig);
uint16_ow ECDSA_sign(ECC_CURVE_PARAM *curveParam, uint8_ow *prikey, uint8_ow *message, uint16_ow message_len,uint8_ow *rand, uint8_ow hash_flag, uint8_ow *sig);
//uint16_ow ECDSA_verify(ECC_CURVE_PARAM *curveParam, ECC_POINT *pubkey, uint8_ow *message, uint16_ow message_len, uint8_ow *sig);
uint16_ow ECDSA_verify(ECC_CURVE_PARAM *curveParam, ECC_POINT *pubkey, uint8_ow *message, uint16_ow message_len,uint8_ow hash_flag, uint8_ow *sig);
uint16_ow ECDSA_recover_public(ECC_CURVE_PARAM *curveParam,uint8_ow *sig,uint32_ow sig_len,uint8_ow *msg,uint32_ow msg_len,uint8_ow hash_flag,uint8_ow *pubkey);
#endif /* ECDSA_h */
