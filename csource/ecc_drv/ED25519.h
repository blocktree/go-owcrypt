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

#ifndef ED25519_h
#define ED25519_h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha512.h"
#include "sha256.h"

#include "ecc_set.h"
#include "type.h"

//point = [scalar]*G
//all in little-endian
void ED25519_point_mul_base(uint8_ow *scalar, uint8_ow *point);
//point2 = point1 + [scalar]*B
//B for basepoint
//all in little-endian
uint8_ow ED25519_point_add_mul_base(uint8_ow *point1, uint8_ow *scalar, uint8_ow *point2);

void ED25519_genPubkey(uint8_ow *prikey, uint8_ow *pubkey);
void ED25519_Sign(uint8_ow *prikey, uint8_ow *message, uint16_ow message_len, uint8_ow *sig, uint32_ow type);
uint16_ow ED25519_Verify(uint8_ow *pubkey, uint8_ow *message, uint16_ow message_len, uint8_ow *sig);
void ED25519_get_order(uint8_ow *order);
#endif /* ED25519_h */
