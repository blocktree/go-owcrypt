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

#ifndef pbkdf2_h
#define pbkdf2_h
#include "type.h"
#include "hmac.h"

/*
 @function:Apply a pseudorandom function to derive keys
 @paramter[in] pw pointer to pass words
 @paramter[in] pw_len denotes the byte length of pw
 @paramter[in] salt pointer to the salt
 @paramter[in]salt_len denotes the byte length of salt
 @paramter[in]iterations denotes the iteration times
 @paramter[out]out pointer to the derived key
 @paramter[in]out_len denotes byte length of derived key
 */
void pbkdf2_hamc_sha512(uint8_ow *pw,uint32_ow pw_len,uint8_ow *salt,uint32_ow salt_len,uint32_ow iterations,uint8_ow *out,uint32_ow out_len);

#endif /* pbkdf2_h */
