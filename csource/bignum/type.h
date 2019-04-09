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

#ifndef type_h
#define type_h


typedef  unsigned char        uint8_ow;
typedef  signed char          int8_ow;
typedef  unsigned short       uint16_ow;
typedef  short                int16_ow;
typedef  int                  int32_ow;
typedef  unsigned int         uint32_ow;
typedef  unsigned long long   uint64_ow;
typedef  long long            int64_ow;

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

typedef int BOOL;
#endif /* type_h */
