/**
 * @file sha512.h
 * @brief SHA-512 (Secure Hash Algorithm 512)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2024 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneCRYPTO Open.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.4.4
 **/

#ifndef _SHA512_H
#define _SHA512_H

//Dependencies
#include <stdlib.h>
#include "sha2_base.h"


//SHA-512 block size
#define SHA512_BLOCK_SIZE 128
//SHA-512 digest size
#define SHA512_DIGEST_SIZE 64
//Minimum length of the padding string
#define SHA512_MIN_PAD_SIZE 17
//Common interface for hash algorithms
#define SHA512_HASH_ALGO (&sha512HashAlgo)


/**
 * @brief SHA-512 algorithm context
 **/

typedef struct
{
   union
   {
      uint64_t h[8];
      uint8_t digest[64];
   };
   union
   {
      uint64_t w[16];
      uint8_t buffer[128];
   };
   size_t size;
   uint64_t totalSize;
} Sha512Context;


//SHA-512 related constants
extern const uint8_t SHA512_OID[9];
extern const HashAlgo sha512HashAlgo;

//SHA-512 related functions
void sha512Compute(const void *data, size_t length, uint8_t *digest);
void sha512Init(Sha512Context *context);
void sha512Update(Sha512Context *context, const void *data, size_t length);
void sha512Final(Sha512Context *context, uint8_t *digest);
void sha512ProcessBlock(Sha512Context *context);


#endif
