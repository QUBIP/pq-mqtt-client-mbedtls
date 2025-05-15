/**
 * @file sha512_224.c
 * @brief SHA-512/224 (Secure Hash Algorithm)
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
 * @section Description
 *
 * SHA-512/224 is a secure hash algorithm for computing a condensed representation
 * of an electronic message. Refer to FIPS 180-4 for more details
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.4.4
 **/

//Dependencies
#include "sha2_base.h"
#include "sha512_224.h"


//SHA-512/224 object identifier (2.16.840.1.101.3.4.2.5)
const uint8_t SHA512_224_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05};

//Common interface for hash algorithms
const HashAlgo sha512_224HashAlgo =
{
   "SHA-512/224",
   SHA512_224_OID,
   sizeof(SHA512_224_OID),
   sizeof(Sha512_224Context),
   SHA512_224_BLOCK_SIZE,
   SHA512_224_DIGEST_SIZE,
   SHA512_224_MIN_PAD_SIZE,
   1,
   (HashAlgoCompute) sha512_224Compute,
   (HashAlgoInit) sha512_224Init,
   (HashAlgoUpdate) sha512_224Update,
   (HashAlgoFinal) sha512_224Final,
   NULL
};


/**
 * @brief Digest a message using SHA-512/224
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

void sha512_224Compute(const void *data, size_t length, uint8_t *digest)
{

   Sha512_224Context *context;
   context = malloc(sizeof(Sha512_224Context));

   //Initialize the SHA-512/224 context
   sha512_224Init(context);
   //Digest the message
   sha512_224Update(context, data, length);
   //Finalize the SHA-512/224 message digest
   sha512_224Final(context, digest);

   free(context);

}


/**
 * @brief Initialize SHA-512/224 message digest context
 * @param[in] context Pointer to the SHA-512/224 context to initialize
 **/

void sha512_224Init(Sha512_224Context *context)
{
   //Set initial hash value
   context->h[0] = 0x8C3D37C819544DA2;
   context->h[1] = 0x73E1996689DCD4D6;
   context->h[2] = 0x1DFAB7AE32FF9C82;
   context->h[3] = 0x679DD514582F9FCF;
   context->h[4] = 0x0F6D2B697BD44DA8;
   context->h[5] = 0x77E36F7304C48942;
   context->h[6] = 0x3F9D85A86A1D36C8;
   context->h[7] = 0x1112E6AD91D692A1;

   //Number of bytes in the buffer
   context->size = 0;
   //Total length of the message
   context->totalSize = 0;
}


/**
 * @brief Update the SHA-512/224 context with a portion of the message being hashed
 * @param[in] context Pointer to the SHA-512/224 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void sha512_224Update(Sha512_224Context *context, const void *data, size_t length)
{
   //The function is defined in the exact same manner as SHA-512
   sha512Update(context, data, length);
}


/**
 * @brief Finish the SHA-512/224 message digest
 * @param[in] context Pointer to the SHA-512/224 context
 * @param[out] digest Calculated digest (optional parameter)
 **/

void sha512_224Final(Sha512_224Context *context, uint8_t *digest)
{
   //The function is defined in the exact same manner as SHA-512
   sha512Final(context, NULL);

   //Copy the resulting digest
   if(digest != NULL)
   {
      memcpy(digest, context->digest, SHA512_224_DIGEST_SIZE);
   }
}
