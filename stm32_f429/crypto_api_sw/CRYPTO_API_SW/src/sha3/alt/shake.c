/**
 * @file shake.c
 * @brief SHAKE128 and SHAKE256 extendable-output functions
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
 * SHAKE is a function on binary data in which the output can be extended to any
 * desired length. SHAKE128 supports 128 bits of security strength. SHAKE256
 * supports 256 bits of security strength. Refer to FIPS 202 for more details
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.4.4
 **/

#include "shake.h"


//SHAKE128 object identifier (2.16.840.1.101.3.4.2.11)
const uint8_t shake128Oid[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B};
//SHAKE256 object identifier (2.16.840.1.101.3.4.2.12)
const uint8_t shake256Oid[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C};


/**
 * @brief Digest a message using SHAKE128 or SHAKE256
 * @param[in] strength Number of bits of security (128 for SHAKE128 and
 *   256 for SHAKE256)
 * @param[in] input Pointer to the input data
 * @param[in] inputLen Length of the input data
 * @param[out] output Pointer to the output data
 * @param[in] outputLen Expected length of the output data
 * @return Error code
 **/

void shakeCompute(uint_t strength, const void *input, size_t inputLen, uint8_t *output, size_t outputLen)
{

    ShakeContext *context;
    context = malloc(sizeof(ShakeContext));

    //Initialize the SHAKE context
    shakeInit(context, strength);

    //Absorb input data
    shakeAbsorb(context, input, inputLen);
    //Finish absorbing phase
    shakeFinal(context);
    //Extract data from the squeezing phase
    shakeSqueeze(context, output, outputLen);

    free(context);

}


/**
 * @brief Initialize SHAKE context
 * @param[in] context Pointer to the SHAKE context to initialize
 * @param[in] strength Number of bits of security (128 for SHAKE128 and
 *   256 for SHAKE256)
 * @return Error code
 **/

void shakeInit(ShakeContext *context, uint_t strength)
{

    keccakInit(&context->keccakContext, 2 * strength);

}


/**
 * @brief Absorb data
 * @param[in] context Pointer to the SHAKE context
 * @param[in] input Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void shakeAbsorb(ShakeContext *context, const void *input, size_t length)
{
   //Absorb the input data
   keccakAbsorb(&context->keccakContext, input, length);
}


/**
 * @brief Finish absorbing phase
 * @param[in] context Pointer to the SHAKE context
 **/

void shakeFinal(ShakeContext *context)
{
   //Finish absorbing phase (padding byte is 0x1F for XOFs)
   keccakFinal(&context->keccakContext, KECCAK_SHAKE_PAD);
}


/**
 * @brief Extract data from the squeezing phase
 * @param[in] context Pointer to the SHAKE context
 * @param[out] output Output string
 * @param[in] length Desired output length, in bytes
 **/

void shakeSqueeze(ShakeContext *context, uint8_t *output, size_t length)
{
   //Extract data from the squeezing phase
   keccakSqueeze(&context->keccakContext, output, length);
}

