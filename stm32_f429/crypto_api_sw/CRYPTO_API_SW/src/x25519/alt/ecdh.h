/**
 * @file ecdh.h
 * @brief ECDH (Elliptic Curve Diffie-Hellman) key exchange
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

#ifndef _ECDH_H
#define _ECDH_H

//Dependencies
// #include "ec.h"
#include "../../trng/trng.h"
#include "x25519.h"
#include "x448.h"


/**
 * @brief ECDH context
 **/

/*
typedef struct
{
   EcDomainParameters params; ///<EC domain parameters
   EcPrivateKey da;           ///<One's own EC private key
   EcPublicKey qa;            ///<One's own EC public key
   EcPublicKey qb;            ///<Peer's EC public key
} EcdhContext;


//ECDH related functions
void ecdhInit(EcdhContext *context);
void ecdhFree(EcdhContext *context);

void ecdhGenerateKeyPair(EcdhContext *context, const PrngAlgo *prngAlgo,
   void *prngContext);

void ecdhCheckPublicKey(const EcDomainParameters *params, EcPoint *publicKey);

void ecdhComputeSharedSecret(EcdhContext *context,
   uint8_t *output, size_t outputSize, size_t *outputLen);
*/

void ecdhGenerateKeyPair(unsigned int curve, unsigned char* pri_key, unsigned char* pub_key);
void ecdhComputeSharedSecret(unsigned int curve, const unsigned char *pri_key, const unsigned char *pub_key,
   uint8_t *output);


#endif
