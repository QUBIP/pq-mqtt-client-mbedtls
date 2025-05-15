/**
  * @file eddsa.h
  * @brief EdDSA header
  *
  * @section License
  *
  * MIT License
  *
  * Copyright (c) 2024 Eros Camacho
  *
  * Permission is hereby granted, free of charge, to any person obtaining a copy
  * of this software and associated documentation files (the "Software"), to deal
  * in the Software without restriction, including without limitation the rights
  * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  * copies of the Software, and to permit persons to whom the Software is
  * furnished to do so, subject to the following conditions:
  *
  * The above copyright notice and this permission notice shall be included in all
  * copies or substantial portions of the Software.
  *
  * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  * SOFTWARE.
  *
  *
  *
  * @author Eros Camacho-Ruiz (camacho@imse-cnm.csic.es)
  * @version 4.0
  **/

#ifndef EDDSA_H
#define	EDDSA_H

#ifdef OPENSSL

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#elif MBEDTLS

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/ecp.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#else

#include "../trng/trng.h"
#include "alt/ed25519.h"
#include "alt/ed448.h"

#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void EDDSA25519_GEN_KEYS(unsigned char** pri_key, unsigned char** pub_key, unsigned int* pri_len, unsigned int* pub_len);
void EDDSA25519_SIGN(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pri_key, const unsigned int pri_len, unsigned char** sig, unsigned int* sig_len);
void EDDSA25519_VERIFY(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pub_key, const unsigned int pub_len, const unsigned char* sig, const unsigned int sig_len, unsigned int* result);

void EDDSA448_GEN_KEYS(unsigned char** pri_key, unsigned char** pub_key, unsigned int* pri_len, unsigned int* pub_len);
void EDDSA448_SIGN(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pri_key, const unsigned int pri_len, unsigned char** sig, unsigned int* sig_len);
void EDDSA448_VERIFY(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pub_key, const unsigned int pub_len, const unsigned char* sig, const unsigned int sig_len, unsigned int* result);


#endif