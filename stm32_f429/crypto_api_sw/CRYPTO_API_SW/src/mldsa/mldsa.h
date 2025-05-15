/**
  * @file mldsa.h
  * @brief ML-DSA header
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
  * @version 5.0
  **/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "src/params.h"
#include "src/packing.h"
#include "src/polyvec.h"
#include "src/poly.h"
#include "src/randombytes.h"
#include "src/symmetric.h"
#include "src/fips202.h"

void MLDSA_44_GEN_KEYS(unsigned char* pri_key, unsigned char* pub_key);
void MLDSA_65_GEN_KEYS(unsigned char* pri_key, unsigned char* pub_key);
void MLDSA_87_GEN_KEYS(unsigned char* pri_key, unsigned char* pub_key);

void MLDSA_44_SIGN(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pri_key, unsigned char* sig, unsigned int* sig_len, unsigned char* ctx, unsigned int ctxlen);
void MLDSA_65_SIGN(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pri_key, unsigned char* sig, unsigned int* sig_len, unsigned char* ctx, unsigned int ctxlen);
void MLDSA_87_SIGN(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pri_key, unsigned char* sig, unsigned int* sig_len, unsigned char* ctx, unsigned int ctxlen);

int crypto_sign_signature_44(uint8_t* sig, size_t* siglen, const uint8_t* m, size_t mlen, const uint8_t* ctx, size_t ctxlen, const uint8_t rnd[RNDBYTES], const uint8_t* sk);
int crypto_sign_signature_65(uint8_t* sig, size_t* siglen, const uint8_t* m, size_t mlen, const uint8_t* ctx, size_t ctxlen, const uint8_t rnd[RNDBYTES], const uint8_t* sk);
int crypto_sign_signature_87(uint8_t* sig, size_t* siglen, const uint8_t* m, size_t mlen, const uint8_t* ctx, size_t ctxlen, const uint8_t rnd[RNDBYTES], const uint8_t* sk);

void MLDSA_44_VERIFY(const unsigned char* msg, unsigned int msg_len, const unsigned char* pub_key, const unsigned char* sig, unsigned int sig_len, unsigned int* result, const unsigned char* ctx, unsigned int ctxlen);
void MLDSA_65_VERIFY(const unsigned char* msg, unsigned int msg_len, const unsigned char* pub_key, const unsigned char* sig, unsigned int sig_len, unsigned int* result, const unsigned char* ctx, unsigned int ctxlen);
void MLDSA_87_VERIFY(const unsigned char* msg, unsigned int msg_len, const unsigned char* pub_key, const unsigned char* sig, unsigned int sig_len, unsigned int* result, const unsigned char* ctx, unsigned int ctxlen);