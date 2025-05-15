/**
  * @file mldsa.h
  * @brief SLH-DSA header
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
  * @version 6.0
  **/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "src/nistapi.h"
#include "src/randombytes.h"

void SLHDSA_SHAKE_128_F_GEN_KEYS(unsigned char* pri_key, unsigned char* pub_key);
void SLHDSA_SHAKE_128_S_GEN_KEYS(unsigned char* pri_key, unsigned char* pub_key);
void SLHDSA_SHAKE_192_F_GEN_KEYS(unsigned char* pri_key, unsigned char* pub_key);
void SLHDSA_SHAKE_192_S_GEN_KEYS(unsigned char* pri_key, unsigned char* pub_key);
void SLHDSA_SHAKE_256_F_GEN_KEYS(unsigned char* pri_key, unsigned char* pub_key);
void SLHDSA_SHAKE_256_S_GEN_KEYS(unsigned char* pri_key, unsigned char* pub_key);

void SLHDSA_SHAKE_128_F_SIGN(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pri_key, unsigned char* sig, unsigned int* sig_len);
void SLHDSA_SHAKE_128_S_SIGN(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pri_key, unsigned char* sig, unsigned int* sig_len);
void SLHDSA_SHAKE_192_F_SIGN(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pri_key, unsigned char* sig, unsigned int* sig_len);
void SLHDSA_SHAKE_192_S_SIGN(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pri_key, unsigned char* sig, unsigned int* sig_len);
void SLHDSA_SHAKE_256_F_SIGN(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pri_key, unsigned char* sig, unsigned int* sig_len);
void SLHDSA_SHAKE_256_S_SIGN(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pri_key, unsigned char* sig, unsigned int* sig_len);

void SLHDSA_SHAKE_128_F_VERIFY(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pub_key, const unsigned char* sig, const unsigned int sig_len, unsigned int* result);
void SLHDSA_SHAKE_128_S_VERIFY(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pub_key, const unsigned char* sig, const unsigned int sig_len, unsigned int* result);
void SLHDSA_SHAKE_192_F_VERIFY(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pub_key, const unsigned char* sig, const unsigned int sig_len, unsigned int* result);
void SLHDSA_SHAKE_192_S_VERIFY(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pub_key, const unsigned char* sig, const unsigned int sig_len, unsigned int* result);
void SLHDSA_SHAKE_256_F_VERIFY(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pub_key, const unsigned char* sig, const unsigned int sig_len, unsigned int* result);
void SLHDSA_SHAKE_256_S_VERIFY(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pub_key, const unsigned char* sig, const unsigned int sig_len, unsigned int* result);