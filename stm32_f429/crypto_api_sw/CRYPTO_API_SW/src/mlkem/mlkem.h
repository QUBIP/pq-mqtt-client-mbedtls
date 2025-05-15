/**
  * @file mlkem.h
  * @brief ML-KEM header
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

#ifndef MLKEM_H
#define MLKEM_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "src/params.h"
#include "src/indcpa.h"
#include "src/verify.h"
#include "src/symmetric.h"
#include "src/randombytes.h"

void MLKEM_512_GEN_KEYS(unsigned char* pk, unsigned char* sk);
void MLKEM_768_GEN_KEYS(unsigned char* pk, unsigned char* sk);
void MLKEM_1024_GEN_KEYS(unsigned char* pk, unsigned char* sk);

void MLKEM_512_ENC(unsigned char* ct, unsigned char* ss, const unsigned char* pk);
void MLKEM_768_ENC(unsigned char* ct, unsigned char* ss, const unsigned char* pk);
void MLKEM_1024_ENC(unsigned char* ct, unsigned char* ss, const unsigned char* pk);

void MLKEM_512_DEC(unsigned char* ss, const unsigned char* ct, const unsigned char* sk, unsigned int* result);
void MLKEM_768_DEC(unsigned char* ss, const unsigned char* ct, const unsigned char* sk, unsigned int* result);
void MLKEM_1024_DEC(unsigned char* ss, const unsigned char* ct, const unsigned char* sk, unsigned int* result);

#endif