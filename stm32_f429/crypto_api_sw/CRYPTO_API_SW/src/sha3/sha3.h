/**
  * @file sha3.h
  * @brief SHA3 header
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

#ifndef SHA3_H
#define	SHA3_H

#ifdef OPENSSL
#include <openssl/sha.h>
#include <openssl/evp.h>
#elif MBEDTLS
#include "mbedtls/sha3.h"
#else
#include "alt/sha3_224.h"
#include "alt/sha3_256.h"
#include "alt/sha3_384.h"
#include "alt/sha3_512.h"
#include "alt/shake.h"
#endif

#include <string.h>
#include <stdio.h>

void SHA3_224(unsigned char* input, unsigned int len_input, unsigned char* md_value);
void SHA3_256(unsigned char* input, unsigned int len_input, unsigned char* md_value);
void SHA3_384(unsigned char* input, unsigned int len_input, unsigned char* md_value);
void SHA3_512(unsigned char* input, unsigned int len_input, unsigned char* md_value);
void SHAKE_128(unsigned char* input, unsigned int len_input, unsigned char* md_value, unsigned int len_md);
void SHAKE_256(unsigned char* input, unsigned int len_input, unsigned char* md_value, unsigned int len_md);



#endif
