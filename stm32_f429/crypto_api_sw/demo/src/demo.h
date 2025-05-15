/**
  * @file demo.h
  * @brief Demo header
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

#ifndef DEMO_H
#define DEMO_H

#ifdef CRYPTO_INST
#include <crypto_api_sw.h>
#else
#include "../../crypto_api_sw.h"
#endif

#include "test_func.h"

void demo_rsa(unsigned int bits, unsigned int verb);
void demo_eddsa(unsigned int mode, unsigned int verb);
void demo_x25519(unsigned int mode, unsigned int verb);
void demo_aes(unsigned int bits, unsigned int verb);
void demo_sha2(unsigned int verb);
void demo_sha3(unsigned int verb);
void demo_hkdf(unsigned int verb);
void demo_trng(unsigned int bits, unsigned verb);
void demo_mlkem(unsigned int mode, unsigned int verb);
void demo_mldsa(unsigned int mode, unsigned int verb);
void demo_slhdsa(unsigned char mode[12], unsigned int verb);

// test - speed
void test_aes(unsigned char mode[4], unsigned int bits, unsigned int n_test, unsigned int verb, time_result* tr_en, time_result* tr_de);
void test_sha3(unsigned int sel, unsigned int n_test, time_result* tr, unsigned int verb);
void test_sha2(unsigned int sel, unsigned int n_test, time_result* tr, unsigned int verb);
void test_rsa(unsigned int bits, unsigned int n_test, unsigned int verb, time_result* tr_kg, time_result* tr_en, time_result* tr_de);
void test_eddsa(unsigned int mode, unsigned int n_test, unsigned int verb, time_result* tr_kg, time_result* tr_si, time_result* tr_ve);
void test_x25519(unsigned int mode, unsigned int n_test, unsigned int verb, time_result* tr_kg, time_result* tr_ss);
void test_hkdf(unsigned int bytes, unsigned int n_test, unsigned int verb, time_result* tr);
void test_trng(unsigned int mode, unsigned int bits, unsigned int n_test, time_result* tr, unsigned int verb);
void test_mlkem(unsigned int mode, unsigned int n_test, unsigned int verb, time_result* tr_kg, time_result* tr_en, time_result* tr_de);
void test_mldsa(unsigned int mode, unsigned int n_test, unsigned int verb, time_result* tr_kg, time_result* tr_si, time_result* tr_ve);
void test_slhdsa(unsigned char mode[12], unsigned int n_test, unsigned int verb, time_result* tr_kg, time_result* tr_si, time_result* tr_ve);

// nist-demo
void demo_mldsa_nist(unsigned int verb);

#endif