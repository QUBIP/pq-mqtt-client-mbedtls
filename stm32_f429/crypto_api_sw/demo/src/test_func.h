/**
  * @file test_func.h
  * @brief Extra functions for Demo header
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

#ifndef TEST_FUNC_H
#define	TEST_FUNC_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <sys/time.h>

typedef struct {
	unsigned int aes;
	unsigned int sha3;
	unsigned int sha2;
	unsigned int hkdf;
	unsigned int rsa;
	unsigned int eddsa;
	unsigned int ecdh;
	unsigned int mlkem;
	unsigned int mldsa;
	unsigned int slhdsa;
	unsigned int drbg;
	unsigned int n_test;
} data_conf;


typedef struct {
	uint64_t time_mean_value_sw;
	uint64_t time_max_value_sw;
	uint64_t time_min_value_sw;
	uint64_t val_result;
} time_result;

int test_random(unsigned char* random, unsigned int size);
void print_result_valid(unsigned char* str, unsigned int fail);
void print_result_double_valid(unsigned char* str, unsigned char* str2, unsigned int fail);
void print_results(unsigned int verb, unsigned int n_test, time_result tr);
void print_results_str_1_tab_3(unsigned int n_test, unsigned char* str, time_result tr1, time_result tr2, time_result tr3);
void print_results_str_1_tab_2(unsigned int n_test, unsigned char* str, time_result tr1, time_result tr2);
void print_results_str_1_tab_1(unsigned int n_test, unsigned char* str, time_result tr);
void print_results_str_2_tab_1(unsigned int n_test, unsigned char* str1, unsigned char* str2, time_result tr);
void read_conf(data_conf* data);
void show_array(const unsigned char* r, const unsigned int size, const unsigned int mod);
int cmpchar(unsigned char* in1, unsigned char* in2, unsigned int len);
void char2hex(unsigned char* in, unsigned char* out);
void char_to_hex(unsigned char in0, unsigned char in1, unsigned char* out);
void print_title_demo();

#ifdef CRYPTO_ARM 
uint32_t timeInMicroseconds();
#else
uint64_t timeInMicroseconds();
#endif
#endif