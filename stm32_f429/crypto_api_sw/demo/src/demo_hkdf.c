/**
  * @file demo_hkdf.c
  * @brief Validation test for HKDF-SHA256 code
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

#include "demo.h"
#include "test_func.h"

void demo_hkdf(unsigned int verb) {

    unsigned char* char_key = "2b7e151628aed2a6abf7158809cf4f3c";
    unsigned char key[16]; char2hex(char_key, key);
    unsigned char* char_salt = "000102030405060708090a0b0c0d0e0f";
    unsigned char salt[16]; char2hex(char_salt, salt);
    unsigned char* char_info = "000102030405060708090a0b0c0d0e0f";
    unsigned char info[16]; char2hex(char_info, info);

    /*
    unsigned char* char_exp_16 = "5741255ef44f7f27d09b6c1dabf36ff6";
    unsigned char exp_16[16]; char2hex(char_exp_16, exp_16);
    unsigned char* char_exp_32 = "5741255ef44f7f27d09b6c1dabf36ff621cbc56558759ee6476d9375809dc26f";
    unsigned char exp_32[32]; char2hex(char_exp_32, exp_32);
    unsigned char* char_exp_64 = "5741255ef44f7f27d09b6c1dabf36ff621cbc56558759ee6476d9375809dc26ff95533e12b9d04c5df62074b301ea3f6229833469cb4c9af9592ce38e189248a";
    unsigned char exp_64[64]; char2hex(char_exp_64, exp_64);
    unsigned char* char_exp_128 = "5741255ef44f7f27d09b6c1dabf36ff621cbc56558759ee6476d9375809dc26ff95533e12b9d04c5df62074b301ea3f6229833469cb4c9af9592ce38e189248a82fa555c62290cffff7fdb924f6139c38c88f707fecf47b93efba103489be3436f5c0d3021d862728494b81ae6da5116ff9142ef2258bd11424f2359c48af262";
    unsigned char exp_128[128]; char2hex(char_exp_128, exp_128);
    */

    unsigned char* char_exp_128 = "5741255ef44f7f27d09b6c1dabf36ff621cbc56558759ee6476d9375809dc26ff95533e12b9d04c5df62074b301ea3f6229833469cb4c9af9592ce38e189248a82fa555c62290cffff7fdb924f6139c38c88f707fecf47b93efba103489be3436f5c0d3021d862728494b81ae6da5116ff9142ef2258bd11424f2359c48af262";
    unsigned char exp_128[128]; char2hex(char_exp_128, exp_128);

    unsigned char out_16[16];
    hkdf_sha256(key, 16, salt, 16, info, 16, out_16, 16);
    print_result_double_valid("HKDF-SHA256", "16 bytes", memcmp(exp_128, out_16, 16));

    if (verb >= 1) show_array(out_16, 16, 32);

    unsigned char out_32[32];
    hkdf_sha256(key, 16, salt, 16, info, 16, out_32, 32);
    print_result_double_valid("HKDF-SHA256", "32 bytes", memcmp(exp_128, out_32, 32));

    if (verb >= 1) show_array(out_32, 32, 32);

    unsigned char out_64[64];
    hkdf_sha256(key, 16, salt, 16, info, 16, out_64, 64);
    print_result_double_valid("HKDF-SHA256", "64 bytes", memcmp(exp_128, out_64, 64));

    if (verb >= 1) show_array(out_64, 64, 32);

    unsigned char out_128[128];
    hkdf_sha256(key, 16, salt, 16, info, 16, out_128, 128);
    print_result_double_valid("HKDF-SHA256", "128 bytes", memcmp(exp_128, out_128, 128));

    if (verb >= 1) show_array(out_128, 128, 32);




}