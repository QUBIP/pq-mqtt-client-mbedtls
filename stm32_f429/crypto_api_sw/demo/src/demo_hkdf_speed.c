/**
  * @file demo_hkdf_speed.c
  * @brief Performance test for HKDF-SHA256 code
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

void test_hkdf(unsigned int bytes, unsigned int n_test, unsigned int verb, time_result* tr) {

    uint64_t start_t, stop_t;

    //-- Initialize to avoid 1st measure error
    start_t = timeInMicroseconds();
    stop_t = timeInMicroseconds();

    tr->time_mean_value_sw = 0;
    tr->time_max_value_sw = 0;
    tr->time_min_value_sw = 0;
    tr->val_result = 0;

    uint64_t time_sw = 0;
    uint64_t time_total_sw = 0;

    unsigned char* char_key = "2b7e151628aed2a6abf7158809cf4f3c";
    unsigned char key[16]; char2hex(char_key, key);
    unsigned char* char_salt = "000102030405060708090a0b0c0d0e0f";
    unsigned char salt[16]; char2hex(char_salt, salt);
    unsigned char* char_info = "000102030405060708090a0b0c0d0e0f";
    unsigned char info[16]; char2hex(char_info, info);

    unsigned char* char_exp_16 = "5741255ef44f7f27d09b6c1dabf36ff6";
    unsigned char exp_16[16]; char2hex(char_exp_16, exp_16);
    unsigned char* char_exp_32 = "5741255ef44f7f27d09b6c1dabf36ff621cbc56558759ee6476d9375809dc26f";
    unsigned char exp_32[32]; char2hex(char_exp_32, exp_32);
    unsigned char* char_exp_64 = "5741255ef44f7f27d09b6c1dabf36ff621cbc56558759ee6476d9375809dc26ff95533e12b9d04c5df62074b301ea3f6229833469cb4c9af9592ce38e189248a";
    unsigned char exp_64[64]; char2hex(char_exp_64, exp_64);
    unsigned char* char_exp_128 = "5741255ef44f7f27d09b6c1dabf36ff621cbc56558759ee6476d9375809dc26ff95533e12b9d04c5df62074b301ea3f6229833469cb4c9af9592ce38e189248a82fa555c62290cffff7fdb924f6139c38c88f707fecf47b93efba103489be3436f5c0d3021d862728494b81ae6da5116ff9142ef2258bd11424f2359c48af262";
    unsigned char exp_128[128]; char2hex(char_exp_128, exp_128);

    unsigned char out_16[16];
    unsigned char out_32[32];
    unsigned char out_64[64];
    unsigned char out_128[128];

    /*
    if (bits == 16)         printf("\n\n -- Test HKDF 16 bits --");
    else if (bits == 32)    printf("\n\n -- Test HKDF 32 bits --");
    else if (bits == 64)    printf("\n\n -- Test HKDF 64 bits --");
    else if (bits == 128)   printf("\n\n -- Test HKDF 128 bits --");
    */

    for (unsigned int test = 1; test <= n_test; test++) {
        if (bytes == 16) {
            start_t = timeInMicroseconds();
            hkdf_sha256(key, 16, salt, 16, info, 16, out_16, 16);
            stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW HKDF: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            
            if (!memcmp(exp_16, out_16, 16))    tr->val_result++;

            if (verb >= 3) show_array(out_16, 16, 32);
        }

        else if (bytes == 32) {
            start_t = timeInMicroseconds();
            hkdf_sha256(key, 16, salt, 16, info, 16, out_32, 32);
            stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW HKDF: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));

            if (!memcmp(exp_32, out_32, 32))    tr->val_result++;

            if (verb >= 3) show_array(out_32, 32, 32);
        }

        else if (bytes == 64) {
            start_t = timeInMicroseconds();
            hkdf_sha256(key, 16, salt, 16, info, 16, out_64, 64);
            stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW HKDF: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));

            if (!memcmp(exp_64, out_64, 64))   tr->val_result++;

            if (verb >= 3) show_array(out_64, 64, 32);
        }

        else if (bytes == 128) {
            start_t = timeInMicroseconds();
            hkdf_sha256(key, 16, salt, 16, info, 16, out_128, 128);
            stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW HKDF: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));

            if (!memcmp(exp_128, out_128, 128)) tr->val_result++;

            if (verb >= 3) show_array(out_128, 128, 32);
        }

        time_sw = stop_t - start_t;
        time_total_sw += time_sw;

        if (test == 1)									tr->time_min_value_sw = time_sw;
        else if (tr->time_min_value_sw > time_sw)		tr->time_min_value_sw = time_sw;
        if (tr->time_max_value_sw < time_sw)			tr->time_max_value_sw = time_sw;
    }

    tr->time_mean_value_sw = (uint64_t)(time_total_sw / n_test);




}