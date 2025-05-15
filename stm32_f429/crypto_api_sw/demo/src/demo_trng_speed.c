/**
  * @file demo_trng_speed.c
  * @brief Performance test for Random Number Generator code
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

void test_trng(unsigned int mode, unsigned int bits, unsigned int n_test, time_result* tr, unsigned int verb)
{
    unsigned int bytes = (int)(bits / 8);
    unsigned char* random_trng; random_trng = malloc(bytes);
    unsigned char* random_ctr;  random_ctr = malloc(bytes);
    unsigned char* random_hmac;  random_hmac = malloc(bytes);

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

    /*
    if (mode == 0)        printf("\n\n -- Test TRNG %d bits --", bits);
    else if (mode == 1)   printf("\n\n -- Test CTR-DRBG %d bits --", bits);
    else if (mode == 2)   printf("\n\n -- Test HASH-DRBG %d bits --", bits);
    */

    for (unsigned int test = 1; test <= n_test; test++) {

        if (mode == 0) {
            start_t = timeInMicroseconds();
            trng(random_trng, bytes); // from crypto_api_sw.h
            stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            if (!test_random(random_trng, bytes)) tr->val_result++;
            if (verb >= 2) show_array(random_trng, bytes, 32);
        }
        else if (mode == 1) {
            start_t = timeInMicroseconds();
            ctr_drbg(random_ctr, bytes); // from crypto_api_sw.h
            stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            if (!test_random(random_ctr, bytes)) tr->val_result++;
            if (verb >= 2) show_array(random_ctr, bytes, 32);
        }
        else if (mode == 2) {
            start_t = timeInMicroseconds();
            hash_drbg(random_hmac, bytes); // from crypto_api_sw.h
            stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            if (!test_random(random_hmac, bytes)) tr->val_result++;
            if (verb >= 2) show_array(random_hmac, bytes, 32);
        }

        time_sw = stop_t - start_t;
        time_total_sw += time_sw;

        if (test == 1)                               tr->time_min_value_sw = time_sw;
        else if (tr->time_min_value_sw > time_sw)    tr->time_min_value_sw = time_sw;

        if (tr->time_max_value_sw < time_sw)         tr->time_max_value_sw = time_sw;


    }

    tr->time_mean_value_sw = (uint64_t)(time_total_sw / n_test);

    free(random_trng);
    free(random_ctr);
    free(random_hmac);
}
