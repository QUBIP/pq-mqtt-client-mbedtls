 /**
  * @file demo_trng_speed.c
  * @brief Performance Test for TRNG Code
  *
  * @section License
  *
  * Secure Element for QUBIP Project
  *
  * This Secure Element repository for QUBIP Project is subject to the
  * BSD 3-Clause License below.
  *
  * Copyright (c) 2024,
  *         Eros Camacho-Ruiz
  *         Pablo Navarro-Torrero
  *         Pau Ortega-Castro
  *         Apurba Karmakar
  *         Macarena C. Martínez-Rodríguez
  *         Piedad Brox
  *
  * All rights reserved.
  *
  * This Secure Element was developed by Instituto de Microelectrónica de
  * Sevilla - IMSE (CSIC/US) as part of the QUBIP Project, co-funded by the
  * European Union under the Horizon Europe framework programme
  * [grant agreement no. 101119746].
  *
  * -----------------------------------------------------------------------
  *
  * Redistribution and use in source and binary forms, with or without
  * modification, are permitted provided that the following conditions are met:
  *
  * 1. Redistributions of source code must retain the above copyright notice, this
  *    list of conditions and the following disclaimer.
  *
  * 2. Redistributions in binary form must reproduce the above copyright notice,
  *    this list of conditions and the following disclaimer in the documentation
  *    and/or other materials provided with the distribution.
  *
  * 3. Neither the name of the copyright holder nor the names of its
  *    contributors may be used to endorse or promote products derived from
  *    this software without specific prior written permission.
  *
  * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
  *
  *
  *
  *
  * @author Eros Camacho-Ruiz (camacho@imse-cnm.csic.es)
  * @version 1.0
  **/

#include "demo.h"
#include "test_func.h"

void test_trng_hw(unsigned int mode, unsigned int bits, unsigned int n_test, time_result* tr, unsigned int verb, INTF interface)
{
    unsigned int bytes = (int)(bits / 8);
    unsigned char* random_trng; random_trng = malloc(bytes);
    unsigned char* random_ctr;  random_ctr = malloc(bytes);
    unsigned char* random_hmac;  random_hmac = malloc(bytes);

    uint64_t start_t, stop_t;

    //-- Initialize to avoid 1st measure error
    start_t = timeInMicroseconds();
    stop_t = timeInMicroseconds();

    tr->time_mean_value = 0;
    tr->time_max_value = 0;
    tr->time_min_value = 0;
    tr->val_result = 0;

    uint64_t time_hw = 0;
    uint64_t time_total_hw = 0;

    /*
    if (mode == 0)        printf("\n\n -- Test TRNG %d bits --", bits);
    else if (mode == 1)   printf("\n\n -- Test CTR-DRBG %d bits --", bits);
    else if (mode == 2)   printf("\n\n -- Test HASH-DRBG %d bits --", bits);
    */

    for (unsigned int test = 1; test <= n_test; test++) {

        if (mode == 0) {
            start_t = timeInMicroseconds();
            trng_hw(random_trng, bytes, interface); // from crypto_api_sw.h
            stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            if (!test_random(random_trng, bytes)) tr->val_result++;
            if (verb >= 2) show_array(random_trng, bytes, 32);
        }
        else if (mode == 1) {
        /*
            start_t = timeInMicroseconds();
            ctr_drbg(random_ctr, bytes); // from crypto_api_sw.h
            stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            if (!test_random(random_ctr, bytes)) tr->val_result++;
            if (verb >= 2) show_array(random_ctr, bytes, 32);
        */
        }
        else if (mode == 2) {
        /*    
            start_t = timeInMicroseconds();
            hash_drbg(random_hmac, bytes); // from crypto_api_sw.h
            stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            if (!test_random(random_hmac, bytes)) tr->val_result++;
            if (verb >= 2) show_array(random_hmac, bytes, 32);
        */
        }

        time_hw = stop_t - start_t;
        time_total_hw += time_hw;

        if (test == 1)                               tr->time_min_value = time_hw;
        else if (tr->time_min_value > time_hw)    tr->time_min_value = time_hw;

        if (tr->time_max_value < time_hw)         tr->time_max_value = time_hw;


    }

    tr->time_mean_value = (uint64_t)(time_total_hw / n_test);

    free(random_trng);
    free(random_ctr);
    free(random_hmac);
}
