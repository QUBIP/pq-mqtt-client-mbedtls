/**
  * @file demo_x25519_speed.c
  * @brief Performance Test for ECDH Code
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

void test_x25519_hw(unsigned int mode, unsigned int n_test, unsigned int verb, time_result* tr_kg, time_result* tr_ss, INTF interface) {

#ifdef AXI
    unsigned int clk_index = 0;
    float clk_frequency;
    float set_clk_frequency = FREQ_X25519;
    Set_Clk_Freq(clk_index, &clk_frequency, &set_clk_frequency, (int) verb);
#endif

    uint64_t start_t, stop_t;

    //-- Initialize to avoid 1st measure error
    start_t = timeInMicroseconds();
    stop_t = timeInMicroseconds();

    tr_kg->time_mean_value = 0;
    tr_kg->time_max_value = 0;
    tr_kg->time_min_value = 0;
    tr_kg->val_result = 0;

    tr_ss->time_mean_value = 0;
    tr_ss->time_max_value = 0;
    tr_ss->time_min_value = 0;
    tr_ss->val_result = 0;

    uint64_t time_hw = 0;
    uint64_t time_total_kg_hw = 0;
    uint64_t time_total_ss_hw = 0;

    // ---- KEY GEN ---- //
    unsigned char* pub_key_A;
    unsigned char* pri_key_A;
    unsigned int pub_len_A;
    unsigned int pri_len_A;

    unsigned char* pub_key_B;
    unsigned char* pri_key_B;
    unsigned int pub_len_B;
    unsigned int pri_len_B;

    unsigned char* ss_A;
    unsigned int ss_len_A;
    unsigned char* ss_B;
    unsigned int ss_len_B;

    /*
    if (mode == 25519)        printf("\n\n -- Test X25519 --");
    if (mode == 448)          printf("\n\n -- Test X448 --");
    */


    for (unsigned int test = 1; test <= n_test; test++) {

        if (mode == 25519) {
            // KEY GEN
            start_t = timeInMicroseconds();
            x25519_genkeys_hw(&pri_key_A, &pub_key_A, &pri_len_A, &pub_len_A, interface);
            stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW GEN KEY A: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));

            time_hw = stop_t - start_t;
            time_total_kg_hw += time_hw;

            if (test == 1)									tr_kg->time_min_value = time_hw;
            else if (tr_kg->time_min_value > time_hw)	tr_kg->time_min_value = time_hw;
            if (tr_kg->time_max_value < time_hw)			tr_kg->time_max_value = time_hw;

            if (verb >= 2) printf("\n pub_len: %d (bytes)", pub_len_A);
            if (verb >= 2) printf("\n pri_len: %d (bytes)", pri_len_A);

            if (verb >= 3) { printf("\n public key: ");   show_array(pub_key_A, pub_len_A, 32); }
            if (verb >= 3) { printf("\n private key: "); show_array(pri_key_A, pri_len_A, 32); }

            start_t = timeInMicroseconds();
            x25519_genkeys_hw(&pri_key_B, &pub_key_B, &pri_len_B, &pub_len_B, interface);
            stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW GEN KEY A: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));

            time_hw = stop_t - start_t;
            time_total_kg_hw += time_hw;

            if (test == 1)									tr_kg->time_min_value = time_hw;
            else if (tr_kg->time_min_value > time_hw)	tr_kg->time_min_value = time_hw;
            if (tr_kg->time_max_value < time_hw)			tr_kg->time_max_value = time_hw;

            if (verb >= 2) printf("\n pub_len: %d (bytes)", pub_len_B);
            if (verb >= 2) printf("\n pri_len: %d (bytes)", pri_len_B);

            if (verb >= 3) { printf("\n public key: ");   show_array(pub_key_B, pub_len_B, 32); }
            if (verb >= 3) { printf("\n private key: "); show_array(pri_key_B, pri_len_B, 32); }

            // SHARED-SECRET
            start_t = timeInMicroseconds();
            x25519_ss_gen_hw(&ss_A, &ss_len_A, pub_key_B, pub_len_B, pri_key_A, pri_len_A, interface); // A Side
            stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW GEN KEY A: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));

            time_hw = stop_t - start_t;
            time_total_ss_hw += time_hw;

            if (test == 1)									tr_ss->time_min_value = time_hw;
            else if (tr_ss->time_min_value > time_hw)	tr_ss->time_min_value = time_hw;
            if (tr_ss->time_max_value < time_hw)			tr_ss->time_max_value = time_hw;

            if (verb >= 2) printf("\n ss_len_A: %d (bytes)", ss_len_A);
            if (verb >= 3) { printf("\n ss_A: ");   show_array(ss_A, ss_len_A, 32); }

            start_t = timeInMicroseconds();
            x25519_ss_gen_hw(&ss_B, &ss_len_B, pub_key_A, pub_len_A, pri_key_B, pri_len_B, interface); // B Side
            stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW GEN KEY A: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));

            time_hw = stop_t - start_t;
            time_total_ss_hw += time_hw;

            if (test == 1)									tr_ss->time_min_value = time_hw;
            else if (tr_ss->time_min_value > time_hw)	tr_ss->time_min_value = time_hw;
            if (tr_ss->time_max_value < time_hw)			tr_ss->time_max_value = time_hw;

            if (verb >= 2) printf("\n ss_len_B: %d (bytes)", ss_len_B);
            if (verb >= 3) { printf("\n ss_B: ");   show_array(ss_B, ss_len_B, 32); }

            if (!memcmp(ss_A, ss_B, ss_len_A)) tr_ss->val_result++;
        }

        else if (mode == 448) {
        /*
            // KEY GEN
            start_t = timeInMicroseconds();
            x448_genkeys(&pri_key_A, &pub_key_A, &pri_len_A, &pub_len_A);
            stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW GEN KEY A: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));

            time_hw = stop_t - start_t;
            time_total_kg_hw += time_hw;

            if (test == 1)									tr_kg->time_min_value = time_hw;
            else if (tr_kg->time_min_value > time_hw)	tr_kg->time_min_value = time_hw;
            if (tr_kg->time_max_value < time_hw)			tr_kg->time_max_value = time_hw;

            if (verb >= 2) printf("\n pub_len: %d (bytes)", pub_len_A);
            if (verb >= 2) printf("\n pri_len: %d (bytes)", pri_len_A);

            if (verb >= 3) { printf("\n public key: ");   show_array(pub_key_A, pub_len_A, 32); }
            if (verb >= 3) { printf("\n private key: "); show_array(pri_key_A, pri_len_A, 32); }

            start_t = timeInMicroseconds();
            x448_genkeys(&pri_key_B, &pub_key_B, &pri_len_B, &pub_len_B);
            stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW GEN KEY A: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));

            time_hw = stop_t - start_t;
            time_total_kg_hw += time_hw;

            if (test == 1)									tr_kg->time_min_value = time_hw;
            else if (tr_kg->time_min_value > time_hw)	tr_kg->time_min_value = time_hw;
            if (tr_kg->time_max_value < time_hw)			tr_kg->time_max_value = time_hw;

            if (verb >= 2) printf("\n pub_len: %d (bytes)", pub_len_B);
            if (verb >= 2) printf("\n pri_len: %d (bytes)", pri_len_B);

            if (verb >= 3) { printf("\n public key: ");   show_array(pub_key_B, pub_len_B, 32); }
            if (verb >= 3) { printf("\n private key: "); show_array(pri_key_B, pri_len_B, 32); }

            // SHARED-SECRET
            start_t = timeInMicroseconds();
            x448_ss_gen(&ss_A, &ss_len_A, (const unsigned char*)pub_key_B, pub_len_B, (const unsigned char*)pri_key_A, pri_len_A); // A Side
            stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW GEN KEY A: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));

            time_hw = stop_t - start_t;
            time_total_ss_hw += time_hw;

            if (test == 1)									tr_ss->time_min_value = time_hw;
            else if (tr_ss->time_min_value > time_hw)	tr_ss->time_min_value = time_hw;
            if (tr_ss->time_max_value < time_hw)			tr_ss->time_max_value = time_hw;

            if (verb >= 2) printf("\n ss_len_A: %d (bytes)", ss_len_A);
            if (verb >= 3) { printf("\n ss_A: ");   show_array(ss_A, ss_len_A, 32); }

            start_t = timeInMicroseconds();
            x448_ss_gen(&ss_B, &ss_len_B, (const unsigned char*)pub_key_A, pub_len_A, (const unsigned char*)pri_key_B, pri_len_B); // B Side
            stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW GEN KEY A: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));

            time_hw = stop_t - start_t;
            time_total_ss_hw += time_hw;

            if (test == 1)									tr_ss->time_min_value = time_hw;
            else if (tr_ss->time_min_value > time_hw)	tr_ss->time_min_value = time_hw;
            if (tr_ss->time_max_value < time_hw)			tr_ss->time_max_value = time_hw;

            if (verb >= 2) printf("\n ss_len_B: %d (bytes)", ss_len_B);
            if (verb >= 3) { printf("\n ss_B: ");   show_array(ss_B, ss_len_B, 32); }

            if (!memcmp(ss_A, ss_B, ss_len_A)) tr_ss->val_result++;
        */
        }


    }

    tr_kg->time_mean_value = (uint64_t)(time_total_kg_hw / (2 * n_test));
    tr_ss->time_mean_value = (uint64_t)(time_total_ss_hw / (2 * n_test));
#ifdef AXI
    set_clk_frequency = FREQ_TYPICAL;
    Set_Clk_Freq(clk_index, &clk_frequency, &set_clk_frequency, (int)verb);
#endif
}

