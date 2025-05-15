/**
  * @file demo_x25519_speed.c
  * @brief Performance test for ECDH code
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

void test_x25519(unsigned int mode, unsigned int n_test, unsigned int verb, time_result* tr_kg, time_result* tr_ss) {

    uint64_t start_t, stop_t;

    //-- Initialize to avoid 1st measure error
    start_t = timeInMicroseconds();
    stop_t = timeInMicroseconds();

    tr_kg->time_mean_value_sw = 0;
    tr_kg->time_max_value_sw = 0;
    tr_kg->time_min_value_sw = 0;
    tr_kg->val_result = 0;

    tr_ss->time_mean_value_sw = 0;
    tr_ss->time_max_value_sw = 0;
    tr_ss->time_min_value_sw = 0;
    tr_ss->val_result = 0;

    uint64_t time_sw = 0;
    uint64_t time_total_kg_sw = 0;
    uint64_t time_total_ss_sw = 0;

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
            x25519_genkeys(&pri_key_A, &pub_key_A, &pri_len_A, &pub_len_A);
            stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW GEN KEY A: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));

            time_sw = stop_t - start_t;
            time_total_kg_sw += time_sw;

            if (test == 1)									tr_kg->time_min_value_sw = time_sw;
            else if (tr_kg->time_min_value_sw > time_sw)	tr_kg->time_min_value_sw = time_sw;
            if (tr_kg->time_max_value_sw < time_sw)			tr_kg->time_max_value_sw = time_sw;

            if (verb >= 2) printf("\n pub_len: %d (bytes)", pub_len_A);
            if (verb >= 2) printf("\n pri_len: %d (bytes)", pri_len_A);

            if (verb >= 3) { printf("\n public key: ");   show_array(pub_key_A, pub_len_A, 32); }
            if (verb >= 3) { printf("\n private key: "); show_array(pri_key_A, pri_len_A, 32); }

            start_t = timeInMicroseconds();
            x25519_genkeys(&pri_key_B, &pub_key_B, &pri_len_B, &pub_len_B);
            stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW GEN KEY A: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));

            time_sw = stop_t - start_t;
            time_total_kg_sw += time_sw;

            if (test == 1)									tr_kg->time_min_value_sw = time_sw;
            else if (tr_kg->time_min_value_sw > time_sw)	tr_kg->time_min_value_sw = time_sw;
            if (tr_kg->time_max_value_sw < time_sw)			tr_kg->time_max_value_sw = time_sw;

            if (verb >= 2) printf("\n pub_len: %d (bytes)", pub_len_B);
            if (verb >= 2) printf("\n pri_len: %d (bytes)", pri_len_B);

            if (verb >= 3) { printf("\n public key: ");   show_array(pub_key_B, pub_len_B, 32); }
            if (verb >= 3) { printf("\n private key: "); show_array(pri_key_B, pri_len_B, 32); }

            // SHARED-SECRET
            start_t = timeInMicroseconds();
            x25519_ss_gen(&ss_A, &ss_len_A, (const unsigned char*)pub_key_B, pub_len_B, (const unsigned char*)pri_key_A, pri_len_A); // A Side
            stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW GEN KEY A: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));

            time_sw = stop_t - start_t;
            time_total_ss_sw += time_sw;

            if (test == 1)									tr_ss->time_min_value_sw = time_sw;
            else if (tr_ss->time_min_value_sw > time_sw)	tr_ss->time_min_value_sw = time_sw;
            if (tr_ss->time_max_value_sw < time_sw)			tr_ss->time_max_value_sw = time_sw;

            if (verb >= 2) printf("\n ss_len_A: %d (bytes)", ss_len_A);
            if (verb >= 3) { printf("\n ss_A: ");   show_array(ss_A, ss_len_A, 32); }

            start_t = timeInMicroseconds();
            x25519_ss_gen(&ss_B, &ss_len_B, (const unsigned char*)pub_key_A, pub_len_A, (const unsigned char*)pri_key_B, pri_len_B); // B Side
            stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW GEN KEY A: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));

            time_sw = stop_t - start_t;
            time_total_ss_sw += time_sw;

            if (test == 1)									tr_ss->time_min_value_sw = time_sw;
            else if (tr_ss->time_min_value_sw > time_sw)	tr_ss->time_min_value_sw = time_sw;
            if (tr_ss->time_max_value_sw < time_sw)			tr_ss->time_max_value_sw = time_sw;

            if (verb >= 2) printf("\n ss_len_B: %d (bytes)", ss_len_B);
            if (verb >= 3) { printf("\n ss_B: ");   show_array(ss_B, ss_len_B, 32); }

            if (!memcmp(ss_A, ss_B, ss_len_A)) tr_ss->val_result++;
        }

        else if (mode == 448) {
            // KEY GEN
            start_t = timeInMicroseconds();
            x448_genkeys(&pri_key_A, &pub_key_A, &pri_len_A, &pub_len_A);
            stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW GEN KEY A: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));

            time_sw = stop_t - start_t;
            time_total_kg_sw += time_sw;

            if (test == 1)									tr_kg->time_min_value_sw = time_sw;
            else if (tr_kg->time_min_value_sw > time_sw)	tr_kg->time_min_value_sw = time_sw;
            if (tr_kg->time_max_value_sw < time_sw)			tr_kg->time_max_value_sw = time_sw;

            if (verb >= 2) printf("\n pub_len: %d (bytes)", pub_len_A);
            if (verb >= 2) printf("\n pri_len: %d (bytes)", pri_len_A);

            if (verb >= 3) { printf("\n public key: ");   show_array(pub_key_A, pub_len_A, 32); }
            if (verb >= 3) { printf("\n private key: "); show_array(pri_key_A, pri_len_A, 32); }

            start_t = timeInMicroseconds();
            x448_genkeys(&pri_key_B, &pub_key_B, &pri_len_B, &pub_len_B);
            stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW GEN KEY A: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));

            time_sw = stop_t - start_t;
            time_total_kg_sw += time_sw;

            if (test == 1)									tr_kg->time_min_value_sw = time_sw;
            else if (tr_kg->time_min_value_sw > time_sw)	tr_kg->time_min_value_sw = time_sw;
            if (tr_kg->time_max_value_sw < time_sw)			tr_kg->time_max_value_sw = time_sw;

            if (verb >= 2) printf("\n pub_len: %d (bytes)", pub_len_B);
            if (verb >= 2) printf("\n pri_len: %d (bytes)", pri_len_B);

            if (verb >= 3) { printf("\n public key: ");   show_array(pub_key_B, pub_len_B, 32); }
            if (verb >= 3) { printf("\n private key: "); show_array(pri_key_B, pri_len_B, 32); }

            // SHARED-SECRET
            start_t = timeInMicroseconds();
            x448_ss_gen(&ss_A, &ss_len_A, (const unsigned char*)pub_key_B, pub_len_B, (const unsigned char*)pri_key_A, pri_len_A); // A Side
            stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW GEN KEY A: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));

            time_sw = stop_t - start_t;
            time_total_ss_sw += time_sw;

            if (test == 1)									tr_ss->time_min_value_sw = time_sw;
            else if (tr_ss->time_min_value_sw > time_sw)	tr_ss->time_min_value_sw = time_sw;
            if (tr_ss->time_max_value_sw < time_sw)			tr_ss->time_max_value_sw = time_sw;

            if (verb >= 2) printf("\n ss_len_A: %d (bytes)", ss_len_A);
            if (verb >= 3) { printf("\n ss_A: ");   show_array(ss_A, ss_len_A, 32); }

            start_t = timeInMicroseconds();
            x448_ss_gen(&ss_B, &ss_len_B, (const unsigned char*)pub_key_A, pub_len_A, (const unsigned char*)pri_key_B, pri_len_B); // B Side
            stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW GEN KEY A: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));

            time_sw = stop_t - start_t;
            time_total_ss_sw += time_sw;

            if (test == 1)									tr_ss->time_min_value_sw = time_sw;
            else if (tr_ss->time_min_value_sw > time_sw)	tr_ss->time_min_value_sw = time_sw;
            if (tr_ss->time_max_value_sw < time_sw)			tr_ss->time_max_value_sw = time_sw;

            if (verb >= 2) printf("\n ss_len_B: %d (bytes)", ss_len_B);
            if (verb >= 3) { printf("\n ss_B: ");   show_array(ss_B, ss_len_B, 32); }

            if (!memcmp(ss_A, ss_B, ss_len_A)) tr_ss->val_result++;

        }


    }

    tr_kg->time_mean_value_sw = (uint64_t)(time_total_kg_sw / (2 * n_test));
    tr_ss->time_mean_value_sw = (uint64_t)(time_total_ss_sw / (2 * n_test));

}

