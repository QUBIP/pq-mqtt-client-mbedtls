/**
  * @file demo_rsa_speed.c
  * @brief Performance test for RSA code
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

void test_rsa(unsigned int bits, unsigned int n_test, unsigned int verb, time_result* tr_kg, time_result* tr_en, time_result* tr_de) {

    uint64_t start_t, stop_t;

    //-- Initialize to avoid 1st measure error
    start_t = timeInMicroseconds();
    stop_t = timeInMicroseconds();

    tr_kg->time_mean_value_sw = 0;
    tr_kg->time_max_value_sw = 0;
    tr_kg->time_min_value_sw = 0;
    tr_kg->val_result = 0;

    tr_en->time_mean_value_sw = 0;
    tr_en->time_max_value_sw = 0;
    tr_en->time_min_value_sw = 0;
    tr_en->val_result = 0;

    tr_de->time_mean_value_sw = 0;
    tr_de->time_max_value_sw = 0;
    tr_de->time_min_value_sw = 0;
    tr_de->val_result = 0;

    uint64_t time_sw = 0;
    uint64_t time_total_kg_sw = 0;
    uint64_t time_total_en_sw = 0;
    uint64_t time_total_de_sw = 0;

    // ---- RSA ---- //
    unsigned char* pub_key;
    unsigned char* pri_key;
    unsigned int pub_len;
    unsigned int pri_len;

    unsigned int key_size_rsa = bits;

    unsigned char msg[50] = "Hello, this is the SE of QUBIP project";

    unsigned char* ciphertext;
    unsigned int ciphertext_len;
    unsigned char* result;
    unsigned int result_len;
    
    // printf("\n\n -- Test RSA PKE %d --", bits);

    for (unsigned int test = 1; test <= n_test; test++) {

        // keygen
        start_t = timeInMicroseconds();
        rsa_genkeys(key_size_rsa, &pri_key, &pub_key, &pri_len, &pub_len);
        stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW GEN KEYS: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));

        time_sw = stop_t - start_t;
        time_total_kg_sw += time_sw;

        if (test == 1)										tr_kg->time_min_value_sw = time_sw;
        else if (tr_kg->time_min_value_sw > time_sw)		tr_kg->time_min_value_sw = time_sw;
        if (tr_kg->time_max_value_sw < time_sw)				tr_kg->time_max_value_sw = time_sw;

        if (verb >= 2) printf("\n pub_len: %d (bytes)", pub_len);
        if (verb >= 2) printf("\n pri_len: %d (bytes)", pri_len);

        if (verb >= 3) { printf("\n public key: ");   show_array(pub_key, pub_len, 32); }
        if (verb >= 3) { printf("\n private key: "); show_array(pri_key, pri_len, 32); }


        // encrypt
        start_t = timeInMicroseconds();
        rsa_encrypt(msg, strlen(msg), (const unsigned char**)&pub_key, pub_len, &ciphertext, &ciphertext_len);
        stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW ENCRYPT: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));

        time_sw = stop_t - start_t;
        time_total_en_sw += time_sw;

        if (test == 1)										tr_en->time_min_value_sw = time_sw;
        else if (tr_en->time_min_value_sw > time_sw)		tr_en->time_min_value_sw = time_sw;
        if (tr_en->time_max_value_sw < time_sw)				tr_en->time_max_value_sw = time_sw;

        if (verb >= 2) printf("\n len_cipher: %d (bytes)", ciphertext_len);
        if (verb >= 3) { printf("\n ciphertext: ");   show_array(ciphertext, ciphertext_len, 32); }

        // decrypt
        start_t = timeInMicroseconds();
        rsa_decrypt(&result, &result_len, (const unsigned char**)&pri_key, pri_len, ciphertext, ciphertext_len);
        stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW DECAP: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));

        time_sw = stop_t - start_t;
        time_total_de_sw += time_sw;

        if (test == 1)										tr_de->time_min_value_sw = time_sw;
        else if (tr_de->time_min_value_sw > time_sw)		tr_de->time_min_value_sw = time_sw;
        if (tr_de->time_max_value_sw < time_sw)				tr_de->time_max_value_sw = time_sw;

        if (verb >= 3) printf("\n len_msg: %d (bytes)", result_len);
        if (verb >= 2) printf("\n original msg: %s", msg);
        if (verb >= 2) printf("\n recover msg: %s", result);


        if (!memcmp(msg, result, result_len)) tr_de->val_result++;

    }

    tr_kg->time_mean_value_sw = (uint64_t)(time_total_kg_sw / n_test);
    tr_en->time_mean_value_sw = (uint64_t)(time_total_en_sw / n_test);
    tr_de->time_mean_value_sw = (uint64_t)(time_total_de_sw / n_test);

}