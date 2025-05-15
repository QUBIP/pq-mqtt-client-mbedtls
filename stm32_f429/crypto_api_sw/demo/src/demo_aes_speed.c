/**
  * @file demo_aes_speed.c
  * @brief Performance test for AES code
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

void test_aes(unsigned char mode[4], unsigned int bits, unsigned int n_test,  unsigned int verb, time_result* tr_en, time_result* tr_de) {

    uint64_t start_t, stop_t;

    //-- Initialize to avoid 1st measure error
    start_t = timeInMicroseconds();
    stop_t = timeInMicroseconds();

    tr_en->time_mean_value_sw = 0;
    tr_en->time_max_value_sw = 0;
    tr_en->time_min_value_sw = 0;
    tr_en->val_result = 0;

    tr_de->time_mean_value_sw = 0;
    tr_de->time_max_value_sw = 0;
    tr_de->time_min_value_sw = 0;
    tr_de->val_result = 0;

    uint64_t time_sw = 0;
    uint64_t time_total_en_sw = 0;
    uint64_t time_total_de_sw = 0;

    // unsigned char msg[128] = "Hello, this is the SE of QUBIP project";
    unsigned char msg[1024];

    // Variable declaration 
    // 128
    unsigned char* recovered_msg_128;
    unsigned int recovered_msg_128_len;

    unsigned char* char_key_128 = "2b7e151628aed2a6abf7158809cf4f3c";
    unsigned char key_128[16]; char2hex(char_key_128, key_128);
    unsigned char* char_iv_128 = "000102030405060708090a0b0c0d0e0f";
    unsigned char iv_128[16]; char2hex(char_iv_128, iv_128);
    unsigned char* char_add_128 = "000102030405060708090a0b0c0d0e0f";
    unsigned char add_128[16]; char2hex(char_add_128, add_128);

    unsigned char* ciphertext_128;
    unsigned int ciphertext_128_len = 0;

    ciphertext_128 = malloc(1080); memset(ciphertext_128, 0, 1080); // It is neccesary to add some bytes more
    recovered_msg_128 = malloc(1024); memset(recovered_msg_128, 0, 1024);

    unsigned char* mac_128;
    unsigned int mac_128_len;
    mac_128 = malloc(16); memset(mac_128, 0, 16);

    // 192
    unsigned char* recovered_msg_192;
    unsigned int recovered_msg_192_len;

    unsigned char* char_key_192 = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
    unsigned char key_192[24]; char2hex(char_key_192, key_192);
    unsigned char* char_iv_192 = "000102030405060708090a0b0c0d0e0f";
    unsigned char iv_192[16]; char2hex(char_iv_192, iv_192);
    unsigned char* char_add_192 = "000102030405060708090a0b0c0d0e0f";
    unsigned char add_192[16]; char2hex(char_add_192, add_192);

    unsigned char* ciphertext_192; 
    unsigned int ciphertext_192_len;

    ciphertext_192 = malloc(1080); memset(ciphertext_192, 0, 1080);
    recovered_msg_192 = malloc(1024); memset(recovered_msg_192, 0, 1024);

    unsigned char* mac_192;
    unsigned int mac_192_len;
    mac_192 = malloc(16); memset(mac_192, 0, 16);

    // 256
    unsigned char* recovered_msg_256;
    unsigned int recovered_msg_256_len;

    unsigned char* char_key_256 = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    unsigned char key_256[32]; char2hex(char_key_256, key_256);
    unsigned char* char_iv_256 = "000102030405060708090a0b0c0d0e0f";
    unsigned char iv_256[16]; char2hex(char_iv_256, iv_256);
    unsigned char* char_add_256 = "000102030405060708090a0b0c0d0e0f";
    unsigned char add_256[16]; char2hex(char_add_256, add_256);

    unsigned char* ciphertext_256;
    unsigned int ciphertext_256_len;

    ciphertext_256 = malloc(1080);  memset(ciphertext_256, 0, 1080);
    recovered_msg_256 = malloc(1024); memset(recovered_msg_256, 0, 1024);

    unsigned char* mac_256;
    unsigned int mac_256_len;
    mac_256 = malloc(16); memset(mac_256, 0, 16);

    // tag
    unsigned char tag[16]; memset(tag, 0, 16);
    unsigned char tag_8[8]; memset(tag_8, 0, 8);
    unsigned int result = 0;

    unsigned int ecb    = !memcmp(mode, "ecb", 4);
    unsigned int cbc    = !memcmp(mode, "cbc", 4);
    unsigned int gcm    = !memcmp(mode, "gcm", 4);
    unsigned int ccm    = !memcmp(mode, "ccm", 4);
    unsigned int cmac   = !memcmp(mode, "cmac", 4);

    /*
    if (bits == 128 & ecb)    printf("\n\n -- Test AES-128-ECB --"); 
    if (bits == 128 & cbc)    printf("\n\n -- Test AES-128-CBC --");
    if (bits == 128 & gcm)    printf("\n\n -- Test AES-128-GCM --");
    if (bits == 128 & ccm)    printf("\n\n -- Test AES-128-CCM-8 --");
    if (bits == 128 & cmac)   printf("\n\n -- Test AES-128-CMAC --");

    if (bits == 192 & ecb)    printf("\n\n -- Test AES-192-ECB --");
    if (bits == 192 & cbc)    printf("\n\n -- Test AES-192-CBC --");
    if (bits == 192 & gcm)    printf("\n\n -- Test AES-192-GCM --");
    if (bits == 192 & ccm)    printf("\n\n -- Test AES-192-CCM-8 --");
    if (bits == 192 & cmac)   printf("\n\n -- Test AES-192-CMAC --");

    if (bits == 256 & ecb)    printf("\n\n -- Test AES-256-ECB --");
    if (bits == 256 & cbc)    printf("\n\n -- Test AES-256-CBC --");
    if (bits == 256 & gcm)    printf("\n\n -- Test AES-256-GCM --");
    if (bits == 256 & ccm)    printf("\n\n -- Test AES-256-CCM-8 --");
    if (bits == 256 & cmac)   printf("\n\n -- Test AES-256-CMAC --");
    */

    for (int test = 1; test <= n_test; test++) {
        
        trng(msg, 1024);

        if (verb >= 1) printf("\n test: %d", test);

        if (ecb) {
            if (bits == 128) {
                start_t = timeInMicroseconds();
                aes_128_ecb_encrypt(key_128, ciphertext_128, &ciphertext_128_len, msg, 1024);
                stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW ENCRYPT: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            }
            else if (bits == 192) {
                start_t = timeInMicroseconds();
                aes_192_ecb_encrypt(key_192, ciphertext_192, &ciphertext_192_len, msg, 1024);
                stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW ENCRYPT: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            }
            else if (bits == 256) {
                start_t = timeInMicroseconds();
                aes_256_ecb_encrypt(key_256, ciphertext_256, &ciphertext_256_len, msg, 1024);
                stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW ENCRYPT: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            }

            time_sw = stop_t - start_t;
            time_total_en_sw += time_sw;

            if (test == 1)										tr_en->time_min_value_sw = time_sw;
            else if (tr_en->time_min_value_sw > time_sw)		tr_en->time_min_value_sw = time_sw;
            if (tr_en->time_max_value_sw < time_sw)				tr_en->time_max_value_sw = time_sw;

            if (bits == 128) {
                start_t = timeInMicroseconds();
                aes_128_ecb_decrypt(key_128, ciphertext_128, ciphertext_128_len, recovered_msg_128, &recovered_msg_128_len);
                stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW DECRYPT: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            }
            else if (bits == 192) {
                start_t = timeInMicroseconds();
                aes_192_ecb_decrypt(key_192, ciphertext_192, ciphertext_192_len, recovered_msg_192, &recovered_msg_192_len);
                stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW DECRYPT: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            }
            else if (bits == 256) {
                start_t = timeInMicroseconds();
                aes_256_ecb_decrypt(key_256, ciphertext_256, ciphertext_256_len, recovered_msg_256, &recovered_msg_256_len);
                stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW DECRYPT: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            }

            time_sw = stop_t - start_t;
            time_total_de_sw += time_sw;

            if (test == 1)										tr_de->time_min_value_sw = time_sw;
            else if (tr_de->time_min_value_sw > time_sw)		tr_de->time_min_value_sw = time_sw;
            if (tr_de->time_max_value_sw < time_sw)				tr_de->time_max_value_sw = time_sw;

            if (bits == 128) {
                if (verb >= 3) { printf("\n original msg: "); show_array(msg, 1024, 32); }
                if (verb >= 3) { printf("\n recover msg: "); show_array(recovered_msg_128, 1024, 32); }
                if (!memcmp(msg, recovered_msg_128, 1024)) tr_de->val_result++;
            }
            else if (bits == 192) {
                if (verb >= 3) { printf("\n original msg: "); show_array(msg, 1024, 32); }
                if (verb >= 3) { printf("\n recover msg: "); show_array(recovered_msg_192, 1024, 32); }
                if (!memcmp(msg, recovered_msg_192, 1024)) tr_de->val_result++;
            }
            else if (bits == 256) {
                if (verb >= 3) { printf("\n original msg: "); show_array(msg, 1024, 32); }
                if (verb >= 3) { printf("\n recover msg: "); show_array(recovered_msg_256, 1024, 32); }
                if (!memcmp(msg, recovered_msg_256, 1024)) tr_de->val_result++;
            }
        
        }
        else if (cbc) {
            if (bits == 128) {
                start_t = timeInMicroseconds();
                aes_128_cbc_encrypt(key_128, iv_128, ciphertext_128, &ciphertext_128_len, msg, 1024);
                stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW ENCRYPT: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            }
            else if (bits == 192) {
                start_t = timeInMicroseconds();
                aes_192_cbc_encrypt(key_192, iv_192, ciphertext_192, &ciphertext_192_len, msg, 1024);
                stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW ENCRYPT: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            }
            else if (bits == 256) {
                start_t = timeInMicroseconds();
                aes_256_cbc_encrypt(key_256, iv_256, ciphertext_256, &ciphertext_256_len, msg, 1024);
                stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW ENCRYPT: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            }

            time_sw = stop_t - start_t;
            time_total_en_sw += time_sw;

            if (test == 1)										tr_en->time_min_value_sw = time_sw;
            else if (tr_en->time_min_value_sw > time_sw)		tr_en->time_min_value_sw = time_sw;
            if (tr_en->time_max_value_sw < time_sw)				tr_en->time_max_value_sw = time_sw;

            if (bits == 128) {
                start_t = timeInMicroseconds();
                aes_128_cbc_decrypt(key_128, iv_128, ciphertext_128, ciphertext_128_len, recovered_msg_128, &recovered_msg_128_len);
                stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW DECRYPT: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            }
            else if (bits == 192) {
                start_t = timeInMicroseconds();
                aes_192_cbc_decrypt(key_192, iv_192, ciphertext_192, ciphertext_192_len, recovered_msg_192, &recovered_msg_192_len);
                stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW DECRYPT: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            }
            else if (bits == 256) {
                start_t = timeInMicroseconds();
                aes_256_cbc_decrypt(key_256, iv_256, ciphertext_256, ciphertext_256_len, recovered_msg_256, &recovered_msg_256_len);
                stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW DECRYPT: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            }

            time_sw = stop_t - start_t;
            time_total_de_sw += time_sw;

            if (test == 1)										tr_de->time_min_value_sw = time_sw;
            else if (tr_de->time_min_value_sw > time_sw)		tr_de->time_min_value_sw = time_sw;
            if (tr_de->time_max_value_sw < time_sw)				tr_de->time_max_value_sw = time_sw;

            if (bits == 128) {
                if (verb >= 3) printf("\n original msg: %s", msg);
                if (verb >= 3) printf("\n recover msg: %s", recovered_msg_128);
                if (!memcmp(msg, recovered_msg_128, 1024)) tr_de->val_result++;
            }
            else if (bits == 192) {
                if (verb >= 3) printf("\n original msg: %s", msg);
                if (verb >= 3) printf("\n recover msg: %s", recovered_msg_192);
                if (!memcmp(msg, recovered_msg_192, 1024)) tr_de->val_result++;
            }
            else if (bits == 256) {
                if (verb >= 3) printf("\n original msg: %s", msg);
                if (verb >= 3) printf("\n recover msg: %s", recovered_msg_256);
                if (!memcmp(msg, recovered_msg_256, 1024)) tr_de->val_result++;
            }

        }
        else if (gcm) {
            if (bits == 128) {
                start_t = timeInMicroseconds();
                aes_128_gcm_encrypt(key_128, iv_128, 16, ciphertext_128, &ciphertext_128_len, msg, 1024, add_128, 16, tag);
                stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW ENCRYPT: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            }
            else if (bits == 192) {
                start_t = timeInMicroseconds();
                aes_192_gcm_encrypt(key_192, iv_192, 16, ciphertext_192, &ciphertext_192_len, msg, 1024, add_192, 16, tag);
                stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW ENCRYPT: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            }
            else if (bits == 256) {
                start_t = timeInMicroseconds();
                aes_256_gcm_encrypt(key_256, iv_256, 16, ciphertext_256, &ciphertext_256_len, msg, 1024, add_256, 16, tag);
                stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW ENCRYPT: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            }

            time_sw = stop_t - start_t;
            time_total_en_sw += time_sw;

            if (test == 1)										tr_en->time_min_value_sw = time_sw;
            else if (tr_en->time_min_value_sw > time_sw)		tr_en->time_min_value_sw = time_sw;
            if (tr_en->time_max_value_sw < time_sw)				tr_en->time_max_value_sw = time_sw;

            if (bits == 128) {
                start_t = timeInMicroseconds();
                aes_128_gcm_decrypt(key_128, iv_128, 16, ciphertext_128, ciphertext_128_len, recovered_msg_128, &recovered_msg_128_len, add_128, 16, tag, &result);
                stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW DECRYPT: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            }
            else if (bits == 192) {
                start_t = timeInMicroseconds();
                aes_192_gcm_decrypt(key_192, iv_192, 16, ciphertext_192, ciphertext_192_len, recovered_msg_192, &recovered_msg_192_len, add_192, 16, tag, &result);
                stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW DECRYPT: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            }
            else if (bits == 256) {
                start_t = timeInMicroseconds();
                aes_256_gcm_decrypt(key_256, iv_256, 16, ciphertext_256, ciphertext_256_len, recovered_msg_256, &recovered_msg_256_len, add_256, 16, tag, &result);
                stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW DECRYPT: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            }

            time_sw = stop_t - start_t;
            time_total_de_sw += time_sw;

            if (test == 1)										tr_de->time_min_value_sw = time_sw;
            else if (tr_de->time_min_value_sw > time_sw)		tr_de->time_min_value_sw = time_sw;
            if (tr_de->time_max_value_sw < time_sw)				tr_de->time_max_value_sw = time_sw;

            if (bits == 128) {
                if (verb >= 3) printf("\n original msg: %s", msg);
                if (verb >= 3) printf("\n recover msg: %s", recovered_msg_128);
                if (!result) tr_de->val_result++;
            }
            else if (bits == 192) {
                if (verb >= 3) printf("\n original msg: %s", msg);
                if (verb >= 3) printf("\n recover msg: %s", recovered_msg_192);
                if (!result) tr_de->val_result++;
            }
            else if (bits == 256) {
                if (verb >= 3) printf("\n original msg: %s", msg);
                if (verb >= 3) printf("\n recover msg: %s", recovered_msg_256);
                if (!result) tr_de->val_result++;
            }

        }
        else if (ccm) {
            if (bits == 128) {
                start_t = timeInMicroseconds();
                aes_128_ccm_8_encrypt(key_128, iv_128, 16, ciphertext_128, &ciphertext_128_len, msg, 1024, add_128, 16, tag_8);
                stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW ENCRYPT: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            }
            else if (bits == 192) {
                start_t = timeInMicroseconds();
                aes_192_ccm_8_encrypt(key_192, iv_192, 16, ciphertext_192, &ciphertext_192_len, msg, 1024, add_192, 16, tag_8);
                stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW ENCRYPT: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            }
            else if (bits == 256) {
                start_t = timeInMicroseconds();
                aes_256_ccm_8_encrypt(key_256, iv_256, 16, ciphertext_256, &ciphertext_256_len, msg, 1024, add_256, 16, tag_8);
                stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW ENCRYPT: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            }

            time_sw = stop_t - start_t;
            time_total_en_sw += time_sw;

            if (test == 1)										tr_en->time_min_value_sw = time_sw;
            else if (tr_en->time_min_value_sw > time_sw)		tr_en->time_min_value_sw = time_sw;
            if (tr_en->time_max_value_sw < time_sw)				tr_en->time_max_value_sw = time_sw;

            if (bits == 128) {
                start_t = timeInMicroseconds();
                aes_128_ccm_8_decrypt(key_128, iv_128, 16, ciphertext_128, ciphertext_128_len, recovered_msg_128, &recovered_msg_128_len, add_128, 16, tag_8, &result);
                stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW DECRYPT: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            }
            else if (bits == 192) {
                start_t = timeInMicroseconds();
                aes_192_ccm_8_decrypt(key_192, iv_192, 16, ciphertext_192, ciphertext_192_len, recovered_msg_192, &recovered_msg_192_len, add_192, 16, tag_8, &result);
                stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW DECRYPT: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            }
            else if (bits == 256) {
                start_t = timeInMicroseconds();
                aes_256_ccm_8_decrypt(key_256, iv_256, 16, ciphertext_256, ciphertext_256_len, recovered_msg_256, &recovered_msg_256_len, add_256, 16, tag_8, &result);
                stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW DECRYPT: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            }

            time_sw = stop_t - start_t;
            time_total_de_sw += time_sw;

            if (test == 1)										tr_de->time_min_value_sw = time_sw;
            else if (tr_de->time_min_value_sw > time_sw)		tr_de->time_min_value_sw = time_sw;
            if (tr_de->time_max_value_sw < time_sw)				tr_de->time_max_value_sw = time_sw;

            if (bits == 128) {
                if (verb >= 3) printf("\n original msg: %s", msg);
                if (verb >= 3) printf("\n recover msg: %s", recovered_msg_128);
                if (!result) tr_de->val_result++;
            }
            else if (bits == 192) {
                if (verb >= 3) printf("\n original msg: %s", msg);
                if (verb >= 3) printf("\n recover msg: %s", recovered_msg_192);
                if (!result) tr_de->val_result++;
            }
            else if (bits == 256) {
                if (verb >= 3) printf("\n original msg: %s", msg);
                if (verb >= 3) printf("\n recover msg: %s", recovered_msg_256);
                if (!result) tr_de->val_result++;
            }

        }
        else if (cmac) {
            if (bits == 128) {
                start_t = timeInMicroseconds();
                aes_128_cmac(key_128, mac_128, &mac_128_len, msg, 1024);
                stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW CMAC: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            }
            else if (bits == 192) {
                start_t = timeInMicroseconds();
                aes_192_cmac(key_192, mac_192, &mac_192_len, msg, 1024);
                stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW CMAC: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            }
            else if (bits == 256) {
                start_t = timeInMicroseconds();
                aes_256_cmac(key_256, mac_256, &mac_256_len, msg, 1024);
                stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW CMAC: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));
            }

            time_sw = stop_t - start_t;
            time_total_en_sw += time_sw;

            if (test == 1)										tr_en->time_min_value_sw = time_sw;
            else if (tr_en->time_min_value_sw > time_sw)		tr_en->time_min_value_sw = time_sw;
            if (tr_en->time_max_value_sw < time_sw)				tr_en->time_max_value_sw = time_sw;

            if (bits == 128) {
                if (verb >= 3) { printf("\n Obtained Result: ");  show_array(mac_128, 16, 32); }
                tr_en->val_result = 0xFFFFFFFF; // We can not compare the result
            }
            else if (bits == 192) {
                if (verb >= 3) { printf("\n Obtained Result: ");  show_array(mac_192, 16, 32); }
                tr_en->val_result = 0xFFFFFFFF;
            }
            else if (bits == 256) {
                if (verb >= 3) { printf("\n Obtained Result: ");  show_array(mac_256, 16, 32); }
                tr_en->val_result = 0xFFFFFFFF;
            }

        }
    }

    tr_en->time_mean_value_sw = (uint64_t)(time_total_en_sw / n_test);
    tr_de->time_mean_value_sw = (uint64_t)(time_total_de_sw / n_test);

    free(mac_128);
    free(mac_192);
    free(mac_256);

    free(ciphertext_128);
    free(recovered_msg_128);
    free(ciphertext_192);
    free(recovered_msg_192);
    free(ciphertext_256);
    free(recovered_msg_256);

}