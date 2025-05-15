/**
  * @file demo_sha3.c
  * @brief Validation test for SHA3 code
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

#ifndef OPENSSL
#define SHA224_DIGEST_LENGTH 28
#define SHA256_DIGEST_LENGTH 32
#define SHA384_DIGEST_LENGTH 48
#define SHA512_DIGEST_LENGTH 64
#endif

void demo_sha3(unsigned int verb) {

    // ---- SHA3 ---- //
    unsigned char* input;
    unsigned int len_input;
    unsigned char* md;

    unsigned char* exp_res_3_224 = "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7";
    unsigned char* exp_res_3_256 = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
    unsigned char* exp_res_3_384 = "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004";
    unsigned char* exp_res_3_512 = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
    unsigned char* exp_res_s_128 = "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26";
    unsigned char* exp_res_s_256 = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be";

    unsigned char res_3_224[28]; char2hex(exp_res_3_224, res_3_224);
    unsigned char res_3_256[32]; char2hex(exp_res_3_256, res_3_256);
    unsigned char res_3_384[48]; char2hex(exp_res_3_384, res_3_384);
    unsigned char res_3_512[64]; char2hex(exp_res_3_512, res_3_512);
    unsigned char res_s_128[32]; char2hex(exp_res_s_128, res_s_128);
    unsigned char res_s_256[64]; char2hex(exp_res_s_256, res_s_256);

    input = malloc(32);
    input[0] = (unsigned char)('\0');
    len_input = 0;

    // ---- sha3_224 ---- //
    md = malloc(SHA224_DIGEST_LENGTH);
    sha3_224(input, len_input, md);
    if (verb >= 1) {
        printf("\n Obtained Result: ");  show_array(md, SHA224_DIGEST_LENGTH, 32);
        printf("\n Expected Result: ");  show_array(res_3_224, SHA224_DIGEST_LENGTH, 32);
    }
    print_result_valid("SHA3-224", memcmp(md, res_3_224, SHA224_DIGEST_LENGTH));
    free(md);

    // ---- sha3_256 ---- //
    md = malloc(SHA256_DIGEST_LENGTH);
    sha3_256(input, len_input, md);
    if (verb >= 1) {
        printf("\n Obtained Result: ");  show_array(md, SHA256_DIGEST_LENGTH, 32);
        printf("\n Expected Result: ");  show_array(res_3_256, SHA256_DIGEST_LENGTH, 32);
    }
    print_result_valid("SHA3-256", memcmp(md, res_3_256, SHA256_DIGEST_LENGTH));
    free(md);

    // ---- sha3_384 ---- //
    md = malloc(SHA384_DIGEST_LENGTH);
    sha3_384(input, len_input, md);
    if (verb >= 1) {
        printf("\n Obtained Result: ");  show_array(md, SHA384_DIGEST_LENGTH, 32);
        printf("\n Expected Result: ");  show_array(res_3_384, SHA384_DIGEST_LENGTH, 32);
    }
    print_result_valid("SHA3-384", memcmp(md, res_3_384, SHA384_DIGEST_LENGTH));
    free(md);

    // ---- sha3_512 ---- //
    md = malloc(SHA512_DIGEST_LENGTH);
    sha3_512(input, len_input, md);
    if (verb >= 1) {
        printf("\n Obtained Result: ");  show_array(md, SHA512_DIGEST_LENGTH, 32);
        printf("\n Expected Result: ");  show_array(res_3_512, SHA512_DIGEST_LENGTH, 32);
    }
    print_result_valid("SHA3-512", memcmp(md, res_3_512, SHA512_DIGEST_LENGTH));
    free(md);

    // ---- shake_128 ---- //
    md = malloc(32);
    shake_128(input, len_input, md, 32);
    if (verb >= 1) {
        printf("\n Obtained Result: ");  show_array(md, 32, 32);
        printf("\n Expected Result: ");  show_array(res_s_128, 32, 32);
    }
    print_result_valid("SHAKE-128", memcmp(md, res_s_128, 32));
    free(md);

    // ---- shake_256 ---- //
    md = malloc(64);
    shake_256(input, len_input, md, 64);
    if (verb >= 1) {
        printf("\n Obtained Result: ");  show_array(md, 64, 32);
        printf("\n Expected Result: ");  show_array(res_s_256, 64, 32);
    }
    print_result_valid("SHAKE-256", memcmp(md, res_s_256, 64));
    free(md);

}