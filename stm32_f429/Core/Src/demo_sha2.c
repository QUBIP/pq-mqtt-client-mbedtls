/**
  * @file demo_sha2.c
  * @brief Validation Test for SHA2 Code
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

#ifndef OPENSSL
#define SHA224_DIGEST_LENGTH 28
#define SHA256_DIGEST_LENGTH 32
#define SHA384_DIGEST_LENGTH 48
#define SHA512_DIGEST_LENGTH 64
#endif

void demo_sha2_hw(unsigned int verb, INTF interface) {

    // ---- SHA2 ---- //
    unsigned char* input;
    unsigned int len_input;
    unsigned char* md; 

    unsigned char *exp_res_224 = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f";
    unsigned char *exp_res_256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    unsigned char *exp_res_384 = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b";
    unsigned char *exp_res_512 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
    unsigned char *exp_res_512_224 = "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4";
    unsigned char *exp_res_512_256 = "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a";

    unsigned char res_224[28]; char2hex(exp_res_224, res_224);
    unsigned char res_256[32]; char2hex(exp_res_256, res_256);
    unsigned char res_384[48]; char2hex(exp_res_384, res_384);
    unsigned char res_512[64]; char2hex(exp_res_512, res_512);
    unsigned char res_512_224[28]; char2hex(exp_res_512_224, res_512_224);
    unsigned char res_512_256[32]; char2hex(exp_res_512_256, res_512_256);

    input       = malloc(32);
    input[0]    = (unsigned char)('\0');
    len_input   = 0;

    // ---- sha_224 ---- //
    /*
    md = malloc(SHA224_DIGEST_LENGTH);
    sha_224(input, len_input, md);
    if (verb >= 1) {
        printf("\n Obtained Result: ");  show_array(md, SHA224_DIGEST_LENGTH, 32);
        printf("\n Expected Result: ");  show_array(res_224, SHA224_DIGEST_LENGTH, 32);
    }

    print_result_valid("SHA-224", memcmp(md, res_224, SHA224_DIGEST_LENGTH));

    free(md);
    */
    // ---- sha_256 ---- //
    md      = malloc(SHA256_DIGEST_LENGTH);
    sha_256_hw(input, len_input, md, interface);
    if (verb >= 1) {
        printf("\n Obtained Result: ");  show_array(md, SHA256_DIGEST_LENGTH, 32);
        printf("\n Expected Result: ");  show_array(res_256, SHA256_DIGEST_LENGTH, 32);
    }
    print_result_valid("SHA-256", memcmp(md, res_256, SHA256_DIGEST_LENGTH));
    free(md);
    
    // ---- sha_384 ---- //
    md = malloc(SHA384_DIGEST_LENGTH);
    sha_384_hw(input, len_input, md, interface);
    if (verb >= 1) {
        printf("\n Obtained Result: ");  show_array(md, SHA384_DIGEST_LENGTH, 32);
        printf("\n Expected Result: ");  show_array(res_384, SHA384_DIGEST_LENGTH, 32);
    }
    print_result_valid("SHA-384", memcmp(md, res_384, SHA384_DIGEST_LENGTH));
    free(md);

    // ---- sha_512 ---- //
    md = malloc(SHA512_DIGEST_LENGTH);
    sha_512_hw(input, len_input, md, interface);
    if (verb >= 1) {
        printf("\n Obtained Result: ");  show_array(md, SHA512_DIGEST_LENGTH, 32);
        printf("\n Expected Result: ");  show_array(res_512, SHA512_DIGEST_LENGTH, 32);
    }
    print_result_valid("SHA-512", memcmp(md, res_512, SHA512_DIGEST_LENGTH));
    free(md);
    /*
    // ---- sha_512_224 ---- //
    md = malloc(SHA224_DIGEST_LENGTH);
    sha_512_224(input, len_input, md);
    if (verb >= 1) {
        printf("\n Obtained Result: ");  show_array(md, SHA224_DIGEST_LENGTH, 32);
        printf("\n Expected Result: ");  show_array(res_512_224, SHA224_DIGEST_LENGTH, 32);
    }
    print_result_valid("SHA-512/224", memcmp(md, res_512_224, SHA224_DIGEST_LENGTH));
    free(md);
    */
    // ---- sha_512_256 ---- //
    md = malloc(SHA256_DIGEST_LENGTH);
    sha_512_256_hw(input, len_input, md, interface);
    if (verb >= 1) {
        printf("\n Obtained Result: ");  show_array(md, SHA256_DIGEST_LENGTH, 32);
        printf("\n Expected Result: ");  show_array(res_512_256, SHA256_DIGEST_LENGTH, 32);
    }
    print_result_valid("SHA-512/256", memcmp(md, res_512_256, SHA256_DIGEST_LENGTH));
    free(md);

}