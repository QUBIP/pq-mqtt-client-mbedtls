/**
  * @file demo_mlkem.c
  * @brief Validation test for MLKEM code
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

void demo_mlkem(unsigned int mode, unsigned int verb) {

    if (mode == 512) {
        // ---- MLKEM-512 ---- //
        uint8_t* pk;
        uint8_t* sk;

        pk = malloc(800);
        sk = malloc(1632);

        mlkem512_genkeys(pk, sk);

        if (verb >= 3) printf("\n pub_len: %d (bytes)", 800);
        if (verb >= 3) printf("\n pri_len: %d (bytes)", 1632);

        if (verb >= 3) { printf("\n public key: ");     show_array(pk, 800, 32); }
        if (verb >= 3) { printf("\n private key: ");    show_array(sk, 1632, 32); }

        uint8_t* ss;
        uint8_t* ct;

        ss = malloc(32);
        ct = malloc(768);

        mlkem512_enc(ct, ss, pk);

        if (verb >= 3) printf("\n ss_len: %d (bytes)", 32);
        if (verb >= 3) printf("\n ct_len: %d (bytes)", 768);

        if (verb >= 1) { printf("\n ss: ");    show_array(ss, 32, 32); }
        if (verb >= 2) { printf("\n ct: ");    show_array(ct, 768, 32); }

        unsigned int result;
        uint8_t* ss1;
        ss1 = malloc(32);

        mlkem512_dec(ss1, ct, sk, &result);

        if (verb >= 3) printf("\n ss1_len: %d (bytes)", 32);
        if (verb >= 1) { printf("\n ss1: ");    show_array(ss1, 32, 32); }

        print_result_valid("MLKEM-512", result);

        free(pk);
        free(sk);
        free(ss);
        free(ct);
        free(ss1);

    }
    else if (mode == 768) {
        // ---- MLKEM-768 ---- //
        uint8_t* pk;
        uint8_t* sk;

        pk = malloc(1184);
        sk = malloc(2400);

        mlkem768_genkeys(pk, sk);

        if (verb >= 3) printf("\n pub_len: %d (bytes)", 1184);
        if (verb >= 3) printf("\n pri_len: %d (bytes)", 2400);

        if (verb >= 3) { printf("\n public key: ");     show_array(pk, 1184, 32); }
        if (verb >= 3) { printf("\n private key: ");    show_array(sk, 2400, 32); }

        uint8_t* ss;
        uint8_t* ct;

        ss = malloc(32);
        ct = malloc(1088);

        mlkem768_enc(ct, ss, pk);

        if (verb >= 3) printf("\n ss_len: %d (bytes)", 32);
        if (verb >= 3) printf("\n ct_len: %d (bytes)", 1088);

        if (verb >= 1) { printf("\n ss: ");    show_array(ss, 32, 32); }
        if (verb >= 2) { printf("\n ct: ");    show_array(ct, 1088, 32); }

        unsigned int result;
        uint8_t* ss1;
        ss1 = malloc(32);

        mlkem768_dec(ss1, ct, sk, &result);

        if (verb >= 3) printf("\n ss1_len: %d (bytes)", 32);
        if (verb >= 1) { printf("\n ss1: ");    show_array(ss1, 32, 32); }

        print_result_valid("MLKEM-768", result);

        free(pk);
        free(sk);
        free(ss);
        free(ss1);
        free(ct);
    
    }
    else {
        // ---- MLKEM-1024 ---- //
        uint8_t* pk;
        uint8_t* sk;

        pk = malloc(1568);
        sk = malloc(3168);

        mlkem1024_genkeys(pk, sk);

        if (verb >= 3) printf("\n pub_len: %d (bytes)", 1568);
        if (verb >= 3) printf("\n pri_len: %d (bytes)", 3168);

        if (verb >= 3) { printf("\n public key: ");     show_array(pk, 1568, 32); }
        if (verb >= 3) { printf("\n private key: ");    show_array(sk, 3168, 32); }

        uint8_t* ss;
        uint8_t* ct;

        ss = malloc(32);
        ct = malloc(1568);

        mlkem1024_enc(ct, ss, pk);

        if (verb >= 3) printf("\n ss_len: %d (bytes)", 32);
        if (verb >= 3) printf("\n ct_len: %d (bytes)", 1568);

        if (verb >= 1) { printf("\n ss: ");    show_array(ss, 32, 32); }
        if (verb >= 2) { printf("\n ct: ");    show_array(ct, 1568, 32); }

        unsigned int result;
        uint8_t* ss1;
        ss1 = malloc(32);

        mlkem1024_dec(ss1, ct, sk, &result);

        if (verb >= 3) printf("\n ss1_len: %d (bytes)", 32);
        if (verb >= 1) { printf("\n ss1: ");    show_array(ss1, 32, 32); }

        print_result_valid("MLKEM-1024", result);

        free(pk);
        free(sk);
        free(ss);
        free(ss1);
        free(ct);

    }

}