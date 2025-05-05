/**
  * @file demo_mldsa.c
  * @brief Validation test for MLDSA code
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
#include "crypto_api_sw.h"

void demo_mldsa(unsigned int mode, unsigned int verb) {

    unsigned char msg[50] = "Hello, this is the SE of QUBIP project";

    unsigned int result = 1;

    // ---- EDDSA ---- //
    if (mode == 44) {

        unsigned char* pub_key;
        unsigned char* pri_key;
        unsigned int pub_len;
        unsigned int pri_len;

        unsigned char* sig;
        unsigned int sig_len;

        pri_len = 2560;
        pub_len = 1312;
        pri_key = malloc(pri_len);
        pub_key = malloc(pub_len);

        sig_len = 2420;
        sig = malloc(sig_len);

        mldsa44_genkeys(pri_key, pub_key);

        if (verb >= 2) printf("\n pub_len: %d (bytes)", pub_len);
        if (verb >= 2) printf("\n pri_len: %d (bytes)", pri_len);

        if (verb >= 3) { printf("\n public key: ");   show_array(pub_key, pub_len, 32); }
        if (verb >= 3) { printf("\n private key: "); show_array(pri_key, pri_len, 32); }

        mldsa44_sig(msg, strlen(msg), (const unsigned char*)pri_key, sig, &sig_len, NULL, 0);

        if (verb >= 3) { printf("\n signature: ");   show_array(sig, sig_len, 32); }

        mldsa44_verify(msg, strlen(msg), (const unsigned char*)pub_key, (const unsigned char*)sig, sig_len, &result, NULL, 0);

        print_result_valid("MLDSA-44", result);

        free(pri_key);
        free(pub_key);
        free(sig);

    }
    
    else if (mode == 65) {

        unsigned char* pub_key;
        unsigned char* pri_key;
        unsigned int pub_len;
        unsigned int pri_len;

        unsigned char* sig;
        unsigned int sig_len;

        pri_len = 4032;
        pub_len = 1952;
        pri_key = malloc(pri_len);
        pub_key = malloc(pub_len);

        sig_len = 3309;
        sig = malloc(sig_len);

        mldsa65_genkeys(pri_key, pub_key);

        if (verb >= 2) printf("\n pub_len: %d (bytes)", pub_len);
        if (verb >= 2) printf("\n pri_len: %d (bytes)", pri_len);

        if (verb >= 3) { printf("\n public key: ");   show_array(pub_key, pub_len, 32); }
        if (verb >= 3) { printf("\n private key: "); show_array(pri_key, pri_len, 32); }

        mldsa65_sig(msg, strlen(msg), (const unsigned char*)pri_key, sig, &sig_len, NULL, 0);

        if (verb >= 3) { printf("\n signature: ");   show_array(sig, sig_len, 32); }

        mldsa65_verify(msg, strlen(msg), (const unsigned char*)pub_key, (const unsigned char*)sig, sig_len, &result, NULL, 0);

        print_result_valid("MLDSA-65", result);

        free(pri_key);
        free(pub_key);
        free(sig);
    }

    else {

        unsigned char* pub_key;
        unsigned char* pri_key;
        unsigned int pub_len;
        unsigned int pri_len;

        unsigned char* sig;
        unsigned int sig_len;

        pri_len = 4896;
        pub_len = 2592;
        pri_key = malloc(pri_len);
        pub_key = malloc(pub_len);

        sig_len = 4627;
        sig = malloc(sig_len);

        mldsa87_genkeys(pri_key, pub_key);

        if (verb >= 2) printf("\n pub_len: %d (bytes)", pub_len);
        if (verb >= 2) printf("\n pri_len: %d (bytes)", pri_len);

        if (verb >= 3) { printf("\n public key: ");   show_array(pub_key, pub_len, 32); }
        if (verb >= 3) { printf("\n private key: "); show_array(pri_key, pri_len, 32); }

        mldsa87_sig(msg, strlen(msg), (const unsigned char*)pri_key, sig, &sig_len, NULL, 0);

        if (verb >= 3) { printf("\n signature: ");   show_array(sig, sig_len, 32); }

        mldsa87_verify(msg, strlen(msg), (const unsigned char*)pub_key, (const unsigned char*)sig, sig_len, &result, NULL, 0);

        print_result_valid("MLDSA-87", result);

        free(pri_key);
        free(pub_key);
        free(sig);
    
    }

    
}
