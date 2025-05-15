/**
  * @file demo_slhdsa.c
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
  * @version 6.0
  **/ 

#include "demo.h"
#include "test_func.h"

void demo_slhdsa(unsigned char mode[12], unsigned int verb) {

    unsigned char msg[50] = "Hello, this is the SE of QUBIP project";

    unsigned int result = 1;
    unsigned int len_msg = strlen(msg);

    // ---- SLHDSA ---- //
    if (!memcmp(mode, "shake-128-f", 12)) {

        if (verb >= 2) { printf("\n original msg"); show_array(msg, len_msg, 32); }

        unsigned char* pub_key;
        unsigned char* pri_key;
        unsigned int pub_len;
        unsigned int pri_len;

        unsigned char* sig;
        unsigned int sig_len;

        pri_len = 64; // CRYPTO_SECRETKEYBYTES_SHAKE_128_F;
        pub_len = 32; // CRYPTO_PUBLICKEYBYTES_SHAKE_128_F;
        pri_key = malloc(pri_len);
        pub_key = malloc(pub_len);

        sig_len = 17088; // CRYPTO_BYTES_SHAKE_128_F ;
        sig = malloc(sig_len);

        slhdsa_shake128f_genkeys(pri_key, pub_key);

        if (verb >= 2) printf("\n pub_len: %d (bytes)", pub_len);
        if (verb >= 2) printf("\n pri_len: %d (bytes)", pri_len);

        if (verb >= 3) { printf("\n public key: ");   show_array(pub_key, pub_len, 32); }
        if (verb >= 3) { printf("\n private key: "); show_array(pri_key, pri_len, 32); }

        slhdsa_shake128f_sig(msg, len_msg, (const unsigned char*)pri_key, sig, &sig_len);

        if (verb >= 3) { printf("\n signature: ");   show_array(sig, sig_len, 32); }

        slhdsa_shake128f_verify(msg, len_msg, (const unsigned char*)pub_key, (const unsigned char*)sig, sig_len, &result);

        print_result_valid("SLHDSA-SHAKE-128-F", result);

        free(pri_key);
        free(pub_key);
        free(sig);

    }
    
    else if (!memcmp(mode, "shake-128-s", 12)) {

        if (verb >= 2) { printf("\n original msg"); show_array(msg, len_msg, 32); }

        unsigned char* pub_key;
        unsigned char* pri_key;
        unsigned int pub_len;
        unsigned int pri_len;

        unsigned char* sig;
        unsigned int sig_len;

        pri_len = 64;  // CRYPTO_SECRETKEYBYTES_SHAKE_128_S;
        pub_len = 32;  // CRYPTO_PUBLICKEYBYTES_SHAKE_128_S;
        pri_key = malloc(pri_len);
        pub_key = malloc(pub_len);

        sig_len = 7856; // CRYPTO_BYTES_SHAKE_128_S + len_msg;
        sig = malloc(sig_len);

        slhdsa_shake128s_genkeys(pri_key, pub_key);

        if (verb >= 2) printf("\n pub_len: %d (bytes)", pub_len);
        if (verb >= 2) printf("\n pri_len: %d (bytes)", pri_len);

        if (verb >= 3) { printf("\n public key: ");   show_array(pub_key, pub_len, 32); }
        if (verb >= 3) { printf("\n private key: "); show_array(pri_key, pri_len, 32); }

        slhdsa_shake128s_sig(msg, len_msg, (const unsigned char*)pri_key, sig, &sig_len);

        if (verb >= 3) { printf("\n signature: ");   show_array(sig, sig_len, 32); }

        slhdsa_shake128s_verify(msg, len_msg, (const unsigned char*)pub_key, (const unsigned char*)sig, sig_len, &result);

        print_result_valid("SLHDSA-SHAKE-128-S", result);

        free(pri_key);
        free(pub_key);
        free(sig);

    }

    else if (!memcmp(mode, "shake-192-f", 12)) {

        if (verb >= 2) { printf("\n original msg"); show_array(msg, len_msg, 32); }

        unsigned char* pub_key;
        unsigned char* pri_key;
        unsigned int pub_len;
        unsigned int pri_len;

        unsigned char* sig;
        unsigned int sig_len;

        pri_len = 96;  // CRYPTO_SECRETKEYBYTES_SHAKE_192_F;
        pub_len = 48;  // CRYPTO_PUBLICKEYBYTES_SHAKE_192_F;
        pri_key = malloc(pri_len);
        pub_key = malloc(pub_len);

        sig_len = 35664; // CRYPTO_BYTES_SHAKE_192_F + len_msg;
        sig = malloc(sig_len);

        slhdsa_shake192f_genkeys(pri_key, pub_key);

        if (verb >= 2) printf("\n pub_len: %d (bytes)", pub_len);
        if (verb >= 2) printf("\n pri_len: %d (bytes)", pri_len);

        if (verb >= 3) { printf("\n public key: ");   show_array(pub_key, pub_len, 32); }
        if (verb >= 3) { printf("\n private key: "); show_array(pri_key, pri_len, 32); }

        slhdsa_shake192f_sig(msg, len_msg, (const unsigned char*)pri_key, sig, &sig_len);

        if (verb >= 3) { printf("\n signature: ");   show_array(sig, sig_len, 32); }

        slhdsa_shake192f_verify(msg, len_msg, (const unsigned char*)pub_key, (const unsigned char*)sig, sig_len, &result);

        print_result_valid("SLHDSA-SHAKE-192-F", result);

        free(pri_key);
        free(pub_key);
        free(sig);

    }

    else if (!memcmp(mode, "shake-192-s", 12)) {

        if (verb >= 2) { printf("\n original msg"); show_array(msg, len_msg, 32); }

        unsigned char* pub_key;
        unsigned char* pri_key;
        unsigned int pub_len;
        unsigned int pri_len;

        unsigned char* sig;
        unsigned int sig_len;

        pri_len = 96;  // CRYPTO_SECRETKEYBYTES_SHAKE_192_S;
        pub_len = 48;  // CRYPTO_PUBLICKEYBYTES_SHAKE_192_S;
        pri_key = malloc(pri_len);
        pub_key = malloc(pub_len);

        sig_len = 16224; // CRYPTO_BYTES_SHAKE_192_S + len_msg;
        sig = malloc(sig_len);

        slhdsa_shake192s_genkeys(pri_key, pub_key);

        if (verb >= 2) printf("\n pub_len: %d (bytes)", pub_len);
        if (verb >= 2) printf("\n pri_len: %d (bytes)", pri_len);

        if (verb >= 3) { printf("\n public key: ");   show_array(pub_key, pub_len, 32); }
        if (verb >= 3) { printf("\n private key: "); show_array(pri_key, pri_len, 32); }

        slhdsa_shake192s_sig(msg, len_msg, (const unsigned char*)pri_key, sig, &sig_len);

        if (verb >= 3) { printf("\n signature: ");   show_array(sig, sig_len, 32); }

        slhdsa_shake192s_verify(msg, len_msg, (const unsigned char*)pub_key, (const unsigned char*)sig, sig_len, &result);

        print_result_valid("SLHDSA-SHAKE-192-S", result);

        free(pri_key);
        free(pub_key);
        free(sig);

    }

    else if (!memcmp(mode, "shake-256-f", 12)) {

        if (verb >= 2) { printf("\n original msg"); show_array(msg, len_msg, 32); }

        unsigned char* pub_key;
        unsigned char* pri_key;
        unsigned int pub_len;
        unsigned int pri_len;

        unsigned char* sig;
        unsigned int sig_len;

        pri_len = 128;  // CRYPTO_SECRETKEYBYTES_SHAKE_256_F;
        pub_len = 64;  // CRYPTO_PUBLICKEYBYTES_SHAKE_256_F;
        pri_key = malloc(pri_len);
        pub_key = malloc(pub_len);

        sig_len = 49856; // CRYPTO_BYTES_SHAKE_256_F + len_msg;
        sig = malloc(sig_len);

        slhdsa_shake256f_genkeys(pri_key, pub_key);

        if (verb >= 2) printf("\n pub_len: %d (bytes)", pub_len);
        if (verb >= 2) printf("\n pri_len: %d (bytes)", pri_len);

        if (verb >= 3) { printf("\n public key: ");   show_array(pub_key, pub_len, 32); }
        if (verb >= 3) { printf("\n private key: "); show_array(pri_key, pri_len, 32); }

        slhdsa_shake256f_sig(msg, len_msg, (const unsigned char*)pri_key, sig, &sig_len);

        if (verb >= 3) { printf("\n signature: ");   show_array(sig, sig_len, 32); }

        slhdsa_shake256f_verify(msg, len_msg, (const unsigned char*)pub_key, (const unsigned char*)sig, sig_len, &result);

        print_result_valid("SLHDSA-SHAKE-256-F", result);

        free(pri_key);
        free(pub_key);
        free(sig);

    }

    else if (!memcmp(mode, "shake-256-s", 12)) {

        if (verb >= 2) { printf("\n original msg"); show_array(msg, len_msg, 32); }

        unsigned char* pub_key;
        unsigned char* pri_key;
        unsigned int pub_len;
        unsigned int pri_len;

        unsigned char* sig;
        unsigned int sig_len;

        pri_len = 128;  // CRYPTO_SECRETKEYBYTES_SHAKE_256_S;
        pub_len = 64;  // CRYPTO_PUBLICKEYBYTES_SHAKE_256_S;
        pri_key = malloc(pri_len);
        pub_key = malloc(pub_len);

        sig_len = 29792; // CRYPTO_BYTES_SHAKE_256_S + len_msg;
        sig = malloc(sig_len);

        slhdsa_shake256s_genkeys(pri_key, pub_key);

        if (verb >= 2) printf("\n pub_len: %d (bytes)", pub_len);
        if (verb >= 2) printf("\n pri_len: %d (bytes)", pri_len);

        if (verb >= 3) { printf("\n public key: ");   show_array(pub_key, pub_len, 32); }
        if (verb >= 3) { printf("\n private key: "); show_array(pri_key, pri_len, 32); }

        slhdsa_shake256s_sig(msg, len_msg, (const unsigned char*)pri_key, sig, &sig_len);

        if (verb >= 3) { printf("\n signature: ");   show_array(sig, sig_len, 32); }

        slhdsa_shake256s_verify(msg, len_msg, (const unsigned char*)pub_key, (const unsigned char*)sig, sig_len, &result);

        print_result_valid("SLHDSA-SHAKE-256-S", result);

        free(pri_key);
        free(pub_key);
        free(sig);

    }


    
}