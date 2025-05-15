/**
  * @file demo_x25519.c
  * @brief Validation test for ECDH code
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

void demo_x25519(unsigned int mode, unsigned int verb) {

    // ---- KEY GEN ---- //
    unsigned char* pub_key_A;
    unsigned char* pri_key_A;
    unsigned int pub_len_A;
    unsigned int pri_len_A;

    if (mode == 25519)   x25519_genkeys(&pri_key_A, &pub_key_A, &pri_len_A, &pub_len_A);
    else                x448_genkeys(&pri_key_A, &pub_key_A, &pri_len_A, &pub_len_A);

    if (verb >= 2) printf("\n pub_len: %d (bytes)", pub_len_A);
    if (verb >= 2) printf("\n pri_len: %d (bytes)", pri_len_A);

    if (verb >= 3) { printf("\n public key: ");   show_array(pub_key_A, pub_len_A, 32); }
    if (verb >= 3) { printf("\n private key: "); show_array(pri_key_A, pri_len_A, 32); }

    unsigned char* pub_key_B;
    unsigned char* pri_key_B;
    unsigned int pub_len_B;
    unsigned int pri_len_B;

    if (mode == 25519)   x25519_genkeys(&pri_key_B, &pub_key_B, &pri_len_B, &pub_len_B);
    else                x448_genkeys(&pri_key_B, &pub_key_B, &pri_len_B, &pub_len_B);

    if (verb >= 2) printf("\n pub_len: %d (bytes)", pub_len_B);
    if (verb >= 2) printf("\n pri_len: %d (bytes)", pri_len_B);

    if (verb >= 3) { printf("\n public key: ");   show_array(pub_key_B, pub_len_B, 32); }
    if (verb >= 3) { printf("\n private key: "); show_array(pri_key_B, pri_len_B, 32); }

    // --- SHARED_SECRET --- //

    unsigned char* ss_A;
    unsigned int ss_len_A;
    if (mode == 25519)
        x25519_ss_gen(&ss_A, &ss_len_A, (const unsigned char*)pub_key_B, pub_len_B, (const unsigned char*)pri_key_A, pri_len_A); // A Side
    else
        x448_ss_gen(&ss_A, &ss_len_A, (const unsigned char*)pub_key_B, pub_len_B, (const unsigned char*)pri_key_A, pri_len_A); // A Side

    unsigned char* ss_B;
    unsigned int ss_len_B;
    if (mode == 25519)
        x25519_ss_gen(&ss_B, &ss_len_B, (const unsigned char*)pub_key_A, pub_len_A, (const unsigned char*)pri_key_B, pri_len_B); // B Side
    else
        x448_ss_gen(&ss_B, &ss_len_B, (const unsigned char*)pub_key_A, pub_len_A, (const unsigned char*)pri_key_B, pri_len_B); // B Side

    if (verb >= 2) printf("\n ss_len_A: %d (bytes)", ss_len_A);
    if (verb >= 3) { printf("\n ss_A: ");   show_array(ss_A, ss_len_A, 32); }

    if (verb >= 2) printf("\n ss_len_B: %d (bytes)", ss_len_B);
    if (verb >= 3) { printf("\n ss_B: ");   show_array(ss_B, ss_len_B, 32); }

    unsigned char s_mode[20];
    if (mode == 25519)  sprintf(s_mode, "%s", "X25519 KEM");
    else                sprintf(s_mode, "%s", "X448 KEM");

    print_result_valid(s_mode, memcmp(ss_A, ss_B, ss_len_A));


}