/**
  * @file demo_x25519.c
  * @brief Validation Test for ECDH Code
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

void demo_x25519_hw(unsigned int mode, unsigned int verb, INTF interface) {

#ifdef AXI
    unsigned int clk_index = 0;
    float clk_frequency;
    float set_clk_frequency = FREQ_X25519;
    Set_Clk_Freq(clk_index, &clk_frequency, &set_clk_frequency, (int) verb);
#endif

    // ---- KEY GEN ---- //
    unsigned char* pub_key_A;
    unsigned char* pri_key_A;
    unsigned int pub_len_A;
    unsigned int pri_len_A;

    if (mode == 25519)   x25519_genkeys_hw(&pri_key_A, &pub_key_A, &pri_len_A, &pub_len_A, interface);
    // else                x448_genkeys(&pri_key_A, &pub_key_A, &pri_len_A, &pub_len_A);

    if (verb >= 2) printf("\n pub_len: %d (bytes)", pub_len_A);
    if (verb >= 2) printf("\n pri_len: %d (bytes)", pri_len_A);

    if (verb >= 3) { printf("\n public key: ");   show_array(pub_key_A, pub_len_A, 32); }
    if (verb >= 3) { printf("\n private key: "); show_array(pri_key_A, pri_len_A, 32); }

    unsigned char* pub_key_B;
    unsigned char* pri_key_B;
    unsigned int pub_len_B;
    unsigned int pri_len_B;
 
    if (mode == 25519)   x25519_genkeys_hw(&pri_key_B, &pub_key_B, &pri_len_B, &pub_len_B, interface);
    // else                x448_genkeys(&pri_key_B, &pub_key_B, &pri_len_B, &pub_len_B);

    if (verb >= 2) printf("\n pub_len: %d (bytes)", pub_len_B);
    if (verb >= 2) printf("\n pri_len: %d (bytes)", pri_len_B);

    if (verb >= 3) { printf("\n public key: ");   show_array(pub_key_B, pub_len_B, 32); }
    if (verb >= 3) { printf("\n private key: "); show_array(pri_key_B, pri_len_B, 32); }

    // --- SHARED_SECRET --- //

    unsigned char* ss_A;
    unsigned int ss_len_A;
    if (mode == 25519)
        x25519_ss_gen_hw(&ss_A, &ss_len_A, pub_key_B, pub_len_B, pri_key_A, pri_len_A, interface); // A Side
    // else
        // x448_ss_gen(&ss_A, &ss_len_A, (const unsigned char*)pub_key_B, pub_len_B, (const unsigned char*)pri_key_A, pri_len_A); // A Side

    unsigned char* ss_B;
    unsigned int ss_len_B;
    if (mode == 25519)
        x25519_ss_gen_hw(&ss_B, &ss_len_B, pub_key_A, pub_len_A, pri_key_B, pri_len_B, interface); // B Side
    // else
        // x448_ss_gen(&ss_B, &ss_len_B, (const unsigned char*)pub_key_A, pub_len_A, (const unsigned char*)pri_key_B, pri_len_B); // B Side

    if (verb >= 2) printf("\n ss_len_A: %d (bytes)", ss_len_A);
    if (verb >= 3) { printf("\n ss_A: ");   show_array(ss_A, ss_len_A, 32); }

    if (verb >= 2) printf("\n ss_len_B: %d (bytes)", ss_len_B);
    if (verb >= 3) { printf("\n ss_B: ");   show_array(ss_B, ss_len_B, 32); }

    unsigned char s_mode[20];
    if (mode == 25519)  sprintf(s_mode, "%s", "X25519 KEM");
    // else                sprintf(s_mode, "%s", "X448 KEM");

    print_result_valid(s_mode, memcmp(ss_A, ss_B, ss_len_A));

#ifdef AXI
    set_clk_frequency = FREQ_TYPICAL;
    Set_Clk_Freq(clk_index, &clk_frequency, &set_clk_frequency, (int)verb);
#endif
}