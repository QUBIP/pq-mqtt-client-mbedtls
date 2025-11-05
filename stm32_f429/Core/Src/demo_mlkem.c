/**
  * @file  demo_mlkem.c
  * @brief Validation Test for MLKEM Code
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

void demo_mlkem_hw(unsigned int mode, unsigned int verb, INTF interface) {

#ifdef AXI
    unsigned int clk_index = 0;
    float clk_frequency;
    float set_clk_frequency = FREQ_MLKEM;
    Set_Clk_Freq(clk_index, &clk_frequency, &set_clk_frequency, (int)verb);
#endif

    bool is_external    = false;
    uint8_t key_id_1    = 0;
    uint8_t key_id_2    = 0;
    uint8_t key_id_3    = 0;

    /* unsigned char* char_seed_test = "1EB4400A01629D517974E2CD85B9DEF59082DE508E6F9C2B0E341E12965955CA";
    unsigned char seed_test[32]; char2hex(char_seed_test, seed_test); */

    if (mode == 512) {

        if (!is_external)
	    {
	    	secmem_store_key(ID_MLKEM, &key_id_1, is_external, NULL, 0, interface);
            // secmem_store_key(ID_MLKEM, &key_id_1, 1, seed_test, 32, interface);      // Test specific Key
	    }

        // ---- MLKEM-512 ---- //
        unsigned char *pk_512;
		unsigned char *sk_512;

		pk_512 = malloc(800);
		sk_512 = malloc(1632);

		mlkem512_genkeys_hw(pk_512, sk_512, is_external, &key_id_1, interface);

        if (verb >= 3) printf("\n pub_len: %d (bytes)", 800);
        if (verb >= 3) printf("\n pri_len: %d (bytes)", 1632);

        if (verb >= 3) { printf("\n public key: ");     show_array(pk_512, 800, 32); }
        if (verb >= 3) { printf("\n private key: ");    show_array(sk_512, 1632, 32); }

        unsigned char ss[32];
		unsigned char *ct_512;
		ct_512 = malloc(768);

		mlkem512_enc_hw(pk_512, ct_512, ss, interface);

        if (verb >= 3) printf("\n ss_len: %d (bytes)", 32);
        if (verb >= 3) printf("\n ct_len: %d (bytes)", 768);

        if (verb >= 1) { printf("\n ss: ");    show_array(ss, 32, 32); }
        if (verb >= 2) { printf("\n ct: ");    show_array(ct_512, 768, 32); }

        unsigned char ss1[32];
		unsigned int result;

		mlkem512_dec_hw(sk_512, ct_512, ss1, &result, is_external, &key_id_1, interface);

        if (verb >= 3) printf("\n ss1_len: %d (bytes)", 32);
        if (verb >= 1) { printf("\n ss1: ");    show_array(ss1, 32, 32); }

        print_result_valid("MLKEM-512", !(result >> 1)); // 01: bad result; 11: good result

        free(sk_512);
		free(pk_512);
		free(ct_512);

    }
    else if (mode == 768) {

        if (!is_external)
	    {
	    	secmem_store_key(ID_MLKEM, &key_id_2, is_external, NULL, 0, interface);
            // secmem_store_key(ID_MLKEM, &key_id_2, 1, seed_test, 32, interface);
	    }

        // ---- MLKEM-768 ---- //
        unsigned char* pk_768;
		unsigned char* sk_768;

		pk_768 = malloc(1184);
		sk_768 = malloc(2400);

		mlkem768_genkeys_hw(pk_768, sk_768, is_external, &key_id_2, interface);

        if (verb >= 3) printf("\n pub_len: %d (bytes)", 1184);
        if (verb >= 3) printf("\n pri_len: %d (bytes)", 2400);

        if (verb >= 3) { printf("\n public key: ");     show_array(pk_768, 1184, 32); }
        if (verb >= 3) { printf("\n private key: ");    show_array(sk_768, 2400, 32); }

        unsigned char ss[32];
		unsigned char* ct_768;
		ct_768 = malloc(1088);

		mlkem768_enc_hw(pk_768, ct_768, ss, interface);

        if (verb >= 3) printf("\n ss_len: %d (bytes)", 32);
        if (verb >= 3) printf("\n ct_len: %d (bytes)", 1088);

        if (verb >= 1) { printf("\n ss: ");    show_array(ss, 32, 32); }
        if (verb >= 2) { printf("\n ct: ");    show_array(ct_768, 1088, 32); }

        unsigned char ss1[32];
		unsigned int result = 0;

		mlkem768_dec_hw(sk_768, ct_768, ss1, &result, is_external, &key_id_2, interface);

        if (verb >= 3) printf("\n ss1_len: %d (bytes)", 32);
        if (verb >= 1) { printf("\n ss1: ");    show_array(ss1, 32, 32); }

        print_result_valid("MLKEM-768", !(result >> 1)); // 01: bad result; 11: good result

        free(sk_768);
		free(pk_768);
		free(ct_768);
    
    }
    else {

        if (!is_external)
	    {
	    	secmem_store_key(ID_MLKEM, &key_id_3, is_external, NULL, 0, interface);
            // secmem_store_key(ID_MLKEM, &key_id_3, 1, seed_test, 32, interface);
	    }

        // ---- MLKEM-1024 ---- //
        unsigned char* pk_1024;
		unsigned char* sk_1024;

		pk_1024 = malloc(1568);
		sk_1024 = malloc(3168);

		mlkem1024_genkeys_hw(pk_1024, sk_1024, is_external, &key_id_3, interface);

        if (verb >= 3) printf("\n pub_len: %d (bytes)", 1568);
        if (verb >= 3) printf("\n pri_len: %d (bytes)", 3168);

        if (verb >= 3) { printf("\n public key: ");     show_array(pk_1024, 1568, 32); }
        if (verb >= 3) { printf("\n private key: ");    show_array(sk_1024, 3168, 32); }

        unsigned char ss[32];
		unsigned char* ct_1024;
		ct_1024 = malloc(1568);

		mlkem1024_enc_hw(pk_1024, ct_1024, ss, interface);

        if (verb >= 3) printf("\n ss_len: %d (bytes)", 32);
        if (verb >= 3) printf("\n ct_len: %d (bytes)", 1568);

        if (verb >= 1) { printf("\n ss: ");    show_array(ss, 32, 32); }
        if (verb >= 2) { printf("\n ct: ");    show_array(ct_1024, 1568, 32); }

        unsigned char ss1[32];
		unsigned int result = 0;

		mlkem1024_dec_hw(sk_1024, ct_1024, ss1, &result, is_external, &key_id_3, interface);

        if (verb >= 3) printf("\n ss1_len: %d (bytes)", 32);
        if (verb >= 1) { printf("\n ss1: ");    show_array(ss1, 32, 32); }

        print_result_valid("MLKEM-1024", !(result >> 1)); // 01: bad result; 11: good result

        free(sk_1024);
		free(pk_1024);
		free(ct_1024);

    }

#ifdef AXI
    set_clk_frequency = FREQ_TYPICAL;
    Set_Clk_Freq(clk_index, &clk_frequency, &set_clk_frequency, (int)verb);
#endif

}