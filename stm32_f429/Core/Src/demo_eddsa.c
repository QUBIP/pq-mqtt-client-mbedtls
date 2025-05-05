/**
 * @file demo_eddsa.c
 * @brief EDDSA Validation Test Code
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
#include "crypto_api_sw.h"

void demo_eddsa_hw(unsigned int mode, unsigned int verb, INTF interface) {

#ifdef AXI
	unsigned int clk_index = 0;
	float clk_frequency;
	float set_clk_frequency = FREQ_EDDSA;
    Set_Clk_Freq(clk_index, &clk_frequency, &set_clk_frequency, (int) verb);
#endif

	// ---- EDDSA ---- //
	if (mode == 25519) {
		unsigned char *pub_key;
		unsigned char *pri_key;
		unsigned int pub_len;
		unsigned int pri_len;

		eddsa25519_genkeys_hw(&pri_key, &pub_key, &pri_len, &pub_len,
				interface);

		if (verb >= 2)
			printf("\n pub_len: %d (bytes)", pub_len);
		if (verb >= 2)
			printf("\n pri_len: %d (bytes)", pri_len);

		if (verb >= 3) {
			printf("\n public key: ");
			show_array(pub_key, pub_len, 32);
		}
		if (verb >= 3) {
			printf("\n private key: ");
			show_array(pri_key, pri_len, 32);
		}

		unsigned char msg[] = "Hello, this is the SE of QUBIP project";

		unsigned char *sig;
		unsigned int sig_len;

		//EDDSA25519_SIGN(
		/*
		 const unsigned char* msg,
		 const unsigned int msg_len,
		 const unsigned char* pri_key,
		 const unsigned int pri_len,
		 unsigned char** sig,
		 unsigned int* sig_len)
		 */
		eddsa25519_sign(msg, strlen((const char*) msg), pri_key, pri_len, &sig, &sig_len);


		//eddsa25519_sign_hw(msg, strlen((const char*) msg), pri_key, pri_len, pub_key, pub_len, &sig, &sig_len, interface);

		if (verb >= 3) {
			printf("\n signature: ");
			show_array(sig, sig_len, 32);
		}

		unsigned int result;

		eddsa25519_verify_hw(msg, strlen((const char*) msg), pub_key, pub_len,
				sig, 64, &result, interface);
		print_result_valid("EdDSA-25519 HW", !result);

		/*
		 * Software
		 void EDDSA25519_VERIFY(
		 const unsigned char* msg,
		 const unsigned int msg_len,
		 const unsigned char* pub_key,
		 const unsigned int pub_len,
		 const unsigned char* sig,
		 const unsigned int sig_len,
		 unsigned int* result)

		 */

		// eddsa25519_verify(msg, strlen((const char*) msg), pub_key, pub_len, sig, 64, &result);
		// print_result_valid("EdDSA-25519 SW", !result);
	} else {
		/*
		 unsigned char* pub_key;
		 unsigned char* pri_key;
		 unsigned int pub_len;
		 unsigned int pri_len;

		 eddsa448_genkeys(&pri_key, &pub_key, &pri_len, &pub_len);

		 if (verb >= 2) printf("\n pub_len: %d (bytes)", pub_len);
		 if (verb >= 2) printf("\n pri_len: %d (bytes)", pri_len);

		 if (verb >= 3) { printf("\n public key: ");   show_array(pub_key, pub_len, 32); }
		 if (verb >= 3) { printf("\n private key: "); show_array(pri_key, pri_len, 32); }


		 unsigned char msg[50] = "Hello, this is the SE of QUBIP project";

		 unsigned char* sig;
		 unsigned int sig_len;
		 eddsa448_sign(msg, strlen(msg), (const unsigned char*)pri_key, pri_len, &sig, &sig_len);

		 if (verb >= 3) { printf("\n signature: ");   show_array(sig, sig_len, 32); }

		 unsigned int result = 1;
		 eddsa448_verify(msg, strlen(msg), (const unsigned char*)pub_key, pub_len, (const unsigned char*)sig, sig_len, &result);

		 print_result_valid("EdDSA-448", result);
		 */
	}
#ifdef AXI
    set_clk_frequency = FREQ_TYPICAL;
    Set_Clk_Freq(clk_index, &clk_frequency, &set_clk_frequency, (int)verb);
#endif
}
