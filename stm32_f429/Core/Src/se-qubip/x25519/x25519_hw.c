/**
 * @file x25519_hw.c
 * @brief X25519 Test File
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

////////////////////////////////////////////////////////////////////////////////////
// Company: IMSE-CNM CSIC
// Engineer: Pablo Navarro Torrero
//
// Create Date: 01/07/2025
// File Name: x25519_hw.c
// Project Name: SE-QUBIP
// Target Devices: PYNQ-Z2
// Description:
//
//		X25519 HW Handler Functions
//
////////////////////////////////////////////////////////////////////////////////////
#include "x25519_hw.h"

/////////////////////////////////////////////////////////////////////////////////////////////
// GENERATE PUBLIC KEY
/////////////////////////////////////////////////////////////////////////////////////////////

void x25519_genkeys_hw(unsigned char **pri_key, unsigned char **pub_key,
		unsigned int *pri_len, unsigned int *pub_len, bool ext_key,
		uint8_t *key_id, INTF interface) {
	//-- Generate a random private key
	*pri_len = X25519_BYTES;
	*pub_len = X25519_BYTES;

	*pri_key = (unsigned char*) pvPortMalloc(*pri_len);
	*pub_key = (unsigned char*) pvPortMalloc(*pub_len);

	if (ext_key) {
		gen_priv_key(*pri_key, *pri_len);
	} else {
		uint8_t key[64];
		secmem_get_key(ID_X25519, *key_id, key, interface);
		memcpy(*pri_key, key, 32);
	}

	// unsigned char test_x25519[32] = {0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a};

	/* static int counter = 0;

	 unsigned char test_x25519_A[32] = {0x5C, 0xAF, 0x7B, 0x42, 0xBD, 0xCC, 0xFF, 0x54, 0xBC, 0x0B, 0x6B, 0x9B, 0x18, 0xAA, 0x58, 0xC3, 0xD1, 0xC0, 0xDE, 0x15, 0xF0, 0x60, 0xA1, 0xDF, 0x5A, 0x34, 0xBA, 0xA1, 0xA1, 0x84, 0x34, 0x9B};
	 unsigned char test_x25519_B[32] = {0x3D, 0xBA, 0x85, 0xFC, 0x8E, 0xAC, 0xF3, 0xDD, 0x0E, 0x8F, 0xC4, 0x01, 0x97, 0x46, 0x84, 0x6C, 0x46, 0xD5, 0x7B, 0xBA, 0x48, 0x3E, 0xB7, 0xAC, 0x04, 0xAA, 0x2F, 0x7C, 0x6B, 0x43, 0xCF, 0xE8};

	 if (counter == 0) memcpy(*pri_key, test_x25519_A, 32);
	 else memcpy(*pri_key, test_x25519_B, 32);

	 counter++;
	 */

	/*
	 printf("Private = 0x");
	 for (int i = 0; i < X25519_BYTES; i++)
	 {
	 printf("%02x", *(*pri_key + i));
	 }
	 printf("\n");
	 */

	//-- se_code = { {(32'b) 64-bit data_packages}, {14'b0}, {x25519_ss_gen, x25519_genkeys}, {(16'b)X25519} }
	uint64_t control = 0;
	while (control != CMD_SE_CODE) {
		picorv32_control(interface, &control);
	}
	uint16_t x25519_op_sel = ((uint16_t) !ext_key << 15)
			| ((uint16_t) (*key_id << 9)) | 1;
	uint64_t se_code = ((uint32_t) x25519_op_sel << 16) | ECDH_SE_CODE;
	write_INTF(interface, &se_code, PICORV32_DATA_IN, AXI_BYTES);

	//-- Send Private Key
	if (ext_key) {
		while (control != CMD_SE_WRITE) {
			picorv32_control(interface, &control);
		}
		for (int i = X25519_BYTES / AXI_BYTES - 1; i >= 0; i--) {
			write_INTF(interface, *pri_key + i * AXI_BYTES, PICORV32_DATA_IN,
					AXI_BYTES);
		}
	}

	//-- Read Private Key
	while (control != CMD_SE_READ) {
		picorv32_control(interface, &control);
	}
	for (int i = X25519_BYTES / AXI_BYTES - 1; i >= 0; i--) {
		read_INTF(interface, *pub_key + i * AXI_BYTES, PICORV32_DATA_OUT,
				AXI_BYTES);
	}

	while (control != CMD_SE_CODE) {
		picorv32_control(interface, &control);
	}
}

/////////////////////////////////////////////////////////////////////////////////////////////
// X25519 ECDH
/////////////////////////////////////////////////////////////////////////////////////////////

void x25519_ss_gen_hw(unsigned char **shared_secret,
		unsigned int *shared_secret_len, unsigned char *pub_key,
		unsigned int pub_len, unsigned char *pri_key, unsigned int pri_len,
		bool ext_key, uint8_t *key_id, INTF interface) {

	pub_len = X25519_BYTES;
	pri_len = X25519_BYTES;
	*shared_secret_len = X25519_BYTES;

	*shared_secret = (unsigned char*) pvPortMalloc(*shared_secret_len);

	//-- se_code = { {(32'b) 64-bit data_packages}, {14'b0}, {x25519_ss_gen, x25519_genkeys}, {(16'b)X25519} }
	uint64_t control = 0;
	while (control != CMD_SE_CODE) {
		picorv32_control(interface, &control);
	}
	uint16_t x25519_op_sel = ((uint16_t) !ext_key << 15)
			| ((uint16_t) (*key_id << 9)) | 2;
	uint64_t se_code = ((uint32_t) x25519_op_sel << 16) | ECDH_SE_CODE;
	write_INTF(interface, &se_code, PICORV32_DATA_IN, AXI_BYTES);

	//-- Send Private Key
	if (ext_key) {
		while (control != CMD_SE_WRITE) {
			picorv32_control(interface, &control);
		}
		for (int i = X25519_BYTES / AXI_BYTES - 1; i >= 0; i--) {
			write_INTF(interface, pri_key + i * AXI_BYTES, PICORV32_DATA_IN,
					AXI_BYTES);
		}
	}

	while (control != CMD_SE_WRITE) {
		picorv32_control(interface, &control);
	}

	//-- Send Public Key
	for (int i = X25519_BYTES / AXI_BYTES - 1; i >= 0; i--) {
		write_INTF(interface, pub_key + i * AXI_BYTES, PICORV32_DATA_IN,
				AXI_BYTES);
	}

	//-- Read Shared Secret
	while (control != CMD_SE_READ) {
		picorv32_control(interface, &control);
	}
	for (int i = X25519_BYTES / AXI_BYTES - 1; i >= 0; i--) {
		read_INTF(interface, *shared_secret + i * AXI_BYTES, PICORV32_DATA_OUT,
				AXI_BYTES);
	}

	while (control != CMD_SE_CODE) {
		picorv32_control(interface, &control);
	}
}

