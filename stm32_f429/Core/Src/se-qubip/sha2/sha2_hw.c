/**
 * @file sha2_hw.c
 * @brief SHA2 Test File
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

#include "sha2_hw.h"

void sha_256_hw_func(unsigned char *in, unsigned int length, unsigned char *out,
		INTF interface) {
	sha2_hw(interface, in, out, length * 8, MODE_SHA_2_256, 0);

	// printf("\ndata_in = 0x");
	// for (int i = 0; i < length; i++) printf("%02x", in[i]);
	// printf("\ndata_out = 0x");
	// for (int i = 0; i < SHA_2_256_DIGEST_LENGTH; i++) printf("%02x", out[i]);
}

void sha_384_hw_func(unsigned char *in, unsigned int length, unsigned char *out,
		INTF interface) {
	sha2_hw(interface, in, out, length * 8, MODE_SHA_2_384, 0);

	// printf("\ndata_in = 0x");
	// for (int i = 0; i < length; i++) printf("%02x", in[i]);
	// printf("\ndata_out = 0x");
	// for (int i = 0; i < SHA_2_384_DIGEST_LENGTH; i++) printf("%02x", out[i]);
}

void sha_512_hw_func(unsigned char *in, unsigned int length, unsigned char *out,
		INTF interface) {
	sha2_hw(interface, in, out, length * 8, MODE_SHA_2_512, 0);

	// printf("\ndata_in = 0x");
	// for (int i = 0; i < length; i++) printf("%02x", in[i]);
	// printf("\ndata_out = 0x");
	// for (int i = 0; i < SHA_2_512_DIGEST_LENGTH; i++) printf("%02x", out[i]);
}

void sha_512_256_hw_func(unsigned char *in, unsigned int length,
		unsigned char *out, INTF interface) {
	sha2_hw(interface, in, out, length * 8, MODE_SHA_2_512_256, 0);

	// printf("\ndata_in = 0x");
	// for (int i = 0; i < length; i++) printf("%02x", in[i]);
	// printf("\ndata_out = 0x");
	// for (int i = 0; i < SHA_2_256_DIGEST_LENGTH; i++) printf("%02x", out[i]);
}

void sha2_hw(INTF interface, unsigned char *in, unsigned char *out,
		unsigned long long int length, unsigned int VERSION, int DBG) {
	//-- se_code = { {(32'b) 64-bit data_packages}, {12'b0}, {SHAKE-256, SHAKE-128, SHA-3-512, SHA-3-256}, {(16'b)SHA-3} }
	uint64_t control = 0;
	while (control != CMD_SE_CODE) {
		picorv32_control(interface, &control);
	}
	const uint8_t sha_2_code = SHA_2_SE_CODE;
	uint16_t sha_2_op_sel = (uint16_t) VERSION;

	uint64_t se_code = ((uint32_t) sha_2_op_sel << 16) + sha_2_code;
	write_INTF(interface, &se_code, PICORV32_DATA_IN, AXI_BYTES);

	// ------- Number of hash blocks ----- //
	uint64_t op_version;

	if (VERSION == 1)
		op_version = 0 << 2; // SHA-256
	else if (VERSION == 2)
		op_version = 1 << 2; // SHA-384
	else if (VERSION == 3)
		op_version = 2 << 2; // SHA-512
	else if (VERSION == 4)
		op_version = 3 << 2; // SHA-512/256
	else
		op_version = 0 << 2;

	unsigned int size_len;
	if (!op_version)
		size_len = 64;
	else
		size_len = 128;

	unsigned int block_size;
	if (!op_version)
		block_size = 512;
	else
		block_size = 1024;

	unsigned int out_packages;
	if (VERSION == 1)
		out_packages = SHA_2_256_DIGEST_LENGTH / 8 * 2;     // SHA-256
	else if (VERSION == 2)
		out_packages = SHA_2_384_DIGEST_LENGTH / 8;         // SHA-384
	else if (VERSION == 3)
		out_packages = SHA_2_512_DIGEST_LENGTH / 8;         // SHA-512
	else if (VERSION == 4)
		out_packages = SHA_2_256_DIGEST_LENGTH / 8;         // SHA-512/256
	else
		out_packages = 0;

	uint64_t hb_num =
			(unsigned long long int) ((length + size_len) / block_size) + 1; //3 bits for padding

	if (DBG == 1) {
		printf("\n hb_num = %ld", hb_num);
		printf("\n length = %lld", length);
	}

	unsigned char *buffer_in;
	unsigned char *buffer_out;
	unsigned char buffer_256[8] = { 0 };

	buffer_in = (unsigned char*) pvPortMalloc(hb_num * block_size / 8);
	buffer_out = (unsigned char*) pvPortMalloc(out_packages * 8);
	memset(buffer_in, 0, hb_num * block_size / 8);
	memcpy(buffer_in, in, length / 8);

	// printf("\nbuffer_in = 0x");
	// for (int i = 0; i < hb_num * block_size / 8; i++) printf("%02x", buffer_in[i]);
	// fflush(stdout);

	//-- Send Length in bits
	while (control != CMD_SE_WRITE) {
		picorv32_control(interface, &control);
	}
	write_INTF(interface, &length, PICORV32_DATA_IN, AXI_BYTES);

	// ------- Send Data --------//
	uint32_t packages_2_write = 0;
	uint32_t packages_sent = 0;

	uint64_t SIZE_BLOCK_PACKAGES = 1024 / 64;
	uint64_t hb_packages = hb_num * SIZE_BLOCK_PACKAGES;
	uint64_t max_fifo_hb_packages = (127 / SIZE_BLOCK_PACKAGES)
			* SIZE_BLOCK_PACKAGES;

	while (hb_packages != 0) {
		if (hb_packages > max_fifo_hb_packages) {
			packages_2_write = max_fifo_hb_packages;
		} else {
			packages_2_write = hb_packages;
		}

		// printf("\npackages_2_write = %d", packages_2_write);
		// fflush(stdout);

		picorv32_control(interface, &control);
		while (control != CMD_SE_WRITE) {
			picorv32_control(interface, &control);
		}

		if (!op_version) {
			for (int i = 0; i < packages_2_write; i++) {
				buffer_256[4] = buffer_in[0
						+ (i + packages_sent) * (AXI_BYTES / 2)];
				buffer_256[5] = buffer_in[1
						+ (i + packages_sent) * (AXI_BYTES / 2)];
				buffer_256[6] = buffer_in[2
						+ (i + packages_sent) * (AXI_BYTES / 2)];
				buffer_256[7] = buffer_in[3
						+ (i + packages_sent) * (AXI_BYTES / 2)];
				write_INTF(interface, buffer_256, PICORV32_DATA_IN, AXI_BYTES);
			}
		} else {
			for (int i = 0; i < packages_2_write; i++) {
				write_INTF(interface,
						buffer_in + (i + packages_sent) * AXI_BYTES,
						PICORV32_DATA_IN, AXI_BYTES);
			}
		}

		hb_packages -= packages_2_write;
		packages_sent += packages_2_write;

		// printf("\nhb_packages = %d", hb_packages);
		// fflush(stdout);

		while ((control != CMD_SE_READ) & (control != CMD_SE_WAIT)) {
			picorv32_control(interface, &control);
			if (control == CMD_SE_WAIT)
				read_INTF(interface, out, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
		}

		if ((control == CMD_SE_READ) || (hb_packages == 0)) {
			while (control != CMD_SE_READ) {
				picorv32_control(interface, &control);
			}
			if (!op_version) {
				for (int i = 0; i < out_packages; i++) {
					read_INTF(interface, buffer_256, PICORV32_DATA_OUT,
							AXI_BYTES);
					memcpy(buffer_out + i * (AXI_BYTES / 2), buffer_256 + 4, 4);
				}
			} else {
				for (int i = 0; i < out_packages; i++) {
					read_INTF(interface, buffer_out + i * AXI_BYTES,
							PICORV32_DATA_OUT, AXI_BYTES);
				}
			}
		}
	}

	if (!op_version)
		memcpy(out, buffer_out, out_packages * 4);
	else
		memcpy(out, buffer_out, out_packages * 8);

	while (control != CMD_SE_CODE) {
		picorv32_control(interface, &control);
	}
}
