/**
 * @file sha3_shake_hw.c
 * @brief SHA3 SHAKE Test File
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

#include "sha3_shake_hw.h"

void sha3_256_hw_func(unsigned char *in, unsigned int length,
		unsigned char *out, INTF interface) {
	sha3_shake_hw(in, out, length * 8, SHA_3_256_LEN_OUT, MODE_SHA_3_256,
			SHA_3_256_SIZE_BLOCK, interface, 0);

	// printf("\ndata_in = 0x");
	// for (int i = 0; i < length; i++) printf("%02x", in[i]);
	// printf("\ndata_out = 0x");
	// for (int i = 0; i < SHA_3_256_LEN_OUT / 8; i++) printf("%02x", out[i]);
}

void sha3_512_hw_func(unsigned char *in, unsigned int length,
		unsigned char *out, INTF interface) {
	sha3_shake_hw(in, out, length * 8, SHA_3_512_LEN_OUT, MODE_SHA_3_512,
			SHA_3_512_SIZE_BLOCK, interface, 0);

	// printf("\ndata_in = 0x");
	// for (int i = 0; i < length; i++) printf("%02x", in[i]);
	// printf("\ndata_out = 0x");
	// for (int i = 0; i < SHA_3_512_LEN_OUT / 8; i++) printf("%02x", out[i]);
}

void shake128_hw_func(unsigned char *in, unsigned int length,
		unsigned char *out, unsigned int length_out, INTF interface) {
	sha3_shake_hw(in, out, length * 8, length_out * 8, MODE_SHAKE_128,
			SHAKE_128_SIZE_BLOCK, interface, 0);

	// printf("\ndata_in = 0x");
	// for (int i = 0; i < length; i++) printf("%02x", in[i]);
	// printf("\ndata_out = 0x");
	// for (int i = 0; i < length_out; i++) printf("%02x", out[i]);
}

void shake256_hw_func(unsigned char *in, unsigned int length,
		unsigned char *out, unsigned int length_out, INTF interface) {
	sha3_shake_hw(in, out, length * 8, length_out * 8, MODE_SHAKE_256,
			SHAKE_256_SIZE_BLOCK, interface, 0);

	// printf("\ndata_in = 0x");
	// for (int i = 0; i < length; i++) printf("%02x", in[i]);
	// printf("\ndata_out = 0x");
	// for (int i = 0; i < length_out; i++) printf("%02x", out[i]);
}

void sha3_shake_hw(unsigned char *in, unsigned char *out, unsigned int length,
		unsigned int length_out, int VERSION, int SIZE_BLOCK, INTF interface,
		int DBG) {
	//-- se_code = { {(32'b) 64-bit data_packages}, {12'b0}, {SHAKE-256, SHAKE-128, SHA-3-512, SHA-3-256}, {(16'b)SHA-3} }
	uint64_t control = 0;
	while (control != CMD_SE_CODE) {
		picorv32_control(interface, &control);
	}
	const uint8_t sha_3_code = SHA_3_SE_CODE;
	uint16_t sha_3_op_sel = (uint16_t) VERSION;

	uint64_t se_code = ((uint32_t) sha_3_op_sel << 16) + sha_3_code;
	write_INTF(interface, &se_code, PICORV32_DATA_IN, AXI_BYTES);

	// ------- Number of hash blocks and Padding ----- //
	uint32_t hb_num = (length / SIZE_BLOCK) + 1;
	uint32_t hb_num_out = (length_out / SIZE_BLOCK) + 1;
	uint32_t pos_pad = (length % SIZE_BLOCK) / 8;

	unsigned char *buffer_in;
	unsigned char *buffer_out;

	buffer_in = (unsigned char*) malloc(hb_num * SIZE_BLOCK / 8);
	buffer_out = (unsigned char*) malloc(hb_num_out * SIZE_BLOCK / 8);
	memset(buffer_in, 0, hb_num * SIZE_BLOCK / 8);
	memcpy(buffer_in, in, length / 8);

	if (DBG == 1) {
		printf("\n hb_num \t= %d", hb_num);
		printf("\n hb_num_out \t= %d", hb_num_out);
		printf("\n length \t= %d", length);
		printf("\n length_out \t= %d", length_out);
		printf("\n pos_pad \t= %d\n", pos_pad);
	}

	//-- Send number of Hash Blocks
	while (control != CMD_SE_WRITE) {
		picorv32_control(interface, &control);
	}
	write_INTF(interface, &hb_num, PICORV32_DATA_IN, AXI_BYTES);

	while (control != CMD_SE_WAIT) {
		picorv32_control(interface, &control);
	}
	write_INTF(interface, &length_out, PICORV32_DATA_IN, AXI_BYTES);

	while (control != CMD_SE_WRITE) {
		picorv32_control(interface, &control);
	}
	write_INTF(interface, &pos_pad, PICORV32_DATA_IN, AXI_BYTES);

	// ------- Send Data --------//
	uint32_t packages_2_write = 0;
	uint32_t packages_sent = 0;

	uint64_t SIZE_BLOCK_PACKAGES = SIZE_BLOCK / 64;
	uint64_t hb_packages = hb_num * SIZE_BLOCK_PACKAGES;
	// uint64_t hb_out_packages		= hb_num_out * SIZE_BLOCK_PACKAGES;
	uint64_t out_packages = length_out / 64 + 1;
	uint64_t max_fifo_hb_packages = (128 / SIZE_BLOCK_PACKAGES)
			* SIZE_BLOCK_PACKAGES;

	/* printf("\nSIZE_BLOCK_PACKAGES = %d", SIZE_BLOCK_PACKAGES);
	 printf("\nhb_packages = %d", hb_packages);
	 printf("\nout_packages = %d", out_packages);
	 printf("\nmax_fifo_hb_packages = %d", max_fifo_hb_packages);
	 fflush(stdout); */

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

		for (int i = 0; i < packages_2_write; i++) {
			write_INTF(interface, buffer_in + (i + packages_sent) * AXI_BYTES,
					PICORV32_DATA_IN, AXI_BYTES);
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

		if ((control == CMD_SE_READ) || (hb_packages == 0 && hb_num_out == 1)) {
			while (control != CMD_SE_READ) {
				picorv32_control(interface, &control);
			}
			for (int i = 0; i < out_packages; i++) {
				read_INTF(interface, buffer_out + i * AXI_BYTES,
						PICORV32_DATA_OUT, AXI_BYTES);
			}
		}
	}

	// ------- Continue reading if SHAKE --------//
	uint32_t packages_2_read = 0;
	uint32_t packages_received = 0;
	if (hb_num_out > 1) {
		while (out_packages != 0) {
			if (out_packages > max_fifo_hb_packages) {
				packages_2_read = max_fifo_hb_packages;
			} else {
				packages_2_read = out_packages;
			}

			picorv32_control(interface, &control);
			while (control != CMD_SE_READ) {
				picorv32_control(interface, &control);
				if (control == CMD_SE_WAIT)
					read_INTF(interface, out, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
			}

			for (int i = 0; i < packages_2_read; i++) {
				read_INTF(interface,
						buffer_out + (i + packages_received) * AXI_BYTES,
						PICORV32_DATA_OUT, AXI_BYTES);
				// printf("\nbuffer_out = 0x");
				// for (int j = 0; j < AXI_BYTES; j++) printf("%02x", *(buffer_out + (i + packages_received) * AXI_BYTES + j));
			}

			out_packages -= packages_2_read;
			packages_received += packages_2_read;

			packages_2_read = 0;
		}

	}

	memcpy(out, buffer_out, length_out / 8);

	while (control != CMD_SE_CODE) {
		picorv32_control(interface, &control);
	}

	free(buffer_in);
	free(buffer_out);
}
