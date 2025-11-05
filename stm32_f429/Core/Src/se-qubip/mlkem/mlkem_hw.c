/**
 * @file mlkem_hw.c
 * @brief MLKEM Test File
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
#include "mlkem_hw.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>


static void randombytes(uint8_t* out, size_t outlen) {

	srand(HAL_GetTick());

	for (int i = 0; i < outlen; i++) {
		out[i] = (uint8_t)rand();
	}
}



void mlkem_512_gen_keys_hw(unsigned char *pk, unsigned char *sk, bool ext_key,
		uint8_t *key_id, INTF interface) {

	mlkem_gen_keys_hw(2, pk, sk, ext_key, key_id, interface);

}
void mlkem_768_gen_keys_hw(unsigned char *pk, unsigned char *sk, bool ext_key,
		uint8_t *key_id, INTF interface) {

	mlkem_gen_keys_hw(3, pk, sk, ext_key, key_id, interface);

}
void mlkem_1024_gen_keys_hw(unsigned char *pk, unsigned char *sk, bool ext_key,
		uint8_t *key_id, INTF interface) {

	mlkem_gen_keys_hw(4, pk, sk, ext_key, key_id, interface);

}

void mlkem_512_enc_hw(unsigned char *pk, unsigned char *ct, unsigned char *ss,
		INTF interface) {

	mlkem_enc_hw(2, pk, ct, ss, interface);

}
void mlkem_768_enc_hw(unsigned char *pk, unsigned char *ct, unsigned char *ss,
		INTF interface) {

	mlkem_enc_hw(3, pk, ct, ss, interface);

}
void mlkem_1024_enc_hw(unsigned char *pk, unsigned char *ct, unsigned char *ss,
		INTF interface) {

	mlkem_enc_hw(4, pk, ct, ss, interface);

}

void mlkem_512_dec_hw(unsigned char *sk, unsigned char *ct, unsigned char *ss,
		unsigned int *result, bool ext_key, uint8_t *key_id, INTF interface) {

	mlkem_dec_hw(2, sk, ct, ss, result, ext_key, key_id, interface);

}
void mlkem_768_dec_hw(unsigned char *sk, unsigned char *ct, unsigned char *ss,
		unsigned int *result, bool ext_key, uint8_t *key_id, INTF interface) {

	mlkem_dec_hw(3, sk, ct, ss, result, ext_key, key_id, interface);

}
void mlkem_1024_dec_hw(unsigned char *sk, unsigned char *ct, unsigned char *ss,
		unsigned int *result, bool ext_key, uint8_t *key_id, INTF interface) {

	mlkem_dec_hw(4, sk, ct, ss, result, ext_key, key_id, interface);

}

void mlkem_gen_keys_hw(int k, unsigned char *pk, unsigned char *sk,
		bool ext_key, uint8_t *key_id, INTF interface) {
	//-- Generate random
	unsigned long long int d64[4];
	unsigned long long int z64[4];

	if (ext_key) {
		uint8_t d[32];
		uint8_t z[32];
		randombytes(d, 32);
		memcpy(d64, d, 32);
		randombytes(z, 32);
		memcpy(z64, z, 32);

		/* d64[0] = 0x519d62010a40b41e;
		 d64[1] = 0xf5deb985cde27479;
		 d64[2] = 0x2b9c6f8e50de8290;
		 d64[3] = 0xca555996121e340e;

		 z64[0] = 0xfe0338161141391a;
		 z64[1] = 0x7586a635c319852e;
		 z64[2] = 0x5f2ba2afad8e3356;
		 z64[3] = 0x93d6cc60054357c5; */
	}

	//-- se_code = { {(32'b) 64-bit data_packages}, {10'b0}, {k = 4, k = 3, k = 2, DEC, ENC, KEY_GEN}, {(16'b)MLKEM} }
	uint64_t next_block = 0;
	uint64_t control = 0;
	while (control != CMD_SE_CODE) {
		picorv32_control(interface, &control);
	}
	const uint8_t mlkem_code = MLKEM_SE_CODE;
	uint16_t mlkem_op_sel = ((uint16_t) !ext_key << 15)
			| ((uint16_t) (*key_id << 9)) | (1 << (k + 1)) | (1 << 0);

	uint64_t se_code = ((uint32_t) mlkem_op_sel << 16) + mlkem_code;
	write_INTF(interface, &se_code, PICORV32_DATA_IN, AXI_BYTES);

	uint32_t LEN_EK;					// Bytes
	uint32_t LEN_DK;					// Bytes
	uint32_t LEN_EK_packages;			// Packages of 64-bit
	uint32_t LEN_DK_packages;			// Packages of 64-bit
	uint32_t LEN_EK_blocks;				// Blocks of #FIFO_DEPTH-1 * 64-bit
	uint32_t LEN_DK_blocks;				// Blocks of #FIFO_DEPTH-1 * 64-bit
	uint32_t LEN_EK_rem;				// Remaining packages of 64-bit
	uint32_t LEN_DK_rem;				// Remaining packages of 64-bit

	//-- k = 2
	if (k == 2) {
		LEN_EK = 800;
		LEN_DK = 1632;
	}
	//-- k = 3
	else if (k == 3) {
		LEN_EK = 1184;
		LEN_DK = 2400;
	}
	//-- k = 4
	else if (k == 4) {
		LEN_EK = 1568;
		LEN_DK = 3168;
	} else {
		LEN_EK = 800;
		LEN_DK = 1632;
	}

	LEN_EK_packages = LEN_EK >> 3;
	LEN_DK_packages = LEN_DK >> 3;
	LEN_EK_blocks = LEN_EK_packages / (FIFO_OUT_DEPTH - 2);
	LEN_DK_blocks = LEN_DK_packages / (FIFO_OUT_DEPTH - 2);
	LEN_EK_rem = LEN_EK_packages % (FIFO_OUT_DEPTH - 2);
	LEN_DK_rem = LEN_DK_packages % (FIFO_OUT_DEPTH - 2);

	if (ext_key) {
		while (control != CMD_SE_WRITE) {
			picorv32_control(interface, &control);
		}

		//-- Send seed (d)
		for (int i = 0; i < 4; i++) {
			write_INTF(interface, d64 + i, PICORV32_DATA_IN, AXI_BYTES);
		}

		//-- Send seed z
		for (int i = 0; i < 4; i++) {
			write_INTF(interface, z64 + i, PICORV32_DATA_IN, AXI_BYTES);
		}
	}

	//-- Read sk
	uint32_t packages_read = 0;
	for (int i = 0; i < LEN_DK_blocks; i++) {
		while (control != CMD_SE_READ) {
			picorv32_control(interface, &control);
		}

		for (int j = 0; j < FIFO_OUT_DEPTH - 2; j++) {
			read_INTF(interface, sk + (j + packages_read) * AXI_BYTES,
					PICORV32_DATA_OUT, AXI_BYTES);
		}
		packages_read += FIFO_OUT_DEPTH - 2;

		while (control != CMD_SE_WAIT) {
			picorv32_control(interface, &control);
			if (control == CMD_SE_WAIT)
				read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
		}
	}

	while (control != CMD_SE_READ) {
		picorv32_control(interface, &control);
	}

	for (int i = 0; i < LEN_DK_rem; i++) {
		read_INTF(interface, sk + (i + packages_read) * AXI_BYTES,
				PICORV32_DATA_OUT, AXI_BYTES);
	}
	packages_read = 0;

	while (control != CMD_SE_WAIT) {
		picorv32_control(interface, &control);
		if (control == CMD_SE_WAIT)
			read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
	}

	//-- Read pk
	for (int i = 0; i < LEN_EK_blocks; i++) {
		while (control != CMD_SE_READ) {
			picorv32_control(interface, &control);
		}

		for (int j = 0; j < FIFO_OUT_DEPTH - 2; j++) {
			read_INTF(interface, pk + (j + packages_read) * AXI_BYTES,
					PICORV32_DATA_OUT, AXI_BYTES);
		}
		packages_read += FIFO_OUT_DEPTH - 2;

		while (control != CMD_SE_WAIT) {
			picorv32_control(interface, &control);
			if (control == CMD_SE_WAIT)
				read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
		}
	}

	while (control != CMD_SE_READ) {
		picorv32_control(interface, &control);
	}

	for (int i = 0; i < LEN_EK_rem; i++) {
		read_INTF(interface, pk + (i + packages_read) * AXI_BYTES,
				PICORV32_DATA_OUT, AXI_BYTES);
	}

	while (control != CMD_SE_CODE) {
		picorv32_control(interface, &control);
	}
}

void mlkem_enc_hw(int k, unsigned char *pk, unsigned char *ct,
		unsigned char *ss, INTF interface) {
	//-- se_code = { {(32'b) 64-bit data_packages}, {10'b0}, {k = 4, k = 3, k = 2, DEC, ENC, KEY_GEN}, {(16'b)MLKEM} }
	uint64_t next_block = 0;
	uint64_t control = 0;
	while (control != CMD_SE_CODE) {
		picorv32_control(interface, &control);
	}
	const uint8_t mlkem_code = MLKEM_SE_CODE;
	uint16_t mlkem_op_sel = (1 << (k + 1)) | (1 << 1);

	uint64_t se_code = ((uint32_t) mlkem_op_sel << 16) + mlkem_code;
	write_INTF(interface, &se_code, PICORV32_DATA_IN, AXI_BYTES);

	uint32_t LEN_EK;					// Bytes
	uint32_t LEN_CT;					// Bytes
	uint32_t LEN_EK_packages;			// Packages of 64-bit
	uint32_t LEN_CT_packages;			// Packages of 64-bit
	uint32_t LEN_EK_blocks;				// Blocks of #FIFO_DEPTH-1 * 64-bit
	uint32_t LEN_CT_blocks;				// Blocks of #FIFO_DEPTH-1 * 64-bit
	uint32_t LEN_EK_rem;				// Remaining packages of 64-bit
	uint32_t LEN_CT_rem;				// Remaining packages of 64-bit

	//-- k = 2
	if (k == 2) {
		LEN_EK = 800 - 32;
		LEN_CT = 768;
	}
	//-- k = 3
	else if (k == 3) {
		LEN_EK = 1184 - 32;
		LEN_CT = 1088;
	}
	//-- k = 4
	else if (k == 4) {
		LEN_EK = 1568 - 32;
		LEN_CT = 1568;
	} else {
		LEN_EK = 800 - 32;
		LEN_CT = 768;
	}

	LEN_EK_packages = LEN_EK >> 3;
	LEN_CT_packages = LEN_CT >> 3;
	LEN_EK_blocks = LEN_EK_packages / (FIFO_OUT_DEPTH - 2);
	LEN_CT_blocks = LEN_CT_packages / (FIFO_OUT_DEPTH - 2);
	LEN_EK_rem = LEN_EK_packages % (FIFO_OUT_DEPTH - 2);
	LEN_CT_rem = LEN_CT_packages % (FIFO_OUT_DEPTH - 2);

	//-- Generate random
	/* uint8_t m[32]; unsigned long long int m64[4];
	 randombytes(m, 32); memcpy(m64, m, 32); */

	unsigned long long int m64[4];
	m64[0] = 0x72407c18ae6c9baf;
	m64[1] = 0x1070e33b3f9dfc56;
	m64[2] = 0x28a187e6d055afff;
	m64[3] = 0xd38468eb627f7cf1;

	//-- Send PK
	uint32_t packages_send = 0;
	for (int i = 0; i < LEN_EK_blocks; i++) {
		while (control != CMD_SE_WRITE) {
			picorv32_control(interface, &control);
		}

		for (int j = 0; j < FIFO_OUT_DEPTH - 2; j++) {
			write_INTF(interface, pk + (j + packages_send) * AXI_BYTES,
					PICORV32_DATA_IN, AXI_BYTES);
		}
		packages_send += FIFO_OUT_DEPTH - 2;

		while (control != CMD_SE_WAIT) {
			picorv32_control(interface, &control);
			if (control == CMD_SE_WAIT)
				read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
		}
	}
	while (control != CMD_SE_WRITE) {
		picorv32_control(interface, &control);
	}

	for (int i = 0; i < LEN_EK_rem; i++) {
		write_INTF(interface, pk + (i + packages_send) * AXI_BYTES,
				PICORV32_DATA_IN, AXI_BYTES);
	}
	packages_send += LEN_EK_rem;

	while (control != CMD_SE_WAIT) {
		picorv32_control(interface, &control);
		if (control == CMD_SE_WAIT)
			read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
	}

	//-- Send Seed
	while (control != CMD_SE_WRITE) {
		picorv32_control(interface, &control);
	}
	for (int i = 0; i < 4; i++) {
		write_INTF(interface, pk + (i + packages_send) * AXI_BYTES,
				PICORV32_DATA_IN, AXI_BYTES);
	}
	packages_send = 0;

	//-- Send msg (m)
	for (int i = 0; i < 4; i++) {
		write_INTF(interface, m64 + i, PICORV32_DATA_IN, AXI_BYTES);
	}

	//-- Read CT
	uint32_t packages_read = 0;
	for (int i = 0; i < LEN_CT_blocks; i++) {
		while (control != CMD_SE_READ) {
			picorv32_control(interface, &control);
		}

		for (int j = 0; j < FIFO_OUT_DEPTH - 2; j++) {
			read_INTF(interface, ct + (j + packages_read) * AXI_BYTES,
					PICORV32_DATA_OUT, AXI_BYTES);
		}
		packages_read += FIFO_OUT_DEPTH - 2;

		while (control != CMD_SE_WAIT) {
			picorv32_control(interface, &control);
			if (control == CMD_SE_WAIT)
				read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
		}
	}

	while (control != CMD_SE_READ) {
		picorv32_control(interface, &control);
	}

	for (int i = 0; i < LEN_CT_rem; i++) {
		read_INTF(interface, ct + (i + packages_read) * AXI_BYTES,
				PICORV32_DATA_OUT, AXI_BYTES);
	}
	packages_read = 0;

	while (control != CMD_SE_WAIT) {
		picorv32_control(interface, &control);
		if (control == CMD_SE_WAIT)
			read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
	}

	//-- Read SS
	while (control != CMD_SE_READ) {
		picorv32_control(interface, &control);
	}

	for (int i = 0; i < 4; i++) {
		read_INTF(interface, ss + i * AXI_BYTES, PICORV32_DATA_OUT, AXI_BYTES);
	}

	while (control != CMD_SE_CODE) {
		picorv32_control(interface, &control);
	}
}

void mlkem_dec_hw(int k, unsigned char *sk, unsigned char *ct,
		unsigned char *ss, unsigned int *result, bool ext_key, uint8_t *key_id,
		INTF interface) {
	//-- se_code = { {(32'b) 64-bit data_packages}, {10'b0}, {k = 4, k = 3, k = 2, DEC, ENC, KEY_GEN}, {(16'b)MLKEM} }
	uint64_t next_block = 0;
	uint64_t control = 0;
	while (control != CMD_SE_CODE) {
		picorv32_control(interface, &control);
	}
	const uint8_t mlkem_code = MLKEM_SE_CODE;
	uint16_t mlkem_op_sel = ((uint16_t) !ext_key << 15)
			| ((uint16_t) (*key_id << 9)) | (1 << (k + 1)) | (1 << 2);

	uint64_t se_code = ((uint32_t) mlkem_op_sel << 16) + mlkem_code;
	write_INTF(interface, &se_code, PICORV32_DATA_IN, AXI_BYTES);

	uint32_t LEN_EK;
	uint32_t LEN_DK;
	uint32_t LEN_PKE;					// Bytes
	uint32_t LEN_CT;					// Bytes
	uint32_t LEN_PKE_packages;			// Packages of 64-bit
	uint32_t LEN_CT_packages;			// Packages of 64-bit
	uint32_t LEN_PKE_blocks;			// Blocks of #FIFO_DEPTH-1 * 64-bit
	uint32_t LEN_CT_blocks;				// Blocks of #FIFO_DEPTH-1 * 64-bit
	uint32_t LEN_PKE_rem;				// Remaining packages of 64-bit
	uint32_t LEN_CT_rem;				// Remaining packages of 64-bit

	//-- k = 2
	if (k == 2) {
		LEN_EK = 800;
		LEN_DK = 1632;
		LEN_PKE = LEN_DK - LEN_EK - 32 - 32;
		LEN_CT = 768;
	}
	//-- k = 3
	else if (k == 3) {
		LEN_EK = 1184;
		LEN_DK = 2400;
		LEN_PKE = LEN_DK - LEN_EK - 32 - 32;
		LEN_CT = 1088;
	}
	//-- k = 4
	else if (k == 4) {
		LEN_EK = 1568;
		LEN_DK = 3168;
		LEN_PKE = LEN_DK - LEN_EK - 32 - 32;
		LEN_CT = 1568;
	} else {
		LEN_EK = 800;
		LEN_DK = 1632;
		LEN_PKE = LEN_DK - LEN_EK - 32 - 32;
		LEN_CT = 768;
	}

	LEN_PKE_packages = LEN_PKE >> 3;
	LEN_CT_packages = LEN_CT >> 3;
	LEN_PKE_blocks = LEN_PKE_packages / (FIFO_OUT_DEPTH - 2);
	LEN_CT_blocks = LEN_CT_packages / (FIFO_OUT_DEPTH - 2);
	LEN_PKE_rem = LEN_PKE_packages % (FIFO_OUT_DEPTH - 2);
	LEN_CT_rem = LEN_CT_packages % (FIFO_OUT_DEPTH - 2);

	//-- Send SK
	uint32_t packages_send = 0;
	if (ext_key) {
		for (int i = 0; i < LEN_PKE_blocks; i++) {
			while (control != CMD_SE_WRITE) {
				picorv32_control(interface, &control);
			}

			for (int j = 0; j < FIFO_OUT_DEPTH - 2; j++) {
				write_INTF(interface, sk + (j + packages_send) * AXI_BYTES,
						PICORV32_DATA_IN, AXI_BYTES);
			}
			packages_send += FIFO_OUT_DEPTH - 2;

			while (control != CMD_SE_WAIT) {
				picorv32_control(interface, &control);
				if (control == CMD_SE_WAIT)
					read_INTF(interface, &next_block, PICORV32_DATA_OUT,
							AXI_BYTES); // Send a read signal to continue
			}
		}
		while (control != CMD_SE_WRITE) {
			picorv32_control(interface, &control);
		}

		for (int i = 0; i < LEN_PKE_rem; i++) {
			write_INTF(interface, sk + (i + packages_send) * AXI_BYTES,
					PICORV32_DATA_IN, AXI_BYTES);
		}
		packages_send += LEN_PKE_rem;

		while (control != CMD_SE_WAIT) {
			picorv32_control(interface, &control);
			if (control == CMD_SE_WAIT)
				read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
		}

		//-- Send PK
		for (int i = 0; i < LEN_PKE_blocks; i++) {
			while (control != CMD_SE_WRITE) {
				picorv32_control(interface, &control);
			}

			for (int j = 0; j < FIFO_OUT_DEPTH - 2; j++) {
				write_INTF(interface, sk + (j + packages_send) * AXI_BYTES,
						PICORV32_DATA_IN, AXI_BYTES);
			}
			packages_send += FIFO_OUT_DEPTH - 2;

			while (control != CMD_SE_WAIT) {
				picorv32_control(interface, &control);
				if (control == CMD_SE_WAIT)
					read_INTF(interface, &next_block, PICORV32_DATA_OUT,
							AXI_BYTES); // Send a read signal to continue
			}
		}
		while (control != CMD_SE_WRITE) {
			picorv32_control(interface, &control);
		}

		for (int i = 0; i < LEN_PKE_rem; i++) {
			write_INTF(interface, sk + (i + packages_send) * AXI_BYTES,
					PICORV32_DATA_IN, AXI_BYTES);
		}
		packages_send += LEN_PKE_rem;

		while (control != CMD_SE_WAIT) {
			picorv32_control(interface, &control);
			if (control == CMD_SE_WAIT)
				read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
		}
	}

	//-- Send CT
	packages_send = 0;
	for (int i = 0; i < LEN_CT_blocks; i++) {
		while (control != CMD_SE_WRITE) {
			picorv32_control(interface, &control);
		}

		for (int j = 0; j < FIFO_OUT_DEPTH - 2; j++) {
			write_INTF(interface, ct + (j + packages_send) * AXI_BYTES,
					PICORV32_DATA_IN, AXI_BYTES);
		}
		packages_send += FIFO_OUT_DEPTH - 2;

		while (control != CMD_SE_WAIT) {
			picorv32_control(interface, &control);
			if (control == CMD_SE_WAIT)
				read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
		}
	}
	while (control != CMD_SE_WRITE) {
		picorv32_control(interface, &control);
	}

	for (int i = 0; i < LEN_CT_rem; i++) {
		write_INTF(interface, ct + (i + packages_send) * AXI_BYTES,
				PICORV32_DATA_IN, AXI_BYTES);
	}
	packages_send += LEN_CT_rem;

	while (control != CMD_SE_WAIT) {
		picorv32_control(interface, &control);
		if (control == CMD_SE_WAIT)
			read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
	}
	packages_send = 0;

	//-- Send Seed
	if (ext_key) {
		while (control != CMD_SE_WRITE) {
			picorv32_control(interface, &control);
		}
		for (int i = 0; i < 4; i++) {
			write_INTF(interface, sk + i * AXI_BYTES + LEN_DK - 32 - 32 - 32,
					PICORV32_DATA_IN, AXI_BYTES);
		}

		//-- Send HEK
		for (int i = 0; i < 4; i++) {
			write_INTF(interface, sk + i * AXI_BYTES + LEN_DK - 32 - 32,
					PICORV32_DATA_IN, AXI_BYTES);
		}

		//-- Send Z
		for (int i = 0; i < 4; i++) {
			write_INTF(interface, sk + i * AXI_BYTES + LEN_DK - 32,
					PICORV32_DATA_IN, AXI_BYTES);
		}
	}

	//-- Read SS
	while (control != CMD_SE_READ) {
		picorv32_control(interface, &control);
	}

	for (int i = 0; i < 4; i++) {
		read_INTF(interface, ss + i * AXI_BYTES, PICORV32_DATA_OUT, AXI_BYTES);
	}

	//-- Read Result
	while (control != CMD_SE_WAIT) {
		picorv32_control(interface, &control);
		if (control == CMD_SE_WAIT)
			read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
	}
	while (control != CMD_SE_READ) {
		picorv32_control(interface, &control);
	}
	uint64_t result_64;
	read_INTF(interface, &result_64, PICORV32_DATA_OUT, AXI_BYTES);

	*result = result_64;

	while (control != CMD_SE_CODE) {
		picorv32_control(interface, &control);
	}
}

