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

  #include "../../se-qubip/sha2/sha2_hw.h"


void sha_256_hw_func(unsigned char* in, unsigned int length, unsigned char* out, INTF interface)
{
	sha2_hw(interface, in, out, length * 8, 1, 0);
}

void sha_384_hw_func(unsigned char* in, unsigned int length, unsigned char* out, INTF interface)
{
	sha2_hw(interface, in, out, length * 8, 2, 0);
}

void sha_512_hw_func(unsigned char* in, unsigned int length, unsigned char* out, INTF interface)
{
	sha2_hw(interface, in, out, length * 8, 3, 0);
}

void sha_512_256_hw_func(unsigned char* in, unsigned int length, unsigned char* out, INTF interface)
{
	sha2_hw(interface, in, out, length * 8, 4, 0);
}


void sha2_interface_init(INTF interface, unsigned long long int length, int VERSION, int DBG) {

	unsigned long long int op;
	unsigned long long int op_version;

	if (VERSION == 1)		op_version = 0 << 2; // SHA-256
	else if (VERSION == 2)	op_version = 1 << 2; // SHA-384
	else if (VERSION == 3)	op_version = 2 << 2; // SHA-512
	else if (VERSION == 4)	op_version = 3 << 2; // SHA-512/256
	else					op_version = 0 << 2;

	op = (unsigned long long int)ADD_SHA2 << 32 | ((op_version | 0) & 0xFFFFFFFF); // RESET
	write_INTF(interface, &op, CONTROL, sizeof(unsigned long long int));

	unsigned long long int reg_addr;
	unsigned long long int reg_data_in;
	unsigned long long tic = 0, toc; 
	// ----------- LOAD PADDING ---------- //
	if (DBG == 2) {
		printf("  -- sha2_interface - Loading data padding ...................... \n");
		tic = Wtime();
	}

	op = (unsigned long long int)ADD_SHA2 << 32 | ((op_version | LOAD_LENGTH_SHA2) & 0xFFFFFFFF); // LOAD_LENGTH
	write_INTF(interface, &op, CONTROL, sizeof(unsigned long long int));

	reg_addr = (unsigned long long int)(0);
	if(!op_version) reg_data_in = (unsigned long long int)(length);
	else			reg_data_in = (unsigned long long int)(0);
	write_INTF(interface, &reg_addr, ADDRESS, sizeof(unsigned long long int));
	write_INTF(interface, &reg_data_in, DATA_IN, sizeof(unsigned long long int));

	reg_addr = (unsigned long long int)(1);
	reg_data_in = (unsigned long long int)(length);
	write_INTF(interface, &reg_addr, ADDRESS, sizeof(unsigned long long int));
	write_INTF(interface, &reg_data_in, DATA_IN, sizeof(unsigned long long int));

	if (DBG == 3) printf(" length: %lld\n\r", reg_data_in);

	if (DBG == 2) {
		toc = Wtime() - tic;
		printf("(%3llu us.)\n", toc);
	}


}

void sha2_interface(INTF interface, unsigned long long int* a, unsigned long long int* b, unsigned long long int length, int last_hb, int VERSION, int DBG) {

	unsigned long long int end_op = 0;
	unsigned long long int reg_addr;
	unsigned long long int reg_data_in;
	unsigned long long int reg_data_out;
	unsigned long long tic = 0, toc;

	unsigned long long int op;
	unsigned long long int op_version;

	if (VERSION == 1)		op_version = 0 << 2; // SHA-256
	else if (VERSION == 2)	op_version = 1 << 2; // SHA-384
	else if (VERSION == 3)	op_version = 2 << 2; // SHA-512
	else if (VERSION == 4)	op_version = 3 << 2; // SHA-512/256
	else					op_version = 0 << 2;


	// ----------- LOAD ------------------ //
	if (DBG == 2) {
		printf("  -- sha2_interface - Loading data .............................. \n");
		tic = Wtime();
	}

	op = (unsigned long long int)ADD_SHA2 << 32 | ((op_version | LOAD_SHA2) & 0xFFFFFFFF); // LOAD
	write_INTF(interface, &op, CONTROL, sizeof(unsigned long long int));

	for (int i = 0; i < 16; i++) {
			reg_addr = (unsigned long long int)(i);
			reg_data_in = (unsigned long long int)(a[i]);
			write_INTF(interface, &reg_addr, ADDRESS, sizeof(unsigned long long int));
			write_INTF(interface, &reg_data_in, DATA_IN, sizeof(unsigned long long int));
			if (DBG == 3) printf(" a(%d): %02llx\n\r", i, a[i]);
	}

	if (DBG == 2) {
		toc = Wtime() - tic;
		printf("(%3llu us.)\n", toc);
	}

	// ----------- OPERATING ------------- //
	if (DBG == 2) {
		printf("  -- sha2_interface - Operating .............. \n");
		tic = Wtime();
	}

	op = (unsigned long long int)ADD_SHA2 << 32 | ((op_version | START_SHA2) & 0xFFFFFFFF); // LOAD
	write_INTF(interface, &op, CONTROL, sizeof(unsigned long long int));

	// wait END_OP
	while (!end_op) read_INTF(interface, &end_op, END_OP, sizeof(unsigned long long int));

	if (DBG == 2) {
		toc = Wtime() - tic;
		printf("(%3llu us.)\n", toc);
	}

	if (last_hb) {
		// ----------- READ ------------- //
		if (DBG == 2) {
			printf("  -- sha2_interface - Reading output .............................. \n");
			tic = Wtime();
		}

		for (int i = 0; i < 8; i++) {
			reg_addr = (unsigned long long int)(i);
			write_INTF(interface, &reg_addr, ADDRESS, sizeof(unsigned long long int));
			read_INTF(interface, &reg_data_out, DATA_OUT, sizeof(unsigned long long int));
			b[i] = reg_data_out;
			if (DBG == 3) printf(" b(%d): %02llx\n\r", i, b[i]);
		}

		if (DBG == 2) {
			toc = Wtime() - tic;
			printf("(%3llu us.)\n", toc);
		}
	}
	
}



void sha2_hw(INTF interface, unsigned char* in, unsigned char* out, unsigned long long int length, unsigned int VERSION, int DBG) {

	unsigned long long int hb_num;
	unsigned long long int ind;
	int last_hb = 0;

	unsigned long long int buffer_in[16];
	unsigned long long int buffer_out[8];
	unsigned long long int buf_1, buf_2;

	unsigned char in_prev[1024 / 8];

	unsigned long long tic = 0, toc;

	// ------- Number of hash blocks ----- //
	unsigned long long int op_version;

	if (VERSION == 1)		op_version = 0 << 2; // SHA-256
	else if (VERSION == 2)	op_version = 1 << 2; // SHA-384
	else if (VERSION == 3)	op_version = 2 << 2; // SHA-512
	else if (VERSION == 4)	op_version = 3 << 2; // SHA-512/256
	else					op_version = 0 << 2;

	unsigned int size_len;
	if (!op_version)	size_len = 64;
	else				size_len = 128;

	unsigned int block_size;
	if (!op_version)	block_size = 512;
	else				block_size = 1024;

	hb_num = (unsigned long long int)((length+size_len) / block_size) + 1; //3 bits for padding

	if (DBG == 1) {
		printf("\n hb_num = %lld", hb_num);
		printf("\n length = %lld", length);
	}

	// ------- SHA2 Initialization --------//

	sha2_interface_init(interface, length, VERSION, DBG);

	// ------- Operation ---------------- //
	for (unsigned int hb = 1; hb <= hb_num; hb++) {
		ind = (hb - 1) * (block_size / 8);
		for (int j = 0; j < (block_size / 8); j++) {
			if ((ind + j) >= (length / 8))	in_prev[j] = 0x00;
			else							in_prev[j] = in[ind + j];
		}
		// memcpy(in_prev, in + ind, sizeof(unsigned char) * (SIZE_BLOCK / 8));
		ind = 0;
		for (int i = 0; i < 16; i++) {
			if (!op_version) {

				buffer_in[i] =
					0x00000000 |
					((unsigned long long)(in_prev[ind + 3]) << 0) |
					((unsigned long long)(in_prev[ind + 2]) << 8) |
					((unsigned long long)(in_prev[ind + 1]) << 16) |
					((unsigned long long)(in_prev[ind + 0]) << 24);
				ind = ind + 4;
			}
			else {
				buffer_in[i] =
					((unsigned long long)(in_prev[ind + 7]) << 0) |
					((unsigned long long)(in_prev[ind + 6]) << 8) |
					((unsigned long long)(in_prev[ind + 5]) << 16) |
					((unsigned long long)(in_prev[ind + 4]) << 24) |
					((unsigned long long)(in_prev[ind + 3]) << 32) |
					((unsigned long long)(in_prev[ind + 2]) << 40) |
					((unsigned long long)(in_prev[ind + 1]) << 48) |
					((unsigned long long)(in_prev[ind + 0]) << 56);
				ind = ind + 8;
			}

			if (DBG == 1) printf("in[%lld] = %02x \t in[%lld] = %02x \t in[%lld] = %02x \t in[%lld] = %02x \n", ind, in_prev[ind], ind + 1, in_prev[ind + 1], ind + 2, in_prev[ind + 2], ind + 3, in_prev[ind + 3]);
			if (DBG == 1) printf("buffer_in[%d] = %02llx \n", i, buffer_in[i]);
		}

		if (hb == hb_num) last_hb = 1;
		sha2_interface(interface, buffer_in, buffer_out, length, last_hb, VERSION, DBG);
	}


	// ---- Read ----- //
	if (VERSION == 1) {
		for (int i = 0; i < 8; i++) {
			ind = i * 4;
			out[ind + 3] = (buffer_out[i] & 0x00000000000000FF) >> 0;
			out[ind + 2] = (buffer_out[i] & 0x000000000000FF00) >> 8;
			out[ind + 1] = (buffer_out[i] & 0x0000000000FF0000) >> 16;
			out[ind + 0] = (buffer_out[i] & 0x00000000FF000000) >> 24;
		}
	}
	else if (VERSION == 2) {
		for (int i = 0; i < 6; i++) {
			ind = i * 8;
			out[ind + 7] = (buffer_out[i] & 0x00000000000000FF) >> 0;
			out[ind + 6] = (buffer_out[i] & 0x000000000000FF00) >> 8;
			out[ind + 5] = (buffer_out[i] & 0x0000000000FF0000) >> 16;
			out[ind + 4] = (buffer_out[i] & 0x00000000FF000000) >> 24;
			out[ind + 3] = (buffer_out[i] & 0x000000FF00000000) >> 32;
			out[ind + 2] = (buffer_out[i] & 0x0000FF0000000000) >> 40;
			out[ind + 1] = (buffer_out[i] & 0x00FF000000000000) >> 48;
			out[ind + 0] = (buffer_out[i] & 0xFF00000000000000) >> 56;
		}
	}
	else if (VERSION == 4) {
		for (int i = 0; i < 4; i++) {
			ind = i * 8;
			out[ind + 7] = (buffer_out[i] & 0x00000000000000FF) >> 0;
			out[ind + 6] = (buffer_out[i] & 0x000000000000FF00) >> 8;
			out[ind + 5] = (buffer_out[i] & 0x0000000000FF0000) >> 16;
			out[ind + 4] = (buffer_out[i] & 0x00000000FF000000) >> 24;
			out[ind + 3] = (buffer_out[i] & 0x000000FF00000000) >> 32;
			out[ind + 2] = (buffer_out[i] & 0x0000FF0000000000) >> 40;
			out[ind + 1] = (buffer_out[i] & 0x00FF000000000000) >> 48;
			out[ind + 0] = (buffer_out[i] & 0xFF00000000000000) >> 56;
		}
	}
	else {
		for (int i = 0; i < 8; i++) {
			ind = i * 8;
			out[ind + 7] = (buffer_out[i] & 0x00000000000000FF) >> 0;
			out[ind + 6] = (buffer_out[i] & 0x000000000000FF00) >> 8;
			out[ind + 5] = (buffer_out[i] & 0x0000000000FF0000) >> 16;
			out[ind + 4] = (buffer_out[i] & 0x00000000FF000000) >> 24;
			out[ind + 3] = (buffer_out[i] & 0x000000FF00000000) >> 32;
			out[ind + 2] = (buffer_out[i] & 0x0000FF0000000000) >> 40;
			out[ind + 1] = (buffer_out[i] & 0x00FF000000000000) >> 48;
			out[ind + 0] = (buffer_out[i] & 0xFF00000000000000) >> 56;
		}
	}
	


}
