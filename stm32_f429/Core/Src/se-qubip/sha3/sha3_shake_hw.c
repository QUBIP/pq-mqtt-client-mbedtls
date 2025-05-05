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

#include "../../se-qubip/sha3/sha3_shake_hw.h"

void sha3_256_hw_func(unsigned char* in, unsigned int length, unsigned char* out, INTF interface)
{
	sha3_shake_hw(in, out, length*8, 256, 1, 1088, 256, interface, 0);
}

void sha3_512_hw_func(unsigned char* in, unsigned int length, unsigned char* out, INTF interface)
{
	sha3_shake_hw(in, out, length*8, 512, 2, 576, 512, interface, 0);
}

void shake128_hw_func(unsigned char* in, unsigned int length, unsigned char* out, unsigned int length_out, INTF interface)
{
	sha3_shake_hw(in, out, length*8, length_out*8, 3, 1344, 128, interface, 0);
}

void shake256_hw_func(unsigned char* in, unsigned int length, unsigned char* out, unsigned int length_out, INTF interface)
{
	sha3_shake_hw(in, out, length*8, length_out*8, 4, 1088, 256, interface, 0);
}

void sha3_shake_interface_init(INTF interface, int VERSION) {
	unsigned long long int op;
	unsigned long long int op_version;
 
	if (VERSION == 1)	op_version = 2 << 2; // SHA3-256
	else if (VERSION == 2)	op_version = 3 << 2; // SHA3-512
	else if (VERSION == 3)	op_version = 0 << 2; // SHAKE-128
	else if (VERSION == 4)	op_version = 1 << 2; // SHAKE-256
	else					op_version = 2 << 2;

	op = (unsigned long long int)ADD_SHA3 << 32 | ((op_version | 0) & 0xFFFFFFFF);; // RESET OFF
	write_INTF(interface, &op, CONTROL, sizeof(unsigned long long int));

}

void sha3_shake_interface(unsigned long long int* a, unsigned long long int* b, INTF interface, unsigned int pos_pad, int pad, int shake, int VERSION, int SIZE_SHA3, int SIZE_BLOCK, int DBG) {

	unsigned long long int op;
	unsigned long long int op_version;
	unsigned long long int end_op = 0;
	unsigned long long int reg_addr;
	unsigned long long int reg_data_in;
	unsigned long long int reg_data_out;
	unsigned long long tic = 0, toc;

	if (VERSION == 1)	op_version = 2 << 2; // SHA3-256
	else if (VERSION == 2)	op_version = 3 << 2; // SHA3-512
	else if (VERSION == 3)	op_version = 0 << 2; // SHAKE-128
	else if (VERSION == 4)	op_version = 1 << 2; // SHAKE-256
	else					op_version = 2 << 2;

	if (shake != 1) {
		if (pad) {

			// ----------- LOAD LENGTH ---------- //
			if (DBG == 2) {
				printf("  -- sha3_interface - Loading data padding ...................... \n");
				tic = Wtime();
			}

			op = (unsigned long long int)ADD_SHA3 << 32 | ((op_version | LOAD_LENGTH) & 0xFFFFFFFF); // LOAD
			write_INTF(interface, &op, CONTROL, sizeof(unsigned long long int));

			reg_addr = (unsigned long long int)(0);
			reg_data_in = (unsigned long long int)(pos_pad);
			write_INTF(interface, &reg_addr, ADDRESS, sizeof(unsigned long long int));
			write_INTF(interface, &reg_data_in, DATA_IN, sizeof(unsigned long long int));
			if (DBG == 3) printf(" pos_pad: %lld\n\r", reg_data_in);

			if (DBG == 2) {
				toc = Wtime() - tic;
				printf("(%3llu us.)\n", toc);
			}
		}

		// ----------- LOAD ------------------ //
		if (DBG == 2) {
			printf("  -- sha3_interface - Loading data .............................. \n");
			tic = Wtime();
		}

		op = (unsigned long long int)ADD_SHA3 << 32 | ((op_version | LOAD) & 0xFFFFFFFF); // LOAD
		write_INTF(interface, &op, CONTROL, sizeof(unsigned long long int));

		for (int i = 0; i < (SIZE_BLOCK / 64); i++) {
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
	}


	// ----------- OPERATING ------------- //
	if (DBG == 2) {
		printf("  -- sha3_interface - Operating .............. \n");
		tic = Wtime();
	}

	op = (unsigned long long int)ADD_SHA3 << 32 | ((op_version | START) & 0xFFFFFFFF);; // START
	write_INTF(interface, &op, CONTROL, sizeof(unsigned long long int));

	// wait END_OP
	while (!end_op) read_INTF(interface, &end_op, END_OP, sizeof(unsigned long long int));


	if (DBG == 2) {
		toc = Wtime() - tic;
		printf("(%3llu us.)\n", toc);
	}

	// ----------- READ ------------- //
	if (pad) {
		if (DBG == 2) {
			printf("  -- sha3_interface - Reading output .............................. \n");
			tic = Wtime();
		}

		if (shake) {
			for (int i = 0; i < (SIZE_BLOCK / 64); i++) {
				reg_addr = (unsigned long long int)(i);
				write_INTF(interface, &reg_addr, ADDRESS, sizeof(unsigned long long int));
				read_INTF(interface, &reg_data_out, DATA_OUT, sizeof(unsigned long long int));
				b[i] = reg_data_out;
				if (DBG == 3) printf(" b(%d): %02llx\n\r", i, b[i]);
			}
		}
		else {
			for (int i = 0; i < (int)ceil((double)SIZE_SHA3 / (double)64); i++) {
				reg_addr = (unsigned long long int)(i);
				write_INTF(interface, &reg_addr, ADDRESS, sizeof(unsigned long long int));
				read_INTF(interface, &reg_data_out, DATA_OUT, sizeof(unsigned long long int));
				b[i] = reg_data_out;
				if (DBG == 3) printf(" b(%d): %02llx\n\r", i, b[i]);
			}
		}



		if (DBG == 2) {
			toc = Wtime() - tic;
			printf("(%3llu us.)\n", toc);
		}

		op = (unsigned long long int)ADD_SHA3 << 32 | ((op_version | LOAD_LENGTH) & 0xFFFFFFFF);; // ENABLE_SHAKE
		write_INTF(interface, &op, CONTROL, sizeof(unsigned long long int));

	}
}

void sha3_shake_hw(unsigned char* in, unsigned char* out, unsigned int length, unsigned int length_out, int VERSION, int SIZE_BLOCK, int SIZE_SHA3, INTF interface, int DBG) {

	unsigned int hb_num;
	unsigned int hb_num_out;
	unsigned int pos_pad;
	unsigned int ind;
	int last_hb = 0;
	int shake = 0;

	unsigned long long int* buffer_in;
	unsigned long long int* buffer_out;

	buffer_in = malloc(sizeof(unsigned long long int) * (SIZE_BLOCK / 64));
	buffer_out = malloc(sizeof(unsigned long long int) * (SIZE_BLOCK / 64));

	unsigned char in_prev[1344 / 8];
	// memset(in_prev, 0, sizeof(unsigned char) * (1344 / 8));
	// in_prev = malloc(sizeof(unsigned char) * ((SIZE_BLOCK / 8) + 1));

	// ------- Number of hash blocks ----- //
	hb_num = (length / SIZE_BLOCK) + 1;
	hb_num_out = (length_out / SIZE_BLOCK) + 1;
	pos_pad = length % SIZE_BLOCK;

	if (DBG == 1) {
		printf("\n hb_num = %d \n", hb_num);
		printf("\n hb_num_out = %d \n", hb_num_out);
		printf("\n length = %d \n", length);
		printf("\n pos_pad = %d \n", pos_pad);
	}

	// ------- SHA3 Initialization --------//

	sha3_shake_interface_init(interface, VERSION);

	// ------- Operation ---------------- //

	for (unsigned int hb = 1; hb <= hb_num; hb++) {

		ind = (hb - 1) * (SIZE_BLOCK / 8);
		for (int j = 0; j < (SIZE_BLOCK / 8); j++) {
			if ((ind + j) >= (length / 8))	in_prev[j] = 0x00;
			else							in_prev[j] = in[ind + j];
		}
		// memcpy(in_prev, in + ind, sizeof(unsigned char) * (SIZE_BLOCK / 8));
		ind = 0;
		for (int i = 0; i < (SIZE_BLOCK / 64); i++) {
			
			memcpy(buffer_in + i, in_prev + ind, 8);

			if (DBG == 1) printf("in[%d] = %02x \t in[%d] = %02x \t in[%d] = %02x \t in[%d] = %02x \n", ind, in_prev[ind], ind + 1, in_prev[ind + 1], ind + 2, in_prev[ind + 2], ind + 3, in_prev[ind + 3]);
			if (DBG == 1) printf("buffer_in[%d] = %02llx \n", i, buffer_in[i]);
			ind = ind + 8;
		}

		if (hb == hb_num)						last_hb = 1;
		else									last_hb = 0;

		if (length_out > SIZE_SHA3)				shake = 2;
		else									shake = 0;

		if (DBG == 1) {
			printf("\n last_hb = %d \n", last_hb);
		}

		sha3_shake_interface(buffer_in, buffer_out, interface, (pos_pad / 8), last_hb, shake, VERSION, SIZE_SHA3, SIZE_BLOCK, DBG); // shake = 0
	}

	// ------- Change Out Format --------- //
	if (hb_num_out > hb_num) {
		for (int i = 0; i < (SIZE_BLOCK / 64); i++) {
			ind = i * 8;
			/*
			out[ind + 0] = (buffer_out[i] & 0x00000000000000FF) >> 0;
			out[ind + 1] = (buffer_out[i] & 0x000000000000FF00) >> 8;
			out[ind + 2] = (buffer_out[i] & 0x0000000000FF0000) >> 16;
			out[ind + 3] = (buffer_out[i] & 0x00000000FF000000) >> 24;
			out[ind + 4] = (buffer_out[i] & 0x000000FF00000000) >> 32;
			out[ind + 5] = (buffer_out[i] & 0x0000FF0000000000) >> 40;
			out[ind + 6] = (buffer_out[i] & 0x00FF000000000000) >> 48;
			out[ind + 7] = (buffer_out[i] & 0xFF00000000000000) >> 56;
			*/
			memcpy(out + ind, buffer_out + i, 8 * sizeof(unsigned char));
		}

		int hb_shake = 0;
		for (unsigned int hb = hb_num; hb < hb_num_out; hb++) {
			sha3_shake_interface(buffer_in, buffer_out, interface, (pos_pad / 8), last_hb, 1, VERSION, SIZE_SHA3, SIZE_BLOCK, DBG);
			hb_shake++;
			for (int i = 0; i < (SIZE_BLOCK / 64); i++) {
				ind = i * 8 + hb_shake * (SIZE_BLOCK / 8);
				memcpy(out + ind, buffer_out + i, 8 * sizeof(unsigned char));
			}
		}
	}
	else {
		for (int i = 0; i < (int)ceil((double)length_out / (double)64); i++) {
			ind = i * 8;
			memcpy(out + ind, buffer_out + i, 8 * sizeof(unsigned char));
		}
	}

}
