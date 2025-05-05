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



void mlkem_512_gen_keys_hw(unsigned char* pk, unsigned char* sk, INTF interface) {

	mlkem_gen_keys_hw(2, pk, sk, interface);

}
void mlkem_768_gen_keys_hw(unsigned char* pk, unsigned char* sk, INTF interface) {

	mlkem_gen_keys_hw(3, pk, sk, interface);

}
void mlkem_1024_gen_keys_hw(unsigned char* pk, unsigned char* sk, INTF interface) {

	mlkem_gen_keys_hw(4, pk, sk, interface);

}

void mlkem_512_enc_hw(unsigned char* pk, unsigned char* ct, unsigned char* ss, INTF interface) {

	mlkem_enc_hw(2, pk, ct, ss, interface);

}
void mlkem_768_enc_hw(unsigned char* pk, unsigned char* ct, unsigned char* ss, INTF interface) {

	mlkem_enc_hw(3, pk, ct, ss, interface);

}
void mlkem_1024_enc_hw(unsigned char* pk, unsigned char* ct, unsigned char* ss, INTF interface) {

	mlkem_enc_hw(4, pk, ct, ss, interface);

}

void mlkem_512_dec_hw(unsigned char* sk, unsigned char* ct, unsigned char* ss, unsigned int* result, INTF interface) {

	mlkem_dec_hw(2, sk, ct, ss, result, interface);
	
}
void mlkem_768_dec_hw(unsigned char* sk, unsigned char* ct, unsigned char* ss, unsigned int* result, INTF interface) {
	
	mlkem_dec_hw(3, sk, ct, ss, result, interface);

}
void mlkem_1024_dec_hw(unsigned char* sk, unsigned char* ct, unsigned char* ss, unsigned int* result, INTF interface) {
	
	mlkem_dec_hw(4, sk, ct, ss, result, interface);

}

void mlkem_gen_keys_hw(int k, unsigned char* pk, unsigned char* sk, INTF interface) {

	
	uint8_t d[32]; unsigned long long int d64[4];
	uint8_t z[32]; unsigned long long int z64[4];
	randombytes(d, 32); memcpy(d64, d, 32);
	randombytes(z, 32); memcpy(z64, z, 32);
	

	/*
	unsigned long long int d64[4];
	d64[0] = 0x519d62010a40b41e;
	d64[1] = 0xf5deb985cde27479;
	d64[2] = 0x2b9c6f8e50de8290;
	d64[3] = 0xca555996121e340e;

	unsigned long long int z64[4];
	z64[0] = 0xfe0338161141391a;
	z64[1] = 0x7586a635c319852e;
	z64[2] = 0x5f2ba2afad8e3356;
	z64[3] = 0x93d6cc60054357c5;
	*/

	unsigned long long int reg_addr;
	unsigned long long int reg_data_out;
	unsigned long long int reg_data_in;
	
	unsigned long long int op;
	unsigned long long int op_mode;

	if (k == 2)				op_mode = MLKEM_GEN_KEYS_512	<< 4; 
	else if (k == 3)		op_mode = MLKEM_GEN_KEYS_768	<< 4; 
	else if (k == 4)		op_mode = MLKEM_GEN_KEYS_1024	<< 4; 
	else					op_mode = MLKEM_GEN_KEYS_512	<< 4;

	unsigned int LEN_EK;
	unsigned int LEN_DK;

	if (k == 2)			LEN_EK = 800;
	else if (k == 3)	LEN_EK = 1184;
	else if (k == 4)	LEN_EK = 1568;
	else				LEN_EK = 800;

	if (k == 2)			LEN_DK = 1632;
	else if (k == 3)	LEN_DK = 2400;
	else if (k == 4)	LEN_DK = 3168;
	else				LEN_DK = 1632;

	op = (unsigned long long int)ADD_MLKEM << 32 | ((op_mode | MLKEM_RESET) & 0xFFFFFFFF);
	write_INTF(interface, &op, CONTROL, sizeof(unsigned long long int));

	// -- load seed (d) -- //
	op = (unsigned long long int)ADD_MLKEM << 32 | ((op_mode | MLKEM_LOAD_COINS) & 0xFFFFFFFF); // LOAD_D
	write_INTF(interface, &op, CONTROL, sizeof(unsigned long long int));

	for (int i = 0; i < 4; i++) {
		reg_addr = (unsigned long long int)(i);
		write_INTF(interface, &reg_addr, ADDRESS, sizeof(unsigned long long int));
		reg_data_in = d64[i];
		write_INTF(interface, &reg_data_in, DATA_IN, sizeof(unsigned long long int));
	}

	// -- load z -- //
	op = (unsigned long long int)ADD_MLKEM << 32 | ((op_mode | MLKEM_LOAD_SS) & 0xFFFFFFFF); // LOAD_Z
	write_INTF(interface, &op, CONTROL, sizeof(unsigned long long int));

	for (int i = 0; i < 4; i++) {
		reg_addr = (unsigned long long int)(i);
		write_INTF(interface, &reg_addr, ADDRESS, sizeof(unsigned long long int));
		reg_data_in = z64[i];
		write_INTF(interface, &reg_data_in, DATA_IN, sizeof(unsigned long long int));
	}

	// -- start -- //
	op = (unsigned long long int)ADD_MLKEM << 32 | ((op_mode | MLKEM_START) & 0xFFFFFFFF); // START
	write_INTF(interface, &op, CONTROL, sizeof(unsigned long long int));

	unsigned long long int end_op = 0;
	// wait END_OP
	while (!end_op) read_INTF(interface, &end_op, END_OP, sizeof(unsigned long long int));

	// read sk
	op = (unsigned long long int)ADD_MLKEM << 32 | ((op_mode | MLKEM_READ_SK) & 0xFFFFFFFF);; // MLKEM_START
	write_INTF(interface, &op, CONTROL, sizeof(unsigned long long int));

	for (int i = 0; i < (LEN_DK / 8); i++) {
		reg_addr = (unsigned long long int)(i + (LEN_EK / 8));
		write_INTF(interface, &reg_addr, ADDRESS, sizeof(unsigned long long int));
		read_INTF(interface, &reg_data_out, DATA_OUT, sizeof(unsigned long long int));
		memcpy(sk + 8*i, &reg_data_out, 8);
	}

	// read pk
	op = (unsigned long long int)ADD_MLKEM << 32 | ((op_mode | MLKEM_READ_PK) & 0xFFFFFFFF);; // MLKEM_READ_EK
	write_INTF(interface, &op, CONTROL, sizeof(unsigned long long int));

	for (int i = 0; i < (LEN_EK / 8); i++) {
		reg_addr = (unsigned long long int)(i);
		write_INTF(interface, &reg_addr, ADDRESS, sizeof(unsigned long long int));
		read_INTF(interface, &reg_data_out, DATA_OUT, sizeof(unsigned long long int));
		memcpy(pk + 8 * i, &reg_data_out, 8);
	}


}

void mlkem_enc_hw(int k, unsigned char* pk, unsigned char* ct, unsigned char* ss, INTF interface) {

	
	uint8_t m[32]; unsigned long long int m64[4];
	randombytes(m, 32); memcpy(m64, m, 32);
	

	/*
	unsigned long long int m64[4];
	m64[0] = 0x72407c18ae6c9baf;
	m64[1] = 0x1070e33b3f9dfc56;
	m64[2] = 0x28a187e6d055afff;
	m64[3] = 0xd38468eb627f7cf1;
	*/

	unsigned long long int op;
	unsigned long long int op_mode;

	unsigned long long int reg_addr;
	unsigned long long int reg_data_out;
	unsigned long long int reg_data_in;

	if (k == 2)				op_mode = MLKEM_ENCAP_512		<< 4;
	else if (k == 3)		op_mode = MLKEM_ENCAP_768		<< 4;
	else if (k == 4)		op_mode = MLKEM_ENCAP_1024		<< 4;
	else					op_mode = MLKEM_ENCAP_512		<< 4;

	unsigned int LEN_EK;
	unsigned int LEN_CT;

	if (k == 2)			LEN_EK = 800;
	else if (k == 3)	LEN_EK = 1184;
	else if (k == 4)	LEN_EK = 1568;
	else				LEN_EK = 800;

	if (k == 2)			LEN_CT = 768;
	else if (k == 3)	LEN_CT = 1088;
	else if (k == 4)	LEN_CT = 1568;
	else				LEN_CT = 768;

	op = (unsigned long long int)ADD_MLKEM << 32 | ((op_mode | MLKEM_RESET) & 0xFFFFFFFF); // MLKEM_RESET ON
	write_INTF(interface, &op, CONTROL, sizeof(unsigned long long int));

	// load_pk
	op = (unsigned long long int)ADD_MLKEM << 32 | ((op_mode | MLKEM_LOAD_PK) & 0xFFFFFFFF);  // MLKEM_LOAD_PK 
	write_INTF(interface, &op, CONTROL, sizeof(unsigned long long int));

	for (int i = 0; i < ((LEN_EK - 32) / 8); i++) {
		reg_addr = (unsigned long long int)(i);
		write_INTF(interface, &reg_addr, ADDRESS, sizeof(unsigned long long int));
		memcpy(&reg_data_in, pk + (8*i), 8);
		write_INTF(interface, &reg_data_in, DATA_IN, sizeof(unsigned long long int));
	}

	// load_seed
	op = (unsigned long long int)ADD_MLKEM << 32 | ((op_mode | MLKEM_LOAD_COINS) & 0xFFFFFFFF);  // MLKEM_LOAD_SEED
	write_INTF(interface, &op, CONTROL, sizeof(unsigned long long int));

	for (int i = 0; i < 4; i++) {
		reg_addr = (unsigned long long int)(i);
		write_INTF(interface, &reg_addr, ADDRESS, sizeof(unsigned long long int));
		memcpy(&reg_data_in, pk + (8*i + (LEN_EK-32)), 8);
		write_INTF(interface, &reg_data_in, DATA_IN, sizeof(unsigned long long int));
	}

	// -- load msg (m) -- //
	op = (unsigned long long int)ADD_MLKEM << 32 | ((op_mode | MLKEM_LOAD_SS) & 0xFFFFFFFF); // LOAD_M
	write_INTF(interface, &op, CONTROL, sizeof(unsigned long long int));

	for (int i = 0; i < 4; i++) {
		reg_addr = (unsigned long long int)(i);
		write_INTF(interface, &reg_addr, ADDRESS, sizeof(unsigned long long int));
		reg_data_in = m64[i];
		write_INTF(interface, &reg_data_in, DATA_IN, sizeof(unsigned long long int));
	}


	// start
	op = (unsigned long long int)ADD_MLKEM << 32 | ((op_mode | MLKEM_START) & 0xFFFFFFFF); // MLKEM_START
	write_INTF(interface, &op, CONTROL, sizeof(unsigned long long int));

	unsigned long long int end_op = 0;
	// wait END_OP
	while (!end_op) read_INTF(interface, &end_op, END_OP, sizeof(unsigned long long int));

	// read ct
	op = (unsigned long long int)ADD_MLKEM << 32 | ((op_mode | MLKEM_READ_CT) & 0xFFFFFFFF);; // MLKEM_READ_CT
	write_INTF(interface, &op, CONTROL, sizeof(unsigned long long int));

	for (int i = 0; i < (LEN_CT / 8); i++) {
		reg_addr = (unsigned long long int)(i);
		write_INTF(interface, &reg_addr, ADDRESS, sizeof(unsigned long long int));
		read_INTF(interface, &reg_data_out, DATA_OUT, sizeof(unsigned long long int));
		memcpy(ct + 8 * i, &reg_data_out, 8);
	}

	// read ss
	op = (unsigned long long int)ADD_MLKEM << 32 | ((op_mode | MLKEM_READ_SS) & 0xFFFFFFFF); // MLKEM_READ_K(SS)
	write_INTF(interface, &op, CONTROL, sizeof(unsigned long long int));

	for (int i = 0; i < 4; i++) {
		reg_addr = (unsigned long long int)(i + (LEN_CT / 8));
		write_INTF(interface, &reg_addr, ADDRESS, sizeof(unsigned long long int));
		read_INTF(interface, &reg_data_out, DATA_OUT, sizeof(unsigned long long int));
		memcpy(ss + 8 * i, &reg_data_out, 8);
	}

}

void mlkem_dec_hw(int k, unsigned char* sk, unsigned char* ct, unsigned char* ss, unsigned int* result, INTF interface) {

	unsigned long long int op;
	unsigned long long int op_mode;

	unsigned long long int reg_addr;
	unsigned long long int reg_data_out;
	unsigned long long int reg_data_in;

	if (k == 2)				op_mode = MLKEM_DECAP_512 << 4;
	else if (k == 3)		op_mode = MLKEM_DECAP_768 << 4;
	else if (k == 4)		op_mode = MLKEM_DECAP_1024 << 4;
	else					op_mode = MLKEM_DECAP_512 << 4;

	unsigned int LEN_EK;
	unsigned int LEN_DK;
	unsigned int LEN_CT;

	if (k == 2)			LEN_EK = 800;
	else if (k == 3)	LEN_EK = 1184;
	else if (k == 4)	LEN_EK = 1568;
	else				LEN_EK = 800;

	if (k == 2)			LEN_DK = 1632;
	else if (k == 3)	LEN_DK = 2400;
	else if (k == 4)	LEN_DK = 3168;
	else				LEN_DK = 1632;

	if (k == 2)			LEN_CT = 768;
	else if (k == 3)	LEN_CT = 1088;
	else if (k == 4)	LEN_CT = 1568;
	else				LEN_CT = 768;

	unsigned int LEN_PKE = LEN_DK - LEN_EK - 32 - 32;

	op = (unsigned long long int)ADD_MLKEM << 32 | ((op_mode | MLKEM_RESET) & 0xFFFFFFFF);; // MLKEM_RESET ON
	write_INTF(interface, &op, CONTROL, sizeof(unsigned long long int));

	// load_sk
	op = (unsigned long long int)ADD_MLKEM << 32 | ((op_mode | MLKEM_LOAD_SK) & 0xFFFFFFFF);; // MLKEM_LOAD_SK
	write_INTF(interface, &op, CONTROL, sizeof(unsigned long long int));

	for (int i = 0; i < (LEN_PKE / 8); i++) {
		reg_addr = (unsigned long long int)(i);
		write_INTF(interface, &reg_addr, ADDRESS, sizeof(unsigned long long int));
		memcpy(&reg_data_in, sk + (8 * i), 8);
		write_INTF(interface, &reg_data_in, DATA_IN, sizeof(unsigned long long int));
	}

	// load_pk
	op = (unsigned long long int)ADD_MLKEM << 32 | ((op_mode | MLKEM_LOAD_PK) & 0xFFFFFFFF);; // MLKEM_LOAD_PK
	write_INTF(interface, &op, CONTROL, sizeof(unsigned long long int));

	for (int i = 0; i < (LEN_PKE / 8); i++) {
		reg_addr = (unsigned long long int)(i);
		write_INTF(interface, &reg_addr, ADDRESS, sizeof(unsigned long long int));
		memcpy(&reg_data_in, sk + ((8 * i) + LEN_PKE), 8);
		write_INTF(interface, &reg_data_in, DATA_IN, sizeof(unsigned long long int));
	}

	// load_ct
	op = (unsigned long long int)ADD_MLKEM << 32 | ((op_mode | MLKEM_LOAD_CT) & 0xFFFFFFFF);; // MLKEM_LOAD_CT
	write_INTF(interface, &op, CONTROL, sizeof(unsigned long long int));

	for (int i = 0; i < (LEN_CT / 8); i++) {
		reg_addr = (unsigned long long int)(i);
		write_INTF(interface, &reg_addr, ADDRESS, sizeof(unsigned long long int));
		memcpy(&reg_data_in, ct + (8 * i), 8);
		write_INTF(interface, &reg_data_in, DATA_IN, sizeof(unsigned long long int));
	}

	// load_seed
	op = (unsigned long long int)ADD_MLKEM << 32 | ((op_mode | MLKEM_LOAD_COINS) & 0xFFFFFFFF);; // MLKEM_LOAD_SEED
	write_INTF(interface, &op, CONTROL, sizeof(unsigned long long int));

	for (int i = 0; i < 4; i++) {
		reg_addr = (unsigned long long int)(i);
		write_INTF(interface, &reg_addr, ADDRESS, sizeof(unsigned long long int));
		memcpy(&reg_data_in, sk + (8*i + (LEN_DK - 32 - 32 - 32)), 8);
		write_INTF(interface, &reg_data_in, DATA_IN, sizeof(unsigned long long int));
	}

	// load_hek
	op = (unsigned long long int)ADD_MLKEM << 32 | ((op_mode | MLKEM_LOAD_HEK) & 0xFFFFFFFF);; // MLKEM_LOAD_SEED
	write_INTF(interface, &op, CONTROL, sizeof(unsigned long long int));

	for (int i = 0; i < 4; i++) {
		reg_addr = (unsigned long long int)(i);
		write_INTF(interface, &reg_addr, ADDRESS, sizeof(unsigned long long int));
		memcpy(&reg_data_in, sk + (8 * i + (LEN_DK - 32 - 32)), 8);
		write_INTF(interface, &reg_data_in, DATA_IN, sizeof(unsigned long long int));
	}

	// load_z
	op = (unsigned long long int)ADD_MLKEM << 32 | ((op_mode | MLKEM_LOAD_PS) & 0xFFFFFFFF);; // MLKEM_LOAD_SEED
	write_INTF(interface, &op, CONTROL, sizeof(unsigned long long int));

	for (int i = 0; i < 4; i++) {
		reg_addr = (unsigned long long int)(i);
		write_INTF(interface, &reg_addr, ADDRESS, sizeof(unsigned long long int));
		memcpy(&reg_data_in, sk + (8 * i + (LEN_DK - 32)), 8);
		write_INTF(interface, &reg_data_in, DATA_IN, sizeof(unsigned long long int));
	}


	// start
	op = (unsigned long long int)ADD_MLKEM << 32 | ((op_mode | MLKEM_START) & 0xFFFFFFFF);; // MLKEM_START
	write_INTF(interface, &op, CONTROL, sizeof(unsigned long long int));

	unsigned long long int end_op = 0;
	// wait END_OP
	while (!end_op) read_INTF(interface, &end_op, END_OP, sizeof(unsigned long long int));

	*result = end_op; // 01: bad result, 11: good result
	
	// read ss
	op = (unsigned long long int)ADD_MLKEM << 32 | ((op_mode | MLKEM_READ_SS) & 0xFFFFFFFF); // MLKEM_READ_K(SS)
	write_INTF(interface, &op, CONTROL, sizeof(unsigned long long int));

	for (int i = 0; i < 4; i++) {
		reg_addr = (unsigned long long int)(i);
		write_INTF(interface, &reg_addr, ADDRESS, sizeof(unsigned long long int));
		read_INTF(interface, &reg_data_out, DATA_OUT, sizeof(unsigned long long int));
		memcpy(ss + 8 * i, &reg_data_out, 8);
	}

}

