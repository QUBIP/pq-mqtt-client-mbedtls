/**
 * @file eddsa_hw.c
 * @brief EdDSA25519 Test File
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
// File Name: eddsa_hw.c
// Project Name: SE-QUBIP
// Target Devices: PYNQ-Z2
// Description:
//
//		EdDSA25519 HW Handler Functions
//
////////////////////////////////////////////////////////////////////////////////////
#include "eddsa_hw.h"

/////////////////////////////////////////////////////////////////////////////////////////////
// EDDSA25519 GENERATE PUBLIC KEY
/////////////////////////////////////////////////////////////////////////////////////////////

void eddsa25519_genkeys_hw(unsigned char **pri_key, unsigned char **pub_key,
		unsigned int *pri_len, unsigned int *pub_len, bool ext_key,
		uint8_t *key_id, INTF interface) {
	//-- Generate a random private key
	*pri_len = EDDSA_BYTES;
	*pub_len = EDDSA_BYTES;

	*pri_key = (unsigned char*) malloc(*pri_len);
	*pub_key = (unsigned char*) malloc(*pub_len);

	if (ext_key) {
		gen_priv_key(*pri_key, *pri_len);
	} else {
		uint8_t key[64];
		secmem_get_key(ID_EDDSA, *key_id, key, interface);
		memcpy(*pri_key, key, 32);
	}

	// unsigned char test_private_key[32] = {0x64, 0x39, 0xe5, 0x39, 0x4f, 0x42, 0x67, 0x2c, 0x44, 0x0f, 0x9b, 0x18, 0x2f, 0x7e, 0x1c, 0x50, 0xb5, 0x4a, 0xb6, 0x61, 0x06, 0x8d, 0xc6, 0x02, 0xbb, 0x84, 0x67, 0x45, 0xa3, 0xca, 0xb0, 0x22};
	// memcpy(*pri_key, test_private_key, 32);

	/*
	 printf("Private = 0x");
	 for (int i = 0; i < EDDSA_BYTES; i++)
	 {
	 printf("%02x", *(*pri_key + i));
	 }
	 printf("\n");
	 */

	//-- se_code = { {(32'b) 64-bit data_packages}, {13'b0}, {eddsa25519_verify, eddsa25519_sign, eddsa25519_genkeys}, {(16'b)EdDSA25519} }
	uint64_t control = 0;
	while (control != CMD_SE_CODE) {
		picorv32_control(interface, &control);
	}
	uint64_t eddsa_op_sel = ((uint16_t) !ext_key << 15)
			| ((uint16_t) (*key_id << 9)) | EDDSA_OP_KEY_GEN;
	uint64_t se_code = ((uint32_t) eddsa_op_sel << 16) | ECDSA_SE_CODE;
	write_INTF(interface, &se_code, PICORV32_DATA_IN, AXI_BYTES);

	//-- Send Private Key
	if (ext_key) {
		while (control != CMD_SE_WRITE) {
			picorv32_control(interface, &control);
		}
		for (int i = EDDSA_BYTES / AXI_BYTES - 1; i >= 0; i--) {
			write_INTF(interface, *pri_key + i * AXI_BYTES, PICORV32_DATA_IN,
					AXI_BYTES);
		}
	}

	//-- Read Private Key
	while (control != CMD_SE_READ) {
		picorv32_control(interface, &control);
	}
	for (int i = EDDSA_BYTES / AXI_BYTES - 1; i >= 0; i--) {
		read_INTF(interface, *pub_key + i * AXI_BYTES, PICORV32_DATA_OUT,
				AXI_BYTES);
	}

	while (control != CMD_SE_CODE) {
		picorv32_control(interface, &control);
	}
}

/////////////////////////////////////////////////////////////////////////////////////////////
// EDDSA25519 SIGNATURE GENERATION
/////////////////////////////////////////////////////////////////////////////////////////////

void eddsa25519_sign_hw(unsigned char *msg, unsigned int msg_len,
		unsigned char *pri_key, unsigned int pri_len, unsigned char *pub_key,
		unsigned int pub_len, unsigned char **sig, unsigned int *sig_len,
		bool ext_key, uint8_t *key_id, INTF interface) {
	//-- Signature Size
	*sig_len = SIG_BYTES;
	*sig = (unsigned char*) malloc(*sig_len);

	//-- Number of Message Blocks and Padding
	unsigned int complete_len = ((msg_len + MSG_BLOCK_BYTES - 1)
			/ MSG_BLOCK_BYTES) * MSG_BLOCK_BYTES + HASH_1_OFFSET_BYTES; // Add extra BYTES for the Hash offset
	unsigned char *msg_pad;

	msg_pad = (unsigned char*) malloc(complete_len);
	memset(msg_pad, 0, complete_len);
	memcpy(msg_pad, msg, msg_len);

	//-- se_code = { {(32'b) 64-bit data_packages}, {13'b0}, {eddsa25519_verify, eddsa25519_sign, eddsa25519_genkeys}, {(16'b)EdDSA25519} }
	uint64_t control = 0;
	while (control != CMD_SE_CODE) {
		picorv32_control(interface, &control);
	}
	uint64_t eddsa_op_sel = ((uint16_t) !ext_key << 15)
			| ((uint16_t) (*key_id << 9)) | EDDSA_OP_SIGN;
	uint64_t se_code = ((uint32_t) eddsa_op_sel << 16) | ECDSA_SE_CODE;
	write_INTF(interface, &se_code, PICORV32_DATA_IN, AXI_BYTES);

	//-- Send Message Length
	while (control != CMD_SE_WAIT) {
		picorv32_control(interface, &control);
	}
	uint64_t msg_len_bits = msg_len * 8;
	write_INTF(interface, &msg_len_bits, PICORV32_DATA_IN, AXI_BYTES); // MESSAGE LENGTH

	//-- Send Public & Private Key & 1st Message
	if (ext_key) {
		while (control != CMD_SE_WRITE) {
			picorv32_control(interface, &control);
		}

		for (int i = EDDSA_BYTES / AXI_BYTES - 1; i >= 0; i--) {
			write_INTF(interface, pri_key + i * AXI_BYTES, PICORV32_DATA_IN,
					AXI_BYTES);   // PRIVATE KEY
		}

		for (int i = EDDSA_BYTES / AXI_BYTES - 1; i >= 0; i--) {
			write_INTF(interface, pub_key + i * AXI_BYTES, PICORV32_DATA_IN,
					AXI_BYTES);   // PUBLIC KEY
		}
	}

	while (control != CMD_SE_WRITE) {
		picorv32_control(interface, &control);
	}

	for (int i = MSG_BLOCK_BYTES / AXI_BYTES - 1; i >= 0; i--) {
		write_INTF(interface, msg_pad + i * AXI_BYTES, PICORV32_DATA_IN,
				AXI_BYTES);   // 1st MESSAGE BLOCK
	}

	//-- Bytes Sent
	unsigned int bytes_sent = HASH_1_OFFSET_BYTES;
	bool is_1st_hash_2 = true;

	//-- Loop until all message blocks are processed for the 1st HASH
	unsigned int packages_sent = 0; // 64-bit packages sent to manage FIFO

	while (bytes_sent <= msg_len + 16) {
		while (control != CMD_SE_WRITE) {
			picorv32_control(interface, &control);
		}

		for (int i = MSG_BLOCK_BYTES / AXI_BYTES - 1; i >= 0; i--) {
			write_INTF(interface, msg_pad + bytes_sent + i * AXI_BYTES,
					PICORV32_DATA_IN, AXI_BYTES);   // Next MESSAGE BLOCK
		}

		bytes_sent += MSG_BLOCK_BYTES;
		packages_sent += MSG_BLOCK_BYTES / 8;

		if (packages_sent == (FIFO_IN_DEPTH - MSG_BLOCK_BYTES / 8)) {
			while (control != CMD_SE_WAIT) {
				picorv32_control(interface, &control);
				if (control == CMD_SE_WAIT)
					read_INTF(interface, *sig, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
			}
			packages_sent = 0;
		}
	}

	//-- Update the number of bytes sent for the 2nd HASH
	if (msg_len + 16 >= HASH_2_OFFSET_BYTES) {
		bytes_sent = 0;
	}

	//-- Loop until all message blocks are processed for the 2nd HASH
	while (bytes_sent <= msg_len + 16) {
		while (control != CMD_SE_WRITE) {
			picorv32_control(interface, &control);
		}

		for (int i = MSG_BLOCK_BYTES / AXI_BYTES - 1; i >= 0; i--) {
			write_INTF(interface, msg_pad + bytes_sent + i * AXI_BYTES,
					PICORV32_DATA_IN, AXI_BYTES);   // Next MESSAGE BLOCK
		}

		bytes_sent += MSG_BLOCK_BYTES;
		packages_sent += MSG_BLOCK_BYTES / 8;

		if (is_1st_hash_2) {
			bytes_sent -= 64;
			is_1st_hash_2 = false;
		}

		if (packages_sent == (FIFO_IN_DEPTH - MSG_BLOCK_BYTES / 8)) {
			while (control != CMD_SE_WAIT) {
				picorv32_control(interface, &control);
				if (control == CMD_SE_WAIT)
					read_INTF(interface, *sig, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
			}
			packages_sent = 0;
		}
	}

	//-- Read Signature
	while (control != CMD_SE_READ) {
		picorv32_control(interface, &control);
	}
	for (int i = SIG_BYTES / AXI_BYTES - 1; i >= 0; i--) {
		read_INTF(interface, *sig + i * AXI_BYTES, PICORV32_DATA_OUT,
				AXI_BYTES);
	}

	while (control != CMD_SE_CODE) {
		picorv32_control(interface, &control);
	}
}

/////////////////////////////////////////////////////////////////////////////////////////////
// EDDSA25519 SIGNATURE VERIFICATION
/////////////////////////////////////////////////////////////////////////////////////////////

void eddsa25519_verify_hw(unsigned char *msg, unsigned int msg_len,
		unsigned char *pub_key, unsigned int pub_len, unsigned char *sig,
		unsigned int sig_len, unsigned int *result, bool ext_key,
		uint8_t *key_id, INTF interface) {
	//-- Number of Message Blocks and Padding
	unsigned int complete_len = ((msg_len + MSG_BLOCK_BYTES - 1)
			/ MSG_BLOCK_BYTES) * MSG_BLOCK_BYTES + HASH_1_OFFSET_BYTES; // Add extra BYTES for the Hash offset
	unsigned char *msg_pad;

	msg_pad = (unsigned char*) malloc(complete_len);
	memset(msg_pad, 0, complete_len);
	memcpy(msg_pad, msg, msg_len);

	//-- se_code = { {(32'b) 64-bit data_packages}, {13'b0}, {eddsa25519_verify, eddsa25519_sign, eddsa25519_genkeys}, {(16'b)EdDSA25519} }
	uint64_t control = 0;
	while (control != CMD_SE_CODE) {
		picorv32_control(interface, &control);
	}
	uint64_t eddsa_op_sel = ((uint16_t) !ext_key << 15)
			| ((uint16_t) (*key_id << 9)) | EDDSA_OP_VERIFY;
	uint64_t se_code = ((uint32_t) eddsa_op_sel << 16) | ECDSA_SE_CODE;
	write_INTF(interface, &se_code, PICORV32_DATA_IN, AXI_BYTES);

	//-- Send Message Length
	while (control != CMD_SE_WAIT) {
		picorv32_control(interface, &control);
	}
	uint64_t msg_len_bits = msg_len * 8;
	write_INTF(interface, &msg_len_bits, PICORV32_DATA_IN, AXI_BYTES); // MESSAGE LENGTH

	//-- Send Public Key & 1st Message
	if (ext_key) {
		while (control != CMD_SE_WRITE) {
			picorv32_control(interface, &control);
		}

		for (int i = EDDSA_BYTES / AXI_BYTES - 1; i >= 0; i--) {
			write_INTF(interface, pub_key + i * AXI_BYTES, PICORV32_DATA_IN,
					AXI_BYTES);   // PUBLIC KEY
		}
	}

	while (control != CMD_SE_WRITE) {
		picorv32_control(interface, &control);
	}

	for (int i = MSG_BLOCK_BYTES / AXI_BYTES - 1; i >= 0; i--) {
		write_INTF(interface, msg_pad + i * AXI_BYTES, PICORV32_DATA_IN,
				AXI_BYTES);   // 1st MESSAGE BLOCK

		// verilog_display(true, "buffer_in = 0x%02x%02x%02x%02x%02x%02x%02x%02x", buffer_in[0+(i+packages_sent)*AXI_BYTES], buffer_in[1+(i+packages_sent)*AXI_BYTES], buffer_in[2+(i+packages_sent)*AXI_BYTES], buffer_in[3+(i+packages_sent)*AXI_BYTES], buffer_in[4+(i+packages_sent)*AXI_BYTES], buffer_in[5+(i+packages_sent)*AXI_BYTES], buffer_in[6+(i+packages_sent)*AXI_BYTES], buffer_in[7+(i+packages_sent)*AXI_BYTES]);
	}

	//-- Send Signature
	while (control != CMD_SE_WAIT) {
		picorv32_control(interface, &control);
	}

	for (int i = SIG_BYTES / AXI_BYTES - 1; i >= 0; i--) {
		write_INTF(interface, sig + i * AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES); // SIGNATURE

		// verilog_display(true, "buffer_in = 0x%02x%02x%02x%02x%02x%02x%02x%02x", buffer_in[0+(i+packages_sent)*AXI_BYTES], buffer_in[1+(i+packages_sent)*AXI_BYTES], buffer_in[2+(i+packages_sent)*AXI_BYTES], buffer_in[3+(i+packages_sent)*AXI_BYTES], buffer_in[4+(i+packages_sent)*AXI_BYTES], buffer_in[5+(i+packages_sent)*AXI_BYTES], buffer_in[6+(i+packages_sent)*AXI_BYTES], buffer_in[7+(i+packages_sent)*AXI_BYTES]);
	}

	//-- Bytes Sent
	unsigned int bytes_sent = HASH_2_OFFSET_BYTES;

	//-- Loop until all message blocks are processed for the 2nd HASH (There is only 1 hash but equivalent to the 2nd of the sign)
	unsigned int packages_sent = 0; // 64-bit packages sent to manage FIFO

	while (bytes_sent <= msg_len + 16) {
		while (control != CMD_SE_WRITE) {
			picorv32_control(interface, &control);
			if (control == CMD_SE_READ)
				goto EDDSA_READ_RESULT;
		}

		for (int i = MSG_BLOCK_BYTES / AXI_BYTES - 1; i >= 0; i--) {
			write_INTF(interface, msg_pad + bytes_sent + i * AXI_BYTES,
					PICORV32_DATA_IN, AXI_BYTES);   // Next MESSAGE BLOCK
		}

		bytes_sent += MSG_BLOCK_BYTES;
		packages_sent += MSG_BLOCK_BYTES / 8;

		if (packages_sent == (FIFO_IN_DEPTH - MSG_BLOCK_BYTES / 8)) {
			while (control != CMD_SE_WAIT) {
				picorv32_control(interface, &control);
				if (control == CMD_SE_WAIT)
					read_INTF(interface, result, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
				if (control == CMD_SE_READ)
					goto EDDSA_READ_RESULT;
			}
			packages_sent = 0;
		}
	}

	//-- Read Result
	EDDSA_READ_RESULT: uint64_t result_64 = 0;
	while (control != CMD_SE_READ) {
		picorv32_control(interface, &control);
	}
	read_INTF(interface, &result_64, PICORV32_DATA_OUT, AXI_BYTES);

	*result = (unsigned int) result_64;

	while (control != CMD_SE_CODE) {
		picorv32_control(interface, &control);
	}
}
