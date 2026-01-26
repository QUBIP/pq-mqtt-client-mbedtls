#include "scp03/kdf/scp03_kdf.h"
#include <string.h>
#include <stdio.h>

// Helper function for a single KDF operation
static void scp03_kdf_internal(int key_bits, unsigned char *key,
		unsigned char constant, int L_bits, unsigned char *host_challenge,
		unsigned char *card_challenge, unsigned char *output) {
	unsigned char input_data[48]; // Fixed 48-byte buffer for SCP-03 KDF input
	unsigned char prf_result[16]; // CMAC output is always 16 bytes (128 bits)
	unsigned int mac_len = 16;

	int bytes_needed = L_bits / 8;
	int iterations = (bytes_needed + 15) / 16; // Ceil division

	// L parameter for message construction
	unsigned int L = L_bits;

	// ----------------------------------------------------------
	// Construct Fixed Input Data (32 bytes)
	// Structure: [Label (11x00 || Const)] [Sep] [L] [i] [Context]
	// ----------------------------------------------------------

	// 1. Label (12 bytes): 11 bytes of 0x00 followed by Constant
	memset(input_data, 0x00, 11);
	input_data[11] = constant;

	// 2. Separator (1 byte): 0x00
	input_data[12] = 0x00;

	// 3. L (2 bytes): Big Endian
	input_data[13] = (unsigned char) ((L >> 8) & 0xFF);
	input_data[14] = (unsigned char) (L & 0xFF);

	// 4. i (1 byte): Counter, set inside loop at index 15

	// 5. Context (32 bytes): Host Challenge || Card Challenge
	memcpy(&input_data[16], host_challenge, 16);
	memcpy(&input_data[32], card_challenge, 16);

	// ----------------------------------------------------------
	// Iteration Loop (NIST SP 800-108)
	// ----------------------------------------------------------
	int offset = 0;

	for (int i = 1; i <= iterations; i++) {
		// Update Counter 'i'
		input_data[15] = (unsigned char) i;

		// Calculate CMAC
		// Note: CMAC output is always 128 bits (16 bytes) regardless of AES key size
		if (key_bits == 128)
			AES_128_CMAC(key, prf_result, &mac_len, input_data, 48);
		else if (key_bits == 192)
			AES_192_CMAC(key, prf_result, &mac_len, input_data, 48);
		else
			AES_256_CMAC(key, prf_result, &mac_len, input_data, 48);

		// Copy result to output buffer
		int bytes_to_copy = 16;
		if (offset + bytes_to_copy > bytes_needed) {
			bytes_to_copy = bytes_needed - offset;
		}

		memcpy(output + offset, prf_result, bytes_to_copy);
		offset += bytes_to_copy;
	}
}

void scp03_derive_session_keys(int key_bits, unsigned char *static_enc_key,
		unsigned char *static_mac_key, unsigned char *host_challenge,
		unsigned char *card_challenge, unsigned char *session_enc,
		unsigned char *session_mac, unsigned char *session_rmac) {
	// Derive S-ENC (Uses Static K-ENC)
	scp03_kdf_internal(key_bits, static_enc_key, SCP03_CONST_ENC, key_bits,
			host_challenge, card_challenge, session_enc);

	// Derive S-MAC (Uses Static K-MAC)
	scp03_kdf_internal(key_bits, static_mac_key, SCP03_CONST_MAC, key_bits,
			host_challenge, card_challenge, session_mac);

	// Derive S-RMAC (Uses Static K-MAC)
	scp03_kdf_internal(key_bits, static_mac_key, SCP03_CONST_RMAC, key_bits,
			host_challenge, card_challenge, session_rmac);
}

void scp03_calc_cryptograms(int key_bits, unsigned char *s_mac,
		unsigned char *host_challenge, unsigned char *card_challenge,
		unsigned char *card_crypt, unsigned char *host_crypt) {
	// L = 128 bits (16 bytes)
	scp03_kdf_internal(key_bits, s_mac, SCP03_CONST_CARD_CRYPT, 0x80,
			host_challenge, card_challenge, card_crypt);
	scp03_kdf_internal(key_bits, s_mac, SCP03_CONST_HOST_CRYPT, 0x80,
			host_challenge, card_challenge, host_crypt);
}
