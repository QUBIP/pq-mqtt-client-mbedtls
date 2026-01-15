/**
 * @file aes_cbc.c
 * @brief AES CBC mode
 *
 * @section License
 *
 * MIT License
 *
 * Copyright (c) 2024 Eros Camacho
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 *
 *
 * @author Eros Camacho-Ruiz (camacho@imse-cnm.csic.es)
 * @version 4.0
 **/

#include "scp03/aes/aes.h"

// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
// https://csrc.nist.gov/Projects/block-cipher-techniques/BCM
// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

void AES_128_CBC_ENCRYPT(unsigned char *key, unsigned char *iv,
		unsigned char *ciphertext, unsigned int *ciphertext_len,
		unsigned char *plaintext, unsigned int plaintext_len) {
	AesContext aes_ctx;
	aesInit(&aes_ctx, key, 16);

	size_t len = 0;
	*ciphertext_len = plaintext_len;

	unsigned char p[16];
	unsigned char c[16];

	unsigned char iv_block[16];
	memcpy(iv_block, iv, 16);

	//ECB mode operates in a block-by-block fashion
	while (len < plaintext_len) {
		memcpy(p, plaintext + len, 16);

		for (int i = 0; i < 16; i++) {
			p[i] = p[i] ^ iv_block[i];
		}

		//Encrypt current block
		aesEncryptBlock(&aes_ctx, p, c);

		for (int i = 0; i < 16; i++) {
			ciphertext[i + len] = c[i];
		}

		len += 16;

		memcpy(iv_block, c, 16);

	}

}

void AES_128_CBC_DECRYPT(unsigned char *key, unsigned char *iv,
		unsigned char *ciphertext, unsigned int ciphertext_len,
		unsigned char *plaintext, unsigned int *plaintext_len) {
	AesContext aes_ctx;
	aesInit(&aes_ctx, key, 16);

	size_t len = 0;
	*plaintext_len = ciphertext_len;

	unsigned char p[16];
	unsigned char c[16];

	unsigned char iv_block[16];
	memcpy(iv_block, iv, 16);

	//ECB mode operates in a block-by-block fashion
	while (len < ciphertext_len) {
		memcpy(c, ciphertext + len, 16);

		//Encrypt current block
		aesDecryptBlock(&aes_ctx, c, p);

		for (int i = 0; i < 16; i++) {
			plaintext[i + len] = p[i] ^ iv_block[i];
		}

		len += 16;

		memcpy(iv_block, c, 16);

	}

}

void AES_192_CBC_ENCRYPT(unsigned char *key, unsigned char *iv,
		unsigned char *ciphertext, unsigned int *ciphertext_len,
		unsigned char *plaintext, unsigned int plaintext_len) {
	AesContext aes_ctx;
	aesInit(&aes_ctx, key, 24);

	size_t len = 0;
	*ciphertext_len = plaintext_len;

	unsigned char p[16];
	unsigned char c[16];

	unsigned char iv_block[16];
	memcpy(iv_block, iv, 16);

	//ECB mode operates in a block-by-block fashion
	while (len < plaintext_len) {
		memcpy(p, plaintext + len, 16);

		for (int i = 0; i < 16; i++) {
			p[i] = p[i] ^ iv_block[i];
		}

		//Encrypt current block
		aesEncryptBlock(&aes_ctx, p, c);

		for (int i = 0; i < 16; i++) {
			ciphertext[i + len] = c[i];
		}

		len += 16;

		memcpy(iv_block, c, 16);

	}

}

void AES_192_CBC_DECRYPT(unsigned char *key, unsigned char *iv,
		unsigned char *ciphertext, unsigned int ciphertext_len,
		unsigned char *plaintext, unsigned int *plaintext_len) {
	AesContext aes_ctx;
	aesInit(&aes_ctx, key, 24);

	size_t len = 0;
	*plaintext_len = ciphertext_len;

	unsigned char p[16];
	unsigned char c[16];

	unsigned char iv_block[16];
	memcpy(iv_block, iv, 16);

	//ECB mode operates in a block-by-block fashion
	while (len < ciphertext_len) {
		memcpy(c, ciphertext + len, 16);

		//Encrypt current block
		aesDecryptBlock(&aes_ctx, c, p);

		for (int i = 0; i < 16; i++) {
			plaintext[i + len] = p[i] ^ iv_block[i];
		}

		len += 16;

		memcpy(iv_block, c, 16);

	}

}

void AES_256_CBC_ENCRYPT(unsigned char *key, unsigned char *iv,
		unsigned char *ciphertext, unsigned int *ciphertext_len,
		unsigned char *plaintext, unsigned int plaintext_len) {
	AesContext aes_ctx;
	aesInit(&aes_ctx, key, 32);

	size_t len = 0;
	*ciphertext_len = plaintext_len;

	unsigned char p[16];
	unsigned char c[16];

	unsigned char iv_block[16];
	memcpy(iv_block, iv, 16);

	//ECB mode operates in a block-by-block fashion
	while (len < plaintext_len) {
		memcpy(p, plaintext + len, 16);

		for (int i = 0; i < 16; i++) {
			p[i] = p[i] ^ iv_block[i];
		}

		//Encrypt current block
		aesEncryptBlock(&aes_ctx, p, c);

		for (int i = 0; i < 16; i++) {
			ciphertext[i + len] = c[i];
		}

		len += 16;

		memcpy(iv_block, c, 16);

	}

}

void AES_256_CBC_DECRYPT(unsigned char *key, unsigned char *iv,
		unsigned char *ciphertext, unsigned int ciphertext_len,
		unsigned char *plaintext, unsigned int *plaintext_len) {
	AesContext aes_ctx;
	aesInit(&aes_ctx, key, 32);

	size_t len = 0;
	*plaintext_len = ciphertext_len;

	unsigned char p[16];
	unsigned char c[16];

	unsigned char iv_block[16];
	memcpy(iv_block, iv, 16);

	//ECB mode operates in a block-by-block fashion
	while (len < ciphertext_len) {
		memcpy(c, ciphertext + len, 16);

		//Encrypt current block
		aesDecryptBlock(&aes_ctx, c, p);

		for (int i = 0; i < 16; i++) {
			plaintext[i + len] = p[i] ^ iv_block[i];
		}

		len += 16;

		memcpy(iv_block, c, 16);

	}

}

