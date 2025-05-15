
#ifndef _RSA_BASE_H
#define _RSA_BASE_H
	
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "bignum.h"

void rsaGenerateKeyPair(size_t k, uint32_t e, unsigned char** pri_key, unsigned int* len_pri,
	unsigned char** pub_key, unsigned int* len_pub);

void rsaEncrypt(unsigned char* plaintext, unsigned int plaintext_len, const unsigned char** pub_key, unsigned int pub_len,
	unsigned char** ciphertext, unsigned int* ciphertext_len);

void rsaDecrypt(unsigned char** result, unsigned int* result_len, const unsigned char** pri_key, unsigned int pri_len,
	unsigned char* ciphertext, unsigned int ciphertext_len);

#endif