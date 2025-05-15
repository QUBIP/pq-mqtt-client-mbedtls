/**
  * @file mlkem_dec.c
  * @brief ML-KEM Decapsulation code
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

#include "mlkem.h"

void MLKEM_512_DEC(unsigned char* ss, const unsigned char* ct, const unsigned char* sk, unsigned int* result)
{
	int fail;
	uint8_t buf[2 * KYBER_SYMBYTES];
	uint8_t kr[2 * KYBER_SYMBYTES];

	uint8_t cmp[KYBER_CIPHERTEXTBYTES_512 + KYBER_SYMBYTES];
	const uint8_t* pk = sk + KYBER_INDCPA_SECRETKEYBYTES_512;

	indcpa_dec_512(buf, ct, sk);

	memcpy(buf + KYBER_SYMBYTES, sk + KYBER_SECRETKEYBYTES_512 - 2 * KYBER_SYMBYTES, KYBER_SYMBYTES);
	hash_g(kr, buf, 2 * KYBER_SYMBYTES);

	indcpa_enc_512(cmp, buf, pk, kr + KYBER_SYMBYTES);

	fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES_512);

	rkprf_512(ss, sk + KYBER_SECRETKEYBYTES_512 - KYBER_SYMBYTES, ct);

	cmov(ss, kr, KYBER_SYMBYTES, !fail);
	
	*result = fail; // 0 equal
}

void MLKEM_768_DEC(unsigned char* ss, const unsigned char* ct, const unsigned char* sk, unsigned int* result)
{
	int fail;
	uint8_t buf[2 * KYBER_SYMBYTES];
	uint8_t kr[2 * KYBER_SYMBYTES];

	uint8_t cmp[KYBER_CIPHERTEXTBYTES_768 + KYBER_SYMBYTES];
	const uint8_t* pk = sk + KYBER_INDCPA_SECRETKEYBYTES_768;

	indcpa_dec_768(buf, ct, sk);

	memcpy(buf + KYBER_SYMBYTES, sk + KYBER_SECRETKEYBYTES_768 - 2 * KYBER_SYMBYTES, KYBER_SYMBYTES);
	hash_g(kr, buf, 2 * KYBER_SYMBYTES);

	indcpa_enc_768(cmp, buf, pk, kr + KYBER_SYMBYTES);

	fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES_768);

	rkprf_768(ss, sk + KYBER_SECRETKEYBYTES_768 - KYBER_SYMBYTES, ct);

	cmov(ss, kr, KYBER_SYMBYTES, !fail);

	*result = fail; // 0 equal
}

void MLKEM_1024_DEC(unsigned char* ss, const unsigned char* ct, const unsigned char* sk, unsigned int* result)
{
	int fail;
	uint8_t buf[2 * KYBER_SYMBYTES];
	uint8_t kr[2 * KYBER_SYMBYTES];

	uint8_t cmp[KYBER_CIPHERTEXTBYTES_1024 + KYBER_SYMBYTES];
	const uint8_t* pk = sk + KYBER_INDCPA_SECRETKEYBYTES_1024;

	indcpa_dec_1024(buf, ct, sk);

	memcpy(buf + KYBER_SYMBYTES, sk + KYBER_SECRETKEYBYTES_1024 - 2 * KYBER_SYMBYTES, KYBER_SYMBYTES);
	hash_g(kr, buf, 2 * KYBER_SYMBYTES);

	indcpa_enc_1024(cmp, buf, pk, kr + KYBER_SYMBYTES);

	fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES_1024);

	rkprf_1024(ss, sk + KYBER_SECRETKEYBYTES_1024 - KYBER_SYMBYTES, ct);

	cmov(ss, kr, KYBER_SYMBYTES, !fail);

	*result = fail; // 0 equal
}

