/**
  * @file mlkem_enc.c
  * @brief ML-KEM Encapsulation code
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

void MLKEM_512_ENC(unsigned char* ct, unsigned char* ss, const unsigned char* pk)
{
	uint8_t buf[2 * KYBER_SYMBYTES];
	uint8_t kr[2 * KYBER_SYMBYTES];
	uint8_t coins[KYBER_SYMBYTES];

	randombytes_mlkem(coins, KYBER_SYMBYTES);

	memcpy(buf, coins, KYBER_SYMBYTES);

	hash_h(buf + KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES_512);
	hash_g(kr, buf, 2 * KYBER_SYMBYTES);

	indcpa_enc_512(ct, buf, pk, kr + KYBER_SYMBYTES);

	memcpy(ss, kr, KYBER_SYMBYTES);
}

void MLKEM_768_ENC(unsigned char* ct, unsigned char* ss, const unsigned char* pk)
{
	uint8_t buf[2 * KYBER_SYMBYTES];
	uint8_t kr[2 * KYBER_SYMBYTES];
	uint8_t coins[KYBER_SYMBYTES];

	randombytes_mlkem(coins, KYBER_SYMBYTES);

	memcpy(buf, coins, KYBER_SYMBYTES);

	hash_h(buf + KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES_768);
	hash_g(kr, buf, 2 * KYBER_SYMBYTES);

	indcpa_enc_768(ct, buf, pk, kr + KYBER_SYMBYTES);

	memcpy(ss, kr, KYBER_SYMBYTES);
}

void MLKEM_1024_ENC(unsigned char* ct, unsigned char* ss, const unsigned char* pk)
{
	uint8_t buf[2 * KYBER_SYMBYTES];
	uint8_t kr[2 * KYBER_SYMBYTES];
	uint8_t coins[KYBER_SYMBYTES];

	randombytes_mlkem(coins, KYBER_SYMBYTES);

	memcpy(buf, coins, KYBER_SYMBYTES);

	hash_h(buf + KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES_1024);
	hash_g(kr, buf, 2 * KYBER_SYMBYTES);

	indcpa_enc_1024(ct, buf, pk, kr + KYBER_SYMBYTES);

	memcpy(ss, kr, KYBER_SYMBYTES);
}
