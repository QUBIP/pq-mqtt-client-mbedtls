/**
  * @file mlkem_gen.c
  * @brief ML-KEM Key Generation code
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

void MLKEM_512_GEN_KEYS(unsigned char* pk, unsigned char* sk) {

	uint8_t coins[2 * KYBER_SYMBYTES];
	randombytes_mlkem(coins, 2 * KYBER_SYMBYTES);

	indcpa_keypair_512(pk, sk, coins);

	memcpy(sk + KYBER_INDCPA_SECRETKEYBYTES_512, pk, KYBER_INDCPA_PUBLICKEYBYTES_512);
	hash_h(sk + KYBER_SECRETKEYBYTES_512 - 2 * KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES_512);
	memcpy(sk + KYBER_SECRETKEYBYTES_512 - KYBER_SYMBYTES, coins + KYBER_SYMBYTES, KYBER_SYMBYTES);
}

void MLKEM_768_GEN_KEYS(unsigned char* pk, unsigned char* sk) {

	uint8_t coins[2 * KYBER_SYMBYTES];
	randombytes_mlkem(coins, 2 * KYBER_SYMBYTES);

	indcpa_keypair_768(pk, sk, coins);

	memcpy(sk + KYBER_INDCPA_SECRETKEYBYTES_768, pk, KYBER_INDCPA_PUBLICKEYBYTES_768);
	hash_h(sk + KYBER_SECRETKEYBYTES_768 - 2 * KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES_768);
	memcpy(sk + KYBER_SECRETKEYBYTES_768 - KYBER_SYMBYTES, coins + KYBER_SYMBYTES, KYBER_SYMBYTES);
}

void MLKEM_1024_GEN_KEYS(unsigned char* pk, unsigned char* sk) {
	
	uint8_t coins[2 * KYBER_SYMBYTES];
	randombytes_mlkem(coins, 2 * KYBER_SYMBYTES);

	indcpa_keypair_1024(pk, sk, coins);
	
	memcpy(sk + KYBER_INDCPA_SECRETKEYBYTES_1024, pk, KYBER_INDCPA_PUBLICKEYBYTES_1024);
	hash_h(sk + KYBER_SECRETKEYBYTES_1024 - 2 * KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES_1024);
	memcpy(sk + KYBER_SECRETKEYBYTES_1024 - KYBER_SYMBYTES, coins + KYBER_SYMBYTES, KYBER_SYMBYTES);

}
