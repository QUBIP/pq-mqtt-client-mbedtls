/**
  * @file hmac.c
  * @brief HMAC code
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

#include "hmac.h"

void hmac_sha256(unsigned char* key, unsigned int len_key, unsigned char* msg, unsigned int len_msg, unsigned char* hmac) {
	
	unsigned char k_prime[64]; memset(k_prime, 0, 64);

	// Compute k_prime
	if (len_key > 64) {
		sha256Compute(key, len_key, k_prime);
	}
	else {
		memcpy(k_prime, key, len_key);
	}

	// Compute ipad & opad
	unsigned char k_opad[64]; memcpy(k_opad, k_prime, 64);
	unsigned char k_ipad[64]; memcpy(k_ipad, k_prime, 64);
	//XOR the resulting key with ipad
	for (int i = 0; i < 64; i++)
	{
		k_ipad[i] ^= HMAC_IPAD;
		k_opad[i] ^= HMAC_OPAD;
	}

	// Compute H(k_ipad | msg)
	unsigned char* msg_concat;
	msg_concat = malloc(64 + len_msg);
	memcpy(msg_concat, k_ipad, 64);
	memcpy(msg_concat + 64, msg, len_msg);

	unsigned char H1[32];
	sha256Compute(msg_concat, (64 + len_msg), H1);

	unsigned char a[128];
	memcpy(a, k_opad, 64);
	memcpy(a + 64, H1, 32);
	sha256Compute(a, (64 + 32), hmac);

	free(msg_concat);

}