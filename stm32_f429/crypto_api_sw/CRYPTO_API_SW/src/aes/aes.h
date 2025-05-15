/**
  * @file aes.h
  * @brief AES header
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

#ifndef AES_H
#define	AES_H

#ifdef OPENSSL
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#elif MBEDTLS
#include "mbedtls/aes.h"
#include "mbedtls/cmac.h"
#include "mbedtls/cipher.h"
#include "mbedtls/gcm.h"
#include "mbedtls/ccm.h"
#else
#include "alt/aes_base.h"
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>


// --- AES - ECB --- //
void AES_128_ECB_ENCRYPT(unsigned char* key, unsigned char* ciphertext, unsigned int* ciphertext_len, unsigned char* plaintext, unsigned int plaintext_len);
void AES_128_ECB_DECRYPT(unsigned char* key, unsigned char* ciphertext, unsigned int ciphertext_len, unsigned char* plaintext, unsigned int* plaintext_len);
void AES_192_ECB_ENCRYPT(unsigned char* key, unsigned char* ciphertext, unsigned int* ciphertext_len, unsigned char* plaintext, unsigned int plaintext_len);
void AES_192_ECB_DECRYPT(unsigned char* key, unsigned char* ciphertext, unsigned int ciphertext_len, unsigned char* plaintext, unsigned int* plaintext_len);
void AES_256_ECB_ENCRYPT(unsigned char* key, unsigned char* ciphertext, unsigned int* ciphertext_len, unsigned char* plaintext, unsigned int plaintext_len);
void AES_256_ECB_DECRYPT(unsigned char* key, unsigned char* ciphertext, unsigned int ciphertext_len, unsigned char* plaintext, unsigned int* plaintext_len);

// --- AES - CBC --- //
void AES_128_CBC_ENCRYPT(unsigned char* key, unsigned char* iv, unsigned char* ciphertext, unsigned int* ciphertext_len, unsigned char* plaintext, unsigned int plaintext_len);
void AES_128_CBC_DECRYPT(unsigned char* key, unsigned char* iv, unsigned char* ciphertext, unsigned int ciphertext_len, unsigned char* plaintext, unsigned int* plaintext_len);
void AES_192_CBC_ENCRYPT(unsigned char* key, unsigned char* iv, unsigned char* ciphertext, unsigned int* ciphertext_len, unsigned char* plaintext, unsigned int plaintext_len);
void AES_192_CBC_DECRYPT(unsigned char* key, unsigned char* iv, unsigned char* ciphertext, unsigned int ciphertext_len, unsigned char* plaintext, unsigned int* plaintext_len);
void AES_256_CBC_ENCRYPT(unsigned char* key, unsigned char* iv, unsigned char* ciphertext, unsigned int* ciphertext_len, unsigned char* plaintext, unsigned int plaintext_len);
void AES_256_CBC_DECRYPT(unsigned char* key, unsigned char* iv, unsigned char* ciphertext, unsigned int ciphertext_len, unsigned char* plaintext, unsigned int* plaintext_len);

// --- AES - CMAC --- //
void AES_128_CMAC(unsigned char* key, unsigned char* mac, unsigned int* mac_len, unsigned char* msg, unsigned int msg_len);
void AES_192_CMAC(unsigned char* key, unsigned char* mac, unsigned int* mac_len, unsigned char* msg, unsigned int msg_len);
void AES_256_CMAC(unsigned char* key, unsigned char* mac, unsigned int* mac_len, unsigned char* msg, unsigned int msg_len);

// --- AES - GCM --- //
void AES_128_GCM_ENCRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int* ciphertext_len,
    unsigned char* plaintext, unsigned int plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag);
void AES_128_GCM_DECRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int ciphertext_len,
    unsigned char* plaintext, unsigned int* plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag, unsigned int* result);
void AES_192_GCM_ENCRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int* ciphertext_len,
    unsigned char* plaintext, unsigned int plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag);
void AES_192_GCM_DECRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int ciphertext_len,
    unsigned char* plaintext, unsigned int* plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag, unsigned int* result);
void AES_256_GCM_ENCRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int* ciphertext_len,
    unsigned char* plaintext, unsigned int plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag);
void AES_256_GCM_DECRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int ciphertext_len,
    unsigned char* plaintext, unsigned int* plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag, unsigned int* result);

// --- AES - CCM_8 --- //
void AES_128_CCM_8_ENCRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int* ciphertext_len,
    unsigned char* plaintext, unsigned int plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag);
void AES_128_CCM_8_DECRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int ciphertext_len,
    unsigned char* plaintext, unsigned int* plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag, unsigned int* result);
void AES_192_CCM_8_ENCRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int* ciphertext_len,
    unsigned char* plaintext, unsigned int plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag);
void AES_192_CCM_8_DECRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int ciphertext_len,
    unsigned char* plaintext, unsigned int* plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag, unsigned int* result);
void AES_256_CCM_8_ENCRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int* ciphertext_len,
    unsigned char* plaintext, unsigned int plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag);
void AES_256_CCM_8_DECRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int ciphertext_len,
    unsigned char* plaintext, unsigned int* plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag, unsigned int* result);

#endif
