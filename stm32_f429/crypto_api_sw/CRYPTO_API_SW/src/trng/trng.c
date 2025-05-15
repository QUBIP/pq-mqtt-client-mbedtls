/**
  * @file trng.c
  * @brief Random Number Generators code
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

#include "trng.h"

// https://www.openssl.org/docs/man3.3/man3/RAND_bytes.html

#ifdef OPENSSL
void TRNG(unsigned char* out, unsigned int bytes)
{

    RAND_bytes(out, bytes);

}
// https://docs.openssl.org/3.0/man7/EVP_RAND-CTR-DRBG/#notes
// https://docs.openssl.org/3.1/man7/EVP_RAND-SEED-SRC/#examples

void CTR_DRBG(unsigned char* out, unsigned int bytes) {

    EVP_RAND* rand;
    EVP_RAND_CTX* seed, * rctx;
    OSSL_PARAM params[2], * p = params;
    unsigned int strength = 128;

    /* Create and instantiate a seed source */
    rand = EVP_RAND_fetch(NULL, "SEED-SRC", NULL);
    seed = EVP_RAND_CTX_new(rand, NULL);
    EVP_RAND_instantiate(seed, strength, 0, NULL, 0, NULL);
    EVP_RAND_free(rand);

    /* Feed this into a DRBG */
    rand = EVP_RAND_fetch(NULL, "CTR-DRBG", NULL);
    rctx = EVP_RAND_CTX_new(rand, seed);
    EVP_RAND_free(rand);

    /* Configure the DRBG */
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER,
        SN_aes_256_ctr, 0);
    *p = OSSL_PARAM_construct_end();
    EVP_RAND_instantiate(rctx, strength, 0, NULL, 0, params);

    EVP_RAND_generate(rctx, out, bytes, strength, 0, NULL, 0);

    EVP_RAND_CTX_free(rctx);
    EVP_RAND_CTX_free(seed);

}

void HASH_DRBG(unsigned char* out, unsigned int bytes) {
    
    EVP_RAND* rand;
    EVP_RAND_CTX* rctx;
    OSSL_PARAM params[2], * p = params;
    unsigned int strength = 128;

    rand = EVP_RAND_fetch(NULL, "HASH-DRBG", NULL);
    rctx = EVP_RAND_CTX_new(rand, NULL);
    EVP_RAND_free(rand);

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_DIGEST, SN_sha512, 0);
    *p = OSSL_PARAM_construct_end();
    EVP_RAND_instantiate(rctx, strength, 0, NULL, 0, params);

    EVP_RAND_generate(rctx, out, bytes, strength, 0, NULL, 0);

    EVP_RAND_CTX_free(rctx);

}

#elif MBEDTLS
void TRNG(unsigned char* out, unsigned int bytes)
{
    unsigned char* buf;
    buf = malloc(1024);

    size_t len;

    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);

    len = 0;
    while (len < bytes) {
        mbedtls_entropy_func(&entropy, buf + len, 32);
        len += 32;
    }

    memcpy(out, buf, bytes);

}

void CTR_DRBG(unsigned char* out, unsigned int bytes) {
    
    // Entropy function //
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    unsigned char seed[16];
    sprintf(seed, "%ld", time(NULL));
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, seed, 16);

    mbedtls_ctr_drbg_random(&ctr_drbg, out, (size_t)(bytes));

    mbedtls_ctr_drbg_free(&ctr_drbg);

}
void HASH_DRBG(unsigned char* out, unsigned int bytes) {

    // Entropy function //
    mbedtls_hmac_drbg_context hmac_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_hmac_drbg_init(&hmac_drbg);
    mbedtls_entropy_init(&entropy);

    unsigned char seed[16];
    sprintf(seed, "%ld", time(NULL));

    mbedtls_hmac_drbg_seed(&hmac_drbg, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), mbedtls_entropy_func, &entropy, seed, 16);

    mbedtls_hmac_drbg_random(&hmac_drbg, out, (size_t)(bytes));

    mbedtls_hmac_drbg_free(&hmac_drbg);
}

#else

// check in future ... https://github.com/aws-samples/ctr-drbg-with-vector-aes-ni/blob/master/src/ctr_drbg.c

// Section 10.2.1.2
  // kInitMask is the result of encrypting blocks with big-endian value 1, 2
  // and 3 with the all-zero AES-256 key.
static const uint8_t kInit[48] = {
    0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1,
    0xc4, 0xcb, 0x73, 0x8b, 0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
    0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18, 0x72, 0x60, 0x03, 0xca,
    0x37, 0xa6, 0x2a, 0x74, 0xd1, 0xa2, 0xf5, 0x8e, 0x75, 0x06, 0x35, 0x8e,
};

void TRNG(unsigned char* out, unsigned int bytes)
{
    CTR_DRBG(out, bytes);
}

void CTR_DRBG(unsigned char* out, unsigned int bytes) {

    // This version MUST to be adapted ... for test is ENOUGH

    // seed & key generation
    unsigned char seed[48];
    sprintf(seed, "%ld", time(NULL));

    for (int i = 0; i < 48; i++) {
        seed[i] ^= kInit[i];
    }

    unsigned char key[32]; memcpy(key, seed, 32);
    unsigned char counter[16]; memcpy(counter, seed + 32, 16);
    unsigned char ks[16];  memcpy(ks, seed, 16); 

    for (int i = 0; i < 16; i++) {
        ks[i] ^= counter[i];
    }

    AesContext aes_ctx;
    size_t len = 0; 
    size_t len_up = 0;

    unsigned char temp[48];

    // generation
    while (len < bytes) {
        len_up = 0;
        aesInit(&aes_ctx, key, 32);
        // Update
        while (len_up < 48) {
            counter[15] += 1;
            aesEncryptBlock(&aes_ctx, ks, temp + len_up);
            len_up += 16;
        }
        memcpy(key, temp, 32);
        memcpy(counter, temp + 32, 16);
        memcpy(ks, seed, 16);

        memcpy(out + len, temp, 16);
        len += 16;
    }

}
void HASH_DRBG(unsigned char* out, unsigned int bytes) {

    // This version MUST to be adapted ... for test is ENOUGH

    // seed & key generation
    unsigned char seed[64];
    sprintf(seed, "%ld", time(NULL));

    size_t len = 0;

    unsigned char temp[64];

    // generation
    while (len < bytes) {

        sha512Compute(seed, 64, temp);

        for (int i = 0; i < 64; i++) {
            seed[i] ^= temp[i];
        }

        memcpy(out + len, temp, 16);
        len += 16;
    }
    
}


#endif