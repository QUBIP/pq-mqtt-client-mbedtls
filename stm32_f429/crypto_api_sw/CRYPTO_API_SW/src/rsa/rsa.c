/**
  * @file rsa.c
  * @brief RSA code
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

#include "rsa.h"

#include "../../../demo/src/test_func.h"

// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br2.pdf
// https://stackoverflow.com/questions/76683427/extracting-the-encoded-public-key-from-rsa-key-pair-in-openssl-3
// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
// https://github.com/danbev/learning-openssl/blob/master/rsa.c
// https://stackoverflow.com/questions/68102808/how-to-use-openssl-3-0-rsa-in-c

#ifdef OPENSSL

void RSA_GEN_KEYS(unsigned int bits, unsigned char** pri_key, unsigned char** pub_key, unsigned int* pri_len, unsigned int* pub_len) {

    EVP_PKEY* pkey = NULL;
    pkey = EVP_RSA_gen(bits);

    unsigned int pubkey_len;
    pubkey_len = i2d_PublicKey(pkey, NULL);
    *pub_key = malloc(pubkey_len);
    unsigned char* ptr = *pub_key;
    i2d_PublicKey(pkey, &ptr);

    unsigned int prikey_len;
    prikey_len = i2d_PrivateKey(pkey, NULL);
    *pri_key = malloc(prikey_len);
    ptr = *pri_key;
    i2d_PrivateKey(pkey, &ptr);

    *pub_len = pubkey_len;
    *pri_len = prikey_len;

}

void RSA_ENCRYPT(unsigned char* plaintext, unsigned int plaintext_len, const unsigned char** pub_key, unsigned int pub_len,
    unsigned char** ciphertext, unsigned int* ciphertext_len)
{
    EVP_PKEY_CTX* ctx;
    EVP_PKEY* pkey;

    // Decode the public key
    pkey = d2i_PublicKey(EVP_PKEY_RSA, NULL, pub_key, pub_len);
    ctx = EVP_PKEY_CTX_new(pkey, NULL);

    // Init encryption
    EVP_PKEY_encrypt_init(ctx);
    // Set padding
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
    // Return the size of the ciphertext
    EVP_PKEY_encrypt(ctx, NULL, (size_t*)ciphertext_len, plaintext, plaintext_len);
    *ciphertext = malloc(*ciphertext_len);
    // Encrypt
    EVP_PKEY_encrypt(ctx, *ciphertext, (size_t*)ciphertext_len, plaintext, plaintext_len);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
}

void RSA_DECRYPT(unsigned char** result, unsigned int* result_len, const unsigned char** pri_key, unsigned int pri_len,
    unsigned char* ciphertext, unsigned int ciphertext_len)
{

    EVP_PKEY_CTX* ctx;
    EVP_PKEY* pkey;

    size_t len;

    // Decode the public key
    pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, pri_key, pri_len);
    ctx = EVP_PKEY_CTX_new(pkey, NULL);

    // Init encryption
    EVP_PKEY_decrypt_init(ctx);
    // Set padding
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
    // Return the size of the ciphertext
    EVP_PKEY_decrypt(ctx, NULL, &len, ciphertext, ciphertext_len);
    *result = malloc(len);
    // Encrypt
    EVP_PKEY_decrypt(ctx, *result, &len, ciphertext, ciphertext_len);

    *result_len = (unsigned int)len;

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

}

#elif MBEDTLS

void RSA_GEN_KEYS(unsigned int bits, unsigned char** pri_key, unsigned char** pub_key, unsigned int* pri_len, unsigned int* pub_len)
{

    // Entropy function //
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    unsigned char seed[16];
    sprintf(seed, "%ld", time(NULL));
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, seed, 16);

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));

    mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk), mbedtls_ctr_drbg_random, &ctr_drbg, bits, 65537);

    unsigned char buf[8192];
    *pri_len = mbedtls_pk_write_key_der(&pk, buf, 8192);
    *pri_key = malloc(*pri_len);
    mbedtls_pk_write_key_der(&pk, *pri_key, *pri_len);

    *pub_len = mbedtls_pk_write_pubkey_der(&pk, buf, 8192);
    *pub_key = malloc(*pub_len);
    mbedtls_pk_write_pubkey_der(&pk, *pub_key, *pub_len);

}

void RSA_ENCRYPT(unsigned char* plaintext, unsigned int plaintext_len, const unsigned char** pub_key, unsigned int pub_len,
    unsigned char** ciphertext, unsigned int* ciphertext_len)
{

    // Entropy function //
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    unsigned char seed[16];
    sprintf(seed, "%ld", time(NULL));
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, seed, 16);

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    mbedtls_pk_parse_public_key(&pk, *pub_key, (size_t)pub_len);

    unsigned char buf[2048];
    size_t len;
    mbedtls_pk_encrypt(&pk, plaintext, (size_t)plaintext_len, buf, &len, sizeof(buf), mbedtls_ctr_drbg_random, &ctr_drbg);
    *ciphertext_len = len;
    *ciphertext = malloc(len);
    mbedtls_pk_encrypt(&pk, plaintext, (size_t)plaintext_len, *ciphertext, &len, *ciphertext_len, mbedtls_ctr_drbg_random, &ctr_drbg);
}

void RSA_DECRYPT(unsigned char** result, unsigned int* result_len, const unsigned char** pri_key, unsigned int pri_len,
    unsigned char* ciphertext, unsigned int ciphertext_len)
{
    // Entropy function //
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    unsigned char seed[16];
    sprintf(seed, "%ld", time(NULL));
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, seed, 16);

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    mbedtls_pk_parse_key(&pk, *pri_key, (size_t)pri_len, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);

    unsigned char buf[2048];
    size_t len;
    mbedtls_pk_decrypt(&pk, ciphertext, (size_t)ciphertext_len, buf, &len, sizeof(buf), mbedtls_ctr_drbg_random, &ctr_drbg);
    *result_len = len;
    *result = malloc(len);
    mbedtls_pk_decrypt(&pk, ciphertext, (size_t)ciphertext_len, *result, &len, *result_len, mbedtls_ctr_drbg_random, &ctr_drbg);
}

#else

void RSA_GEN_KEYS(unsigned int bits, unsigned char** pri_key, unsigned char** pub_key, unsigned int* pri_len, unsigned int* pub_len)
{
    printf("\n Not supported yet in ALT definition.");

}

void RSA_ENCRYPT(unsigned char* plaintext, unsigned int plaintext_len, const unsigned char** pub_key, unsigned int pub_len,
    unsigned char** ciphertext, unsigned int* ciphertext_len)
{
    printf("\n Not supported yet in ALT definition.");
}

void RSA_DECRYPT(unsigned char** result, unsigned int* result_len, const unsigned char** pri_key, unsigned int pri_len,
    unsigned char* ciphertext, unsigned int ciphertext_len)
{
    printf("\n Not supported yet in ALT definition.");
}

#endif