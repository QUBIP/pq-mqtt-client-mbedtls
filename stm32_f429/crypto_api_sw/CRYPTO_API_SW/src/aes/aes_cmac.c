/**
  * @file aes_cmac.c
  * @brief AES CMAC mode
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

#include "aes.h"

// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
// https://csrc.nist.gov/Projects/block-cipher-techniques/BCM
// https://github.com/rambo/nfc_lock/blob/master/c/cmac_example.c
// https://www.openssl.org/docs/man3.3/man7/OSSL_PROVIDER-default.html
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf

#ifdef OPENSSL
void AES_128_CMAC(unsigned char* key, unsigned char* mac, unsigned int* mac_len, unsigned char* msg, unsigned int msg_len)
{
    EVP_MAC* mac_op = EVP_MAC_fetch(NULL, "CMAC", NULL);
    EVP_MAC_CTX* ctx;
    ctx = EVP_MAC_CTX_new(mac_op);

    size_t len;

    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_utf8_string("cipher", "AES-128-CBC", 0);
    params[1] = OSSL_PARAM_construct_end();

    EVP_MAC_init(ctx, key, 16, params);
    EVP_MAC_update(ctx, msg, msg_len);
    EVP_MAC_final(ctx, mac, &len, 16);
    *mac_len = len;

    EVP_MAC_CTX_free(ctx);

}

void AES_192_CMAC(unsigned char* key, unsigned char* mac, unsigned int* mac_len, unsigned char* msg, unsigned int msg_len)
{
    EVP_MAC* mac_op = EVP_MAC_fetch(NULL, "CMAC", NULL);
    EVP_MAC_CTX* ctx;
    ctx = EVP_MAC_CTX_new(mac_op);

    size_t len;

    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_utf8_string("cipher", "AES-192-CBC", 0);
    params[1] = OSSL_PARAM_construct_end();

    EVP_MAC_init(ctx, key, 24, params);
    EVP_MAC_update(ctx, msg, msg_len);
    EVP_MAC_final(ctx, mac, &len, 16);
    *mac_len = len;

    EVP_MAC_CTX_free(ctx);

}

void AES_256_CMAC(unsigned char* key, unsigned char* mac, unsigned int* mac_len, unsigned char* msg, unsigned int msg_len)
{
    EVP_MAC* mac_op = EVP_MAC_fetch(NULL, "CMAC", NULL);
    EVP_MAC_CTX* ctx;
    ctx = EVP_MAC_CTX_new(mac_op);

    size_t len;

    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_utf8_string("cipher", "AES-256-CBC", 0);
    params[1] = OSSL_PARAM_construct_end();

    EVP_MAC_init(ctx, key, 32, params);
    EVP_MAC_update(ctx, msg, msg_len);
    EVP_MAC_final(ctx, mac, &len, 16);
    *mac_len = len;

    EVP_MAC_CTX_free(ctx);

}

#elif MBEDTLS 

void AES_128_CMAC(unsigned char* key, unsigned char* mac, unsigned int* mac_len, unsigned char* msg, unsigned int msg_len)
{
    mbedtls_cipher_context_t m_ctx;
    const mbedtls_cipher_info_t* cipher_info;
    cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);

    mbedtls_cipher_init(&m_ctx);
    mbedtls_cipher_setup(&m_ctx, cipher_info);

    mbedtls_cipher_cmac_starts(&m_ctx, key, 128);
    mbedtls_cipher_cmac_update(&m_ctx, msg, msg_len);
    mbedtls_cipher_cmac_finish(&m_ctx, mac);

    *mac_len = strlen(mac);
}

void AES_192_CMAC(unsigned char* key, unsigned char* mac, unsigned int* mac_len, unsigned char* msg, unsigned int msg_len)
{
    mbedtls_cipher_context_t m_ctx;
    const mbedtls_cipher_info_t* cipher_info;
    cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_192_ECB);

    mbedtls_cipher_init(&m_ctx);
    mbedtls_cipher_setup(&m_ctx, cipher_info);

    mbedtls_cipher_cmac_starts(&m_ctx, key, 192);
    mbedtls_cipher_cmac_update(&m_ctx, msg, msg_len);
    mbedtls_cipher_cmac_finish(&m_ctx, mac);

    *mac_len = strlen(mac);
}

void AES_256_CMAC(unsigned char* key, unsigned char* mac, unsigned int* mac_len, unsigned char* msg, unsigned int msg_len)
{
    mbedtls_cipher_context_t m_ctx;
    const mbedtls_cipher_info_t* cipher_info;
    cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_ECB);

    mbedtls_cipher_init(&m_ctx);
    mbedtls_cipher_setup(&m_ctx, cipher_info);

    mbedtls_cipher_cmac_starts(&m_ctx, key, 256);
    mbedtls_cipher_cmac_update(&m_ctx, msg, msg_len);
    mbedtls_cipher_cmac_finish(&m_ctx, mac);

    *mac_len = strlen(mac);
}

#else

/**
 * @brief Multiplication by x in GF(2^128)
 * @param[out] x Pointer to the output block
 * @param[out] a Pointer to the input block
 * @param[in] n Size of the block, in bytes
 * @param[in] rb Representation of the irreducible binary polynomial
 **/

void cmacMul(uint8_t* x, const uint8_t* a, size_t n, uint8_t rb)
{
    size_t i;
    uint8_t c;

    //Save the value of the most significant bit
    c = a[0] >> 7;

    //The multiplication of a polynomial by x in GF(2^128) corresponds to a
    //shift of indices
    for (i = 0; i < (n - 1); i++)
    {
        x[i] = (a[i] << 1) | (a[i + 1] >> 7);
    }

    //Shift the last byte of the block to the left
    x[i] = a[i] << 1;

    //If the highest term of the result is equal to one, then perform reduction
    x[i] ^= rb & ~(c - 1);
}
 
void GenSubKeys(unsigned char* key, unsigned int key_len, unsigned char K1[16], unsigned char K2[16])
{
    AesContext aes_ctx;
    aesInit(&aes_ctx, key, key_len);

    size_t len = 0;

    unsigned char p[16];
    unsigned char L[16];

    memset(p, 0, 16);

    aesEncryptBlock(&aes_ctx, p, L); 

    uint8_t rb = 0x87;
    //The subkey K1 is obtained by multiplying L by x in GF(2^b)
    cmacMul(K1, L, 16, rb);
    //The subkey K2 is obtained by multiplying L by x^2 in GF(2^b)
    cmacMul(K2, K1, 16, rb);


}

void AES_128_CMAC(unsigned char* key, unsigned char* mac, unsigned int* mac_len, unsigned char* msg, unsigned int msg_len)
{
    AesContext aes_ctx;
    aesInit(&aes_ctx, key, 16);

    unsigned char K1[16];
    unsigned char K2[16];
    GenSubKeys(key, 16, K1, K2);

    size_t len = 0;
    *mac_len = 16;


    unsigned char p[16];
    unsigned char c[16];

    unsigned char xor_block[16];
    memset(xor_block, 0, 16);

    //ECB mode operates in a block-by-block fashion
    while (len < msg_len)
    {
        memcpy(p, msg + len, 16);

        if (len < (msg_len - 16)) {
            for (int i = 0; i < 16; i++) {
                p[i] = p[i] ^ xor_block[i];
            }
        }
        else { // last one
            for (int i = 0; i < 16; i++) {
                p[i] = p[i] ^ xor_block[i] ^ K1[i];
            }
        }

        //Encrypt current block
        aesEncryptBlock(&aes_ctx, p, c);

        len += 16;

        memcpy(xor_block, c, 16);

    }

    memcpy(mac, c, 16);

}

void AES_192_CMAC(unsigned char* key, unsigned char* mac, unsigned int* mac_len, unsigned char* msg, unsigned int msg_len)
{
    AesContext aes_ctx;
    aesInit(&aes_ctx, key, 24);

    unsigned char K1[16];
    unsigned char K2[16];
    GenSubKeys(key, 24, K1, K2);

    size_t len = 0;
    *mac_len = 16;


    unsigned char p[16];
    unsigned char c[16];

    unsigned char xor_block[16];
    memset(xor_block, 0, 16);

    //ECB mode operates in a block-by-block fashion
    while (len < msg_len)
    {
        memcpy(p, msg + len, 16);

        if (len < (msg_len - 16)) {
            for (int i = 0; i < 16; i++) {
                p[i] = p[i] ^ xor_block[i];
            }
        }
        else { // last one
            for (int i = 0; i < 16; i++) {
                p[i] = p[i] ^ xor_block[i] ^ K1[i];
            }
        }

        //Encrypt current block
        aesEncryptBlock(&aes_ctx, p, c);

        len += 16;

        memcpy(xor_block, c, 16);

    }

    memcpy(mac, c, 16);
}

void AES_256_CMAC(unsigned char* key, unsigned char* mac, unsigned int* mac_len, unsigned char* msg, unsigned int msg_len)
{
    AesContext aes_ctx;
    aesInit(&aes_ctx, key, 32);

    unsigned char K1[16];
    unsigned char K2[16];
    GenSubKeys(key, 32, K1, K2);

    size_t len = 0;
    *mac_len = 16;


    unsigned char p[16];
    unsigned char c[16];

    unsigned char xor_block[16];
    memset(xor_block, 0, 16);

    //ECB mode operates in a block-by-block fashion
    while (len < msg_len)
    {
        memcpy(p, msg + len, 16);

        if (len < (msg_len - 16)) {
            for (int i = 0; i < 16; i++) {
                p[i] = p[i] ^ xor_block[i];
            }
        }
        else { // last one
            for (int i = 0; i < 16; i++) {
                p[i] = p[i] ^ xor_block[i] ^ K1[i];
            }
        }

        //Encrypt current block
        aesEncryptBlock(&aes_ctx, p, c);

        len += 16;

        memcpy(xor_block, c, 16);

    }

    memcpy(mac, c, 16);
}

#endif



