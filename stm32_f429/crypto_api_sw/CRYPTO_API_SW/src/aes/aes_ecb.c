/**
  * @file aes_ecb.c
  * @brief AES ECB mode
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
// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption


#ifdef OPENSSL

void AES_128_ECB_ENCRYPT(unsigned char* key, unsigned char* ciphertext, unsigned int* ciphertext_len, unsigned char* plaintext, unsigned int plaintext_len)
{
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();

    int len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    *ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    *ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

}

void AES_128_ECB_DECRYPT(unsigned char* key, unsigned char* ciphertext, unsigned int ciphertext_len, unsigned char* plaintext, unsigned int* plaintext_len)
{
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();

    unsigned int len = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    *plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    *plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

}


void AES_192_ECB_ENCRYPT(unsigned char* key, unsigned char* ciphertext, unsigned int* ciphertext_len, unsigned char* plaintext, unsigned int plaintext_len)
{
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();

    int len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_192_ecb(), NULL, key, NULL);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    *ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    *ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

}

void AES_192_ECB_DECRYPT(unsigned char* key, unsigned char* ciphertext, unsigned int ciphertext_len, unsigned char* plaintext, unsigned int* plaintext_len)
{
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();

    unsigned int len = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_192_ecb(), NULL, key, NULL);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    *plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    *plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

}


void AES_256_ECB_ENCRYPT(unsigned char* key, unsigned char* ciphertext, unsigned int* ciphertext_len, unsigned char* plaintext, unsigned int plaintext_len)
{
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();

    int len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    *ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    *ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

}

void AES_256_ECB_DECRYPT(unsigned char* key, unsigned char* ciphertext, unsigned int ciphertext_len, unsigned char* plaintext, unsigned int* plaintext_len)
{
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();

    unsigned int len = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    *plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    *plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

}
#elif MBEDTLS 

void AES_128_ECB_ENCRYPT(unsigned char* key, unsigned char* ciphertext, unsigned int* ciphertext_len, unsigned char* plaintext, unsigned int plaintext_len)
{
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    size_t len = 0;

    mbedtls_aes_setkey_enc(&aes, (const unsigned char*)key, 128);

    while (len < plaintext_len) {
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, (const unsigned char*)plaintext + len, ciphertext + len);
        len += 16;
    }

    mbedtls_aes_free(&aes);

    *ciphertext_len = len;
}

void AES_128_ECB_DECRYPT(unsigned char* key, unsigned char* ciphertext, unsigned int ciphertext_len, unsigned char* plaintext, unsigned int* plaintext_len)
{
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    size_t len = 0;

    mbedtls_aes_setkey_dec(&aes, (const unsigned char*)key, 128);

    while (len < ciphertext_len) {
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, (const unsigned char*)ciphertext + len, plaintext + len);
        len += 16;
    }
    mbedtls_aes_free(&aes);

    *plaintext_len = len;
}


void AES_192_ECB_ENCRYPT(unsigned char* key, unsigned char* ciphertext, unsigned int* ciphertext_len, unsigned char* plaintext, unsigned int plaintext_len)
{
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    size_t len = 0;

    mbedtls_aes_setkey_enc(&aes, (const unsigned char*)key, 192);

    while (len < plaintext_len) {
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, (const unsigned char*)plaintext + len, ciphertext + len);
        len += 16;
    }

    mbedtls_aes_free(&aes);

    *ciphertext_len = len;
}

void AES_192_ECB_DECRYPT(unsigned char* key, unsigned char* ciphertext, unsigned int ciphertext_len, unsigned char* plaintext, unsigned int* plaintext_len)
{
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    size_t len = 0;

    mbedtls_aes_setkey_dec(&aes, (const unsigned char*)key, 192);

    while (len < ciphertext_len) {
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, (const unsigned char*)ciphertext + len, plaintext + len);
        len += 16;
    }
    mbedtls_aes_free(&aes);

    *plaintext_len = len;
}


void AES_256_ECB_ENCRYPT(unsigned char* key, unsigned char* ciphertext, unsigned int* ciphertext_len, unsigned char* plaintext, unsigned int plaintext_len)
{
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    size_t len = 0;

    mbedtls_aes_setkey_enc(&aes, (const unsigned char*)key, 256);

    while (len < plaintext_len) {
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, (const unsigned char*)plaintext + len, ciphertext + len);
        len += 16;
    }

    mbedtls_aes_free(&aes);

    *ciphertext_len = len;
}

void AES_256_ECB_DECRYPT(unsigned char* key, unsigned char* ciphertext, unsigned int ciphertext_len, unsigned char* plaintext, unsigned int* plaintext_len)
{
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    size_t len = 0;

    mbedtls_aes_setkey_dec(&aes, (const unsigned char*)key, 256);

    while (len < ciphertext_len) {
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, (const unsigned char*)ciphertext + len, plaintext + len);
        len += 16;
    }
    mbedtls_aes_free(&aes);

    *plaintext_len = len;
}

#else 

void AES_128_ECB_ENCRYPT(unsigned char* key, unsigned char* ciphertext, unsigned int* ciphertext_len, unsigned char* plaintext, unsigned int plaintext_len)
{

    AesContext aes_ctx;
    aesInit(&aes_ctx, key, 16);

    size_t len = 0;
    *ciphertext_len = plaintext_len;

    unsigned char p[16];
    unsigned char c[16];

    //ECB mode operates in a block-by-block fashion
    while (len < plaintext_len)
    {
        memcpy(p, plaintext + len, 16);
        //Encrypt current block
        aesEncryptBlock(&aes_ctx, p, c);
        for (int i = 0; i < 16; i++) {
            ciphertext[i + len] = c[i];
        }
        len += 16;

    }

}

void AES_128_ECB_DECRYPT(unsigned char* key, unsigned char* ciphertext, unsigned int ciphertext_len, unsigned char* plaintext, unsigned int* plaintext_len)
{
    AesContext aes_ctx;
    aesInit(&aes_ctx, key, 16);

    size_t len = 0;
    *plaintext_len = ciphertext_len;

    unsigned char p[16];
    unsigned char c[16];

    //ECB mode operates in a block-by-block fashion
    while (len < ciphertext_len)
    {
        memcpy(c, ciphertext + len, 16);
        //Encrypt current block
        aesDecryptBlock(&aes_ctx, c, p);
        for (int i = 0; i < 16; i++) {
            plaintext[i + len] = p[i];
        }
        len += 16;

    }

    aesDeinit(&aes_ctx);
}

void AES_192_ECB_ENCRYPT(unsigned char* key, unsigned char* ciphertext, unsigned int* ciphertext_len, unsigned char* plaintext, unsigned int plaintext_len)
{

    AesContext aes_ctx;
    aesInit(&aes_ctx, key, 24);

    size_t len = 0;
    *ciphertext_len = plaintext_len;

    unsigned char p[16];
    unsigned char c[16];

    //ECB mode operates in a block-by-block fashion
    while (len < plaintext_len)
    {
        memcpy(p, plaintext + len, 16);
        //Encrypt current block
        aesEncryptBlock(&aes_ctx, p, c);
        for (int i = 0; i < 16; i++) {
            ciphertext[i + len] = c[i];
        }
        len += 16;

    }
}

void AES_192_ECB_DECRYPT(unsigned char* key, unsigned char* ciphertext, unsigned int ciphertext_len, unsigned char* plaintext, unsigned int* plaintext_len)
{
    AesContext aes_ctx;
    aesInit(&aes_ctx, key, 24);

    size_t len = 0;
    *plaintext_len = ciphertext_len;

    unsigned char p[16];
    unsigned char c[16];

    //ECB mode operates in a block-by-block fashion
    while (len < ciphertext_len)
    {
        memcpy(c, ciphertext + len, 16);
        //Encrypt current block
        aesDecryptBlock(&aes_ctx, c, p);
        for (int i = 0; i < 16; i++) {
            plaintext[i + len] = p[i];
        }
        len += 16;

    }

    aesDeinit(&aes_ctx);
}

void AES_256_ECB_ENCRYPT(unsigned char* key, unsigned char* ciphertext, unsigned int* ciphertext_len, unsigned char* plaintext, unsigned int plaintext_len)
{

    AesContext aes_ctx;
    aesInit(&aes_ctx, key, 32);

    size_t len = 0;
    *ciphertext_len = plaintext_len;

    unsigned char p[16];
    unsigned char c[16];

    //ECB mode operates in a block-by-block fashion
    while (len < plaintext_len)
    {
        memcpy(p, plaintext + len, 16);
        //Encrypt current block
        aesEncryptBlock(&aes_ctx, p, c);
        for (int i = 0; i < 16; i++) {
            ciphertext[i + len] = c[i];
        }
        len += 16;

    }
}

void AES_256_ECB_DECRYPT(unsigned char* key, unsigned char* ciphertext, unsigned int ciphertext_len, unsigned char* plaintext, unsigned int* plaintext_len)
{
    AesContext aes_ctx;
    aesInit(&aes_ctx, key, 32);

    size_t len = 0;
    *plaintext_len = ciphertext_len;

    unsigned char p[16];
    unsigned char c[16];

    //ECB mode operates in a block-by-block fashion
    while (len < ciphertext_len)
    {
        memcpy(c, ciphertext + len, 16);
        //Encrypt current block
        aesDecryptBlock(&aes_ctx, c, p);
        for (int i = 0; i < 16; i++) {
            plaintext[i + len] = p[i];
        }
        len += 16;

    }

    aesDeinit(&aes_ctx);
}

#endif 


