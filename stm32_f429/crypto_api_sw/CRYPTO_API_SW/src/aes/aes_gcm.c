/**
  * @file aes_gcm.c
  * @brief AES GCM mode
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

// https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption

#ifdef OPENSSL 
void AES_128_GCM_ENCRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int* ciphertext_len,
    unsigned char* plaintext, unsigned int plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag)
{
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();

    int len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL); // set iv lenght
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len); // provide add data

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len); // provide message
    *ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len); // Finalise encryption
    *ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag); // get the tag

    EVP_CIPHER_CTX_free(ctx);
}

void AES_128_GCM_DECRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int ciphertext_len,
    unsigned char* plaintext, unsigned int* plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag, unsigned int* result)
{
    int len = 0;
    int ret = 0;

    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL); // set iv lenght
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len); // provide add data

    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len); // provide ciphertext
    *plaintext_len = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag); // set expected tag value
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        // Success
        plaintext_len += len;
        *result = 0;
    }
    else {
        /* Verify failed */
        *result = 1;
    }
}

void AES_192_GCM_ENCRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int* ciphertext_len,
    unsigned char* plaintext, unsigned int plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag)
{
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();

    int len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_192_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL); // set iv lenght
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len); // provide add data

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len); // provide message
    *ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len); // Finalise encryption
    *ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag); // get the tag

    EVP_CIPHER_CTX_free(ctx);
}

void AES_192_GCM_DECRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int ciphertext_len,
    unsigned char* plaintext, unsigned int* plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag, unsigned int* result)
{
    int len = 0;
    int ret = 0;

    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, EVP_aes_192_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL); // set iv lenght
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len); // provide add data

    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len); // provide ciphertext
    *plaintext_len = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag); // set expected tag value
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        // Success
        plaintext_len += len;
        *result = 0;
    }
    else {
        /* Verify failed */
        *result = 1;
    }
}


void AES_256_GCM_ENCRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int* ciphertext_len,
    unsigned char* plaintext, unsigned int plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag)
{
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();

    int len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL); // set iv lenght
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len); // provide add data

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len); // provide message
    *ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len); // Finalise encryption
    *ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag); // get the tag

    EVP_CIPHER_CTX_free(ctx);
}

void AES_256_GCM_DECRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int ciphertext_len,
    unsigned char* plaintext, unsigned int* plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag, unsigned int* result)
{
    int len = 0;
    int ret = 0;

    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL); // set iv lenght
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len); // provide add data

    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len); // provide ciphertext
    *plaintext_len = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag); // set expected tag value
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        // Success
        plaintext_len += len;
        *result = 0;
    }
    else {
        /* Verify failed */
        *result = 1;
    }
}

#elif MBEDTLS 

void AES_128_GCM_ENCRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int* ciphertext_len,
    unsigned char* plaintext, unsigned int plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag) {

    mbedtls_gcm_context aes;
    mbedtls_gcm_init(&aes);

    mbedtls_gcm_setkey(&aes, MBEDTLS_CIPHER_ID_AES, (const unsigned char*)key, 128);

    mbedtls_gcm_crypt_and_tag(&aes, MBEDTLS_GCM_ENCRYPT, plaintext_len,
        (const unsigned char*)iv, (size_t)(iv_len),
        (const unsigned char*)aad, (size_t)(aad_len),
        (const unsigned char*)plaintext, ciphertext,
        16, tag);

    mbedtls_gcm_free(&aes);

    *ciphertext_len = plaintext_len;
        
}
void AES_128_GCM_DECRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int ciphertext_len,
    unsigned char* plaintext, unsigned int* plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag, unsigned int* result) {

    mbedtls_gcm_context aes;
    mbedtls_gcm_init(&aes);

    mbedtls_gcm_setkey(&aes, MBEDTLS_CIPHER_ID_AES, (const unsigned char*)key, 128);

    *result =
    mbedtls_gcm_auth_decrypt(&aes, ciphertext_len,
        (const unsigned char*)iv, (size_t)(iv_len),
        (const unsigned char*)aad, (size_t)(aad_len),
        (const unsigned char*)tag, 16,
        (const unsigned char*)ciphertext, plaintext);
    
    mbedtls_gcm_free(&aes);

    *plaintext_len = ciphertext_len;
}

void AES_192_GCM_ENCRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int* ciphertext_len,
    unsigned char* plaintext, unsigned int plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag) {

    mbedtls_gcm_context aes;
    mbedtls_gcm_init(&aes);

    mbedtls_gcm_setkey(&aes, MBEDTLS_CIPHER_ID_AES, (const unsigned char*)key, 192);

    mbedtls_gcm_crypt_and_tag(&aes, MBEDTLS_GCM_ENCRYPT, plaintext_len,
        (const unsigned char*)iv, (size_t)(iv_len),
        (const unsigned char*)aad, (size_t)(aad_len),
        (const unsigned char*)plaintext, ciphertext,
        16, tag);

    mbedtls_gcm_free(&aes);

    *ciphertext_len = plaintext_len;
}
void AES_192_GCM_DECRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int ciphertext_len,
    unsigned char* plaintext, unsigned int* plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag, unsigned int* result) {

    mbedtls_gcm_context aes;
    mbedtls_gcm_init(&aes);

    mbedtls_gcm_setkey(&aes, MBEDTLS_CIPHER_ID_AES, (const unsigned char*)key, 192);

    *result =
        mbedtls_gcm_auth_decrypt(&aes, ciphertext_len,
            (const unsigned char*)iv, (size_t)(iv_len),
            (const unsigned char*)aad, (size_t)(aad_len),
            (const unsigned char*)tag, 16,
            (const unsigned char*)ciphertext, plaintext);

    mbedtls_gcm_free(&aes);

    *plaintext_len = ciphertext_len;
}
void AES_256_GCM_ENCRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int* ciphertext_len,
    unsigned char* plaintext, unsigned int plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag) {

    mbedtls_gcm_context aes;
    mbedtls_gcm_init(&aes);

    mbedtls_gcm_setkey(&aes, MBEDTLS_CIPHER_ID_AES, (const unsigned char*)key, 256);

    mbedtls_gcm_crypt_and_tag(&aes, MBEDTLS_GCM_ENCRYPT, plaintext_len,
        (const unsigned char*)iv, (size_t)(iv_len),
        (const unsigned char*)aad, (size_t)(aad_len),
        (const unsigned char*)plaintext, ciphertext,
        16, tag);

    mbedtls_gcm_free(&aes);

    *ciphertext_len = plaintext_len;
}
void AES_256_GCM_DECRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int ciphertext_len,
    unsigned char* plaintext, unsigned int* plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag, unsigned int* result) {

    mbedtls_gcm_context aes;
    mbedtls_gcm_init(&aes);

    mbedtls_gcm_setkey(&aes, MBEDTLS_CIPHER_ID_AES, (const unsigned char*)key, 256);

    *result =
        mbedtls_gcm_auth_decrypt(&aes, ciphertext_len,
            (const unsigned char*)iv, (size_t)(iv_len),
            (const unsigned char*)aad, (size_t)(aad_len),
            (const unsigned char*)tag, 16,
            (const unsigned char*)ciphertext, plaintext);

    mbedtls_gcm_free(&aes);

    *plaintext_len = ciphertext_len;
}

#else

// https://web.mit.edu/freebsd/head/contrib/wpa/src/crypto/aes-gcm.c

#define BIT(x) (1 << (x))

static void inc32(unsigned char* block)
{
    unsigned int val;
    val = WPA_GET_BE32(block + 16 - 4);
    val++;
    WPA_PUT_BE32(block + 16 - 4, val);
}

static void shift_right_block(unsigned char* v)
{
    unsigned int val;

    val = WPA_GET_BE32(v + 12);
    val >>= 1;
    if (v[11] & 0x01)
        val |= 0x80000000;
    WPA_PUT_BE32(v + 12, val);

    val = WPA_GET_BE32(v + 8);
    val >>= 1;
    if (v[7] & 0x01)
        val |= 0x80000000;
    WPA_PUT_BE32(v + 8, val);

    val = WPA_GET_BE32(v + 4);
    val >>= 1;
    if (v[3] & 0x01)
        val |= 0x80000000;
    WPA_PUT_BE32(v + 4, val);

    val = WPA_GET_BE32(v);
    val >>= 1;
    WPA_PUT_BE32(v, val);
}

static void xor_op(unsigned char* dst, const unsigned char* src)
{
    unsigned int* d = (unsigned int*)dst;
    unsigned int* s = (unsigned int*)src;
    *d++ ^= *s++;
    *d++ ^= *s++;
    *d++ ^= *s++;
    *d++ ^= *s++;
}

/* Multiplication in GF(2^128) */
static void gf_mult(const unsigned char* x, const unsigned char* y, unsigned char* z)
{
    unsigned char v[16];
    int i, j;

    memset(z, 0, 16); /* Z_0 = 0^128 */
    memcpy(v, y, 16); /* V_0 = Y */

    for (i = 0; i < 16; i++) {
        for (j = 0; j < 8; j++) {
            if (x[i] & BIT(7 - j)) {
                /* Z_(i + 1) = Z_i XOR V_i */
                xor_op(z, v);
            }
            else {
                /* Z_(i + 1) = Z_i */
            }

            if (v[15] & 0x01) {
                /* V_(i + 1) = (V_i >> 1) XOR R */
                shift_right_block(v);
                /* R = 11100001 || 0^120 */
                v[0] ^= 0xe1;
            }
            else {
                /* V_(i + 1) = V_i >> 1 */
                shift_right_block(v);
            }
        }
    }
}

static void ghash(const unsigned char* h, const unsigned char* x, size_t xlen, unsigned char* y)
{
    size_t m, i;
    const unsigned char* xpos = x;
    unsigned char tmp[16];

    m = xlen / 16;

    for (i = 0; i < m; i++) {
        /* Y_i = (Y^(i-1) XOR X_i) dot H */
        xor_op(y, xpos);
        xpos += 16;

        /* dot operation:
         * multiplication operation for binary Galois (finite) field of
         * 2^128 elements */
        gf_mult(y, h, tmp);
        memcpy(y, tmp, 16);
    }

    if (x + xlen > xpos) {
        /* Add zero padded last block */
        size_t last = x + xlen - xpos;
        memcpy(tmp, xpos, last);
        memset(tmp + last, 0, sizeof(tmp) - last);

        /* Y_i = (Y^(i-1) XOR X_i) dot H */
        xor_op(y, tmp);

        /* dot operation:
         * multiplication operation for binary Galois (finite) field of
         * 2^128 elements */
        gf_mult(y, h, tmp);
        memcpy(y, tmp, 16);
    }

    /* Return Y_m */
}

static void aes_gctr(AesContext* aes_ctx, const unsigned char* icb, const unsigned char* x, size_t xlen, unsigned char* y)
{
    size_t i, n, last;
    unsigned char cb[16]; 
    unsigned char tmp[16];
    const unsigned char* xpos = x;
    unsigned char* ypos = y;

    n = xlen / 16;

    memcpy(cb, icb, 16);
    /* Full blocks */
    for (i = 0; i < n; i++) {
        aesEncryptBlock(aes_ctx, cb, ypos);
        xor_op(ypos, xpos);
        xpos += 16;
        ypos += 16;
        inc32(cb);
    }

    last = x + xlen - xpos;
    if (last) {
        /* Last, partial block */
        aesEncryptBlock(aes_ctx, cb, tmp);
        for (i = 0; i < last; i++)
            *ypos++ = *xpos++ ^ tmp[i];
    }
}

static void aes_gcm_init_hash_key(AesContext* aes_ctx, unsigned char* key, size_t key_len, unsigned char* H)
{
    aesInit(aes_ctx, key, key_len);

    size_t len = 0;

    unsigned char p[16];
    unsigned char c[16];

    memset(p, 0, 16);
    aesEncryptBlock(aes_ctx, p, c);
    memcpy(H, c, 16);

}

static void aes_gcm_prepare_j0(unsigned char* iv, size_t iv_len, unsigned char* H, unsigned char* J0)
{
    unsigned char len_buf[16];

    if (iv_len == 12) {
        /* Prepare block J_0 = IV || 0^31 || 1 [len(IV) = 96] */
        memcpy(J0, iv, iv_len);
        memset(J0 + iv_len, 0, 16 - iv_len);
        J0[15] = 0x01;
    }
    else {
        /*
         * s = 128 * ceil(len(IV)/128) - len(IV)
         * J_0 = GHASH_H(IV || 0^(s+64) || [len(IV)]_64)
         */
        memset(J0, 0, 16);
        ghash(H, iv, iv_len, J0);
        WPA_PUT_BE64(len_buf, 0);
        WPA_PUT_BE64(len_buf + 8, iv_len * 8);
        ghash(H, len_buf, sizeof(len_buf), J0);
    }
}

static void aes_gcm_gctr(AesContext* aes_ctx, const unsigned char* J0, const unsigned char* in, size_t len, unsigned char* out)
{
    unsigned char J0inc[16];

    memcpy(J0inc, J0, 16);
    inc32(J0inc);
    aes_gctr(aes_ctx, J0inc, in, len, out);
}


static void aes_gcm_ghash(const unsigned char* H, const unsigned char* aad, size_t aad_len, const unsigned char* crypt, size_t crypt_len, unsigned char* S)
{
    unsigned char len_buf[16];

    /*
     * u = 128 * ceil[len(C)/128] - len(C)
     * v = 128 * ceil[len(A)/128] - len(A)
     * S = GHASH_H(A || 0^v || C || 0^u || [len(A)]64 || [len(C)]64)
     * (i.e., zero padded to block size A || C and lengths of each in bits)
     */
    memset(S, 0, 16);
    ghash(H, aad, aad_len, S);
    ghash(H, crypt, crypt_len, S);
    WPA_PUT_BE64(len_buf, aad_len * 8);
    WPA_PUT_BE64(len_buf + 8, crypt_len * 8);
    ghash(H, len_buf, sizeof(len_buf), S);
}

void AES_128_GCM_ENCRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int* ciphertext_len,
    unsigned char* plaintext, unsigned int plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag) {

    unsigned char H[16];
    unsigned char J0[16];
    unsigned char S[16];

    AesContext aes_ctx;

    aes_gcm_init_hash_key(&aes_ctx, key, 16, H);

    aes_gcm_prepare_j0(iv, iv_len, H, J0);

    /* C = GCTR_K(inc_32(J_0), P) */
    aes_gcm_gctr(&aes_ctx, J0, plaintext, plaintext_len, ciphertext);

    aes_gcm_ghash(H, aad, aad_len, ciphertext, plaintext_len, S);

    /* T = MSB_t(GCTR_K(J_0, S)) */
    aes_gctr(&aes_ctx, J0, S, sizeof(S), tag);

    /* Return (C, T) */
    
    *ciphertext_len = plaintext_len;

}
void AES_128_GCM_DECRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int ciphertext_len,
    unsigned char* plaintext, unsigned int* plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag, unsigned int* result) {

    unsigned char H[16];
    unsigned char J0[16];
    unsigned char S[16];
    unsigned char T[16];

    
    AesContext aes_ctx;

    aes_gcm_init_hash_key(&aes_ctx, key, 16, H);

    aes_gcm_prepare_j0(iv, iv_len, H, J0);

    /* P = GCTR_K(inc_32(J_0), C) */
    aes_gcm_gctr(&aes_ctx, J0, ciphertext, ciphertext_len, plaintext);

    aes_gcm_ghash(H, aad, aad_len, ciphertext, ciphertext_len, S);

    /* T' = MSB_t(GCTR_K(J_0, S)) */
    aes_gctr(&aes_ctx, J0, S, sizeof(S), T);

    *result = memcmp(tag, T, 16);

    *plaintext_len = ciphertext_len;
  
}

void AES_192_GCM_ENCRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int* ciphertext_len,
    unsigned char* plaintext, unsigned int plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag) {

    unsigned char H[16];
    unsigned char J0[16];
    unsigned char S[16];

    AesContext aes_ctx;

    aes_gcm_init_hash_key(&aes_ctx, key, 24, H);

    aes_gcm_prepare_j0(iv, iv_len, H, J0);

    /* C = GCTR_K(inc_32(J_0), P) */
    aes_gcm_gctr(&aes_ctx, J0, plaintext, plaintext_len, ciphertext);

    aes_gcm_ghash(H, aad, aad_len, ciphertext, plaintext_len, S);

    /* T = MSB_t(GCTR_K(J_0, S)) */
    aes_gctr(&aes_ctx, J0, S, sizeof(S), tag);

    /* Return (C, T) */

    *ciphertext_len = plaintext_len;
   
}
void AES_192_GCM_DECRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int ciphertext_len,
    unsigned char* plaintext, unsigned int* plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag, unsigned int* result) {

    unsigned char H[16];
    unsigned char J0[16];
    unsigned char S[16];
    unsigned char T[16];


    AesContext aes_ctx;

    aes_gcm_init_hash_key(&aes_ctx, key, 24, H);

    aes_gcm_prepare_j0(iv, iv_len, H, J0);

    /* P = GCTR_K(inc_32(J_0), C) */
    aes_gcm_gctr(&aes_ctx, J0, ciphertext, ciphertext_len, plaintext);

    aes_gcm_ghash(H, aad, aad_len, ciphertext, ciphertext_len, S);

    /* T' = MSB_t(GCTR_K(J_0, S)) */
    aes_gctr(&aes_ctx, J0, S, sizeof(S), T);

    *result = memcmp(tag, T, 16);

    *plaintext_len = ciphertext_len;
    
}
void AES_256_GCM_ENCRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int* ciphertext_len,
    unsigned char* plaintext, unsigned int plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag) {

    unsigned char H[16];
    unsigned char J0[16];
    unsigned char S[16];

    AesContext aes_ctx;

    aes_gcm_init_hash_key(&aes_ctx, key, 32, H);

    aes_gcm_prepare_j0(iv, iv_len, H, J0);

    /* C = GCTR_K(inc_32(J_0), P) */
    aes_gcm_gctr(&aes_ctx, J0, plaintext, plaintext_len, ciphertext);

    aes_gcm_ghash(H, aad, aad_len, ciphertext, plaintext_len, S);

    /* T = MSB_t(GCTR_K(J_0, S)) */
    aes_gctr(&aes_ctx, J0, S, sizeof(S), tag);

    /* Return (C, T) */

    *ciphertext_len = plaintext_len;
    
}
void AES_256_GCM_DECRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int ciphertext_len,
    unsigned char* plaintext, unsigned int* plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag, unsigned int* result) {

    unsigned char H[16];
    unsigned char J0[16];
    unsigned char S[16];
    unsigned char T[16];


    AesContext aes_ctx;

    aes_gcm_init_hash_key(&aes_ctx, key, 32, H);

    aes_gcm_prepare_j0(iv, iv_len, H, J0);

    /* P = GCTR_K(inc_32(J_0), C) */
    aes_gcm_gctr(&aes_ctx, J0, ciphertext, ciphertext_len, plaintext);

    aes_gcm_ghash(H, aad, aad_len, ciphertext, ciphertext_len, S);

    /* T' = MSB_t(GCTR_K(J_0, S)) */
    aes_gctr(&aes_ctx, J0, S, sizeof(S), T);

    *result = memcmp(tag, T, 16);

    *plaintext_len = ciphertext_len;
   
}




#endif