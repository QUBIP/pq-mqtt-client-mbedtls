/**
  * @file aes_ccm.c
  * @brief AES CCM mode
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
void AES_128_CCM_8_ENCRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int* ciphertext_len,
    unsigned char* plaintext, unsigned int plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag)
{
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();

    int len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, iv_len, NULL); // set iv length
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 8, NULL); // set tag length

    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_EncryptUpdate(ctx, NULL, &len, NULL, plaintext_len);

    EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len); // provide add data

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len); // provide message
    *ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len); // Finalise encryption
    *ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, 8, tag); // get the tag

    EVP_CIPHER_CTX_free(ctx);
}

void AES_128_CCM_8_DECRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int ciphertext_len,
    unsigned char* plaintext, unsigned int* plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag, unsigned int* result)
{
    int len = 0;
    int ret = 0;

    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, iv_len, NULL); // set iv length
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 8, tag); // set tag length

    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_DecryptUpdate(ctx, NULL, &len, NULL, ciphertext_len);

    EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len); // provide add data

    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len); // provide ciphertext
    *plaintext_len = len;

    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        // Success
        *plaintext_len += len;
        *result = 0;
    }
    else {
        /* Verify failed */
        *result = 1;
    }
}

void AES_192_CCM_8_ENCRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int* ciphertext_len,
    unsigned char* plaintext, unsigned int plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag)
{
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();

    int len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_192_ccm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, iv_len, NULL); // set iv length
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 8, NULL); // set tag length

    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len); // provide add data

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len); // provide message
    *ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len); // Finalise encryption
    *ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, 8, tag); // get the tag

    EVP_CIPHER_CTX_free(ctx);
}

void AES_192_CCM_8_DECRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int ciphertext_len,
    unsigned char* plaintext, unsigned int* plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag, unsigned int* result)
{
    int len = 0;
    int ret = 0;

    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, EVP_aes_192_ccm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, iv_len, NULL); // set iv length
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 8, tag); // set tag length

    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len); // provide add data

    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len); // provide ciphertext
    *plaintext_len = len;

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

void AES_256_CCM_8_ENCRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int* ciphertext_len,
    unsigned char* plaintext, unsigned int plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag)
{
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();

    int len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_ccm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, iv_len, NULL); // set iv length
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 8, NULL); // set tag length

    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len); // provide add data

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len); // provide message
    *ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len); // Finalise encryption
    *ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, 8, tag); // get the tag

    EVP_CIPHER_CTX_free(ctx);
}

void AES_256_CCM_8_DECRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int ciphertext_len,
    unsigned char* plaintext, unsigned int* plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag, unsigned int* result)
{
    int len = 0;
    int ret = 0;

    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, EVP_aes_256_ccm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, iv_len, NULL); // set iv length
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 8, tag); // set tag length

    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len); // provide add data

    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len); // provide ciphertext
    *plaintext_len = len;

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

void AES_128_CCM_8_ENCRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int* ciphertext_len,
    unsigned char* plaintext, unsigned int plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag) {

    mbedtls_ccm_context aes;
    mbedtls_ccm_init(&aes);

    mbedtls_ccm_setkey(&aes, MBEDTLS_CIPHER_ID_AES, (const unsigned char*)key, 128);

    mbedtls_ccm_encrypt_and_tag(&aes, plaintext_len,
        (const unsigned char*)iv, 8, // max 8 bytes
        (const unsigned char*)aad, (size_t)(aad_len),
        (const unsigned char*)plaintext, ciphertext,
        tag, 8);

    mbedtls_ccm_free(&aes);

    *ciphertext_len = plaintext_len;
}

void AES_128_CCM_8_DECRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int ciphertext_len,
    unsigned char* plaintext, unsigned int* plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag, unsigned int* result) {

    mbedtls_ccm_context aes;
    mbedtls_ccm_init(&aes);

    mbedtls_ccm_setkey(&aes, MBEDTLS_CIPHER_ID_AES, (const unsigned char*)key, 128);

    *result =
        mbedtls_ccm_auth_decrypt(&aes, ciphertext_len,
            (const unsigned char*)iv, 8, // max 8 bytes
            (const unsigned char*)aad, (size_t)(aad_len),
            (const unsigned char*)ciphertext, plaintext,
            (const unsigned char*)tag, 8);

    mbedtls_ccm_free(&aes);

    *plaintext_len = ciphertext_len;
}

void AES_192_CCM_8_ENCRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int* ciphertext_len,
    unsigned char* plaintext, unsigned int plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag) {

    mbedtls_ccm_context aes;
    mbedtls_ccm_init(&aes);

    mbedtls_ccm_setkey(&aes, MBEDTLS_CIPHER_ID_AES, (const unsigned char*)key, 192);

    mbedtls_ccm_encrypt_and_tag(&aes, plaintext_len,
        (const unsigned char*)iv, 8, // max 8 bytes
        (const unsigned char*)aad, (size_t)(aad_len),
        (const unsigned char*)plaintext, ciphertext,
        tag, 8);

    mbedtls_ccm_free(&aes);

    *ciphertext_len = plaintext_len;
}

void AES_192_CCM_8_DECRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int ciphertext_len,
    unsigned char* plaintext, unsigned int* plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag, unsigned int* result) {
    
    mbedtls_ccm_context aes;
    mbedtls_ccm_init(&aes);

    mbedtls_ccm_setkey(&aes, MBEDTLS_CIPHER_ID_AES, (const unsigned char*)key, 192);

    *result =
        mbedtls_ccm_auth_decrypt(&aes, ciphertext_len,
            (const unsigned char*)iv, 8, // max 8 bytes
            (const unsigned char*)aad, (size_t)(aad_len),
            (const unsigned char*)ciphertext, plaintext,
            (const unsigned char*)tag, 8);

    mbedtls_ccm_free(&aes);

    *plaintext_len = ciphertext_len;
}

void AES_256_CCM_8_ENCRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int* ciphertext_len,
    unsigned char* plaintext, unsigned int plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag) {
    
    mbedtls_ccm_context aes;
    mbedtls_ccm_init(&aes);

    mbedtls_ccm_setkey(&aes, MBEDTLS_CIPHER_ID_AES, (const unsigned char*)key, 256);

    mbedtls_ccm_encrypt_and_tag(&aes, plaintext_len,
        (const unsigned char*)iv, 8, // max 8 bytes
        (const unsigned char*)aad, (size_t)(aad_len),
        (const unsigned char*)plaintext, ciphertext,
        tag, 8);

    mbedtls_ccm_free(&aes);

    *ciphertext_len = plaintext_len;
}

void AES_256_CCM_8_DECRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int ciphertext_len,
    unsigned char* plaintext, unsigned int* plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag, unsigned int* result) {
    
    mbedtls_ccm_context aes;
    mbedtls_ccm_init(&aes);

    mbedtls_ccm_setkey(&aes, MBEDTLS_CIPHER_ID_AES, (const unsigned char*)key, 256);

    *result =
        mbedtls_ccm_auth_decrypt(&aes, ciphertext_len,
            (const unsigned char*)iv, 8, // max 8 bytes
            (const unsigned char*)aad, (size_t)(aad_len),
            (const unsigned char*)ciphertext, plaintext,
            (const unsigned char*)tag, 8);

    mbedtls_ccm_free(&aes);

    *plaintext_len = ciphertext_len;
}


#else

/**
  * @brief Format first block B(0)
  * @param[in] q Bit string representation of the octet length of P
  * @param[in] n Nonce
  * @param[in] nLen Length of the nonce
  * @param[in] aLen Length of the additional data
  * @param[in] tLen Length of the MAC
  * @param[out] b Pointer to the buffer where to format B(0)
  * @return Error code
  **/

static void ccmFormatBlock0(size_t q, const uint8_t* n, size_t nLen, size_t aLen,
    size_t tLen, uint8_t* b)
{
    size_t i;
    size_t qLen;

    //Compute the octet length of Q
    qLen = 15 - nLen;

    //Format the leading octet of the first block
    b[0] = (aLen > 0) ? 0x40 : 0x00;
    //Encode the octet length of T
    b[0] |= ((tLen - 2) / 2) << 3;
    //Encode the octet length of Q
    b[0] |= qLen - 1;

    //Copy the nonce
    memcpy(b + 1, n, nLen);

    //Encode the length field Q
    for (i = 0; i < qLen; i++, q >>= 8)
    {
        b[15 - i] = q & 0xFF;
    }

}

/**
 * @brief XOR operation
 * @param[out] x Block resulting from the XOR operation
 * @param[in] a First block
 * @param[in] b Second block
 * @param[in] n Size of the block
 **/

static void ccmXorBlock(uint8_t* x, const uint8_t* a, const uint8_t* b, size_t n)
{
    size_t i;

    //Perform XOR operation
    for (i = 0; i < n; i++)
    {
        x[i] = a[i] ^ b[i];
    }
}

/**
 * @brief Format initial counter value CTR(0)
 * @param[in] n Nonce
 * @param[in] nLen Length of the nonce
 * @param[out] ctr Pointer to the buffer where to format CTR(0)
 **/

static void ccmFormatCounter0(const uint8_t* n, size_t nLen, uint8_t* ctr)
{
    size_t qLen;

    //Compute the octet length of Q
    qLen = 15 - nLen;

    //Format CTR(0)
    ctr[0] = qLen - 1;
    //Copy the nonce
    memcpy(ctr + 1, n, nLen);
    //Initialize counter value
    memset(ctr + 1 + nLen, 0, qLen);
}


/**
 * @brief Increment counter block
 * @param[in,out] ctr Pointer to the counter block
 * @param[in] n Size in bytes of the specific part of the block to be incremented
 **/

void ccmIncCounter(uint8_t* ctr, size_t n)
{
    size_t i;
    uint16_t temp;

    //The function increments the right-most bytes of the block. The remaining
    //left-most bytes remain unchanged
    for (temp = 1, i = 0; i < n; i++)
    {
        //Increment the current byte and propagate the carry
        temp += ctr[15 - i];
        ctr[15 - i] = temp & 0xFF;
        temp >>= 8;
    }
}

void AES_128_CCM_8_ENCRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int* ciphertext_len,
    unsigned char* plaintext, unsigned int plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag) {

    AesContext aes_ctx;
    aesInit(&aes_ctx, key, 16);

    size_t m;
    uint8_t b[16];
    uint8_t y[16];
    uint8_t s[16];

    uint8_t n[8];
    memcpy(n, iv, 8); // between 7 & 13

    //Format first block B(0)
    ccmFormatBlock0(plaintext_len, n, 8, aad_len, 8, b);

    //Set Y(0) = CIPH(B(0))
    aesEncryptBlock(&aes_ctx, b, y);

    //Any additional data?
    if (aad_len > 0)
    {
        //Format the associated data
        memset(b, 0, 16);

        //Check the length of the associated data string
        if (aad_len < 0xFF00)
        {
            //The length is encoded as 2 octets
            STORE16BE(aad_len, b);

            //Number of bytes to copy
            m = MIN(aad_len, 16 - 2);
            //Concatenate the associated data A
            memcpy(b + 2, aad, m);
        }
        else
        {
            //The length is encoded as 6 octets
            b[0] = 0xFF;
            b[1] = 0xFE;

            //MSB is stored first
            STORE32BE(aad_len, b + 2);

            //Number of bytes to copy
            m = MIN(aad_len, 16 - 6);
            //Concatenate the associated data A
            memcpy(b + 6, aad, m);
        }

        //XOR B(1) with Y(0)
        ccmXorBlock(y, b, y, 16);
        //Compute Y(1) = CIPH(B(1) ^ Y(0))
        aesEncryptBlock(&aes_ctx, y, y);

        //Number of remaining data bytes
        aad_len -= m;
        aad += m;

        //Process the remaining data bytes
        while (aad_len > 0)
        {
            //Associated data are processed in a block-by-block fashion
            m = MIN(aad_len, 16);

            //XOR B(i) with Y(i-1)
            ccmXorBlock(y, aad, y, m);
            //Compute Y(i) = CIPH(B(i) ^ Y(i-1))
            aesEncryptBlock(&aes_ctx, y, y);

            //Next block
            aad_len -= m;
            aad += m;
        }
    }

    //Format initial counter value CTR(0)
    ccmFormatCounter0(n, 8, b);

    //Compute S(0) = CIPH(CTR(0))
    aesEncryptBlock(&aes_ctx, b, s);
    //Save MSB(S(0))
    memcpy(tag, s, 8);

    //Encrypt plaintext

    unsigned char p[16];
    unsigned char c[16];
    size_t len = 0;
    //ECB mode operates in a block-by-block fashion
    while (len < plaintext_len)
    {
        memcpy(p, plaintext + len, 16);
        ccmXorBlock(y, p, y, 16);
        //Encrypt current block
        aesEncryptBlock(&aes_ctx, y, y);
        ccmIncCounter(b, 15 - 8);
        aesEncryptBlock(&aes_ctx, b, s);
        ccmXorBlock(c, p, s, 16);
        for (int i = 0; i < 16; i++) {
            ciphertext[i + len] = c[i];
        }
        len += 16;

    }

    //Compute MAC
    ccmXorBlock(tag, tag, y, 8);
    *ciphertext_len = plaintext_len;


}

void AES_128_CCM_8_DECRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int ciphertext_len,
    unsigned char* plaintext, unsigned int* plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag, unsigned int* result) {

    AesContext aes_ctx;
    aesInit(&aes_ctx, key, 16);

    uint8_t mask;
    size_t m;
    uint8_t b[16];
    uint8_t y[16];
    uint8_t r[16];
    uint8_t s[16];

    uint8_t n[8];
    memcpy(n, iv, 8); // between 7 & 13

    //Format first block B(0)
    ccmFormatBlock0(ciphertext_len, n, 8, aad_len, 8, b);

     //Set Y(0) = CIPH(B(0))
    aesEncryptBlock(&aes_ctx, b, y);

    //Any additional data?
    if (aad_len > 0)
    {
        //Format the associated data
        memset(b, 0, 16);

        //Check the length of the associated data string
        if (aad_len < 0xFF00)
        {
            //The length is encoded as 2 octets
            STORE16BE(aad_len, b);

            //Number of bytes to copy
            m = MIN(aad_len, 16 - 2);
            //Concatenate the associated data A
            memcpy(b + 2, aad, m);
        }
        else
        {
            //The length is encoded as 6 octets
            b[0] = 0xFF;
            b[1] = 0xFE;

            //MSB is stored first
            STORE32BE(aad_len, b + 2);

            //Number of bytes to copy
            m = MIN(aad_len, 16 - 6);
            //Concatenate the associated data A
            memcpy(b + 6, aad, m);
        }

        //XOR B(1) with Y(0)
        ccmXorBlock(y, b, y, 16);
        //Compute Y(1) = CIPH(B(1) ^ Y(0))
        aesEncryptBlock(&aes_ctx, y, y);

        //Number of remaining data bytes
        aad_len -= m;
        aad += m;

        //Process the remaining data bytes
        while (aad_len > 0)
        {
            //Associated data are processed in a block-by-block fashion
            m = MIN(aad_len, 16);

            //XOR B(i) with Y(i-1)
            ccmXorBlock(y, aad, y, m);
            //Compute Y(i) = CIPH(B(i) ^ Y(i-1))
            aesEncryptBlock(&aes_ctx, y, y);

            //Next block
            aad_len -= m;
            aad += m;
        }
    }

    //Format initial counter value CTR(0)
    ccmFormatCounter0(n, 8, b);

    //Compute S(0) = CIPH(CTR(0))
    aesEncryptBlock(&aes_ctx, b, s);
    //Save MSB(S(0))
    memcpy(r, s, 8);

    size_t len = 0;
    unsigned char p[16];
    unsigned char c[16];

    //ECB mode operates in a block-by-block fashion
    while (len < ciphertext_len)
    {
        memcpy(c, ciphertext + len, 16);

        ccmIncCounter(b, 15 - 8);
        aesEncryptBlock(&aes_ctx, b, s);

        ccmXorBlock(p, c, s, 16);
        ccmXorBlock(y, p, y, 16);

        aesEncryptBlock(&aes_ctx, y, y);

        for (int i = 0; i < 16; i++) {
            plaintext[i + len] = p[i];
        }
        len += 16;

    }


    //Compute MAC
    ccmXorBlock(r, r, y, 8);

    //The calculated tag is bitwise compared to the received tag. The message
    //is authenticated if and only if the tags match
    for (mask = 0, m = 0; m < 8; m++)
    {
        mask |= r[m] ^ tag[m];
    }

    //Return status code
    if (mask == 0)  *result = 0;
    else            *result = 1;

    *plaintext_len = ciphertext_len;
   
}

void AES_192_CCM_8_ENCRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int* ciphertext_len,
    unsigned char* plaintext, unsigned int plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag) {

    AesContext aes_ctx;
    aesInit(&aes_ctx, key, 24);

    size_t m;
    uint8_t b[16];
    uint8_t y[16];
    uint8_t s[16];

    uint8_t n[8];
    memcpy(n, iv, 8); // between 7 & 13

    //Format first block B(0)
    ccmFormatBlock0(plaintext_len, n, 8, aad_len, 8, b);

    //Set Y(0) = CIPH(B(0))
    aesEncryptBlock(&aes_ctx, b, y);

    //Any additional data?
    if (aad_len > 0)
    {
        //Format the associated data
        memset(b, 0, 16);

        //Check the length of the associated data string
        if (aad_len < 0xFF00)
        {
            //The length is encoded as 2 octets
            STORE16BE(aad_len, b);

            //Number of bytes to copy
            m = MIN(aad_len, 16 - 2);
            //Concatenate the associated data A
            memcpy(b + 2, aad, m);
        }
        else
        {
            //The length is encoded as 6 octets
            b[0] = 0xFF;
            b[1] = 0xFE;

            //MSB is stored first
            STORE32BE(aad_len, b + 2);

            //Number of bytes to copy
            m = MIN(aad_len, 16 - 6);
            //Concatenate the associated data A
            memcpy(b + 6, aad, m);
        }

        //XOR B(1) with Y(0)
        ccmXorBlock(y, b, y, 16);
        //Compute Y(1) = CIPH(B(1) ^ Y(0))
        aesEncryptBlock(&aes_ctx, y, y);

        //Number of remaining data bytes
        aad_len -= m;
        aad += m;

        //Process the remaining data bytes
        while (aad_len > 0)
        {
            //Associated data are processed in a block-by-block fashion
            m = MIN(aad_len, 16);

            //XOR B(i) with Y(i-1)
            ccmXorBlock(y, aad, y, m);
            //Compute Y(i) = CIPH(B(i) ^ Y(i-1))
            aesEncryptBlock(&aes_ctx, y, y);

            //Next block
            aad_len -= m;
            aad += m;
        }
    }

    //Format initial counter value CTR(0)
    ccmFormatCounter0(n, 8, b);

    //Compute S(0) = CIPH(CTR(0))
    aesEncryptBlock(&aes_ctx, b, s);
    //Save MSB(S(0))
    memcpy(tag, s, 8);

    //Encrypt plaintext

    unsigned char p[16];
    unsigned char c[16];
    size_t len = 0;
    //ECB mode operates in a block-by-block fashion
    while (len < plaintext_len)
    {
        memcpy(p, plaintext + len, 16);
        ccmXorBlock(y, p, y, 16);
        //Encrypt current block
        aesEncryptBlock(&aes_ctx, y, y);
        ccmIncCounter(b, 15 - 8);
        aesEncryptBlock(&aes_ctx, b, s);
        ccmXorBlock(c, p, s, 16);
        for (int i = 0; i < 16; i++) {
            ciphertext[i + len] = c[i];
        }
        len += 16;

    }

    //Compute MAC
    ccmXorBlock(tag, tag, y, 8);
    *ciphertext_len = plaintext_len;
    
}

void AES_192_CCM_8_DECRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int ciphertext_len,
    unsigned char* plaintext, unsigned int* plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag, unsigned int* result) {

    AesContext aes_ctx;
    aesInit(&aes_ctx, key, 24);

    uint8_t mask;
    size_t m;
    uint8_t b[16];
    uint8_t y[16];
    uint8_t r[16];
    uint8_t s[16];

    uint8_t n[8];
    memcpy(n, iv, 8); // between 7 & 13

    //Format first block B(0)
    ccmFormatBlock0(ciphertext_len, n, 8, aad_len, 8, b);

    //Set Y(0) = CIPH(B(0))
    aesEncryptBlock(&aes_ctx, b, y);

    //Any additional data?
    if (aad_len > 0)
    {
        //Format the associated data
        memset(b, 0, 16);

        //Check the length of the associated data string
        if (aad_len < 0xFF00)
        {
            //The length is encoded as 2 octets
            STORE16BE(aad_len, b);

            //Number of bytes to copy
            m = MIN(aad_len, 16 - 2);
            //Concatenate the associated data A
            memcpy(b + 2, aad, m);
        }
        else
        {
            //The length is encoded as 6 octets
            b[0] = 0xFF;
            b[1] = 0xFE;

            //MSB is stored first
            STORE32BE(aad_len, b + 2);

            //Number of bytes to copy
            m = MIN(aad_len, 16 - 6);
            //Concatenate the associated data A
            memcpy(b + 6, aad, m);
        }

        //XOR B(1) with Y(0)
        ccmXorBlock(y, b, y, 16);
        //Compute Y(1) = CIPH(B(1) ^ Y(0))
        aesEncryptBlock(&aes_ctx, y, y);

        //Number of remaining data bytes
        aad_len -= m;
        aad += m;

        //Process the remaining data bytes
        while (aad_len > 0)
        {
            //Associated data are processed in a block-by-block fashion
            m = MIN(aad_len, 16);

            //XOR B(i) with Y(i-1)
            ccmXorBlock(y, aad, y, m);
            //Compute Y(i) = CIPH(B(i) ^ Y(i-1))
            aesEncryptBlock(&aes_ctx, y, y);

            //Next block
            aad_len -= m;
            aad += m;
        }
    }

    //Format initial counter value CTR(0)
    ccmFormatCounter0(n, 8, b);

    //Compute S(0) = CIPH(CTR(0))
    aesEncryptBlock(&aes_ctx, b, s);
    //Save MSB(S(0))
    memcpy(r, s, 8);

    size_t len = 0;
    unsigned char p[16];
    unsigned char c[16];

    //ECB mode operates in a block-by-block fashion
    while (len < ciphertext_len)
    {
        memcpy(c, ciphertext + len, 16);

        ccmIncCounter(b, 15 - 8);
        aesEncryptBlock(&aes_ctx, b, s);

        ccmXorBlock(p, c, s, 16);
        ccmXorBlock(y, p, y, 16);

        aesEncryptBlock(&aes_ctx, y, y);

        for (int i = 0; i < 16; i++) {
            plaintext[i + len] = p[i];
        }
        len += 16;

    }


    //Compute MAC
    ccmXorBlock(r, r, y, 8);

    //The calculated tag is bitwise compared to the received tag. The message
    //is authenticated if and only if the tags match
    for (mask = 0, m = 0; m < 8; m++)
    {
        mask |= r[m] ^ tag[m];
    }

    //Return status code
    if (mask == 0)  *result = 0;
    else            *result = 1;

    *plaintext_len = ciphertext_len;
    
}

void AES_256_CCM_8_ENCRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int* ciphertext_len,
    unsigned char* plaintext, unsigned int plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag) {

    AesContext aes_ctx;
    aesInit(&aes_ctx, key, 32);

    size_t m;
    uint8_t b[16];
    uint8_t y[16];
    uint8_t s[16];

    uint8_t n[8];
    memcpy(n, iv, 8); // between 7 & 13

    //Format first block B(0)
    ccmFormatBlock0(plaintext_len, n, 8, aad_len, 8, b);

    //Set Y(0) = CIPH(B(0))
    aesEncryptBlock(&aes_ctx, b, y);

    //Any additional data?
    if (aad_len > 0)
    {
        //Format the associated data
        memset(b, 0, 16);

        //Check the length of the associated data string
        if (aad_len < 0xFF00)
        {
            //The length is encoded as 2 octets
            STORE16BE(aad_len, b);

            //Number of bytes to copy
            m = MIN(aad_len, 16 - 2);
            //Concatenate the associated data A
            memcpy(b + 2, aad, m);
        }
        else
        {
            //The length is encoded as 6 octets
            b[0] = 0xFF;
            b[1] = 0xFE;

            //MSB is stored first
            STORE32BE(aad_len, b + 2);

            //Number of bytes to copy
            m = MIN(aad_len, 16 - 6);
            //Concatenate the associated data A
            memcpy(b + 6, aad, m);
        }

        //XOR B(1) with Y(0)
        ccmXorBlock(y, b, y, 16);
        //Compute Y(1) = CIPH(B(1) ^ Y(0))
        aesEncryptBlock(&aes_ctx, y, y);

        //Number of remaining data bytes
        aad_len -= m;
        aad += m;

        //Process the remaining data bytes
        while (aad_len > 0)
        {
            //Associated data are processed in a block-by-block fashion
            m = MIN(aad_len, 16);

            //XOR B(i) with Y(i-1)
            ccmXorBlock(y, aad, y, m);
            //Compute Y(i) = CIPH(B(i) ^ Y(i-1))
            aesEncryptBlock(&aes_ctx, y, y);

            //Next block
            aad_len -= m;
            aad += m;
        }
    }

    //Format initial counter value CTR(0)
    ccmFormatCounter0(n, 8, b);

    //Compute S(0) = CIPH(CTR(0))
    aesEncryptBlock(&aes_ctx, b, s);
    //Save MSB(S(0))
    memcpy(tag, s, 8);

    //Encrypt plaintext

    unsigned char p[16];
    unsigned char c[16];
    size_t len = 0;
    //ECB mode operates in a block-by-block fashion
    while (len < plaintext_len)
    {
        memcpy(p, plaintext + len, 16);
        ccmXorBlock(y, p, y, 16);
        //Encrypt current block
        aesEncryptBlock(&aes_ctx, y, y);
        ccmIncCounter(b, 15 - 8);
        aesEncryptBlock(&aes_ctx, b, s);
        ccmXorBlock(c, p, s, 16);
        for (int i = 0; i < 16; i++) {
            ciphertext[i + len] = c[i];
        }
        len += 16;

    }

    //Compute MAC
    ccmXorBlock(tag, tag, y, 8);
    *ciphertext_len = plaintext_len;
    
}

void AES_256_CCM_8_DECRYPT(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int ciphertext_len,
    unsigned char* plaintext, unsigned int* plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag, unsigned int* result) {

    AesContext aes_ctx;
    aesInit(&aes_ctx, key, 32);

    uint8_t mask;
    size_t m;
    uint8_t b[16];
    uint8_t y[16];
    uint8_t r[16];
    uint8_t s[16];

    uint8_t n[8];
    memcpy(n, iv, 8); // between 7 & 13

    //Format first block B(0)
    ccmFormatBlock0(ciphertext_len, n, 8, aad_len, 8, b);

    //Set Y(0) = CIPH(B(0))
    aesEncryptBlock(&aes_ctx, b, y);

    //Any additional data?
    if (aad_len > 0)
    {
        //Format the associated data
        memset(b, 0, 16);

        //Check the length of the associated data string
        if (aad_len < 0xFF00)
        {
            //The length is encoded as 2 octets
            STORE16BE(aad_len, b);

            //Number of bytes to copy
            m = MIN(aad_len, 16 - 2);
            //Concatenate the associated data A
            memcpy(b + 2, aad, m);
        }
        else
        {
            //The length is encoded as 6 octets
            b[0] = 0xFF;
            b[1] = 0xFE;

            //MSB is stored first
            STORE32BE(aad_len, b + 2);

            //Number of bytes to copy
            m = MIN(aad_len, 16 - 6);
            //Concatenate the associated data A
            memcpy(b + 6, aad, m);
        }

        //XOR B(1) with Y(0)
        ccmXorBlock(y, b, y, 16);
        //Compute Y(1) = CIPH(B(1) ^ Y(0))
        aesEncryptBlock(&aes_ctx, y, y);

        //Number of remaining data bytes
        aad_len -= m;
        aad += m;

        //Process the remaining data bytes
        while (aad_len > 0)
        {
            //Associated data are processed in a block-by-block fashion
            m = MIN(aad_len, 16);

            //XOR B(i) with Y(i-1)
            ccmXorBlock(y, aad, y, m);
            //Compute Y(i) = CIPH(B(i) ^ Y(i-1))
            aesEncryptBlock(&aes_ctx, y, y);

            //Next block
            aad_len -= m;
            aad += m;
        }
    }

    //Format initial counter value CTR(0)
    ccmFormatCounter0(n, 8, b);

    //Compute S(0) = CIPH(CTR(0))
    aesEncryptBlock(&aes_ctx, b, s);
    //Save MSB(S(0))
    memcpy(r, s, 8);

    size_t len = 0;
    unsigned char p[16];
    unsigned char c[16];

    //ECB mode operates in a block-by-block fashion
    while (len < ciphertext_len)
    {
        memcpy(c, ciphertext + len, 16);

        ccmIncCounter(b, 15 - 8);
        aesEncryptBlock(&aes_ctx, b, s);

        ccmXorBlock(p, c, s, 16);
        ccmXorBlock(y, p, y, 16);

        aesEncryptBlock(&aes_ctx, y, y);

        for (int i = 0; i < 16; i++) {
            plaintext[i + len] = p[i];
        }
        len += 16;

    }


    //Compute MAC
    ccmXorBlock(r, r, y, 8);

    //The calculated tag is bitwise compared to the received tag. The message
    //is authenticated if and only if the tags match
    for (mask = 0, m = 0; m < 8; m++)
    {
        mask |= r[m] ^ tag[m];
    }

    //Return status code
    if (mask == 0)  *result = 0;
    else            *result = 1;

    *plaintext_len = ciphertext_len;

}


#endif