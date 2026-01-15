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

#include "scp03/aes/aes.h"

// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
// https://csrc.nist.gov/Projects/block-cipher-techniques/BCM
// https://github.com/rambo/nfc_lock/blob/master/c/cmac_example.c
// https://www.openssl.org/docs/man3.3/man7/OSSL_PROVIDER-default.html
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf

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

    // Loop until we have processed all data.
    int first_pass = 1;

    //ECB mode operates in a block-by-block fashion
    while ((len < msg_len) || first_pass)
    {
        first_pass = 0;
        int remaining = msg_len - len;

        // Check if this is an intermediate block (more than 16 bytes left)
        if (remaining > 16) 
        {
            memcpy(p, msg + len, 16);
            
            // Standard CBC XOR with previous chain
            for (int i = 0; i < 16; i++) {
                p[i] = p[i] ^ xor_block[i];
            }
            
            len += 16;
        }
        else 
        { 
            // --- LAST BLOCK LOGIC ---
            
            // 1. Initialize p to 0 to handle zero-padding automatically
            memset(p, 0, 16);
            
            // 2. Copy remaining bytes (if any)
            if (remaining > 0) {
                memcpy(p, msg + len, remaining);
            }

            // 3. Apply Padding and Select Subkey (K1 vs K2)
            if (remaining == 16) {
                // Complete block: No padding bytes added, XOR with K1
                for (int i = 0; i < 16; i++) {
                    p[i] = p[i] ^ xor_block[i] ^ K1[i];
                }
            } 
            else {
                // Partial block: Add 0x80 padding, XOR with K2
                p[remaining] = 0x80; 
                // Note: p[remaining+1..15] are already 0 from memset
                
                for (int i = 0; i < 16; i++) {
                    p[i] = p[i] ^ xor_block[i] ^ K2[i];
                }
            }
            
            // Force loop termination after this block
            len = msg_len + 1; 
        }

        //Encrypt current block
        aesEncryptBlock(&aes_ctx, p, c);

        // Update chaining value
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

    // Loop until we have processed all data.
    int first_pass = 1;

    //ECB mode operates in a block-by-block fashion
    while ((len < msg_len) || first_pass)
    {
        first_pass = 0;
        int remaining = msg_len - len;

        // Check if this is an intermediate block (more than 16 bytes left)
        if (remaining > 16) 
        {
            memcpy(p, msg + len, 16);
            
            // Standard CBC XOR with previous chain
            for (int i = 0; i < 16; i++) {
                p[i] = p[i] ^ xor_block[i];
            }
            
            len += 16;
        }
        else 
        { 
            // --- LAST BLOCK LOGIC ---
            
            // 1. Initialize p to 0 to handle zero-padding automatically
            memset(p, 0, 16);
            
            // 2. Copy remaining bytes (if any)
            if (remaining > 0) {
                memcpy(p, msg + len, remaining);
            }

            // 3. Apply Padding and Select Subkey (K1 vs K2)
            if (remaining == 16) {
                // Complete block: No padding bytes added, XOR with K1
                for (int i = 0; i < 16; i++) {
                    p[i] = p[i] ^ xor_block[i] ^ K1[i];
                }
            } 
            else {
                // Partial block: Add 0x80 padding, XOR with K2
                p[remaining] = 0x80; 
                // Note: p[remaining+1..15] are already 0 from memset
                
                for (int i = 0; i < 16; i++) {
                    p[i] = p[i] ^ xor_block[i] ^ K2[i];
                }
            }
            
            // Force loop termination after this block
            len = msg_len + 1; 
        }

        //Encrypt current block
        aesEncryptBlock(&aes_ctx, p, c);

        // Update chaining value
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

    // Loop until we have processed all data.
    int first_pass = 1;

    //ECB mode operates in a block-by-block fashion
    while ((len < msg_len) || first_pass)
    {
        first_pass = 0;
        int remaining = msg_len - len;

        // Check if this is an intermediate block (more than 16 bytes left)
        if (remaining > 16) 
        {
            memcpy(p, msg + len, 16);
            
            // Standard CBC XOR with previous chain
            for (int i = 0; i < 16; i++) {
                p[i] = p[i] ^ xor_block[i];
            }
            
            len += 16;
        }
        else 
        { 
            // --- LAST BLOCK LOGIC ---
            
            // 1. Initialize p to 0 to handle zero-padding automatically
            memset(p, 0, 16);
            
            // 2. Copy remaining bytes (if any)
            if (remaining > 0) {
                memcpy(p, msg + len, remaining);
            }

            // 3. Apply Padding and Select Subkey (K1 vs K2)
            if (remaining == 16) {
                // Complete block: No padding bytes added, XOR with K1
                for (int i = 0; i < 16; i++) {
                    p[i] = p[i] ^ xor_block[i] ^ K1[i];
                }
            } 
            else {
                // Partial block: Add 0x80 padding, XOR with K2
                p[remaining] = 0x80; 
                // Note: p[remaining+1..15] are already 0 from memset
                
                for (int i = 0; i < 16; i++) {
                    p[i] = p[i] ^ xor_block[i] ^ K2[i];
                }
            }
            
            // Force loop termination after this block
            len = msg_len + 1; 
        }

        //Encrypt current block
        aesEncryptBlock(&aes_ctx, p, c);

        // Update chaining value
        memcpy(xor_block, c, 16);

    }

    memcpy(mac, c, 16);
}

