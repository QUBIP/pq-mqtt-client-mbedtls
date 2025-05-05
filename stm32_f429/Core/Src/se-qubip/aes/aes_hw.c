/**
 * @file  aes_hw.c
 * @brief AES HW 
 *
 * @section License
 *
 * Secure Element for QUBIP Project
 *
 * This Secure Element repository for QUBIP Project is subject to the
 * BSD 3-Clause License below.
 *
 * Copyright (c) 2024,
 *         Eros Camacho-Ruiz
 *         Pablo Navarro-Torrero
 *         Pau Ortega-Castro
 *         Apurba Karmakar
 *         Macarena C. Martínez-Rodríguez
 *         Piedad Brox
 *
 * All rights reserved.
 *
 * This Secure Element was developed by Instituto de Microelectrónica de
 * Sevilla - IMSE (CSIC/US) as part of the QUBIP Project, co-funded by the
 * European Union under the Horizon Europe framework programme
 * [grant agreement no. 101119746].
 *
 * -----------------------------------------------------------------------
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 *
 *
 * @author Eros Camacho-Ruiz (camacho@imse-cnm.csic.es)
 * @version 1.0
 **/

////////////////////////////////////////////////////////////////////////////////////
// Company: IMSE-CNM CSIC
// Engineer: Pablo Navarro Torrero
//
// Create Date: 26/09/2024
// File Name: aes_hw.c 
// Project Name: SE-QUBIP
// Target Devices: PYNQ-Z2
// Description:
//
//		AES HW Handler Functions
//
////////////////////////////////////////////////////////////////////////////////////

#include "../../se-qubip/aes/aes_hw.h"

/////////////////////////////////////////////////////////////////////////////////////////////
// INTERFACE INIT/START & READ/WRITE & INIT/OPERATE
/////////////////////////////////////////////////////////////////////////////////////////////

void aes_start(INTF interface)
{
    unsigned long long control = (ADD_AES << 32) + AES_RST_OFF;
    write_INTF(interface, &control, CONTROL, AXI_BYTES);
}

void aes_write(unsigned long long address, unsigned long long size, void *data, unsigned long long reset, INTF interface)
{
    unsigned long long addr = address;
    unsigned long long control = (reset) ? (ADD_AES << 32) + AES_INTF_LOAD + AES_RST_ON : (ADD_AES << 32) + AES_INTF_LOAD + AES_RST_OFF;

    write_INTF(interface, &addr, ADDRESS, AXI_BYTES);
    write_INTF(interface, data, DATA_IN, AXI_BYTES);
    write_INTF(interface, &control, CONTROL, AXI_BYTES);

    for (int i = 1; i < size; i++)
    {
        addr = address + i;
        write_INTF(interface, &addr, ADDRESS, AXI_BYTES);
        write_INTF(interface, data + AXI_BYTES * i, DATA_IN, AXI_BYTES);
    }

    control = (reset) ? (ADD_AES << 32) + AES_INTF_OPER + AES_RST_ON : (ADD_AES << 32) + AES_INTF_OPER + AES_RST_OFF;
    write_INTF(interface, &control, CONTROL, AXI_BYTES);
}

void aes_read(unsigned long long address, unsigned long long size, void *data, INTF interface)
{
    unsigned long long control = (ADD_AES << 32) + AES_INTF_READ;
    unsigned long long addr;

    write_INTF(interface, &control, CONTROL, AXI_BYTES);

    for (int i = 0; i < size; i++)
    {
        addr = address + i;
        write_INTF(interface, &addr, ADDRESS, AXI_BYTES);
        read_INTF(interface, data + AXI_BYTES * i, DATA_OUT, AXI_BYTES);
    }
}

void aes_init(unsigned long long aes_control, unsigned char *key, INTF interface)
{
    //-- General and Interface Reset
    unsigned long long control;
    control = (ADD_AES << 32) + AES_INTF_RST + AES_RST_ON;
    write_INTF(interface, &control, CONTROL, AXI_BYTES);
    control = (ADD_AES << 32) + AES_INTF_OPER + AES_RST_ON;
    write_INTF(interface, &control, CONTROL, AXI_BYTES);

    //-- 256-bit key
    unsigned long long key_len = (aes_control >> 1) & 0x03;
    unsigned char key_256[AES_256_KEY];
    memset(key_256, 0, AES_256_KEY);

    if (key_len == AES_128_KEY)
        memcpy(key_256, key, AES_128_KEY);
    else if (key_len == AES_192_KEY)
        memcpy(key_256, key, AES_192_KEY);
    else
        memcpy(key_256, key, AES_256_KEY);

    swapEndianness(key_256, AES_256_KEY);

    //-- Write AES Control and Key
    aes_write(AES_CONTROL, AXI_BYTES / AXI_BYTES, &aes_control, AES_RST_ON, interface);
    aes_write(AES_KEY, AES_256_KEY / AXI_BYTES, key_256, AES_RST_ON, interface);
}

void aes_op(unsigned char *data_in, unsigned char *data_out, INTF interface)
{   
    //-- Write Input Data
    unsigned char data_in_swap[AES_BLOCK];
    memcpy(data_in_swap, data_in, AES_BLOCK);
    swapEndianness(data_in_swap, AES_BLOCK);
    aes_write(AES_PLAINTEXT, AES_BLOCK / AXI_BYTES, data_in_swap, AES_RST_ON, interface);

    //-- Control Signals
    unsigned long long count = 0;
    unsigned long long info  = 0;
    
    //-- Start Execution
    aes_start(interface);

    //-- Detect when finish
    while (count < AES_WAIT_TIME)
    {
        read_INTF(interface, &info, END_OP, AXI_BYTES);

        if (info & 0x1)
            break;

        count++;
    }

    if (count == AES_WAIT_TIME)
        printf("AES FAIL!: TIMEOUT \t%lld\n", count);

    //-- Read Output Data
    aes_read(AES_CIPHERTEXT, AES_BLOCK / AXI_BYTES, data_out, interface);
    swapEndianness(data_out, AES_BLOCK);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ADDITIONAL FUNCTIONS
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static void aes_block_padding(unsigned int len, unsigned int *complete_len, unsigned int *blocks, unsigned char *data, unsigned char **data_padded)
{
    *blocks = (len + AES_BLOCK - 1) / AES_BLOCK; 
    *complete_len = *blocks * AES_BLOCK;
    
    *data_padded =  malloc(*complete_len);
    memset(*data_padded, 0, *complete_len);
    memcpy(*data_padded, data, len);
}

//-- CMAC
/**
* @brief Multiplication by x in GF(2^128)
* @param[out] x Pointer to the output block
* @param[out] a Pointer to the input block
* @param[in] n Size of the block, in bytes
* @param[in] rb Representation of the irreducible binary polynomial
**/

static void cmacMul(uint8_t* x, const uint8_t* a, size_t n, uint8_t rb)
{
    size_t i;
    uint8_t c;

    // Save the value of the most significant bit
    c = a[0] >> 7;

    // The multiplication of a polynomial by x in GF(2^128) corresponds to a
    // shift of indices
    for (i = 0; i < (n - 1); i++)
    {
        x[i] = (a[i] << 1) | (a[i + 1] >> 7);
    }

    // Shift the last byte of the block to the left
    x[i] = a[i] << 1;

    // If the highest term of the result is equal to one, then perform reduction
    x[i] ^= rb & ~(c - 1);
}

static void GenSubKeys(unsigned char *key, unsigned int key_len, unsigned char K1[AES_BLOCK], unsigned char K2[AES_BLOCK], INTF interface)
{
    size_t len = 0;

    unsigned char p[AES_BLOCK];
    unsigned char L[AES_BLOCK];

    memset(p, 0, AES_BLOCK);

    //-- INITIALIZATION: General/Interface Reset & Select Operation & Load Key
    unsigned long long aes_control;

    if (key_len == AES_128_KEY)
        aes_control = (AES_128 << 1) + AES_ENC;
    else if (key_len == AES_192_KEY)
        aes_control = (AES_192 << 1) + AES_ENC;
    else
        aes_control = (AES_256 << 1) + AES_ENC;

    aes_init(aes_control, key, interface);
    
    //-- AES OPERATION
    aes_op(p, L, interface);

    //-- Irreducible Polynomial
    uint8_t rb = 0x87;

    // The subkey K1 is obtained by multiplying L by x in GF(2^b)
    cmacMul(K1, L, 16, rb);

    // The subkey K2 is obtained by multiplying L by x^2 in GF(2^b)
    cmacMul(K2, K1, 16, rb);
}

//-- CCM
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

static void ccmFormatBlock0(size_t q, const uint8_t *n, size_t nLen, size_t aLen, size_t tLen, uint8_t *b)
{
    size_t i;
    size_t qLen;

    // Compute the octet length of Q
    qLen = 15 - nLen;

    // Format the leading octet of the first block
    b[0] = (aLen > 0) ? 0x40 : 0x00;
    // Encode the octet length of T
    b[0] |= ((tLen - 2) / 2) << 3;
    // Encode the octet length of Q
    b[0] |= qLen - 1;

    // Copy the nonce
    memcpy(b + 1, n, nLen);

    // Encode the length field Q
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

static void ccmXorBlock(uint8_t *x, const uint8_t *a, const uint8_t *b, size_t n)
{
    size_t i;

    // Perform XOR operation
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

static void ccmFormatCounter0(const uint8_t *n, size_t nLen, uint8_t *ctr)
{
    size_t qLen;

    // Compute the octet length of Q
    qLen = 15 - nLen;

    // Format CTR(0)
    ctr[0] = qLen - 1;
    // Copy the nonce
    memcpy(ctr + 1, n, nLen);
    // Initialize counter value
    memset(ctr + 1 + nLen, 0, qLen);
}

/**
 * @brief Increment counter block
 * @param[in,out] ctr Pointer to the counter block
 * @param[in] n Size in bytes of the specific part of the block to be incremented
 **/

static void ccmIncCounter(uint8_t *ctr, size_t n)
{
    size_t i;
    uint16_t temp;

    // The function increments the right-most bytes of the block. The remaining
    // left-most bytes remain unchanged
    for (temp = 1, i = 0; i < n; i++)
    {
        // Increment the current byte and propagate the carry
        temp += ctr[15 - i];
        ctr[15 - i] = temp & 0xFF;
        temp >>= 8;
    }
}

//-- GCM
#define BIT(x) (1 << (x))

static void inc32(unsigned char *block)
{
    unsigned int val;
    val = WPA_GET_BE32(block + 16 - 4);
    val++;
    WPA_PUT_BE32(block + 16 - 4, val);
}

static void shift_right_block(unsigned char *v)
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

static void xor_op(unsigned char *dst, const unsigned char *src)
{
    unsigned int *d = (unsigned int *)dst;
    unsigned int *s = (unsigned int *)src;
    *d++ ^= *s++;
    *d++ ^= *s++;
    *d++ ^= *s++;
    *d++ ^= *s++;
}

/* Multiplication in GF(2^128) */
static void gf_mult(const unsigned char *x, const unsigned char *y, unsigned char *z)
{
    unsigned char v[16];
    int i, j;

    memset(z, 0, 16); /* Z_0 = 0^128 */
    memcpy(v, y, 16); /* V_0 = Y */

    for (i = 0; i < 16; i++)
    {
        for (j = 0; j < 8; j++)
        {
            if (x[i] & BIT(7 - j))
            {
                /* Z_(i + 1) = Z_i XOR V_i */
                xor_op(z, v);
            }
            else
            {
                /* Z_(i + 1) = Z_i */
            }

            if (v[15] & 0x01)
            {
                /* V_(i + 1) = (V_i >> 1) XOR R */
                shift_right_block(v);
                /* R = 11100001 || 0^120 */
                v[0] ^= 0xe1;
            }
            else
            {
                /* V_(i + 1) = V_i >> 1 */
                shift_right_block(v);
            }
        }
    }
}

static void ghash(const unsigned char *h, const unsigned char *x, size_t xlen, unsigned char *y)
{
    size_t m, i;
    const unsigned char *xpos = x;
    unsigned char tmp[16];

    m = xlen / 16;

    for (i = 0; i < m; i++)
    {
        /* Y_i = (Y^(i-1) XOR X_i) dot H */
        xor_op(y, xpos);
        xpos += 16;

        /* dot operation:
         * multiplication operation for binary Galois (finite) field of
         * 2^128 elements */
        gf_mult(y, h, tmp);
        memcpy(y, tmp, 16);
    }

    if (x + xlen > xpos)
    {
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

static void aes_gctr(const unsigned char *icb, const unsigned char *x, size_t xlen, unsigned char *y, INTF interface)
{
    size_t i, n, last;
    unsigned char cb[16];
    unsigned char tmp[16];
    const unsigned char *xpos = x;
    unsigned char *ypos = y;

    n = xlen / 16;

    memcpy(cb, icb, 16);
    /* Full blocks */
    for (i = 0; i < n; i++)
    {
        aes_op(cb, ypos, interface);
        xor_op(ypos, xpos);
        xpos += 16;
        ypos += 16;
        inc32(cb);
    }

    last = x + xlen - xpos;
    if (last)
    {
        /* Last, partial block */
        aes_op(cb, tmp, interface);
        for (i = 0; i < last; i++)
            *ypos++ = *xpos++ ^ tmp[i];
    }
}

static void aes_gcm_init_hash_key(unsigned long long aes_control, unsigned char *key, size_t key_len, unsigned char *H, INTF interface)
{
    aes_init(aes_control, key, interface);

    size_t len = 0;

    unsigned char p[16];
    unsigned char c[16];

    memset(p, 0, 16);
    aes_op(p, c, interface);
    memcpy(H, c, 16);
}

static void aes_gcm_prepare_j0(unsigned char *iv, size_t iv_len, unsigned char *H, unsigned char *J0)
{
    unsigned char len_buf[16];

    if (iv_len == 12)
    {
        /* Prepare block J_0 = IV || 0^31 || 1 [len(IV) = 96] */
        memcpy(J0, iv, iv_len);
        memset(J0 + iv_len, 0, 16 - iv_len);
        J0[15] = 0x01;
    }
    else
    {
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

static void aes_gcm_gctr(const unsigned char *J0, const unsigned char *in, size_t len, unsigned char *out, INTF interface)
{
    unsigned char J0inc[16];

    memcpy(J0inc, J0, 16);
    inc32(J0inc);
    aes_gctr(J0inc, in, len, out, interface);
}

static void aes_gcm_ghash(const unsigned char *H, const unsigned char *aad, size_t aad_len, const unsigned char *crypt, size_t crypt_len, unsigned char *S)
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

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AES-128-ECB
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void aes_128_ecb_encrypt_hw(unsigned char *key, unsigned char *ciphertext, unsigned int *ciphertext_len, unsigned char *plaintext, unsigned int plaintext_len, INTF interface)
{
    //-- Number of Blocks and Padding
    unsigned int plaintext_blocks;
    unsigned char *plaintext_padded;

    aes_block_padding(plaintext_len, ciphertext_len, &plaintext_blocks, plaintext, &plaintext_padded);

    /*printf("\nplaintext_padded = 0x");
    for (int i = 0; i < AES_BLOCK * plaintext_blocks; i++) printf("%02x", plaintext_padded[i]); printf("\n");*/
    // printf("\nplaintext = %s\n", plaintext_padded);

    //-- INITIALIZATION: General/Interface Reset & Select Operation & Load Key
    unsigned long long aes_control = (AES_128 << 1) + AES_ENC;
    aes_init(aes_control, key, interface);

    //-- START AES Operation
    for (int i = 0; i < plaintext_blocks; i++)
    {   
        aes_op(plaintext_padded + i * AES_BLOCK, ciphertext + i * AES_BLOCK, interface);
        /*printf("ciphertext = 0x");
        for (int j = 0; j < AES_BLOCK; j++) printf("%02x", ciphertext[i * AES_BLOCK + j]); printf("\n");*/
    }
    // printf("\nciphertext = %s\n", ciphertext);
}

void aes_128_ecb_decrypt_hw(unsigned char *key, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *plaintext, unsigned int *plaintext_len, INTF interface)
{
    //-- Number of Blocks and Padding
    unsigned int ciphertext_blocks;
    unsigned char *ciphertext_padded;

    aes_block_padding(ciphertext_len, plaintext_len, &ciphertext_blocks, ciphertext, &ciphertext_padded);

    /*printf("\nciphertext_padded = 0x");
    for (int i = 0; i < ciphertext_blocks; i++) printf("%02x", ciphertext_padded[i]); printf("\n");*/
    // printf("\nciphertext = %s\n", ciphertext_padded);

    //-- INITIALIZATION: General/Interface Reset & Select Operation & Load Key
    unsigned long long aes_control = (AES_128 << 1) + AES_DEC;
    aes_init(aes_control, key, interface);

    //-- START AES Operation
    for (int i = 0; i < ciphertext_blocks; i++)
    { 
        aes_op(ciphertext_padded + i * AES_BLOCK, plaintext + i * AES_BLOCK, interface);
        /*printf("plaintext = 0x");
        for (int j = 0; j < AES_BLOCK; j++) printf("%02x", plaintext[i * AES_BLOCK + j]); printf("\n");*/
    }
    // printf("\nplaintext = %s\n", ciphertext);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AES-192-ECB
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void aes_192_ecb_encrypt_hw(unsigned char *key, unsigned char *ciphertext, unsigned int *ciphertext_len, unsigned char *plaintext, unsigned int plaintext_len, INTF interface)
{
    //-- Number of Blocks and Padding
    unsigned int plaintext_blocks;
    unsigned char *plaintext_padded;

    aes_block_padding(plaintext_len, ciphertext_len, &plaintext_blocks, plaintext, &plaintext_padded);

    /*printf("\nplaintext_padded = 0x");
    for (int i = 0; i < AES_BLOCK * plaintext_blocks; i++) printf("%02x", plaintext_padded[i]); printf("\n");*/
    // printf("\nplaintext = %s\n", plaintext_padded);

    //-- INITIALIZATION: General/Interface Reset & Select Operation & Load Key
    unsigned long long aes_control = (AES_192 << 1) + AES_ENC;
    aes_init(aes_control, key, interface);

    //-- START AES Operation
    for (int i = 0; i < plaintext_blocks; i++)
    {
        aes_op(plaintext_padded + i * AES_BLOCK, ciphertext + i * AES_BLOCK, interface);
        /*printf("ciphertext = 0x");
        for (int j = 0; j < AES_BLOCK; j++) printf("%02x", ciphertext[i * AES_BLOCK + j]); printf("\n");*/
    }
    // printf("\nciphertext = %s\n", ciphertext);
}

void aes_192_ecb_decrypt_hw(unsigned char *key, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *plaintext, unsigned int *plaintext_len, INTF interface)
{
    //-- Number of Blocks and Padding
    unsigned int ciphertext_blocks;
    unsigned char *ciphertext_padded;

    aes_block_padding(ciphertext_len, plaintext_len, &ciphertext_blocks, ciphertext, &ciphertext_padded);

    /*printf("\nciphertext_padded = 0x");
    for (int i = 0; i < ciphertext_blocks; i++) printf("%02x", ciphertext_padded[i]); printf("\n");*/
    // printf("\nciphertext = %s\n", ciphertext_padded);

    //-- INITIALIZATION: General/Interface Reset & Select Operation & Load Key
    unsigned long long aes_control = (AES_192 << 1) + AES_DEC;
    aes_init(aes_control, key, interface);

    //-- START AES Operation
    for (int i = 0; i < ciphertext_blocks; i++)
    {
        aes_op(ciphertext_padded + i * AES_BLOCK, plaintext + i * AES_BLOCK, interface);
        /*printf("plaintext = 0x");
        for (int j = 0; j < AES_BLOCK; j++) printf("%02x", plaintext[i * AES_BLOCK + j]); printf("\n");*/
    }
    // printf("\nplaintext = %s\n", ciphertext);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AES-256-ECB
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void aes_256_ecb_encrypt_hw(unsigned char *key, unsigned char *ciphertext, unsigned int *ciphertext_len, unsigned char *plaintext, unsigned int plaintext_len, INTF interface)
{
    //-- Number of Blocks and Padding
    unsigned int plaintext_blocks;
    unsigned char *plaintext_padded;

    aes_block_padding(plaintext_len, ciphertext_len, &plaintext_blocks, plaintext, &plaintext_padded);

    /*printf("\nplaintext_padded = 0x");
    for (int i = 0; i < AES_BLOCK * plaintext_blocks; i++) printf("%02x", plaintext_padded[i]); printf("\n");*/
    // printf("\nplaintext = %s\n", plaintext_padded);

    //-- INITIALIZATION: General/Interface Reset & Select Operation & Load Key
    unsigned long long aes_control = (AES_256 << 1) + AES_ENC;
    aes_init(aes_control, key, interface);

    //-- START AES Operation
    for (int i = 0; i < plaintext_blocks; i++)
    {
        aes_op(plaintext_padded + i * AES_BLOCK, ciphertext + i * AES_BLOCK, interface);
        /*printf("ciphertext = 0x");
        for (int j = 0; j < AES_BLOCK; j++) printf("%02x", ciphertext[i * AES_BLOCK + j]); printf("\n");*/
    }
    // printf("\nciphertext = %s\n", ciphertext);
}

void aes_256_ecb_decrypt_hw(unsigned char *key, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *plaintext, unsigned int *plaintext_len, INTF interface)
{
    //-- Number of Blocks and Padding
    unsigned int ciphertext_blocks;
    unsigned char *ciphertext_padded;

    aes_block_padding(ciphertext_len, plaintext_len, &ciphertext_blocks, ciphertext, &ciphertext_padded);

    /*printf("\nciphertext_padded = 0x");
    for (int i = 0; i < ciphertext_blocks; i++) printf("%02x", ciphertext_padded[i]); printf("\n");*/
    // printf("\nciphertext = %s\n", ciphertext_padded);

    //-- INITIALIZATION: General/Interface Reset & Select Operation & Load Key
    unsigned long long aes_control = (AES_256 << 1) + AES_DEC;
    aes_init(aes_control, key, interface);

    //-- START AES Operation
    for (int i = 0; i < ciphertext_blocks; i++)
    {
        aes_op(ciphertext_padded + i * AES_BLOCK, plaintext + i * AES_BLOCK, interface);
        /*printf("plaintext = 0x");
        for (int j = 0; j < AES_BLOCK; j++) printf("%02x", plaintext[i * AES_BLOCK + j]); printf("\n");*/
    }
    // printf("\nplaintext = %s\n", ciphertext);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AES-128-CBC
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void aes_128_cbc_encrypt_hw(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned int *ciphertext_len, unsigned char *plaintext, unsigned int plaintext_len, INTF interface)
{
    //-- Number of Blocks and Padding
    unsigned int plaintext_blocks;
    unsigned char *plaintext_padded;

    aes_block_padding(plaintext_len, ciphertext_len, &plaintext_blocks, plaintext, &plaintext_padded);

    //-- Plaintext/Ciphertext
    unsigned char p[AES_BLOCK];
    unsigned char c[AES_BLOCK];

    //-- INITIALIZATION: General/Interface Reset & Select Operation & Load Key
    unsigned long long aes_control = (AES_128 << 1) + AES_ENC;
    aes_init(aes_control, key, interface);
	
	//------------------------------------------------
    //-- ECB mode operates in a block-by-block fashion
 	//------------------------------------------------
    unsigned char iv_block[AES_BLOCK];
    memcpy(iv_block, iv, AES_BLOCK);

    size_t len = 0;

    //-- Start loop
    while (len < plaintext_len)
    {
        memcpy(p, plaintext_padded + len, AES_BLOCK);

        for (int i = 0; i < AES_BLOCK; i++)
        {
            p[i] = p[i] ^ iv_block[i];
        }

        //-- Encrypt current block
        aes_op(p, c, interface);
		
		//-- Save Ciphertext
        for (int i = 0; i < AES_BLOCK; i++)
        {
            ciphertext[i + len] = c[i];
        }

        len += AES_BLOCK;

        memcpy(iv_block, c, AES_BLOCK);
    }
}

void aes_128_cbc_decrypt_hw(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *plaintext, unsigned int *plaintext_len, INTF interface)
{
    //-- Number of Blocks and Padding
    unsigned int ciphertext_blocks;
    unsigned char *ciphertext_padded;

    aes_block_padding(ciphertext_len, plaintext_len, &ciphertext_blocks, ciphertext, &ciphertext_padded);

    //-- Plaintext/Ciphertext
    unsigned char p[AES_BLOCK];
    unsigned char c[AES_BLOCK];

    //-- INITIALIZATION: General/Interface Reset & Select Operation & Load Key
    unsigned long long aes_control = (AES_128 << 1) + AES_DEC;
    aes_init(aes_control, key, interface);

    //------------------------------------------------
    //-- ECB mode operates in a block-by-block fashion
 	//------------------------------------------------
    unsigned char iv_block[AES_BLOCK];
    memcpy(iv_block, iv, AES_BLOCK);

    size_t len = 0;

    //-- Start loop
    while (len < ciphertext_len)
    {
        memcpy(c, ciphertext_padded + len, AES_BLOCK);

        //-- Decrypt current block
        aes_op(c, p, interface);

		//-- Save Plaintext
        for (int i = 0; i < AES_BLOCK; i++)
        {
            plaintext[i + len] = p[i] ^ iv_block[i];
        }

        len += AES_BLOCK;

        memcpy(iv_block, c, AES_BLOCK);
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AES-192-CBC
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void aes_192_cbc_encrypt_hw(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned int *ciphertext_len, unsigned char *plaintext, unsigned int plaintext_len, INTF interface)
{
    //-- Number of Blocks and Padding
    unsigned int plaintext_blocks;
    unsigned char *plaintext_padded;

    aes_block_padding(plaintext_len, ciphertext_len, &plaintext_blocks, plaintext, &plaintext_padded);

    //-- Plaintext/Ciphertext
    unsigned char p[AES_BLOCK];
    unsigned char c[AES_BLOCK];

    //-- INITIALIZATION: General/Interface Reset & Select Operation & Load Key
    unsigned long long aes_control = (AES_192 << 1) + AES_ENC;
    aes_init(aes_control, key, interface);

    //------------------------------------------------
    //-- ECB mode operates in a block-by-block fashion
    //------------------------------------------------
    unsigned char iv_block[AES_BLOCK];
    memcpy(iv_block, iv, AES_BLOCK);

    size_t len = 0;

    //-- Start loop
    while (len < plaintext_len)
    {
        memcpy(p, plaintext_padded + len, AES_BLOCK);

        for (int i = 0; i < AES_BLOCK; i++)
        {
            p[i] = p[i] ^ iv_block[i];
        }

        //-- Encrypt current block
        aes_op(p, c, interface);

        //-- Save Ciphertext
        for (int i = 0; i < AES_BLOCK; i++)
        {
            ciphertext[i + len] = c[i];
        }

        len += AES_BLOCK;

        memcpy(iv_block, c, AES_BLOCK);
    }
}

void aes_192_cbc_decrypt_hw(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *plaintext, unsigned int *plaintext_len, INTF interface)
{
    //-- Number of Blocks and Padding
    unsigned int ciphertext_blocks;
    unsigned char *ciphertext_padded;

    aes_block_padding(ciphertext_len, plaintext_len, &ciphertext_blocks, ciphertext, &ciphertext_padded);

    //-- Plaintext/Ciphertext
    unsigned char p[AES_BLOCK];
    unsigned char c[AES_BLOCK];

    //-- INITIALIZATION: General/Interface Reset & Select Operation & Load Key
    unsigned long long aes_control = (AES_192 << 1) + AES_DEC;
    aes_init(aes_control, key, interface);

    //------------------------------------------------
    //-- ECB mode operates in a block-by-block fashion
    //------------------------------------------------
    unsigned char iv_block[AES_BLOCK];
    memcpy(iv_block, iv, AES_BLOCK);

    size_t len = 0;

    //-- Start loop
    while (len < ciphertext_len)
    {
        memcpy(c, ciphertext_padded + len, AES_BLOCK);

        //-- Decrypt current block
        aes_op(c, p, interface);

        //-- Save Plaintext
        for (int i = 0; i < AES_BLOCK; i++)
        {
            plaintext[i + len] = p[i] ^ iv_block[i];
        }

        len += AES_BLOCK;

        memcpy(iv_block, c, AES_BLOCK);
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AES-256-CBC
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void aes_256_cbc_encrypt_hw(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned int *ciphertext_len, unsigned char *plaintext, unsigned int plaintext_len, INTF interface)
{
    //-- Number of Blocks and Padding
    unsigned int plaintext_blocks;
    unsigned char *plaintext_padded;

    aes_block_padding(plaintext_len, ciphertext_len, &plaintext_blocks, plaintext, &plaintext_padded);

    //-- Plaintext/Ciphertext
    unsigned char p[AES_BLOCK];
    unsigned char c[AES_BLOCK];

    //-- INITIALIZATION: General/Interface Reset & Select Operation & Load Key
    unsigned long long aes_control = (AES_256 << 1) + AES_ENC;
    aes_init(aes_control, key, interface);

    //------------------------------------------------
    //-- ECB mode operates in a block-by-block fashion
    //------------------------------------------------
    unsigned char iv_block[AES_BLOCK];
    memcpy(iv_block, iv, AES_BLOCK);

    size_t len = 0;

    //-- Start loop
    while (len < plaintext_len)
    {
        memcpy(p, plaintext_padded + len, AES_BLOCK);

        for (int i = 0; i < AES_BLOCK; i++)
        {
            p[i] = p[i] ^ iv_block[i];
        }

        //-- Encrypt current block
        aes_op(p, c, interface);

        //-- Save Ciphertext
        for (int i = 0; i < AES_BLOCK; i++)
        {
            ciphertext[i + len] = c[i];
        }

        len += AES_BLOCK;

        memcpy(iv_block, c, AES_BLOCK);
    }
}

void aes_256_cbc_decrypt_hw(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *plaintext, unsigned int *plaintext_len, INTF interface)
{
    //-- Number of Blocks and Padding
    unsigned int ciphertext_blocks;
    unsigned char *ciphertext_padded;

    aes_block_padding(ciphertext_len, plaintext_len, &ciphertext_blocks, ciphertext, &ciphertext_padded);

    //-- Plaintext/Ciphertext
    unsigned char p[AES_BLOCK];
    unsigned char c[AES_BLOCK];

    //-- INITIALIZATION: General/Interface Reset & Select Operation & Load Key
    unsigned long long aes_control = (AES_256 << 1) + AES_DEC;
    aes_init(aes_control, key, interface);

    //------------------------------------------------
    //-- ECB mode operates in a block-by-block fashion
    //------------------------------------------------
    unsigned char iv_block[AES_BLOCK];
    memcpy(iv_block, iv, AES_BLOCK);

    size_t len = 0;

    //-- Start loop
    while (len < ciphertext_len)
    {
        memcpy(c, ciphertext_padded + len, AES_BLOCK);

        //-- Decrypt current block
        aes_op(c, p, interface);

        //-- Save Plaintext
        for (int i = 0; i < AES_BLOCK; i++)
        {
            plaintext[i + len] = p[i] ^ iv_block[i];
        }

        len += AES_BLOCK;

        memcpy(iv_block, c, AES_BLOCK);
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AES-128-CMAC
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void aes_128_cmac_hw(unsigned char *key, unsigned char *mac, unsigned int *mac_len, unsigned char *msg, unsigned int msg_len, INTF interface)
{
    //-- Number of Blocks and Padding
    unsigned int complete_len;
    unsigned int msg_blocks;
    unsigned char *msg_padded;

    aes_block_padding(msg_len, &complete_len, &msg_blocks, msg, &msg_padded);
    
    //-- Complete Blocks Condition and missing bytes
    unsigned int missing_bytes = complete_len - msg_len;
    unsigned int complete_cond = (missing_bytes == 0) ? 1 : 0;

    if (!complete_cond) msg_padded[msg_len] = 0x80;

    //-- Subkey Generation
    unsigned char K1[AES_BLOCK];
    unsigned char K2[AES_BLOCK];
    GenSubKeys(key, AES_128_KEY, K1, K2, interface);

    //-- Plaintext/Ciphertext 
    unsigned char p[AES_BLOCK];
    unsigned char c[AES_BLOCK];

    //-- ECB mode operates in a block-by-block fashion
    size_t len = 0;
    *mac_len = AES_BLOCK;

    unsigned char xor_block[AES_BLOCK];
    memset(xor_block, 0, AES_BLOCK);

    for (int i = 0; i < msg_blocks; i++)
    {
        memcpy(p, msg_padded + len, AES_BLOCK);

        if (i < msg_blocks - 1)
        {
            for (int i = 0; i < AES_BLOCK; i++)
            {
                p[i] = p[i] ^ xor_block[i];
            }
        }
        else
        { // last one
            if (complete_cond)
            {
                for (int i = 0; i < AES_BLOCK; i++)
                {
                    p[i] = p[i] ^ xor_block[i] ^ K1[i];
                }
            }
            else
            {
                for (int i = 0; i < AES_BLOCK; i++)
                {
                    p[i] = p[i] ^ xor_block[i] ^ K2[i];
                }
            }
        }

        //-- Encrypt current block
        aes_op(p, c, interface);

        //-- Save Ciphertext
        len += AES_BLOCK;

        memcpy(xor_block, c, AES_BLOCK);
    }
    memcpy(mac, c, AES_BLOCK);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AES-192-CMAC
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void aes_192_cmac_hw(unsigned char *key, unsigned char *mac, unsigned int *mac_len, unsigned char *msg, unsigned int msg_len, INTF interface)
{
    //-- Number of Blocks and Padding
    unsigned int complete_len;
    unsigned int msg_blocks;
    unsigned char *msg_padded;

    aes_block_padding(msg_len, &complete_len, &msg_blocks, msg, &msg_padded);

    //-- Complete Blocks Condition and missing bytes
    unsigned int missing_bytes = complete_len - msg_len;
    unsigned int complete_cond = (missing_bytes == 0) ? 1 : 0;

    if (!complete_cond) msg_padded[msg_len] = 0x80;

    //-- Subkey Generation
    unsigned char K1[AES_BLOCK];
    unsigned char K2[AES_BLOCK];
    GenSubKeys(key, AES_192_KEY, K1, K2, interface);

    //-- Plaintext/Ciphertext
    unsigned char p[AES_BLOCK];
    unsigned char c[AES_BLOCK];

    //-- ECB mode operates in a block-by-block fashion
    size_t len = 0;
    *mac_len = AES_BLOCK;

    unsigned char xor_block[AES_BLOCK];
    memset(xor_block, 0, AES_BLOCK);

    for (int i = 0; i < msg_blocks; i++)
    {
        memcpy(p, msg_padded + len, AES_BLOCK);

        if (i < msg_blocks - 1)
        {
            for (int i = 0; i < AES_BLOCK; i++)
            {
                p[i] = p[i] ^ xor_block[i];
            }
        }
        else
        { // last one
            if (complete_cond)
            {
                for (int i = 0; i < AES_BLOCK; i++)
                {
                    p[i] = p[i] ^ xor_block[i] ^ K1[i];
                }
            }
            else
            {
                for (int i = 0; i < AES_BLOCK; i++)
                {
                    p[i] = p[i] ^ xor_block[i] ^ K2[i];
                }
            }
        }

        //-- Encrypt current block
        aes_op(p, c, interface);

        //-- Save Ciphertext
        len += AES_BLOCK;

        memcpy(xor_block, c, AES_BLOCK);
    }
    memcpy(mac, c, AES_BLOCK);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AES-256-CMAC
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void aes_256_cmac_hw(unsigned char *key, unsigned char *mac, unsigned int *mac_len, unsigned char *msg, unsigned int msg_len, INTF interface)
{
    //-- Number of Blocks and Padding
    unsigned int complete_len;
    unsigned int msg_blocks;
    unsigned char *msg_padded;

    aes_block_padding(msg_len, &complete_len, &msg_blocks, msg, &msg_padded);

    //-- Complete Blocks Condition and missing bytes
    unsigned int missing_bytes = complete_len - msg_len;
    unsigned int complete_cond = (missing_bytes == 0) ? 1 : 0;

    if (!complete_cond) msg_padded[msg_len] = 0x80;

    //-- Subkey Generation
    unsigned char K1[AES_BLOCK];
    unsigned char K2[AES_BLOCK];
    GenSubKeys(key, AES_256_KEY, K1, K2, interface);

    //-- Plaintext/Ciphertext
    unsigned char p[AES_BLOCK];
    unsigned char c[AES_BLOCK];

    //-- ECB mode operates in a block-by-block fashion
    size_t len = 0;
    *mac_len = AES_BLOCK;

    unsigned char xor_block[AES_BLOCK];
    memset(xor_block, 0, AES_BLOCK);

    for (int i = 0; i < msg_blocks; i++)
    {
        memcpy(p, msg_padded + len, AES_BLOCK);

        if (i < msg_blocks - 1)
        {
            for (int i = 0; i < AES_BLOCK; i++)
            {
                p[i] = p[i] ^ xor_block[i];
            }
        }
        else
        { // last one
            if (complete_cond)
            {
                for (int i = 0; i < AES_BLOCK; i++)
                {
                    p[i] = p[i] ^ xor_block[i] ^ K1[i];
                }
            }
            else
            {
                for (int i = 0; i < AES_BLOCK; i++)
                {
                    p[i] = p[i] ^ xor_block[i] ^ K2[i];
                }
            }
        }

        //-- Encrypt current block
        aes_op(p, c, interface);

        //-- Save Ciphertext
        len += AES_BLOCK;

        memcpy(xor_block, c, AES_BLOCK);
    }
    memcpy(mac, c, AES_BLOCK);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AES-128-CCM-8
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void aes_128_ccm_8_encrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int *ciphertext_len,
                              unsigned char *plaintext, unsigned int plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, INTF interface)
{
    //-- Number of Blocks and Padding
    unsigned int complete_len;
    unsigned int plaintext_blocks;
    unsigned char *plaintext_padded;

    aes_block_padding(plaintext_len, &complete_len, &plaintext_blocks, plaintext, &plaintext_padded);

    //-- INITIALIZATION: General/Interface Reset & Select Operation & Load Key
    unsigned long long aes_control = (AES_128 << 1) + AES_ENC;
    aes_init(aes_control, key, interface); 

    //-- Format Input
    size_t m;
    uint8_t b[16];
    uint8_t y[16];
    uint8_t s[16];

    uint8_t n[iv_len];
    memcpy(n, iv, iv_len); // between 7 & 13

    // Format first block B(0)
    ccmFormatBlock0(plaintext_len, n, iv_len, aad_len, 8, b);

    // Set Y(0) = CIPH(B(0))
    aes_op(b, y, interface);
    
    // Any additional data?
    if (aad_len > 0)
    {
        // Format the associated data
        memset(b, 0, 16);

        // Check the length of the associated data string
        if (aad_len < 0xFF00)
        {
            // The length is encoded as 2 octets
            STORE16BE(aad_len, b);

            // Number of bytes to copy
            m = MIN(aad_len, 16 - 2);
            // Concatenate the associated data A
            memcpy(b + 2, aad, m);
        }
        else if (aad_len < 0xFFFFFFFF)
        {
            // The length is encoded as 6 octets
            b[0] = 0xFF;
            b[1] = 0xFE;

            // MSB is stored first
            STORE32BE(aad_len, b + 2);

            // Number of bytes to copy
            m = MIN(aad_len, 16 - 6);
            // Concatenate the associated data A
            memcpy(b + 6, aad, m);
        }
        else 
        {
            // The length is encoded as 6 octets
            b[0] = 0xFF;
            b[1] = 0xFF;

            // MSB is stored first
            STORE64BE(aad_len, b + 2);

            // Number of bytes to copy
            m = MIN(aad_len, 16 - 10);
            // Concatenate the associated data A
            memcpy(b + 10, aad, m);
        }

        // XOR B(1) with Y(0)
        ccmXorBlock(y, b, y, 16);
        
        // Compute Y(1) = CIPH(B(1) ^ Y(0))
        aes_op(y, y, interface);

        // Number of remaining data bytes
        aad_len -= m;
        aad += m;

        // Process the remaining data bytes
        while (aad_len > 0)
        {
            // Associated data are processed in a block-by-block fashion
            m = MIN(aad_len, 16);

            // XOR B(i) with Y(i-1)
            ccmXorBlock(y, aad, y, m);
            // Compute Y(i) = CIPH(B(i) ^ Y(i-1))
            aes_op(y, y, interface);

            // Next block
            aad_len -= m;
            aad += m;
        }
    }

    // Format initial counter value CTR(0)
    ccmFormatCounter0(n, iv_len, b);

    // Compute S(0) = CIPH(CTR(0))
    aes_op(b, s, interface);

    // Save MSB(S(0))
    memcpy(tag, s, 8);

    // Encrypt plaintext
    unsigned char p[16];
    unsigned char c[16];
    size_t len = 0;
    // ECB mode operates in a block-by-block fashion
    while (len < plaintext_len)
    {
        memcpy(p, plaintext_padded + len, 16);
        ccmXorBlock(y, p, y, 16);
        // Encrypt current block
        aes_op(y, y ,interface);
        ccmIncCounter(b, 15 - iv_len);
        aes_op(b, s, interface);
        ccmXorBlock(c, p, s, 16);
        for (int i = 0; i < 16; i++)
        {
            ciphertext[i + len] = c[i];
        }
        len += 16;
    }

    // Compute MAC
    ccmXorBlock(tag, tag, y, 8);
    *ciphertext_len = plaintext_len;
}

void aes_128_ccm_8_decrypt_hw(unsigned char* key, unsigned char* iv, unsigned int iv_len, unsigned char* ciphertext, unsigned int ciphertext_len,
                              unsigned char* plaintext, unsigned int* plaintext_len, unsigned char* aad, unsigned int aad_len, unsigned char* tag, unsigned int* result, INTF interface) 
{
    //-- Number of Blocks and Padding
    unsigned int complete_len;
    unsigned int ciphertext_blocks;
    unsigned char *ciphertext_padded;

    aes_block_padding(ciphertext_len, &complete_len, &ciphertext_blocks, ciphertext, &ciphertext_padded);

    //-- INITIALIZATION: General/Interface Reset & Select Operation & Load Key
    unsigned long long aes_control = (AES_128 << 1) + AES_ENC;
    aes_init(aes_control, key, interface);

    uint8_t mask;
    size_t m;
    uint8_t b[16];
    uint8_t y[16];
    uint8_t r[16];
    uint8_t s[16];

    uint8_t n[iv_len];
    memcpy(n, iv, iv_len); // between 7 & 13

    //Format first block B(0)
    ccmFormatBlock0(ciphertext_len, n, iv_len, aad_len, 8, b);

    //Set Y(0) = CIPH(B(0))
    aes_op(b, y, interface);

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
        else if (aad_len < 0xFFFFFFFF)
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
        else
        {
            // The length is encoded as 6 octets
            b[0] = 0xFF;
            b[1] = 0xFF;

            // MSB is stored first
            STORE64BE(aad_len, b + 2);

            // Number of bytes to copy
            m = MIN(aad_len, 16 - 10);
            // Concatenate the associated data A
            memcpy(b + 10, aad, m);
        }

        //XOR B(1) with Y(0)
        ccmXorBlock(y, b, y, 16);
        //Compute Y(1) = CIPH(B(1) ^ Y(0))
        aes_op(y, y, interface);

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
            aes_op(y, y, interface);

            //Next block
            aad_len -= m;
            aad += m;
        }
    }

    //Format initial counter value CTR(0)
    ccmFormatCounter0(n, iv_len, b);

    //Compute S(0) = CIPH(CTR(0))
    aes_op(b, s, interface);
    //Save MSB(S(0))
    memcpy(r, s, 8);

    size_t len = 0;
    unsigned char p[16];
    unsigned char c[16];

    //ECB mode operates in a block-by-block fashion
    while (len < ciphertext_len)
    {
        memcpy(c, ciphertext + len, 16);

        ccmIncCounter(b, 15 - iv_len);
        aes_op(b, s, interface);

        ccmXorBlock(p, c, s, 16);
        ccmXorBlock(y, p, y, 16);

        aes_op(y, y, interface);

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

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AES-192-CCM-8
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void aes_192_ccm_8_encrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int *ciphertext_len,
                              unsigned char *plaintext, unsigned int plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, INTF interface)
{
    //-- Number of Blocks and Padding
    unsigned int complete_len;
    unsigned int plaintext_blocks;
    unsigned char *plaintext_padded;

    aes_block_padding(plaintext_len, &complete_len, &plaintext_blocks, plaintext, &plaintext_padded);

    //-- INITIALIZATION: General/Interface Reset & Select Operation & Load Key
    unsigned long long aes_control = (AES_192 << 1) + AES_ENC;
    aes_init(aes_control, key, interface); 

    //-- Format Input
    size_t m;
    uint8_t b[16];
    uint8_t y[16];
    uint8_t s[16];

    uint8_t n[iv_len];
    memcpy(n, iv, iv_len); // between 7 & 13

    // Format first block B(0)
    ccmFormatBlock0(plaintext_len, n, iv_len, aad_len, 8, b);

    // Set Y(0) = CIPH(B(0))
    aes_op(b, y, interface);
    
    // Any additional data?
    if (aad_len > 0)
    {
        // Format the associated data
        memset(b, 0, 16);

        // Check the length of the associated data string
        if (aad_len < 0xFF00)
        {
            // The length is encoded as 2 octets
            STORE16BE(aad_len, b);

            // Number of bytes to copy
            m = MIN(aad_len, 16 - 2);
            // Concatenate the associated data A
            memcpy(b + 2, aad, m);
        }
        else if (aad_len < 0xFFFFFFFF)
        {
            // The length is encoded as 6 octets
            b[0] = 0xFF;
            b[1] = 0xFE;

            // MSB is stored first
            STORE32BE(aad_len, b + 2);

            // Number of bytes to copy
            m = MIN(aad_len, 16 - 6);
            // Concatenate the associated data A
            memcpy(b + 6, aad, m);
        }
        else 
        {
            // The length is encoded as 6 octets
            b[0] = 0xFF;
            b[1] = 0xFF;

            // MSB is stored first
            STORE64BE(aad_len, b + 2);

            // Number of bytes to copy
            m = MIN(aad_len, 16 - 10);
            // Concatenate the associated data A
            memcpy(b + 10, aad, m);
        }

        // XOR B(1) with Y(0)
        ccmXorBlock(y, b, y, 16);
        
        // Compute Y(1) = CIPH(B(1) ^ Y(0))
        aes_op(y, y, interface);

        // Number of remaining data bytes
        aad_len -= m;
        aad += m;

        // Process the remaining data bytes
        while (aad_len > 0)
        {
            // Associated data are processed in a block-by-block fashion
            m = MIN(aad_len, 16);

            // XOR B(i) with Y(i-1)
            ccmXorBlock(y, aad, y, m);
            // Compute Y(i) = CIPH(B(i) ^ Y(i-1))
            aes_op(y, y, interface);

            // Next block
            aad_len -= m;
            aad += m;
        }
    }

    // Format initial counter value CTR(0)
    ccmFormatCounter0(n, iv_len, b);

    // Compute S(0) = CIPH(CTR(0))
    aes_op(b, s, interface);

    // Save MSB(S(0))
    memcpy(tag, s, 8);

    // Encrypt plaintext
    unsigned char p[16];
    unsigned char c[16];
    size_t len = 0;
    // ECB mode operates in a block-by-block fashion
    while (len < plaintext_len)
    {
        memcpy(p, plaintext_padded + len, 16);
        ccmXorBlock(y, p, y, 16);
        // Encrypt current block
        aes_op(y, y ,interface);
        ccmIncCounter(b, 15 - iv_len);
        aes_op(b, s, interface);
        ccmXorBlock(c, p, s, 16);
        for (int i = 0; i < 16; i++)
        {
            ciphertext[i + len] = c[i];
        }
        len += 16;
    }

    // Compute MAC
    ccmXorBlock(tag, tag, y, 8);
    *ciphertext_len = plaintext_len;
}

void aes_192_ccm_8_decrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int ciphertext_len,
                              unsigned char *plaintext, unsigned int *plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, unsigned int *result, INTF interface)
{
    //-- Number of Blocks and Padding
    unsigned int complete_len;
    unsigned int ciphertext_blocks;
    unsigned char *ciphertext_padded;

    aes_block_padding(ciphertext_len, &complete_len, &ciphertext_blocks, ciphertext, &ciphertext_padded);

    //-- INITIALIZATION: General/Interface Reset & Select Operation & Load Key
    unsigned long long aes_control = (AES_192 << 1) + AES_ENC;
    aes_init(aes_control, key, interface);

    uint8_t mask;
    size_t m;
    uint8_t b[16];
    uint8_t y[16];
    uint8_t r[16];
    uint8_t s[16];

    uint8_t n[iv_len];
    memcpy(n, iv, iv_len); // between 7 & 13

    // Format first block B(0)
    ccmFormatBlock0(ciphertext_len, n, iv_len, aad_len, 8, b);

    // Set Y(0) = CIPH(B(0))
    aes_op(b, y, interface);

    // Any additional data?
    if (aad_len > 0)
    {
        // Format the associated data
        memset(b, 0, 16);

        // Check the length of the associated data string
        if (aad_len < 0xFF00)
        {
            // The length is encoded as 2 octets
            STORE16BE(aad_len, b);

            // Number of bytes to copy
            m = MIN(aad_len, 16 - 2);
            // Concatenate the associated data A
            memcpy(b + 2, aad, m);
        }
        else if (aad_len < 0xFFFFFFFF)
        {
            // The length is encoded as 6 octets
            b[0] = 0xFF;
            b[1] = 0xFE;

            // MSB is stored first
            STORE32BE(aad_len, b + 2);

            // Number of bytes to copy
            m = MIN(aad_len, 16 - 6);
            // Concatenate the associated data A
            memcpy(b + 6, aad, m);
        }
        else
        {
            // The length is encoded as 6 octets
            b[0] = 0xFF;
            b[1] = 0xFF;

            // MSB is stored first
            STORE64BE(aad_len, b + 2);

            // Number of bytes to copy
            m = MIN(aad_len, 16 - 10);
            // Concatenate the associated data A
            memcpy(b + 10, aad, m);
        }

        // XOR B(1) with Y(0)
        ccmXorBlock(y, b, y, 16);
        // Compute Y(1) = CIPH(B(1) ^ Y(0))
        aes_op(y, y, interface);

        // Number of remaining data bytes
        aad_len -= m;
        aad += m;

        // Process the remaining data bytes
        while (aad_len > 0)
        {
            // Associated data are processed in a block-by-block fashion
            m = MIN(aad_len, 16);

            // XOR B(i) with Y(i-1)
            ccmXorBlock(y, aad, y, m);
            // Compute Y(i) = CIPH(B(i) ^ Y(i-1))
            aes_op(y, y, interface);

            // Next block
            aad_len -= m;
            aad += m;
        }
    }

    // Format initial counter value CTR(0)
    ccmFormatCounter0(n, iv_len, b);

    // Compute S(0) = CIPH(CTR(0))
    aes_op(b, s, interface);
    // Save MSB(S(0))
    memcpy(r, s, 8);

    size_t len = 0;
    unsigned char p[16];
    unsigned char c[16];

    // ECB mode operates in a block-by-block fashion
    while (len < ciphertext_len)
    {
        memcpy(c, ciphertext + len, 16);

        ccmIncCounter(b, 15 - iv_len);
        aes_op(b, s, interface);

        ccmXorBlock(p, c, s, 16);
        ccmXorBlock(y, p, y, 16);

        aes_op(y, y, interface);

        for (int i = 0; i < 16; i++)
        {
            plaintext[i + len] = p[i];
        }
        len += 16;
    }

    // Compute MAC
    ccmXorBlock(r, r, y, 8);

    // The calculated tag is bitwise compared to the received tag. The message
    // is authenticated if and only if the tags match
    for (mask = 0, m = 0; m < 8; m++)
    {
        mask |= r[m] ^ tag[m];
    }

    // Return status code
    if (mask == 0)
        *result = 0;
    else
        *result = 1;

    *plaintext_len = ciphertext_len;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AES-256-CCM-8
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void aes_256_ccm_8_encrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int *ciphertext_len,
                              unsigned char *plaintext, unsigned int plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, INTF interface)
{
    //-- Number of Blocks and Padding
    unsigned int complete_len;
    unsigned int plaintext_blocks;
    unsigned char *plaintext_padded;

    aes_block_padding(plaintext_len, &complete_len, &plaintext_blocks, plaintext, &plaintext_padded);

    //-- INITIALIZATION: General/Interface Reset & Select Operation & Load Key
    unsigned long long aes_control = (AES_256 << 1) + AES_ENC;
    aes_init(aes_control, key, interface);

    //-- Format Input
    size_t m;
    uint8_t b[16];
    uint8_t y[16];
    uint8_t s[16];

    uint8_t n[iv_len];
    memcpy(n, iv, iv_len); // between 7 & 13

    // Format first block B(0)
    ccmFormatBlock0(plaintext_len, n, iv_len, aad_len, 8, b);

    // Set Y(0) = CIPH(B(0))
    aes_op(b, y, interface);

    // Any additional data?
    if (aad_len > 0)
    {
        // Format the associated data
        memset(b, 0, 16);

        // Check the length of the associated data string
        if (aad_len < 0xFF00)
        {
            // The length is encoded as 2 octets
            STORE16BE(aad_len, b);

            // Number of bytes to copy
            m = MIN(aad_len, 16 - 2);
            // Concatenate the associated data A
            memcpy(b + 2, aad, m);
        }
        else if (aad_len < 0xFFFFFFFF)
        {
            // The length is encoded as 6 octets
            b[0] = 0xFF;
            b[1] = 0xFE;

            // MSB is stored first
            STORE32BE(aad_len, b + 2);

            // Number of bytes to copy
            m = MIN(aad_len, 16 - 6);
            // Concatenate the associated data A
            memcpy(b + 6, aad, m);
        }
        else
        {
            // The length is encoded as 6 octets
            b[0] = 0xFF;
            b[1] = 0xFF;

            // MSB is stored first
            STORE64BE(aad_len, b + 2);

            // Number of bytes to copy
            m = MIN(aad_len, 16 - 10);
            // Concatenate the associated data A
            memcpy(b + 10, aad, m);
        }

        // XOR B(1) with Y(0)
        ccmXorBlock(y, b, y, 16);

        // Compute Y(1) = CIPH(B(1) ^ Y(0))
        aes_op(y, y, interface);

        // Number of remaining data bytes
        aad_len -= m;
        aad += m;

        // Process the remaining data bytes
        while (aad_len > 0)
        {
            // Associated data are processed in a block-by-block fashion
            m = MIN(aad_len, 16);

            // XOR B(i) with Y(i-1)
            ccmXorBlock(y, aad, y, m);
            // Compute Y(i) = CIPH(B(i) ^ Y(i-1))
            aes_op(y, y, interface);

            // Next block
            aad_len -= m;
            aad += m;
        }
    }

    // Format initial counter value CTR(0)
    ccmFormatCounter0(n, iv_len, b);

    // Compute S(0) = CIPH(CTR(0))
    aes_op(b, s, interface);

    // Save MSB(S(0))
    memcpy(tag, s, 8);

    // Encrypt plaintext
    unsigned char p[16];
    unsigned char c[16];
    size_t len = 0;
    // ECB mode operates in a block-by-block fashion
    while (len < plaintext_len)
    {
        memcpy(p, plaintext_padded + len, 16);
        ccmXorBlock(y, p, y, 16);
        // Encrypt current block
        aes_op(y, y, interface);
        ccmIncCounter(b, 15 - iv_len);
        aes_op(b, s, interface);
        ccmXorBlock(c, p, s, 16);
        for (int i = 0; i < 16; i++)
        {
            ciphertext[i + len] = c[i];
        }
        len += 16;
    }

    // Compute MAC
    ccmXorBlock(tag, tag, y, 8);
    *ciphertext_len = plaintext_len;
}

void aes_256_ccm_8_decrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int ciphertext_len,
                              unsigned char *plaintext, unsigned int *plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, unsigned int *result, INTF interface)
{
    //-- Number of Blocks and Padding
    unsigned int complete_len;
    unsigned int ciphertext_blocks;
    unsigned char *ciphertext_padded;

    aes_block_padding(ciphertext_len, &complete_len, &ciphertext_blocks, ciphertext, &ciphertext_padded);

    //-- INITIALIZATION: General/Interface Reset & Select Operation & Load Key
    unsigned long long aes_control = (AES_256 << 1) + AES_ENC;
    aes_init(aes_control, key, interface);

    uint8_t mask;
    size_t m;
    uint8_t b[16];
    uint8_t y[16];
    uint8_t r[16];
    uint8_t s[16];

    uint8_t n[iv_len];
    memcpy(n, iv, iv_len); // between 7 & 13

    // Format first block B(0)
    ccmFormatBlock0(ciphertext_len, n, iv_len, aad_len, 8, b);

    // Set Y(0) = CIPH(B(0))
    aes_op(b, y, interface);

    // Any additional data?
    if (aad_len > 0)
    {
        // Format the associated data
        memset(b, 0, 16);

        // Check the length of the associated data string
        if (aad_len < 0xFF00)
        {
            // The length is encoded as 2 octets
            STORE16BE(aad_len, b);

            // Number of bytes to copy
            m = MIN(aad_len, 16 - 2);
            // Concatenate the associated data A
            memcpy(b + 2, aad, m);
        }
        else if (aad_len < 0xFFFFFFFF)
        {
            // The length is encoded as 6 octets
            b[0] = 0xFF;
            b[1] = 0xFE;

            // MSB is stored first
            STORE32BE(aad_len, b + 2);

            // Number of bytes to copy
            m = MIN(aad_len, 16 - 6);
            // Concatenate the associated data A
            memcpy(b + 6, aad, m);
        }
        else
        {
            // The length is encoded as 6 octets
            b[0] = 0xFF;
            b[1] = 0xFF;

            // MSB is stored first
            STORE64BE(aad_len, b + 2);

            // Number of bytes to copy
            m = MIN(aad_len, 16 - 10);
            // Concatenate the associated data A
            memcpy(b + 10, aad, m);
        }

        // XOR B(1) with Y(0)
        ccmXorBlock(y, b, y, 16);
        // Compute Y(1) = CIPH(B(1) ^ Y(0))
        aes_op(y, y, interface);

        // Number of remaining data bytes
        aad_len -= m;
        aad += m;

        // Process the remaining data bytes
        while (aad_len > 0)
        {
            // Associated data are processed in a block-by-block fashion
            m = MIN(aad_len, 16);

            // XOR B(i) with Y(i-1)
            ccmXorBlock(y, aad, y, m);
            // Compute Y(i) = CIPH(B(i) ^ Y(i-1))
            aes_op(y, y, interface);

            // Next block
            aad_len -= m;
            aad += m;
        }
    }

    // Format initial counter value CTR(0)
    ccmFormatCounter0(n, iv_len, b);

    // Compute S(0) = CIPH(CTR(0))
    aes_op(b, s, interface);
    // Save MSB(S(0))
    memcpy(r, s, 8);

    size_t len = 0;
    unsigned char p[16];
    unsigned char c[16];

    // ECB mode operates in a block-by-block fashion
    while (len < ciphertext_len)
    {
        memcpy(c, ciphertext + len, 16);

        ccmIncCounter(b, 15 - iv_len);
        aes_op(b, s, interface);

        ccmXorBlock(p, c, s, 16);
        ccmXorBlock(y, p, y, 16);

        aes_op(y, y, interface);

        for (int i = 0; i < 16; i++)
        {
            plaintext[i + len] = p[i];
        }
        len += 16;
    }

    // Compute MAC
    ccmXorBlock(r, r, y, 8);

    // The calculated tag is bitwise compared to the received tag. The message
    // is authenticated if and only if the tags match
    for (mask = 0, m = 0; m < 8; m++)
    {
        mask |= r[m] ^ tag[m];
    }

    // Return status code
    if (mask == 0)
        *result = 0;
    else
        *result = 1;

    *plaintext_len = ciphertext_len;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AES-128-GCM
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void aes_128_gcm_encrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int *ciphertext_len,
                            unsigned char *plaintext, unsigned int plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, INTF interface)
{

    unsigned char H[16];
    unsigned char J0[16];
    unsigned char S[16];

    unsigned long long aes_control = (AES_128 << 1) + AES_ENC;

    aes_gcm_init_hash_key(aes_control, key, AES_128_KEY, H, interface);

    aes_gcm_prepare_j0(iv, iv_len, H, J0);

    /* C = GCTR_K(inc_32(J_0), P) */
    aes_gcm_gctr(J0, plaintext, plaintext_len, ciphertext, interface);

    aes_gcm_ghash(H, aad, aad_len, ciphertext, plaintext_len, S);

    /* T = MSB_t(GCTR_K(J_0, S)) */
    aes_gctr(J0, S, sizeof(S), tag, interface);

    /* Return (C, T) */
    
    *ciphertext_len = plaintext_len;

}

void aes_128_gcm_decrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int ciphertext_len,
                            unsigned char *plaintext, unsigned int *plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, unsigned int *result, INTF interface)
{

    unsigned char H[16];
    unsigned char J0[16];
    unsigned char S[16];
    unsigned char T[16];
    
    unsigned long long aes_control = (AES_128 << 1) + AES_ENC;

    aes_gcm_init_hash_key(aes_control, key, AES_128_KEY, H, interface);

    aes_gcm_prepare_j0(iv, iv_len, H, J0);

    /* P = GCTR_K(inc_32(J_0), C) */
    aes_gcm_gctr(J0, ciphertext, ciphertext_len, plaintext, interface);

    aes_gcm_ghash(H, aad, aad_len, ciphertext, ciphertext_len, S);

    /* T' = MSB_t(GCTR_K(J_0, S)) */
    aes_gctr(J0, S, sizeof(S), T, interface);

    *result = memcmp(tag, T, 16);

    *plaintext_len = ciphertext_len;
  
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AES-192-GCM
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void aes_192_gcm_encrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int *ciphertext_len,
                            unsigned char *plaintext, unsigned int plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, INTF interface)
{

    unsigned char H[16];
    unsigned char J0[16];
    unsigned char S[16];

    unsigned long long aes_control = (AES_192 << 1) + AES_ENC;

    aes_gcm_init_hash_key(aes_control, key, AES_192_KEY, H, interface);

    aes_gcm_prepare_j0(iv, iv_len, H, J0);

    /* C = GCTR_K(inc_32(J_0), P) */
    aes_gcm_gctr(J0, plaintext, plaintext_len, ciphertext, interface);

    aes_gcm_ghash(H, aad, aad_len, ciphertext, plaintext_len, S);

    /* T = MSB_t(GCTR_K(J_0, S)) */
    aes_gctr(J0, S, sizeof(S), tag, interface);

    /* Return (C, T) */

    *ciphertext_len = plaintext_len;
}

void aes_192_gcm_decrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int ciphertext_len,
                            unsigned char *plaintext, unsigned int *plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, unsigned int *result, INTF interface)
{

    unsigned char H[16];
    unsigned char J0[16];
    unsigned char S[16];
    unsigned char T[16];

    unsigned long long aes_control = (AES_192 << 1) + AES_ENC;

    aes_gcm_init_hash_key(aes_control, key, AES_192_KEY, H, interface);

    aes_gcm_prepare_j0(iv, iv_len, H, J0);

    /* P = GCTR_K(inc_32(J_0), C) */
    aes_gcm_gctr(J0, ciphertext, ciphertext_len, plaintext, interface);

    aes_gcm_ghash(H, aad, aad_len, ciphertext, ciphertext_len, S);

    /* T' = MSB_t(GCTR_K(J_0, S)) */
    aes_gctr(J0, S, sizeof(S), T, interface);

    *result = memcmp(tag, T, 16);

    *plaintext_len = ciphertext_len;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AES-256-GCM
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void aes_256_gcm_encrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int *ciphertext_len,
                            unsigned char *plaintext, unsigned int plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, INTF interface)
{

    unsigned char H[16];
    unsigned char J0[16];
    unsigned char S[16];

    unsigned long long aes_control = (AES_256 << 1) + AES_ENC;

    aes_gcm_init_hash_key(aes_control, key, AES_256_KEY, H, interface);

    aes_gcm_prepare_j0(iv, iv_len, H, J0);

    /* C = GCTR_K(inc_32(J_0), P) */
    aes_gcm_gctr(J0, plaintext, plaintext_len, ciphertext, interface);

    aes_gcm_ghash(H, aad, aad_len, ciphertext, plaintext_len, S);

    /* T = MSB_t(GCTR_K(J_0, S)) */
    aes_gctr(J0, S, sizeof(S), tag, interface);

    /* Return (C, T) */

    *ciphertext_len = plaintext_len;
}

void aes_256_gcm_decrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int ciphertext_len,
                            unsigned char *plaintext, unsigned int *plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, unsigned int *result, INTF interface)
{

    unsigned char H[16];
    unsigned char J0[16];
    unsigned char S[16];
    unsigned char T[16];

    unsigned long long aes_control = (AES_256 << 1) + AES_ENC;

    aes_gcm_init_hash_key(aes_control, key, AES_256_KEY, H, interface);

    aes_gcm_prepare_j0(iv, iv_len, H, J0);

    /* P = GCTR_K(inc_32(J_0), C) */
    aes_gcm_gctr(J0, ciphertext, ciphertext_len, plaintext, interface);

    aes_gcm_ghash(H, aad, aad_len, ciphertext, ciphertext_len, S);

    /* T' = MSB_t(GCTR_K(J_0, S)) */
    aes_gctr(J0, S, sizeof(S), T, interface);

    *result = memcmp(tag, T, 16);

    *plaintext_len = ciphertext_len;
}