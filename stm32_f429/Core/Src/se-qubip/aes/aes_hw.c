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

#include "aes_hw.h"

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ADDITIONAL FUNCTIONS
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static void aes_block_padding(unsigned int len, unsigned int *complete_len, unsigned int *blocks, unsigned char *data, unsigned char **data_padded)
{
    *blocks = (len + AES_BLOCK - 1) / AES_BLOCK; 
    *complete_len = *blocks * AES_BLOCK;
    
    *data_padded =  pvPortMalloc(*complete_len);
    memset(*data_padded, 0, *complete_len);
    memcpy(*data_padded, data, len);
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

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AES-ECB-CBC-CMAC HW
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void aes_ecb_cbc_cmac_hw(unsigned char *key, unsigned char *data_out, unsigned int *data_out_len, unsigned char *data_in, unsigned int data_in_len, unsigned char *IV, unsigned int encrypt, unsigned int aes_len, unsigned int aes_mode, bool ext_key, uint8_t key_id, INTF interface)
{
    //-- AES MODES
    uint8_t AES_ECB     = (aes_mode >> 0) & 0x1;
    uint8_t AES_CBC     = (aes_mode >> 1) & 0x1;
    uint8_t AES_CMAC    = (aes_mode >> 2) & 0x1;

    //-- Number of Blocks and Padding
    unsigned int data_in_blocks;
    unsigned char *data_in_padded;

    aes_block_padding(data_in_len, data_out_len, &data_in_blocks, data_in, &data_in_padded);

    //-- Complete Blocks Condition and missing bytes
    unsigned int complete_cond = 0;
    if (AES_CMAC)
    {
        unsigned int missing_bytes = *data_out_len - data_in_len;
        complete_cond = (missing_bytes == 0) ? 1 : 0;

        if (!complete_cond) data_in_padded[data_in_len] = 0x80;

        *data_out_len = AES_BLOCK;
    }

    // printf("\ndata_in_padded = 0x");
    // for (int i = 0; i < AES_BLOCK * data_in_blocks; i++) printf("%02x", data_in_padded[i]); printf("\n");
    // printf("\ndata_in_padded = %s\n", data_in_padded);

    //-- se_code = { {(32'b) 64-bit data_packages}, {7'b0, complete_cond}, {GCM, CCM-8, CMAC, CBC, ECB, 128/192/256, enc/dec}, {(16'b)AES} }
    uint64_t control = 0;
    while (control != CMD_SE_CODE)
    {
        picorv32_control(interface, &control);
    }
    const uint8_t aes_code = AES_SE_CODE;
    uint16_t aes_op_sel     = ((uint16_t) !ext_key << 15) + ((uint16_t) (key_id << 9)) + ((uint16_t) complete_cond << 8) + ((uint16_t) aes_mode << 3) + (aes_len << 1) + encrypt;
    uint32_t data_packages = data_in_blocks * 2;

    uint64_t se_code = ((uint64_t) data_packages << 32) + ((uint32_t) aes_op_sel << 16) + aes_code;
    write_INTF(interface, &se_code, PICORV32_DATA_IN, AXI_BYTES);

    //-- Wait till control is CMD_SE_DATA
    while (control != CMD_SE_WRITE)
    {
        picorv32_control(interface, &control);
    }

    //-- Write Key
    if (ext_key)
    {
        if (aes_len == 3) write_INTF(interface, key + 3 * AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
        if (aes_len >= 2) write_INTF(interface, key + 2 * AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
        write_INTF(interface, key + AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
        write_INTF(interface, key, PICORV32_DATA_IN, AXI_BYTES);
    }

    //-- Write IV if CBC
    if (AES_CBC)
    {
        write_INTF(interface, IV + AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
        write_INTF(interface, IV, PICORV32_DATA_IN, AXI_BYTES);
    }

    unsigned char wait_continue[8] = {0};

    //-- Count the remaining Packages
    uint32_t packages_2_write;
    uint32_t packages_2_read;
    uint32_t packages_sent = 0;

    while (data_packages != 0)
    {
        //-- Wait till control is CMD_SE_DATA
        while (control != CMD_SE_WRITE)
        {
            picorv32_control(interface, &control);
        }

        //-- Send Data
        if (data_packages > FIFO_OUT_DEPTH - 2)
        {
            packages_2_write = FIFO_OUT_DEPTH - 2;
        }
        else
        {
            packages_2_write = data_packages;
        }
        for (int i = 0; i < packages_2_write / 2; i++)
        {
            write_INTF(interface, data_in_padded + (2*i + packages_sent + 1) * AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
            write_INTF(interface, data_in_padded + (2*i + packages_sent) * AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
            data_packages -= 2;
        }

        //-- Wait till control is CMD_SE_READ or CMD_SE_WAIT
        while (control != CMD_SE_READ && control != CMD_SE_WAIT)
        {
            picorv32_control(interface, &control);
            if (control == CMD_SE_WAIT) read_INTF(interface, wait_continue, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
        }

        //-- Read Data
        if (control == CMD_SE_READ)
        {
            if (AES_ECB | AES_CBC)
            {
                packages_2_read = packages_2_write;
            }
            else if (AES_CMAC)
            {
                packages_2_read = 2;
                packages_sent   = 0;
            }

            for (int i = 0; i < packages_2_read / 2; i++)
            {
                read_INTF(interface, data_out + (2*i + packages_sent + 1) * AXI_BYTES, PICORV32_DATA_OUT, AXI_BYTES);
                read_INTF(interface, data_out + (2*i + packages_sent) * AXI_BYTES, PICORV32_DATA_OUT, AXI_BYTES);
            }
        }

        //-- Update the number of packages sent
        packages_sent += packages_2_write;
    }

    while (control != CMD_SE_CODE)
    {
        picorv32_control(interface, &control);
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AES-ECB
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void aes_128_ecb_encrypt_hw(unsigned char *key, unsigned char *ciphertext, unsigned int *ciphertext_len, unsigned char *plaintext, unsigned int plaintext_len, bool ext_key, uint8_t key_id, INTF interface)
{
    aes_ecb_cbc_cmac_hw(key, ciphertext, ciphertext_len, plaintext, plaintext_len, NULL, AES_ENCRYPT, AES_LEN_128, AES_MODE_ECB, ext_key, key_id, interface);
    /*
    printf("\nciphertext = 0x");
    for (int i = 0; i < *ciphertext_len / 16; i++)
    {
        for (int j = 0; j < AES_BLOCK; j++) printf("%02x", ciphertext[i * AES_BLOCK + j]);
        printf("\n               ");
    }
    */
}

void aes_128_ecb_decrypt_hw(unsigned char *key, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *plaintext, unsigned int *plaintext_len, bool ext_key, uint8_t key_id, INTF interface)
{
    aes_ecb_cbc_cmac_hw(key, plaintext, plaintext_len, ciphertext, ciphertext_len, NULL, AES_DECRYPT, AES_LEN_128, AES_MODE_ECB, ext_key, key_id, interface);
    /*
    printf("\nplaintext = 0x");
    for (int i = 0; i < *plaintext_len / 16; i++)
    {
        for (int j = 0; j < AES_BLOCK; j++) printf("%02x", plaintext[i * AES_BLOCK + j]);
        printf("\n              ");
    }
    */
}

void aes_192_ecb_encrypt_hw(unsigned char *key, unsigned char *ciphertext, unsigned int *ciphertext_len, unsigned char *plaintext, unsigned int plaintext_len, bool ext_key, uint8_t key_id, INTF interface)
{
    aes_ecb_cbc_cmac_hw(key, ciphertext, ciphertext_len, plaintext, plaintext_len, NULL, AES_ENCRYPT, AES_LEN_192, AES_MODE_ECB, ext_key, key_id, interface);
    /*
    printf("\nciphertext = 0x");
    for (int i = 0; i < *ciphertext_len / 16; i++)
    {
        for (int j = 0; j < AES_BLOCK; j++) printf("%02x", ciphertext[i * AES_BLOCK + j]);
        printf("\n               ");
    }
    */
}

void aes_192_ecb_decrypt_hw(unsigned char *key, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *plaintext, unsigned int *plaintext_len, bool ext_key, uint8_t key_id, INTF interface)
{
    aes_ecb_cbc_cmac_hw(key, plaintext, plaintext_len, ciphertext, ciphertext_len, NULL, AES_DECRYPT, AES_LEN_192, AES_MODE_ECB, ext_key, key_id, interface);
    /*
    printf("\nplaintext = 0x");
    for (int i = 0; i < *plaintext_len / 16; i++)
    {
        for (int j = 0; j < AES_BLOCK; j++) printf("%02x", plaintext[i * AES_BLOCK + j]);
        printf("\n              ");
    }
     */
}

void aes_256_ecb_encrypt_hw(unsigned char *key, unsigned char *ciphertext, unsigned int *ciphertext_len, unsigned char *plaintext, unsigned int plaintext_len, bool ext_key, uint8_t key_id, INTF interface)
{
    aes_ecb_cbc_cmac_hw(key, ciphertext, ciphertext_len, plaintext, plaintext_len, NULL, AES_ENCRYPT, AES_LEN_256, AES_MODE_ECB, ext_key, key_id, interface);
    /*
    printf("\nciphertext = 0x");
    for (int i = 0; i < *ciphertext_len / 16; i++)
    {
        for (int j = 0; j < AES_BLOCK; j++) printf("%02x", ciphertext[i * AES_BLOCK + j]);
        printf("\n               ");
    }
    */
}

void aes_256_ecb_decrypt_hw(unsigned char *key, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *plaintext, unsigned int *plaintext_len, bool ext_key, uint8_t key_id, INTF interface)
{
    aes_ecb_cbc_cmac_hw(key, plaintext, plaintext_len, ciphertext, ciphertext_len, NULL, AES_DECRYPT, AES_LEN_256, AES_MODE_ECB, ext_key, key_id, interface);
    /*
    printf("\nplaintext = 0x");
    for (int i = 0; i < *plaintext_len / 16; i++)
    {
        for (int j = 0; j < AES_BLOCK; j++) printf("%02x", plaintext[i * AES_BLOCK + j]);
        printf("\n              ");
    }
    */
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AES-CBC
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void aes_128_cbc_encrypt_hw(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned int *ciphertext_len, unsigned char *plaintext, unsigned int plaintext_len, bool ext_key, uint8_t key_id, INTF interface)
{
    aes_ecb_cbc_cmac_hw(key, ciphertext, ciphertext_len, plaintext, plaintext_len, iv, AES_ENCRYPT, AES_LEN_128, AES_MODE_CBC, ext_key, key_id, interface);
    /*
    printf("\nciphertext = 0x");
    for (int i = 0; i < *ciphertext_len / 16; i++)
    {
        for (int j = 0; j < AES_BLOCK; j++) printf("%02x", ciphertext[i * AES_BLOCK + j]);
        printf("\n               ");
    }
    */
}

void aes_128_cbc_decrypt_hw(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *plaintext, unsigned int *plaintext_len, bool ext_key, uint8_t key_id, INTF interface)
{
    aes_ecb_cbc_cmac_hw(key, plaintext, plaintext_len, ciphertext, ciphertext_len, iv, AES_DECRYPT, AES_LEN_128, AES_MODE_CBC, ext_key, key_id, interface);
    /*
    printf("\nplaintext = 0x");
    for (int i = 0; i < *plaintext_len / 16; i++)
    {
        for (int j = 0; j < AES_BLOCK; j++) printf("%02x", plaintext[i * AES_BLOCK + j]);
        printf("\n              ");
    }
    */
}

void aes_192_cbc_encrypt_hw(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned int *ciphertext_len, unsigned char *plaintext, unsigned int plaintext_len, bool ext_key, uint8_t key_id, INTF interface)
{
    aes_ecb_cbc_cmac_hw(key, ciphertext, ciphertext_len, plaintext, plaintext_len, iv, AES_ENCRYPT, AES_LEN_192, AES_MODE_CBC, ext_key, key_id, interface);
    /*
    printf("\nciphertext = 0x");
    for (int i = 0; i < *ciphertext_len / 16; i++)
    {
        for (int j = 0; j < AES_BLOCK; j++) printf("%02x", ciphertext[i * AES_BLOCK + j]);
        printf("\n               ");
    }
    */
}

void aes_192_cbc_decrypt_hw(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *plaintext, unsigned int *plaintext_len, bool ext_key, uint8_t key_id, INTF interface)
{
    aes_ecb_cbc_cmac_hw(key, plaintext, plaintext_len, ciphertext, ciphertext_len, iv, AES_DECRYPT, AES_LEN_192, AES_MODE_CBC, ext_key, key_id, interface);
    /*
    printf("\nplaintext = 0x");
    for (int i = 0; i < *plaintext_len / 16; i++)
    {
        for (int j = 0; j < AES_BLOCK; j++) printf("%02x", plaintext[i * AES_BLOCK + j]);
        printf("\n              ");
    }
    */
}

void aes_256_cbc_encrypt_hw(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned int *ciphertext_len, unsigned char *plaintext, unsigned int plaintext_len, bool ext_key, uint8_t key_id, INTF interface)
{
    aes_ecb_cbc_cmac_hw(key, ciphertext, ciphertext_len, plaintext, plaintext_len, iv, AES_ENCRYPT, AES_LEN_256, AES_MODE_CBC, ext_key, key_id, interface);
    /*
    printf("\nciphertext = 0x");
    for (int i = 0; i < *ciphertext_len / 16; i++)
    {
        for (int j = 0; j < AES_BLOCK; j++) printf("%02x", ciphertext[i * AES_BLOCK + j]);
        printf("\n               ");
    }
    */
}

void aes_256_cbc_decrypt_hw(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *plaintext, unsigned int *plaintext_len, bool ext_key, uint8_t key_id, INTF interface)
{
    aes_ecb_cbc_cmac_hw(key, plaintext, plaintext_len, ciphertext, ciphertext_len, iv, AES_DECRYPT, AES_LEN_256, AES_MODE_CBC, ext_key, key_id, interface);
    /*
    printf("\nplaintext = 0x");
    for (int i = 0; i < *plaintext_len / 16; i++)
    {
        for (int j = 0; j < AES_BLOCK; j++) printf("%02x", plaintext[i * AES_BLOCK + j]);
        printf("\n              ");
    }
    */
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AES-CMAC
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void aes_128_cmac_hw(unsigned char *key, unsigned char *mac, unsigned int *mac_len, unsigned char *msg, unsigned int msg_len, bool ext_key, uint8_t key_id, INTF interface)
{
    aes_ecb_cbc_cmac_hw(key, mac, mac_len, msg, msg_len, NULL, AES_ENCRYPT, AES_LEN_128, AES_MODE_CMAC, ext_key, key_id, interface);

    // printf("\nMAC = 0x");
    // for (int i = 0; i < AES_BLOCK; i++) printf("%02x", mac[i]);
}

void aes_192_cmac_hw(unsigned char *key, unsigned char *mac, unsigned int *mac_len, unsigned char *msg, unsigned int msg_len, bool ext_key, uint8_t key_id, INTF interface)
{
    aes_ecb_cbc_cmac_hw(key, mac, mac_len, msg, msg_len, NULL, AES_ENCRYPT, AES_LEN_192, AES_MODE_CMAC, ext_key, key_id, interface);

    // printf("\nMAC = 0x");
    // for (int i = 0; i < AES_BLOCK; i++) printf("%02x", mac[i]);
}

void aes_256_cmac_hw(unsigned char *key, unsigned char *mac, unsigned int *mac_len, unsigned char *msg, unsigned int msg_len, bool ext_key, uint8_t key_id, INTF interface)
{
    aes_ecb_cbc_cmac_hw(key, mac, mac_len, msg, msg_len, NULL, AES_ENCRYPT, AES_LEN_256, AES_MODE_CMAC, ext_key, key_id, interface);

    // printf("\nMAC = 0x");
    // for (int i = 0; i < AES_BLOCK; i++) printf("%02x", mac[i]);
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AES-CCM-8 HW
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void aes_ccm_8_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *data_out, unsigned int *data_out_len, unsigned char *data_in, unsigned int data_in_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, unsigned int *result, unsigned int encrypt, unsigned int aes_len, bool ext_key, uint8_t key_id, INTF interface)
{
    //-- Number of Blocks and Padding
    unsigned int complete_len;
    unsigned int data_in_blocks;
    unsigned char *data_in_padded;
    
    aes_block_padding(data_in_len, &complete_len, &data_in_blocks, data_in, &data_in_padded);

    //-- Same for AAD
    unsigned int aad_complete_len;
    unsigned int aad_blocks;
    unsigned char *aad_padded;

    unsigned int extra_aad_bytes = 0;

    if (aad_len > 0)
    {
        if (aad_len < 0xFF00)
            extra_aad_bytes = 2;
        else if (aad_len < 0xFFFFFFFF)
            extra_aad_bytes = 6;
        else
            extra_aad_bytes = 10;
    }

    aes_block_padding(aad_len + extra_aad_bytes, &aad_complete_len, &aad_blocks, aad, &aad_padded);
    memset(aad_padded + aad_len, 0, extra_aad_bytes);

    //-- se_code = { {(32'b) 64-bit data_packages}, {7'b0, complete_cond}, {GCM, CCM-8, CMAC, CBC, ECB, 128/192/256, enc/dec}, {(16'b)AES} }
    uint64_t control = 0;
    unsigned char wait_continue[8] = {0};
    while (control != CMD_SE_CODE)
    {
        picorv32_control(interface, &control);
    }

    const uint8_t aes_code = AES_SE_CODE;
    uint16_t aes_op_sel = ((uint16_t) !ext_key << 15) + ((uint16_t) (key_id << 9)) + ((uint16_t) AES_MODE_CCM_8 << 3) + (aes_len << 1) + encrypt;
    uint32_t data_packages;
    uint64_t aad_packages;

    data_packages   = data_in_blocks * 2;
    aad_packages    = aad_blocks * 2;

    uint64_t se_code = ((uint64_t) data_packages << 32) + ((uint32_t) aes_op_sel << 16) + aes_code;
    write_INTF(interface, &se_code, PICORV32_DATA_IN, AXI_BYTES);

    //-- Wait till control is CMD_SE_WAIT
    while (control != CMD_SE_WAIT)
    {
        picorv32_control(interface, &control);
    }

    //-- Write number of AAD blocks
    write_INTF(interface, &aad_packages, PICORV32_DATA_IN, AXI_BYTES);

   // printf("\npackages_count = 0x%lx", aad_packages);
   // fflush(stdout);

    //-- Write Key
    if (ext_key)
    {
        while (control != CMD_SE_WRITE)
        {
            picorv32_control(interface, &control);
        }
        if (aes_len == 3) write_INTF(interface, key + 3 * AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
        if (aes_len >= 2) write_INTF(interface, key + 2 * AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
        write_INTF(interface, key + AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
        write_INTF(interface, key, PICORV32_DATA_IN, AXI_BYTES);
    }

    //-- Format Input
    size_t m;
    uint8_t b[16];
    uint8_t y[16];
    uint8_t s[16];

    uint8_t n[16] = {0};
    memcpy(n, iv, iv_len); // between 7 & 13

    // Format first block B(0)
    ccmFormatBlock0(data_in_len, n, iv_len, aad_len, 8, b);

    //-- Write B(0)
    while (control != CMD_SE_WRITE)
    {
        picorv32_control(interface, &control);
    }
    write_INTF(interface, b + AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
    write_INTF(interface, b, PICORV32_DATA_IN, AXI_BYTES);

    // Process the remaining data bytes
    uint32_t packages_2_write;
    uint32_t packages_2_read;
    uint32_t packages_sent = 0;
    
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
            memcpy(b + 2, aad_padded, m);
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
            memcpy(b + 6, aad_padded, m);
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
            memcpy(b + 10, aad_padded, m);
        }

        // printf("\nb = 0x");
        // for (int i = 0; i < 16; i ++) printf("%02x", b[i]);

        // Write B(1)
        write_INTF(interface, b + AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
        write_INTF(interface, b, PICORV32_DATA_IN, AXI_BYTES);
        aad_packages -= 2;

        // Number of remaining data bytes
        aad_len -= m;
        aad_padded += m;

        while (aad_packages != 0)
        {
            //-- Wait till control is CMD_SE_DATA
            while (control != CMD_SE_WRITE)
            {
                picorv32_control(interface, &control);
            }

            //-- Send Data
            if (aad_packages > FIFO_OUT_DEPTH - 2)
            {
                packages_2_write = FIFO_OUT_DEPTH - 2;
            }
            else
            {
                packages_2_write = aad_packages;
            }

            for (int i = 0; i < packages_2_write / 2; i++)
            {
                // Associated data are processed in a block-by-block fashion
                m = MIN(aad_len, 16);
                // printf("\nm = %ld", m);

                // Write AAD
                write_INTF(interface, aad_padded + AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
                write_INTF(interface, aad_padded, PICORV32_DATA_IN, AXI_BYTES);
                aad_packages -= 2;

                // Next block
                aad_len -= m;
                aad_padded += m;
            }

            //-- Wait till control is CMD_SE_WAIT
            while (control != CMD_SE_WAIT)
            {
                picorv32_control(interface, &control);
                if (control == CMD_SE_WAIT) read_INTF(interface, wait_continue, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
            }
        }
        //-- Wait till control is CMD_SE_WAIT
        while (control != CMD_SE_WAIT)
        {
            picorv32_control(interface, &control);
            if (control == CMD_SE_WAIT) read_INTF(interface, wait_continue, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
        }
    }

    // Format initial counter value CTR(0)
    ccmFormatCounter0(n, iv_len, b);

    // Compute S(0) = CIPH(CTR(0))
    //-- Write CTR(0)
    write_INTF(interface, b + AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
    write_INTF(interface, b, PICORV32_DATA_IN, AXI_BYTES);

    uint32_t packages_received = 0;

    while (data_packages != 0)
    {
        //-- Wait till control is CMD_SE_WRITE
        while (control != CMD_SE_WRITE)
        {
            picorv32_control(interface, &control);
        }

        //-- Send Data
        if (data_packages > (FIFO_OUT_DEPTH - 4) / 2)
        {
            packages_2_write = (FIFO_OUT_DEPTH - 4) / 2;
            packages_2_read = FIFO_OUT_DEPTH - 4;
        }
        else
        {
            packages_2_write = data_packages;
            packages_2_read = data_packages;
        }

        for (int i = 0; i < packages_2_write / 2; i++)
        {
            //-- Send Plaintext
            write_INTF(interface, data_in_padded + (2*i + packages_sent + 1) * AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
            write_INTF(interface, data_in_padded + (2*i + packages_sent) * AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
            //-- Send Counter
            ccmIncCounter(b, 15 - iv_len);
            write_INTF(interface, b + AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
            write_INTF(interface, b, PICORV32_DATA_IN, AXI_BYTES);
            data_packages -= 2;
            // printf("data_in + 2*i + packages_sent = %llx\n", *(data_in + 2*i + packages_sent));
        }

        //-- Wait till control is CMD_SE_READ or CMD_SE_WAIT
        while ((control != CMD_SE_READ) & (control != CMD_SE_WAIT))
        {
            picorv32_control(interface, &control);

            if (control == CMD_SE_WAIT)
            {
                read_INTF(interface, wait_continue, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
            }
        }

        //-- Read Data
        if (control == CMD_SE_READ)
        {
            // packages_2_read = packages_2_write;

            for (int i = 0; i < packages_2_read / 2; i++)
            {
                read_INTF(interface, data_out + (2*i + packages_received + 1) * AXI_BYTES, PICORV32_DATA_OUT, AXI_BYTES);
                read_INTF(interface, data_out + (2*i + packages_received) * AXI_BYTES, PICORV32_DATA_OUT, AXI_BYTES);
            }
            packages_received += packages_2_read;
        }

        //-- Update the number of packages sent
        packages_sent += packages_2_write;
    }

    //-- Wait till control is CMD_SE_WAIT
    int count = 0;
    while (control != CMD_SE_WAIT)
    {
        picorv32_control(interface, &control);
        if (control == CMD_SE_WAIT) read_INTF(interface, wait_continue, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
    }

    //-- Read TAG

    if (encrypt)
    {
        read_INTF(interface, wait_continue, PICORV32_DATA_OUT, AXI_BYTES);     // 1st is not used
        read_INTF(interface, tag, PICORV32_DATA_OUT, AXI_BYTES);
    }
    else
    {
        unsigned char tag_received[8];      // 1st is not used
        read_INTF(interface, wait_continue, PICORV32_DATA_OUT, AXI_BYTES);
        read_INTF(interface, tag_received, PICORV32_DATA_OUT, AXI_BYTES);

        if (memcmp(tag, tag_received, 8) == 0)
            *result = 0;
        else
            *result = 1;
    }

    *data_out_len = data_in_len;

    while (control != CMD_SE_CODE)
    {
        picorv32_control(interface, &control);
    }
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AES-CCM-8
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void aes_128_ccm_8_encrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int *ciphertext_len,
                              unsigned char *plaintext, unsigned int plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, bool ext_key, uint8_t key_id, INTF interface)
{
    aes_ccm_8_hw(key, iv, iv_len, ciphertext, ciphertext_len, plaintext, plaintext_len, aad, aad_len, tag, NULL, AES_ENCRYPT, AES_LEN_128, ext_key, key_id, interface);

    // printf("\n\nciphertext = 0x");
    // for (int i = 0; i < *ciphertext_len; i++)
    // {
    //     printf("%02x", ciphertext[i]);
    // }
    // printf("\ntag = 0x");
    // for (int i = 0; i < 8; i++)
    // {
    //     printf("%02x", tag[i]);
    // }
}

void aes_128_ccm_8_decrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *plaintext, unsigned int *plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, unsigned int *result, bool ext_key, uint8_t key_id, INTF interface)
{
    aes_ccm_8_hw(key, iv, iv_len, plaintext, plaintext_len, ciphertext, ciphertext_len, aad, aad_len, tag, result, AES_DECRYPT, AES_LEN_128, ext_key, key_id, interface);

    // printf("\n\nplaintext = 0x");
    // for (int i = 0; i < *plaintext_len; i++)
    // {
    //     printf("%02x", plaintext[i]);
    // }
    // if (*result == 0)
    //     printf("\nAuthentication PASSED!");
    // else
    //     printf("\nAuthentication FAILED!");
}

void aes_192_ccm_8_encrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int *ciphertext_len,
                              unsigned char *plaintext, unsigned int plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, bool ext_key, uint8_t key_id, INTF interface)
{
    aes_ccm_8_hw(key, iv, iv_len, ciphertext, ciphertext_len, plaintext, plaintext_len, aad, aad_len, tag, NULL, AES_ENCRYPT, AES_LEN_192, ext_key, key_id, interface);

    // printf("\n\nciphertext = 0x");
    // for (int i = 0; i < *ciphertext_len; i++)
    // {
    //     printf("%02x", ciphertext[i]);
    // }
    // printf("\ntag = 0x");
    // for (int i = 0; i < 8; i++)
    // {
    //     printf("%02x", tag[i]);
    // }
}

void aes_192_ccm_8_decrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *plaintext, unsigned int *plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, unsigned int *result, bool ext_key, uint8_t key_id, INTF interface)
{
    aes_ccm_8_hw(key, iv, iv_len, plaintext, plaintext_len, ciphertext, ciphertext_len, aad, aad_len, tag, result, AES_DECRYPT, AES_LEN_192, ext_key, key_id, interface);

    // printf("\n\nplaintext = 0x");
    // for (int i = 0; i < *plaintext_len; i++)
    // {
    //     printf("%02x", plaintext[i]);
    // }
    // if (*result == 0)
    //     printf("\nAuthentication PASSED!");
    // else
    //     printf("\nAuthentication FAILED!");
}

void aes_256_ccm_8_encrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int *ciphertext_len,
                              unsigned char *plaintext, unsigned int plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, bool ext_key, uint8_t key_id, INTF interface)
{
    aes_ccm_8_hw(key, iv, iv_len, ciphertext, ciphertext_len, plaintext, plaintext_len, aad, aad_len, tag, NULL, AES_ENCRYPT, AES_LEN_256, ext_key, key_id, interface);

    // printf("\n\nciphertext = 0x");
    // for (int i = 0; i < *ciphertext_len; i++)
    // {
    //     printf("%02x", ciphertext[i]);
    // }
    // printf("\ntag = 0x");
    // for (int i = 0; i < 8; i++)
    // {
    //     printf("%02x", tag[i]);
    // }
}

void aes_256_ccm_8_decrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *plaintext, unsigned int *plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, unsigned int *result, bool ext_key, uint8_t key_id, INTF interface)
{
    aes_ccm_8_hw(key, iv, iv_len, plaintext, plaintext_len, ciphertext, ciphertext_len, aad, aad_len, tag, result, AES_DECRYPT, AES_LEN_256, ext_key, key_id, interface);

    // printf("\n\nplaintext = 0x");
    // for (int i = 0; i < *plaintext_len; i++)
    // {
    //     printf("%02x", plaintext[i]);
    // }
    // if (*result == 0)
    //     printf("\nAuthentication PASSED!");
    // else
    //     printf("\nAuthentication FAILED!");
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AES-GCM HW
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void aes_gcm_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *data_out, unsigned int *data_out_len, unsigned char *data_in, unsigned int data_in_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, unsigned int *result, unsigned int encrypt, unsigned int aes_len, bool ext_key, uint8_t key_id, INTF interface)
{
    //-- Number of Blocks and Padding
    unsigned int data_in_blocks;
    unsigned char *data_in_padded;
    aes_block_padding(data_in_len, data_out_len, &data_in_blocks, data_in, &data_in_padded);

    unsigned int aad_complete_len;
    unsigned int aad_blocks;
    unsigned char *aad_padded;
    aes_block_padding(aad_len, &aad_complete_len, &aad_blocks, aad, &aad_padded);

    unsigned int iv_complete_len;
    unsigned int iv_blocks;
    unsigned char *iv_padded;
    aes_block_padding(iv_len, &iv_complete_len, &iv_blocks, iv, &iv_padded);

    if (iv_len == 12) iv_padded[15] = 0x01;

    //-- If iv_len != 12 prepare s and iv_new
    unsigned char len_buf[AES_BLOCK];
    WPA_PUT_BE64(len_buf, 0);
    WPA_PUT_BE64(len_buf + 8, iv_len * 8);

    unsigned int iv_new_len = iv_complete_len + AES_BLOCK;
    unsigned char *iv_new;

    iv_new = (unsigned char*) pvPortMalloc(iv_new_len);
    memcpy(iv_new, iv_padded, iv_complete_len);
    memcpy(iv_new + iv_complete_len, len_buf, AES_BLOCK);

    //-- se_code = { {(32'b) 64-bit data_packages}, {7'b0, complete_cond}, {GCM, CCM-8, CMAC, CBC, ECB, 128/192/256, enc/dec}, {(16'b)AES} }
    unsigned char wait_continue[8] = {0};
    uint64_t control = 0;
    while (control != CMD_SE_CODE)
    {
        picorv32_control(interface, &control);
    }
    const uint8_t aes_code  = AES_SE_CODE;
    uint16_t aes_op_sel     = ((uint16_t) !ext_key << 15) + ((uint16_t) (key_id << 9)) + ((uint16_t) AES_MODE_GCM << 3) + (aes_len << 1) + encrypt;
    uint32_t data_packages  = data_in_blocks * 2;

    uint64_t se_code = ((uint64_t) data_packages << 32) + ((uint32_t) aes_op_sel << 16) + aes_code;
    write_INTF(interface, &se_code, PICORV32_DATA_IN, AXI_BYTES);

    //-- Send data, AAD and IV length
    uint64_t u64_data_in_len    = data_in_len;
    uint64_t u64_aad_len        = aad_len;
    uint64_t u64_iv_len;

    if (iv_len == 12) u64_iv_len = iv_len;
    else u64_iv_len = iv_new_len;

    while (control != CMD_SE_WAIT)
    {
        picorv32_control(interface, &control);
    }
    write_INTF(interface, &u64_data_in_len, PICORV32_DATA_IN, AXI_BYTES);

    while (control != CMD_SE_WRITE)
    {
        picorv32_control(interface, &control);
    }
    write_INTF(interface, &u64_aad_len, PICORV32_DATA_IN, AXI_BYTES);

    while (control != CMD_SE_WAIT)
    {
        picorv32_control(interface, &control);
    }
    write_INTF(interface, &u64_iv_len, PICORV32_DATA_IN, AXI_BYTES);

    //-- Write Key
    if (ext_key)
    {
        while (control != CMD_SE_WRITE)
        {
            picorv32_control(interface, &control);
        }
        if (aes_len == 3) write_INTF(interface, key + 3 * AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
        if (aes_len >= 2) write_INTF(interface, key + 2 * AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
        write_INTF(interface, key + 1 * AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
        write_INTF(interface, key, PICORV32_DATA_IN, AXI_BYTES);
    }

    //-- Send IV
    uint32_t blocks_sent = 0;
    uint32_t packages_sent = 0;

    while (control != CMD_SE_WRITE)
    {
        picorv32_control(interface, &control);
    }

    if (iv_len == 12)
    {
        write_INTF(interface, iv_padded + (2 * blocks_sent + 1) * AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
        write_INTF(interface, iv_padded + (2 * blocks_sent) * AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
    }
    else
    {
        for (int i = 0; i < iv_blocks + 1; i++)
        {
            while (control != CMD_SE_WRITE)
            {
                picorv32_control(interface, &control);
            }
            write_INTF(interface, iv_new + (2 * blocks_sent + 1) * AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
            write_INTF(interface, iv_new + (2 * blocks_sent) * AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
            blocks_sent++;
            packages_sent += 2;

            if (((packages_sent) == (FIFO_IN_DEPTH - 2)) || (i == iv_blocks))
            {
                packages_sent = 0;

                picorv32_control(interface, &control);
                while (control != CMD_SE_WAIT)
                {
                    picorv32_control(interface, &control);
                }
            }
        }
    }

    //-- Send a read signal to continue
    read_INTF(interface, wait_continue, PICORV32_DATA_OUT, AXI_BYTES);

    //-- Send AAD
    blocks_sent     = 0;
    packages_sent   = 0;
    for (int i = 0; i < aad_blocks; i++)
    {
        write_INTF(interface, aad_padded + (2 * blocks_sent + 1) * AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
        write_INTF(interface, aad_padded + (2 * blocks_sent) * AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
        blocks_sent++;
        packages_sent += 2;

        if (((packages_sent) == (FIFO_IN_DEPTH - 2)) || (i == aad_blocks - 1))
        {
            packages_sent = 0;

            picorv32_control(interface, &control);
            while (control != CMD_SE_WAIT)
            {
                picorv32_control(interface, &control);
            }
        }
    }

    //-- Send a read signal to continue
    read_INTF(interface, wait_continue, PICORV32_DATA_OUT, AXI_BYTES);

    //-- Send Plaintext/Ciphertext read Ciphertext/Plaintext
    uint32_t packages_received = 0;
    blocks_sent     = 0;
    packages_sent   = 0;
    for (int i = 0; i < data_in_blocks; i++)
    {
        write_INTF(interface, data_in_padded + (2 * blocks_sent + 1) * AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
        write_INTF(interface, data_in_padded + (2 * blocks_sent) * AXI_BYTES, PICORV32_DATA_IN, AXI_BYTES);
        blocks_sent++;
        packages_sent += 2;

        if (((packages_sent) == (FIFO_IN_DEPTH - 2)) || (i == data_in_blocks - 1))
        {
            picorv32_control(interface, &control);
            while (control != CMD_SE_READ)
            {
                picorv32_control(interface, &control);
            }

            if (control == CMD_SE_READ)
            {
                for (int j = 0; j < packages_sent / 2; j++)
                {
                    read_INTF(interface, data_out + (2*j + packages_received + 1) * AXI_BYTES, PICORV32_DATA_OUT, AXI_BYTES);
                    read_INTF(interface, data_out + (2*j + packages_received) * AXI_BYTES, PICORV32_DATA_OUT, AXI_BYTES);
                }
                packages_received += packages_sent;
            }

            packages_sent = 0;
        }
    }

    //-- Read TAG
    unsigned char tag_received[16];

    picorv32_control(interface, &control);
    while (control != CMD_SE_READ)
    {
        picorv32_control(interface, &control);
    }

    if (encrypt)
    {
        read_INTF(interface, tag + AXI_BYTES, PICORV32_DATA_OUT, AXI_BYTES);
        read_INTF(interface, tag, PICORV32_DATA_OUT, AXI_BYTES);
    }
    else
    {
        read_INTF(interface, tag_received + AXI_BYTES, PICORV32_DATA_OUT, AXI_BYTES);
        read_INTF(interface, tag_received, PICORV32_DATA_OUT, AXI_BYTES);

        if (memcmp(tag, tag_received, 16) == 0)
            *result = 0;
        else
            *result = 1;
    }

    *data_out_len = data_in_len;

    while (control != CMD_SE_CODE)
    {
        picorv32_control(interface, &control);
    };
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AES-GCM
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void aes_128_gcm_encrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int *ciphertext_len,
                              unsigned char *plaintext, unsigned int plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, bool ext_key, uint8_t key_id, INTF interface)
{
    aes_gcm_hw(key, iv, iv_len, ciphertext, ciphertext_len, plaintext, plaintext_len, aad, aad_len, tag, NULL, AES_ENCRYPT, AES_LEN_128, ext_key, key_id, interface);

    // printf("\n\nciphertext = 0x");
    // for (int i = 0; i < *ciphertext_len; i++)
    // {
    //     printf("%02x", ciphertext[i]);
    // }
    // printf("\ntag = 0x");
    // for (int i = 0; i < 16; i++)
    // {
    //     printf("%02x", tag[i]);
    // }
}

void aes_128_gcm_decrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *plaintext, unsigned int *plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, unsigned int *result, bool ext_key, uint8_t key_id, INTF interface)
{
    aes_gcm_hw(key, iv, iv_len, plaintext, plaintext_len, ciphertext, ciphertext_len, aad, aad_len, tag, result, AES_DECRYPT, AES_LEN_128, ext_key, key_id, interface);

    // printf("\n\nplaintext = 0x");
    // for (int i = 0; i < *plaintext_len; i++)
    // {
    //     printf("%02x", plaintext[i]);
    // }
    // if (*result == 0)
    //     printf("\nAuthentication PASSED!");
    // else
    //     printf("\nAuthentication FAILED!");
}

void aes_192_gcm_encrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int *ciphertext_len,
                              unsigned char *plaintext, unsigned int plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, bool ext_key, uint8_t key_id, INTF interface)
{
    aes_gcm_hw(key, iv, iv_len, ciphertext, ciphertext_len, plaintext, plaintext_len, aad, aad_len, tag, NULL, AES_ENCRYPT, AES_LEN_192, ext_key, key_id, interface);

    // printf("\n\nciphertext = 0x");
    // for (int i = 0; i < *ciphertext_len; i++)
    // {
    //     printf("%02x", ciphertext[i]);
    // }
    // printf("\ntag = 0x");
    // for (int i = 0; i < 16; i++)
    // {
    //     printf("%02x", tag[i]);
    // }
}

void aes_192_gcm_decrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *plaintext, unsigned int *plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, unsigned int *result, bool ext_key, uint8_t key_id, INTF interface)
{
    aes_gcm_hw(key, iv, iv_len, plaintext, plaintext_len, ciphertext, ciphertext_len, aad, aad_len, tag, result, AES_DECRYPT, AES_LEN_192, ext_key, key_id, interface);

    // printf("\n\nplaintext = 0x");
    // for (int i = 0; i < *plaintext_len; i++)
    // {
    //     printf("%02x", plaintext[i]);
    // }
    // if (*result == 0)
    //     printf("\nAuthentication PASSED!");
    // else
    //     printf("\nAuthentication FAILED!");
}//

void aes_256_gcm_encrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int *ciphertext_len,
                              unsigned char *plaintext, unsigned int plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, bool ext_key, uint8_t key_id, INTF interface)
{
    aes_gcm_hw(key, iv, iv_len, ciphertext, ciphertext_len, plaintext, plaintext_len, aad, aad_len, tag, NULL, AES_ENCRYPT, AES_LEN_256, ext_key, key_id, interface);

    // printf("\n\nciphertext = 0x");
    // for (int i = 0; i < *ciphertext_len; i++)
    // {
    //     printf("%02x", ciphertext[i]);
    // }
    // printf("\ntag = 0x");
    // for (int i = 0; i < 16; i++)
    // {
    //     printf("%02x", tag[i]);
    // }
}

void aes_256_gcm_decrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *plaintext, unsigned int *plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, unsigned int *result, bool ext_key, uint8_t key_id, INTF interface)
{
    aes_gcm_hw(key, iv, iv_len, plaintext, plaintext_len, ciphertext, ciphertext_len, aad, aad_len, tag, result, AES_DECRYPT, AES_LEN_256, ext_key, key_id, interface);

    // printf("\n\nplaintext = 0x");
    // for (int i = 0; i < *plaintext_len; i++)
    // {
    //     printf("%02x", plaintext[i]);
    // }
    // if (*result == 0)
    //     printf("\nAuthentication PASSED!");
    // else
    //     printf("\nAuthentication FAILED!");
}
