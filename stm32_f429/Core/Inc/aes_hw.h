/**
 * @file  aes_hw.h
 * @brief AES HW header
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
// File Name: aes_hw.h
// Project Name: SE-QUBIP
// Target Devices: PYNQ-Z2
// Description:
//
//		AES HW Handler Functions Header File
//
// Additional Comment
//
////////////////////////////////////////////////////////////////////////////////////

#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "intf.h"
#include "conf.h"
#include "picorv32.h"
#include "extra_func.h"

//-- Elements Bit Sizes
#define AES_128_KEY     16
#define AES_192_KEY     24
#define AES_256_KEY     32
#define AES_BLOCK       16

//-- AES Options
#define AES_ENCRYPT         1
#define AES_DECRYPT         0

#define AES_LEN_128         1
#define AES_LEN_192         2
#define AES_LEN_256         3

#define AES_MODE_ECB        (1 << 0)
#define AES_MODE_CBC        (1 << 1)
#define AES_MODE_CMAC       (1 << 2)
#define AES_MODE_CCM_8      (1 << 3)
#define AES_MODE_GCM        (1 << 4)

//-- Misc Operations
#define MIN(a, b) ((a) < (b) ? (a) : (b))

//-- Store unaligned 16-bit integer (big-endian encoding)
#define STORE16BE(a, p)                                 \
    ((uint8_t *)(p))[0] = ((uint16_t)(a) >> 8) & 0xFFU, \
              ((uint8_t *)(p))[1] = ((uint16_t)(a) >> 0) & 0xFFU

//-- Store unaligned 32-bit integer (big-endian encoding)
#define STORE32BE(a, p)                                            \
    ((uint8_t *)(p))[0] = ((uint32_t)(a) >> 24) & 0xFFU,           \
              ((uint8_t *)(p))[1] = ((uint32_t)(a) >> 16) & 0xFFU, \
              ((uint8_t *)(p))[2] = ((uint32_t)(a) >> 8) & 0xFFU,  \
              ((uint8_t *)(p))[3] = ((uint32_t)(a) >> 0) & 0xFFU

//-- Store unaligned 64-bit integer (big-endian encoding)
#define STORE64BE(a, p)                                            \
    ((uint8_t *)(p))[0] = ((uint64_t)(a) >> 56) & 0xFFU,           \
              ((uint8_t *)(p))[1] = ((uint64_t)(a) >> 48) & 0xFFU, \
              ((uint8_t *)(p))[2] = ((uint64_t)(a) >> 40) & 0xFFU, \
              ((uint8_t *)(p))[3] = ((uint64_t)(a) >> 32) & 0xFFU, \
              ((uint8_t *)(p))[4] = ((uint64_t)(a) >> 24) & 0xFFU, \
              ((uint8_t *)(p))[5] = ((uint64_t)(a) >> 16) & 0xFFU, \
              ((uint8_t *)(p))[6] = ((uint64_t)(a) >> 8) & 0xFFU,  \
              ((uint8_t *)(p))[7] = ((uint64_t)(a) >> 0) & 0xFFU

/* Macros for handling unaligned memory accesses */
#define WPA_GET_BE32(a) ((((uint32_t)(a)[0]) << 24) | (((uint32_t)(a)[1]) << 16) | \
                         (((uint32_t)(a)[2]) << 8) | ((uint32_t)(a)[3]))

#define WPA_PUT_BE32(a, val)                                  \
    do                                                        \
    {                                                         \
        (a)[0] = (uint8_t)((((uint32_t)(val)) >> 24) & 0xff); \
        (a)[1] = (uint8_t)((((uint32_t)(val)) >> 16) & 0xff); \
        (a)[2] = (uint8_t)((((uint32_t)(val)) >> 8) & 0xff);  \
        (a)[3] = (uint8_t)(((uint32_t)(val)) & 0xff);         \
    } while (0)

#define WPA_PUT_BE64(a, val)                          \
    do                                                \
    {                                                 \
        (a)[0] = (uint8_t)(((uint64_t)(val)) >> 56);  \
        (a)[1] = (uint8_t)(((uint64_t)(val)) >> 48);  \
        (a)[2] = (uint8_t)(((uint64_t)(val)) >> 40);  \
        (a)[3] = (uint8_t)(((uint64_t)(val)) >> 32);  \
        (a)[4] = (uint8_t)(((uint64_t)(val)) >> 24);  \
        (a)[5] = (uint8_t)(((uint64_t)(val)) >> 16);  \
        (a)[6] = (uint8_t)(((uint64_t)(val)) >> 8);   \
        (a)[7] = (uint8_t)(((uint64_t)(val)) & 0xff); \
    } while (0)

// --- AES HW --- //
void aes_ecb_cbc_cmac_hw(unsigned char *key, unsigned char *data_out, unsigned int *data_out_len, unsigned char *data_in, unsigned int data_in_len, unsigned char *IV, unsigned int encrypt, unsigned int aes_len, unsigned int aes_mode, bool ext_key, uint8_t key_id, INTF interface);
void aes_ccm_8_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *data_out, unsigned int *data_out_len, unsigned char *data_in, unsigned int data_in_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, unsigned int *result, unsigned int encrypt, unsigned int aes_len, bool ext_key, uint8_t key_id, INTF interface);
void aes_gcm_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *data_out, unsigned int *data_out_len, unsigned char *data_in, unsigned int data_in_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, unsigned int *result, unsigned int encrypt, unsigned int aes_len, bool ext_key, uint8_t key_id, INTF interface);

// --- AES - ECB --- //
void aes_128_ecb_encrypt_hw(unsigned char *key, unsigned char *ciphertext, unsigned int *ciphertext_len, unsigned char *plaintext, unsigned int plaintext_len, bool ext_key, uint8_t key_id, INTF interface);
void aes_128_ecb_decrypt_hw(unsigned char *key, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *plaintext, unsigned int *plaintext_len, bool ext_key, uint8_t key_id, INTF interface);
void aes_192_ecb_encrypt_hw(unsigned char *key, unsigned char *ciphertext, unsigned int *ciphertext_len, unsigned char *plaintext, unsigned int plaintext_len, bool ext_key, uint8_t key_id, INTF interface);
void aes_192_ecb_decrypt_hw(unsigned char *key, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *plaintext, unsigned int *plaintext_len, bool ext_key, uint8_t key_id, INTF interface);
void aes_256_ecb_encrypt_hw(unsigned char *key, unsigned char *ciphertext, unsigned int *ciphertext_len, unsigned char *plaintext, unsigned int plaintext_len, bool ext_key, uint8_t key_id, INTF interface);
void aes_256_ecb_decrypt_hw(unsigned char *key, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *plaintext, unsigned int *plaintext_len, bool ext_key, uint8_t key_id, INTF interface);

// --- AES - CBC --- //
void aes_128_cbc_encrypt_hw(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned int *ciphertext_len, unsigned char *plaintext, unsigned int plaintext_len, bool ext_key, uint8_t key_id, INTF interface);
void aes_128_cbc_decrypt_hw(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *plaintext, unsigned int *plaintext_len, bool ext_key, uint8_t key_id, INTF interface);
void aes_192_cbc_encrypt_hw(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned int *ciphertext_len, unsigned char *plaintext, unsigned int plaintext_len, bool ext_key, uint8_t key_id, INTF interface);
void aes_192_cbc_decrypt_hw(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *plaintext, unsigned int *plaintext_len, bool ext_key, uint8_t key_id, INTF interface);
void aes_256_cbc_encrypt_hw(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned int *ciphertext_len, unsigned char *plaintext, unsigned int plaintext_len, bool ext_key, uint8_t key_id, INTF interface);
void aes_256_cbc_decrypt_hw(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *plaintext, unsigned int *plaintext_len, bool ext_key, uint8_t key_id, INTF interface);

// --- AES - CMAC --- //
void aes_128_cmac_hw(unsigned char *key, unsigned char *mac, unsigned int *mac_len, unsigned char *msg, unsigned int msg_len, bool ext_key, uint8_t key_id, INTF interface);
void aes_192_cmac_hw(unsigned char *key, unsigned char *mac, unsigned int *mac_len, unsigned char *msg, unsigned int msg_len, bool ext_key, uint8_t key_id, INTF interface);
void aes_256_cmac_hw(unsigned char *key, unsigned char *mac, unsigned int *mac_len, unsigned char *msg, unsigned int msg_len, bool ext_key, uint8_t key_id, INTF interface);

// --- AES - CCM_8 --- //
void aes_128_ccm_8_encrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int *ciphertext_len, 
                              unsigned char *plaintext, unsigned int plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, bool ext_key, uint8_t key_id, INTF interface);
void aes_128_ccm_8_decrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int ciphertext_len,
                              unsigned char *plaintext, unsigned int *plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, unsigned int *result, bool ext_key, uint8_t key_id, INTF interface);
void aes_192_ccm_8_encrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int *ciphertext_len,
                              unsigned char *plaintext, unsigned int plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, bool ext_key, uint8_t key_id, INTF interface);
void aes_192_ccm_8_decrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int ciphertext_len,
                              unsigned char *plaintext, unsigned int *plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, unsigned int *result, bool ext_key, uint8_t key_id, INTF interface);
void aes_256_ccm_8_encrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int *ciphertext_len,
                              unsigned char *plaintext, unsigned int plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, bool ext_key, uint8_t key_id, INTF interface);
void aes_256_ccm_8_decrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int ciphertext_len,
                              unsigned char *plaintext, unsigned int *plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, unsigned int *result, bool ext_key, uint8_t key_id, INTF interface);

// --- AES - GCM --- //
void aes_128_gcm_encrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int *ciphertext_len,
                            unsigned char *plaintext, unsigned int plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, bool ext_key, uint8_t key_id, INTF interface);
void aes_128_gcm_decrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int ciphertext_len,
                            unsigned char *plaintext, unsigned int *plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, unsigned int *result, bool ext_key, uint8_t key_id, INTF interface);
void aes_192_gcm_encrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int *ciphertext_len,
                            unsigned char *plaintext, unsigned int plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, bool ext_key, uint8_t key_id, INTF interface);
void aes_192_gcm_decrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int ciphertext_len,
                            unsigned char *plaintext, unsigned int *plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, unsigned int *result, bool ext_key, uint8_t key_id, INTF interface);
void aes_256_gcm_encrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int *ciphertext_len,
                            unsigned char *plaintext, unsigned int plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, bool ext_key, uint8_t key_id, INTF interface);
void aes_256_gcm_decrypt_hw(unsigned char *key, unsigned char *iv, unsigned int iv_len, unsigned char *ciphertext, unsigned int ciphertext_len,
                            unsigned char *plaintext, unsigned int *plaintext_len, unsigned char *aad, unsigned int aad_len, unsigned char *tag, unsigned int *result, bool ext_key, uint8_t key_id, INTF interface);

#endif
