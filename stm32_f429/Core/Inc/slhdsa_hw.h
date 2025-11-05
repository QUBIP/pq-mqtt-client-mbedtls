/**
  * @file  slhdsa_hw.h
  * @brief  SLH-DSA HW header
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
// Create Date: 29/07/2025
// File Name: slhdsa_hw.h
// Project Name: SE-QUBIP
// Target Devices: PYNQ-Z2
// Description:
//
//		SLH-DSA HW Handler Functions Header File
//
// Additional Comment
//
////////////////////////////////////////////////////////////////////////////////////

#ifndef SLHDSA_HW_H
#define SLHDSA_HW_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "../common/intf.h"
#include "../common/conf.h"
#include "../common/picorv32.h"
#include "../sha2/sha2_hw.h"
#include "../sha3/sha3_shake_hw.h"
#include "../secmem/secmem_hw.h"


//-- Deterministic
#define SLHDSA_DETERMINISTIC        1

//-- Configuration                  
#define SLHDSA_SEL_KEY_GEN          (1 << 0)                    // Bit 0
#define SLHDSA_SEL_SIGN             (1 << 1)                    // Bit 1
#define SLHDSA_SEL_VERIFY           (1 << 2)                    // Bit 2
#define SLHDSA_SEL_SHA2             (0 << 3)                    // Bit 3
#define SLHDSA_SEL_SHAKE            (1 << 3)                    // Bit 3
#define SLHDSA_SEL_S                (0 << 4)                    // Bit 4
#define SLHDSA_SEL_F                (1 << 4)                    // Bit 4
#define SLHDSA_SEL_128              (1 << 5)                    // Bit 5
#define SLHDSA_SEL_192              (1 << 6)                    // Bit 6
#define SLHDSA_SEL_256              (1 << 7)                    // Bit 7
#define SLHDSA_SEL_DETERMINISTIC    (SLHDSA_DETERMINISTIC << 8) // Bit 8

//  Parameter sets
typedef struct slh_param_s slh_param_t;

struct slh_param_s {
    const char  *alg_id;    //  Algorithm name

    //  core parameters
    uint32_t    n;          //  Security level / hash size { 16,24,32 }.
    uint32_t    h;          //  Bits h used to select FORS key.
    uint32_t    d;          //  Number of hypertree layers d.
    uint32_t    hp;         //  Merkle tree height h' (XMSS).
    uint32_t    a;          //  String length t = 2**a (FORS).
    uint32_t    k;          //  Number of strings (FORS).
    uint32_t    lg_w;       //  Number of bits in chain index (WOTS+)
    uint32_t    m;          //  Length in bytes of message digest.
};
extern const slh_param_t slh_dsa_shake_128s;
extern const slh_param_t slh_dsa_shake_128f;
extern const slh_param_t slh_dsa_shake_192s;
extern const slh_param_t slh_dsa_shake_192f;
extern const slh_param_t slh_dsa_shake_256s;
extern const slh_param_t slh_dsa_shake_256f;
extern const slh_param_t slh_dsa_sha2_128s;
extern const slh_param_t slh_dsa_sha2_128f;
extern const slh_param_t slh_dsa_sha2_192s;
extern const slh_param_t slh_dsa_sha2_192f;
extern const slh_param_t slh_dsa_sha2_256s;
extern const slh_param_t slh_dsa_sha2_256f;

//-- SLH-DSA Pre-Hash Functions
typedef struct slh_ph_func_s slh_ph_func_t; 

struct slh_ph_func_s {
    const char      *alg_id;        //  Algorithm name
    const uint8_t   *oid;           //  Object Identifier
    const size_t    oid_len;        //  Object Identifier Byte Length
    const size_t    digest_len;     //  Output Length of the hash Function
    
    // Hash Function
    void (*hash_function) (unsigned char* in, unsigned int in_len, unsigned char* out, unsigned int out_len, INTF interface);
};

extern const uint8_t OID_SHA_256[];
extern const uint8_t OID_SHA_512[];
extern const uint8_t OID_SHAKE_128[];
extern const uint8_t OID_SHAKE_256[];

extern const slh_ph_func_t slh_dsa_ph_sha_256;
extern const slh_ph_func_t slh_dsa_ph_sha_512;
extern const slh_ph_func_t slh_dsa_ph_shake_128;
extern const slh_ph_func_t slh_dsa_ph_shake_256;

//-- GENERATE PUBLIC KEY
void slhdsa_gen_keys_hw(unsigned char* pri_key, unsigned char* pub_key, uint16_t op_select, const slh_param_t* slh_dsa_parameter, bool ext_key, uint8_t* key_id, INTF interface);

void slhdsa_shake_128_f_gen_keys_hw(unsigned char* pri_key, unsigned char* pub_key, bool ext_key, uint8_t* key_id, INTF interface);
void slhdsa_shake_128_s_gen_keys_hw(unsigned char* pri_key, unsigned char* pub_key, bool ext_key, uint8_t* key_id, INTF interface);
void slhdsa_shake_192_f_gen_keys_hw(unsigned char* pri_key, unsigned char* pub_key, bool ext_key, uint8_t* key_id, INTF interface);
void slhdsa_shake_192_s_gen_keys_hw(unsigned char* pri_key, unsigned char* pub_key, bool ext_key, uint8_t* key_id, INTF interface);
void slhdsa_shake_256_f_gen_keys_hw(unsigned char* pri_key, unsigned char* pub_key, bool ext_key, uint8_t* key_id, INTF interface);
void slhdsa_shake_256_s_gen_keys_hw(unsigned char* pri_key, unsigned char* pub_key, bool ext_key, uint8_t* key_id, INTF interface);

void slhdsa_sha2_128_f_gen_keys_hw(unsigned char* pri_key, unsigned char* pub_key, bool ext_key, uint8_t* key_id, INTF interface);
void slhdsa_sha2_128_s_gen_keys_hw(unsigned char* pri_key, unsigned char* pub_key, bool ext_key, uint8_t* key_id, INTF interface);
void slhdsa_sha2_192_f_gen_keys_hw(unsigned char* pri_key, unsigned char* pub_key, bool ext_key, uint8_t* key_id, INTF interface);
void slhdsa_sha2_192_s_gen_keys_hw(unsigned char* pri_key, unsigned char* pub_key, bool ext_key, uint8_t* key_id, INTF interface);
void slhdsa_sha2_256_f_gen_keys_hw(unsigned char* pri_key, unsigned char* pub_key, bool ext_key, uint8_t* key_id, INTF interface);
void slhdsa_sha2_256_s_gen_keys_hw(unsigned char* pri_key, unsigned char* pub_key, bool ext_key, uint8_t* key_id, INTF interface);

//-- PRE-HASH SIGN
void slhdsa_ph_sign_hw(const slh_ph_func_t *ph, const unsigned char* msg, const unsigned int msg_len, const unsigned char *ctx, const unsigned int ctx_len, const unsigned char* pri_key, unsigned char* sig, unsigned int* sig_len, uint16_t op_select, const slh_param_t* slh_dsa_parameter, bool ext_key, uint8_t* key_id, INTF interface);

void slhdsa_shake_128_f_ph_sign_hw(const slh_ph_func_t *ph, const unsigned char* msg, const unsigned int msg_len, const unsigned char *ctx, const unsigned int ctx_len, const unsigned char* pri_key, unsigned char* sig, unsigned int* sig_len, bool ext_key, uint8_t* key_id, INTF interface);
void slhdsa_shake_128_s_ph_sign_hw(const slh_ph_func_t *ph, const unsigned char* msg, const unsigned int msg_len, const unsigned char *ctx, const unsigned int ctx_len, const unsigned char* pri_key, unsigned char* sig, unsigned int* sig_len, bool ext_key, uint8_t* key_id, INTF interface);
void slhdsa_shake_192_f_ph_sign_hw(const slh_ph_func_t *ph, const unsigned char* msg, const unsigned int msg_len, const unsigned char *ctx, const unsigned int ctx_len, const unsigned char* pri_key, unsigned char* sig, unsigned int* sig_len, bool ext_key, uint8_t* key_id, INTF interface);
void slhdsa_shake_192_s_ph_sign_hw(const slh_ph_func_t *ph, const unsigned char* msg, const unsigned int msg_len, const unsigned char *ctx, const unsigned int ctx_len, const unsigned char* pri_key, unsigned char* sig, unsigned int* sig_len, bool ext_key, uint8_t* key_id, INTF interface);
void slhdsa_shake_256_f_ph_sign_hw(const slh_ph_func_t *ph, const unsigned char* msg, const unsigned int msg_len, const unsigned char *ctx, const unsigned int ctx_len, const unsigned char* pri_key, unsigned char* sig, unsigned int* sig_len, bool ext_key, uint8_t* key_id, INTF interface);
void slhdsa_shake_256_s_ph_sign_hw(const slh_ph_func_t *ph, const unsigned char* msg, const unsigned int msg_len, const unsigned char *ctx, const unsigned int ctx_len, const unsigned char* pri_key, unsigned char* sig, unsigned int* sig_len, bool ext_key, uint8_t* key_id, INTF interface);

void slhdsa_sha2_128_f_ph_sign_hw(const slh_ph_func_t *ph, const unsigned char* msg, const unsigned int msg_len, const unsigned char *ctx, const unsigned int ctx_len, const unsigned char* pri_key, unsigned char* sig, unsigned int* sig_len, bool ext_key, uint8_t* key_id, INTF interface);
void slhdsa_sha2_128_s_ph_sign_hw(const slh_ph_func_t *ph, const unsigned char* msg, const unsigned int msg_len, const unsigned char *ctx, const unsigned int ctx_len, const unsigned char* pri_key, unsigned char* sig, unsigned int* sig_len, bool ext_key, uint8_t* key_id, INTF interface);
void slhdsa_sha2_192_f_ph_sign_hw(const slh_ph_func_t *ph, const unsigned char* msg, const unsigned int msg_len, const unsigned char *ctx, const unsigned int ctx_len, const unsigned char* pri_key, unsigned char* sig, unsigned int* sig_len, bool ext_key, uint8_t* key_id, INTF interface);
void slhdsa_sha2_192_s_ph_sign_hw(const slh_ph_func_t *ph, const unsigned char* msg, const unsigned int msg_len, const unsigned char *ctx, const unsigned int ctx_len, const unsigned char* pri_key, unsigned char* sig, unsigned int* sig_len, bool ext_key, uint8_t* key_id, INTF interface);
void slhdsa_sha2_256_f_ph_sign_hw(const slh_ph_func_t *ph, const unsigned char* msg, const unsigned int msg_len, const unsigned char *ctx, const unsigned int ctx_len, const unsigned char* pri_key, unsigned char* sig, unsigned int* sig_len, bool ext_key, uint8_t* key_id, INTF interface);
void slhdsa_sha2_256_s_ph_sign_hw(const slh_ph_func_t *ph, const unsigned char* msg, const unsigned int msg_len, const unsigned char *ctx, const unsigned int ctx_len, const unsigned char* pri_key, unsigned char* sig, unsigned int* sig_len, bool ext_key, uint8_t* key_id, INTF interface);

//-- PRE-HASH VERIFY
void slhdsa_ph_verify_hw(const slh_ph_func_t *ph, const unsigned char* msg, const unsigned int msg_len, const unsigned char *ctx, const unsigned int ctx_len, const unsigned char* pub_key, const unsigned char* sig, const unsigned int sig_len, unsigned int* result, uint16_t op_select, const slh_param_t* slh_dsa_parameter, bool ext_key, uint8_t* key_id, INTF interface);

void slhdsa_shake_128_f_ph_verify_hw(const slh_ph_func_t *ph, const unsigned char* msg, const unsigned int msg_len, const unsigned char *ctx, const unsigned int ctx_len, const unsigned char* pub_key, const unsigned char* sig, const unsigned int sig_len, unsigned int* result, bool ext_key, uint8_t* key_id, INTF interface);
void slhdsa_shake_128_s_ph_verify_hw(const slh_ph_func_t *ph, const unsigned char* msg, const unsigned int msg_len, const unsigned char *ctx, const unsigned int ctx_len, const unsigned char* pub_key, const unsigned char* sig, const unsigned int sig_len, unsigned int* result, bool ext_key, uint8_t* key_id, INTF interface);
void slhdsa_shake_192_f_ph_verify_hw(const slh_ph_func_t *ph, const unsigned char* msg, const unsigned int msg_len, const unsigned char *ctx, const unsigned int ctx_len, const unsigned char* pub_key, const unsigned char* sig, const unsigned int sig_len, unsigned int* result, bool ext_key, uint8_t* key_id, INTF interface);
void slhdsa_shake_192_s_ph_verify_hw(const slh_ph_func_t *ph, const unsigned char* msg, const unsigned int msg_len, const unsigned char *ctx, const unsigned int ctx_len, const unsigned char* pub_key, const unsigned char* sig, const unsigned int sig_len, unsigned int* result, bool ext_key, uint8_t* key_id, INTF interface);
void slhdsa_shake_256_f_ph_verify_hw(const slh_ph_func_t *ph, const unsigned char* msg, const unsigned int msg_len, const unsigned char *ctx, const unsigned int ctx_len, const unsigned char* pub_key, const unsigned char* sig, const unsigned int sig_len, unsigned int* result, bool ext_key, uint8_t* key_id, INTF interface);
void slhdsa_shake_256_s_ph_verify_hw(const slh_ph_func_t *ph, const unsigned char* msg, const unsigned int msg_len, const unsigned char *ctx, const unsigned int ctx_len, const unsigned char* pub_key, const unsigned char* sig, const unsigned int sig_len, unsigned int* result, bool ext_key, uint8_t* key_id, INTF interface);

void slhdsa_sha2_128_f_ph_verify_hw(const slh_ph_func_t *ph, const unsigned char* msg, const unsigned int msg_len, const unsigned char *ctx, const unsigned int ctx_len, const unsigned char* pub_key, const unsigned char* sig, const unsigned int sig_len, unsigned int* result, bool ext_key, uint8_t* key_id, INTF interface);
void slhdsa_sha2_128_s_ph_verify_hw(const slh_ph_func_t *ph, const unsigned char* msg, const unsigned int msg_len, const unsigned char *ctx, const unsigned int ctx_len, const unsigned char* pub_key, const unsigned char* sig, const unsigned int sig_len, unsigned int* result, bool ext_key, uint8_t* key_id, INTF interface);
void slhdsa_sha2_192_f_ph_verify_hw(const slh_ph_func_t *ph, const unsigned char* msg, const unsigned int msg_len, const unsigned char *ctx, const unsigned int ctx_len, const unsigned char* pub_key, const unsigned char* sig, const unsigned int sig_len, unsigned int* result, bool ext_key, uint8_t* key_id, INTF interface);
void slhdsa_sha2_192_s_ph_verify_hw(const slh_ph_func_t *ph, const unsigned char* msg, const unsigned int msg_len, const unsigned char *ctx, const unsigned int ctx_len, const unsigned char* pub_key, const unsigned char* sig, const unsigned int sig_len, unsigned int* result, bool ext_key, uint8_t* key_id, INTF interface);
void slhdsa_sha2_256_f_ph_verify_hw(const slh_ph_func_t *ph, const unsigned char* msg, const unsigned int msg_len, const unsigned char *ctx, const unsigned int ctx_len, const unsigned char* pub_key, const unsigned char* sig, const unsigned int sig_len, unsigned int* result, bool ext_key, uint8_t* key_id, INTF interface);
void slhdsa_sha2_256_s_ph_verify_hw(const slh_ph_func_t *ph, const unsigned char* msg, const unsigned int msg_len, const unsigned char *ctx, const unsigned int ctx_len, const unsigned char* pub_key, const unsigned char* sig, const unsigned int sig_len, unsigned int* result, bool ext_key, uint8_t* key_id, INTF interface);

#endif // SLHDSA_HW_H
