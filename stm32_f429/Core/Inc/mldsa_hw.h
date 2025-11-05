/**
  * @file mlkem_hw.h
  * @brief MLKEM HW header
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

#ifndef MLDSA_H
#define MLDSA_H

#include "intf.h"
#include "conf.h"
#include "picorv32.h"
#include "sha2_hw.h"
#include "sha3_shake_hw.h"
#include <stdbool.h>

/************************ Gen Keys Functions **********************/
void mldsa44_genkeys_hw(unsigned char d[32], unsigned char* pk, unsigned char* sk, bool ext_key, uint8_t* key_id, INTF interface);
void mldsa65_genkeys_hw(unsigned char d[32], unsigned char* pk, unsigned char* sk, bool ext_key, uint8_t* key_id, INTF interface);
void mldsa87_genkeys_hw(unsigned char d[32], unsigned char* pk, unsigned char* sk, bool ext_key, uint8_t* key_id, INTF interface);
void mldsa_genkeys_hw(int mode, unsigned char d[32], unsigned char* pk, unsigned char* sk, bool ext_key, uint8_t* key_id, INTF interface);

/************************ Signature Functions **********************/
void mldsa44_sign_hw(unsigned char* msg, unsigned int msg_len, unsigned char* sk, unsigned char* sig, unsigned int* sig_len, unsigned char* ctx, unsigned int ctx_len , bool ext_key, uint8_t* key_id, INTF interface);
void mldsa65_sign_hw(unsigned char* msg, unsigned int msg_len, unsigned char* sk, unsigned char* sig, unsigned int* sig_len, unsigned char* ctx, unsigned int ctx_len , bool ext_key, uint8_t* key_id, INTF interface);
void mldsa87_sign_hw(unsigned char* msg, unsigned int msg_len, unsigned char* sk, unsigned char* sig, unsigned int* sig_len, unsigned char* ctx, unsigned int ctx_len , bool ext_key, uint8_t* key_id, INTF interface);
void mldsa_sign_hw(int mode, unsigned char* msg, unsigned int msg_len, unsigned char* sk, unsigned char* sig, unsigned int* sig_len, unsigned char* ctx, unsigned int ctx_len, bool ext_key, uint8_t* key_id, INTF interface);

/************************ Verification Functions **********************/
void mldsa44_verify_hw(unsigned char* msg, unsigned int msg_len, unsigned char* pk, unsigned char* sig, unsigned int sig_len, unsigned char* ctx, unsigned int ctx_len, unsigned int* result , INTF interface);
void mldsa65_verify_hw(unsigned char* msg, unsigned int msg_len, unsigned char* pk, unsigned char* sig, unsigned int sig_len, unsigned char* ctx, unsigned int ctx_len, unsigned int* result , INTF interface);
void mldsa87_verify_hw(unsigned char* msg, unsigned int msg_len, unsigned char* pk, unsigned char* sig, unsigned int sig_len, unsigned char* ctx, unsigned int ctx_len, unsigned int* result , INTF interface);
void mldsa_verify_hw(int mode, unsigned char* msg, unsigned int msg_len, unsigned char* pk, unsigned char* sig, unsigned int sig_len, unsigned char* ctx, unsigned int ctx_len, unsigned int* result, INTF interface);


#endif
