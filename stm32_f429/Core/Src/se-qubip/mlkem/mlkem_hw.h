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

#ifndef MLKEM_H
#define MLKEM_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../../../Inc/se-qubip.h"
#include "../../se-qubip/common/conf.h"
#include "../../se-qubip/common/intf.h"

/************************ MS2XL Constant Definitions **********************/

#define MLKEM_RESET		    0x01
#define MLKEM_LOAD_COINS	0x02
#define MLKEM_LOAD_SK		0x03
#define MLKEM_READ_SK		0x04
#define MLKEM_LOAD_PK		0x05
#define MLKEM_READ_PK		0x06
#define MLKEM_LOAD_CT		0x07
#define MLKEM_READ_CT		0x08
#define MLKEM_LOAD_SS		0x09
#define MLKEM_READ_SS		0x0a
#define MLKEM_LOAD_HEK		0x0b
#define MLKEM_READ_HEK		0x0c
#define MLKEM_LOAD_PS		0x0d
#define MLKEM_READ_PS		0x0e
#define MLKEM_START		    0x0f

#define MLKEM_GEN_KEYS_512	0x05
#define MLKEM_GEN_KEYS_768	0x06
#define MLKEM_GEN_KEYS_1024	0x07
#define MLKEM_ENCAP_512		0x09
#define MLKEM_ENCAP_768		0x0a
#define MLKEM_ENCAP_1024	0x0b
#define MLKEM_DECAP_512		0x0d
#define MLKEM_DECAP_768		0x0e
#define MLKEM_DECAP_1024	0x0f

/************************ MS2XL Function Definitions **********************/

/************************ Gen Keys Functions **********************/
void mlkem_512_gen_keys_hw(unsigned char* pk, unsigned char* sk, INTF interface);
void mlkem_768_gen_keys_hw(unsigned char* pk, unsigned char* sk, INTF interface);
void mlkem_1024_gen_keys_hw(unsigned char* pk, unsigned char* sk, INTF interface);
void mlkem_gen_keys_hw(int k, unsigned char* pk, unsigned char* sk, INTF interface);

/************************ Encryption Functions **********************/
void mlkem_512_enc_hw(unsigned char* pk, unsigned char* ct, unsigned char* ss, INTF interface);
void mlkem_768_enc_hw(unsigned char* pk, unsigned char* ct, unsigned char* ss, INTF interface);
void mlkem_1024_enc_hw(unsigned char* pk, unsigned char* ct, unsigned char* ss, INTF interface);
void mlkem_enc_hw(int k, unsigned char* pk, unsigned char* ct, unsigned char* ss, INTF interface);
/************************ Decryption Functions **********************/
void mlkem_512_dec_hw(unsigned char* sk, unsigned char* ct, unsigned char* ss, unsigned int* result, INTF interface);
void mlkem_768_dec_hw(unsigned char* sk, unsigned char* ct, unsigned char* ss, unsigned int* result, INTF interface);
void mlkem_1024_dec_hw(unsigned char* sk, unsigned char* ct, unsigned char* ss, unsigned int* result, INTF interface);
void mlkem_dec_hw(int k, unsigned char* sk, unsigned char* ct, unsigned char* ss, unsigned int* result, INTF interface);
#endif
