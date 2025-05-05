/**
  * @file eddsa_hw.h
  * @brief EDDSA HW header
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
// Create Date: 13/06/2024
// File Name: eddsa_hw.h
// Project Name: SE-QUBIP
// Target Devices: PYNQ-Z2
// Description:
//
//		EdDSA HW Handler Functions Header File
//
// Additional Comment
//
////////////////////////////////////////////////////////////////////////////////////

#ifndef EDDSA_H
#define EDDSA_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../se-qubip/common/conf.h"
#include "../../se-qubip/common/extra_func.h"
#include "../../se-qubip/common/intf.h"

//-- Elements Bit Sizes
#define BLOCK_BYTES         128
#define SHA_BYTES           64
#define EDDSA_BYTES         32
#define AXI_BYTES           8

//-- Max. Message Length
#define MAX_MSG_LENGTH      2048

//-- Control Operations
#define EDDSA_RST_OFF       0x00
#define EDDSA_RST_ON        0x01
#define EDDSA_INTF_RST      0x02
#define EDDSA_INTF_OPER     0x00
#define EDDSA_INTF_LOAD     0x04
#define EDDSA_INTF_READ     0x08

//-- I/O Addresses
#define EDDSA_ADDR_CTRL     0x0
#define EDDSA_ADDR_PRIV     0x1
#define EDDSA_ADDR_PUB      0x5
#define EDDSA_ADDR_MSG      0x9
#define EDDSA_ADDR_LEN      0x19
#define EDDSA_ADDR_SIGVER   0x1A
#define EDDSA_ADDR_SIGPUB   0x1

//-- Operation Modes
#define EDDSA_OP_GEN_KEY    0x4
#define EDDSA_OP_SIGN       0x8
#define EDDSA_OP_VERIFY     0xC

//-- Debug
#ifdef I2C
    #define EDDSA_WAIT_TIME     50
#else
    #define EDDSA_WAIT_TIME     5000
#endif
#define EDDSA_N_ITER        1000

//-- INTERFACE INIT/START & READ/WRITE
void eddsa25519_init(unsigned long long operation, INTF interface);
void eddsa25519_start(INTF interface);
void eddsa25519_write(unsigned long long address, unsigned long long size, void *data, unsigned long long reset, INTF interface);
void eddsa25519_read(unsigned long long address, unsigned long long size, void *data, INTF interface);

//-- GENERATE PUBLIC KEY
void eddsa25519_genkeys_hw(unsigned char **pri_key, unsigned char **pub_key, unsigned int *pri_len, unsigned int *pub_len, INTF interface);

//-- SIGN
void eddsa25519_sign_hw(unsigned char *msg, unsigned int msg_len, unsigned char *pri_key, unsigned int pri_len, unsigned char *pub_key, unsigned int pub_len, unsigned char **sig, unsigned int *sig_len, INTF interface);

//-- VERIFY
void eddsa25519_verify_hw(unsigned char *msg, unsigned int msg_len, unsigned char *pub_key, unsigned int pub_len, unsigned char *sig, unsigned int sig_len, unsigned int *result, INTF interface);

#endif