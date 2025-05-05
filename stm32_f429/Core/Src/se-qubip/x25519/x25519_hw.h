/**
  * @file  x25519_hw.h
  * @brief  X25519 HW header
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
// Create Date: 09/07/2024
// File Name: x25519_hw.h
// Project Name: SE-QUBIP
// Target Devices: PYNQ-Z2
// Description:
//
//		X25519 HW Handler Functions Header File
//
// Additional Comment
//
////////////////////////////////////////////////////////////////////////////////////

#ifndef X25519_H
#define X25519_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../se-qubip/common/conf.h"
#include "../../se-qubip/common/extra_func.h"
#include "../../se-qubip/common/intf.h"

//-- Elements Bit Sizes
#define X25519_BYTES          32
#define AXI_BYTES              8

//-- Control Operations
#define X25519_RST_OFF      0x00
#define X25519_RST_ON       0x01
#define X25519_INTF_RST     0x02
#define X25519_INTF_OPER    0x00
#define X25519_INTF_LOAD    0x04
#define X25519_INTF_READ    0x08

//-- I/O Addresses
#define X25519_SCALAR      0x0
#define X25519_POINT_IN    0x4
#define X25519_POINT_OUT   0x0

//-- Debug
#ifdef I2C
    #define X25519_WAIT_TIME    50
#else
    #define X25519_WAIT_TIME    5000
#endif
#define X25519_N_ITER       1000

//-- INTERFACE INIT/START & READ/WRITE
void x25519_init(INTF interface);
void x25519_start(INTF interface);
void x25519_write(unsigned long long address, unsigned long long size, void *data, unsigned long long reset, INTF interface);
void x25519_read(unsigned long long address, unsigned long long size, void *data, INTF interface);

//-- GENERATE PUBLIC KEY
void x25519_genkeys_hw(unsigned char **pri_key, unsigned char **pub_key, unsigned int *pri_len, unsigned int *pub_len, INTF interface);

//-- ECDH X25519 OPERATION
void x25519_ss_gen_hw(unsigned char **shared_secret, unsigned int *shared_secret_len, unsigned char *pub_key, unsigned int pub_len, unsigned char *pri_key, unsigned int pri_len, INTF interface);

#endif