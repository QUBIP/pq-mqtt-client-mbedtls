/**
  * @file sha3_shake_hw.h
  * @brief SHA3 SHAKE HW header
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

#ifndef SHA3_SHAKE_H
#define SHA3_SHAKE_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include "intf.h"
#include "conf.h"
#include "picorv32.h"
#include "extra_func.h"

/************************ Interface Constant Definitions **********************/

#define MODE_SHA_3_256              1
#define MODE_SHA_3_512              2
#define MODE_SHAKE_128              3
#define MODE_SHAKE_256              4

#define OP_SHA_3_256                0x08
#define OP_SHA_3_512                0x0C
#define OP_SHAKE_128                0x00
#define OP_SHAKE_256                0x04

#define SHA_3_256_SIZE_BLOCK        1088
#define SHA_3_512_SIZE_BLOCK        576
#define SHAKE_128_SIZE_BLOCK        1344
#define SHAKE_256_SIZE_BLOCK        1088

#define SHA_3_256_LEN_OUT           256
#define SHA_3_512_LEN_OUT           512

void sha3_shake_hw(unsigned char* in, unsigned char* out, unsigned int length, unsigned int length_out, int VERSION, int SIZE_BLOCK, INTF interface, int DBG);

/************************ Main Functions **********************/
void sha3_256_hw_func(unsigned char* in, unsigned int length, unsigned char* out, INTF interface);
void sha3_512_hw_func(unsigned char* in, unsigned int length, unsigned char* out, INTF interface);
void shake128_hw_func(unsigned char* in, unsigned int length, unsigned char* out, unsigned int length_out, INTF interface);
void shake256_hw_func(unsigned char* in, unsigned int length, unsigned char* out, unsigned int length_out, INTF interface);
#endif
