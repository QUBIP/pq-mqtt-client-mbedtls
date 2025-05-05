/**
  * @file trng_hw.h
  * @brief TRNG HW header
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
#ifndef TRNG_H
#define TRNG_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../se-qubip/common/conf.h"
#include "../../se-qubip/common/extra_func.h"
#include "../../se-qubip/common/intf.h"

//-- Elements Bit Sizes
#define TRNG_MAX_BYTES          2048
#define AXI_BYTES              	8

//-- Control Operations
#define TRNG_RST_OFF      		0x00
#define TRNG_RST_ON       		0x01
#define TRNG_INTF_RST     		0x02
#define TRNG_INTF_OPER    		0x00
#define TRNG_INTF_LOAD    		0x04
#define TRNG_INTF_READ    		0x08

//-- I/O Addresses
#define TRNG_IN      	 		0x0
#define TRNG_PUF_ADDW    		0x0
#define TRNG_PUF_OUT   	 		0x1

//-- Debug
#ifdef I2C
    #define TRNG_WAIT_TIME 5000
#else
    #define TRNG_WAIT_TIME 500000
#endif

//-- INTERFACE INIT/START & READ/WRITE
void trng_init(INTF interface);
void trng_start(unsigned int bytes, INTF interface);
void trng_read(unsigned char* out, unsigned int bytes, INTF interface);

//-- TRNG Function
void trng_hw(unsigned char* out, unsigned int bytes, INTF interface);


#endif