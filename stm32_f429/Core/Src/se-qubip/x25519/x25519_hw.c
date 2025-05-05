/**
  * @file x25519_hw.c
  * @brief X25519 Test File
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
// File Name: x25519_hw.c
// Project Name: SE-QUBIP
// Target Devices: PYNQ-Z2
// Description:
//
//		X25519 HW Handler Functions
//
////////////////////////////////////////////////////////////////////////////////////


#include "../../se-qubip/x25519/x25519_hw.h"

/////////////////////////////////////////////////////////////////////////////////////////////
// INTERFACE INIT/START & READ/WRITE
/////////////////////////////////////////////////////////////////////////////////////////////

void x25519_init(INTF interface)
{
    unsigned long long control;

    //-- General and Interface Reset
    control = (ADD_X25519 << 32) + X25519_INTF_RST + X25519_RST_ON;
    write_INTF(interface, &control, CONTROL, AXI_BYTES);
    control = (ADD_X25519 << 32) + X25519_INTF_OPER + X25519_RST_ON;
    write_INTF(interface, &control, CONTROL, AXI_BYTES);
}

void x25519_start(INTF interface)
{
    unsigned long long control = (ADD_X25519 << 32) + X25519_RST_OFF;
    write_INTF(interface, &control, CONTROL, AXI_BYTES);
}

void x25519_write(unsigned long long address, unsigned long long size, void *data, unsigned long long reset, INTF interface)
{
    unsigned long long addr = address;
    unsigned long long control = (reset) ? (ADD_X25519 << 32) + X25519_INTF_LOAD + X25519_RST_ON : (ADD_X25519 << 32) + X25519_INTF_LOAD + X25519_RST_OFF;

    write_INTF(interface, &addr, ADDRESS, AXI_BYTES);
    write_INTF(interface, data, DATA_IN, AXI_BYTES);
    write_INTF(interface, &control, CONTROL, AXI_BYTES);

    for (int i = 1; i < size; i++)
    {
        addr = address + i;
        write_INTF(interface, &addr, ADDRESS, AXI_BYTES);
        write_INTF(interface, data + AXI_BYTES * i, DATA_IN, AXI_BYTES);
    }

    control = (reset) ? (ADD_X25519 << 32) + X25519_INTF_OPER + X25519_RST_ON : (ADD_X25519 << 32) + X25519_INTF_OPER + X25519_RST_OFF;
    write_INTF(interface, &control, CONTROL, AXI_BYTES);
}

void x25519_read(unsigned long long address, unsigned long long size, void *data, INTF interface)
{
    unsigned long long control = (ADD_X25519 << 32) +   X25519_INTF_READ;
    unsigned long long addr;

    write_INTF(interface, &control, CONTROL, AXI_BYTES);

    for (int i = 0; i < size; i++)
    {
        addr = address + i;
        write_INTF(interface, &addr, ADDRESS, AXI_BYTES);
        read_INTF(interface, data + AXI_BYTES * i, DATA_OUT, AXI_BYTES);
    }
}

/////////////////////////////////////////////////////////////////////////////////////////////
// GENERATE PUBLIC KEY
/////////////////////////////////////////////////////////////////////////////////////////////

void x25519_genkeys_hw(unsigned char **pri_key, unsigned char **pub_key, unsigned int *pri_len, unsigned int *pub_len, INTF interface)
{

    *pri_len = X25519_BYTES;
    *pub_len = X25519_BYTES;

    *pri_key = (unsigned char*) malloc(*pri_len);
    *pub_key = (unsigned char*) malloc(*pub_len);

    gen_priv_key(*pri_key, *pri_len);

    /*
    printf("Private = 0x");
    for (int i = 0; i < X25519_BYTES; i++)
    {
        printf("%02x", *(*pri_key + i));
    }
    printf("\n");
    */

    //////////////////////////////////////////////////////////////
    // WRITING ON DEVICE
    //////////////////////////////////////////////////////////////

    unsigned char x25519_base_point[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09};

    unsigned long long info;

    //-- INITIALIZATION: General/Interface Reset & Select Operation
    x25519_init(interface);

    //-- Write Scalar and Input Point
    x25519_write(X25519_SCALAR, X25519_BYTES / AXI_BYTES, *pri_key, X25519_RST_ON, interface);
    x25519_write(X25519_POINT_IN, X25519_BYTES / AXI_BYTES, x25519_base_point, X25519_RST_ON, interface);

    //-- Start Execution
    x25519_start(interface);

    //-- Detect when finish
    int count = 0;

    while (count < X25519_WAIT_TIME)
    {
        read_INTF(interface, &info, END_OP, AXI_BYTES);

        if (info & 0x1) break;

        count++;
    }

    if (count == X25519_WAIT_TIME) printf("X25519 FAIL!: TIMEOUT \t%d\n", count);

    count = 0;

    //////////////////////////////////////////////////////////////
    // RESULTS
    //////////////////////////////////////////////////////////////

    x25519_read(X25519_POINT_OUT, X25519_BYTES / AXI_BYTES, *pub_key, interface);

    /*
    printf("point_out = 0x");
    for (int i = 0; i < X25519_BYTES; i++)
    {
        printf("%02x", *(*pub_key + i));
    }
    printf("\n");
    */

    swapEndianness(*pub_key, *pub_len);
    swapEndianness(*pri_key, *pri_len);
}

/////////////////////////////////////////////////////////////////////////////////////////////
// X25519
/////////////////////////////////////////////////////////////////////////////////////////////

void x25519_ss_gen_hw(unsigned char **shared_secret, unsigned int *shared_secret_len, unsigned char *pub_key, unsigned int pub_len, unsigned char *pri_key, unsigned int pri_len, INTF interface)
{

    pub_len = X25519_BYTES;
    pri_len = X25519_BYTES;
    *shared_secret_len = X25519_BYTES;

    *shared_secret = (unsigned char *) malloc(*shared_secret_len);

    unsigned long long info;

    /*
    //-- Scalar
    printf("pri_key = 0x");
    for (int i = 0; i < X25519_BYTES; i++)
    {
        printf("%02x", *pri_key + i);
    }
    printf("\n");
    */

    /*
    //-- Point_in
    printf("point_in = 0x");
    for (int i = 0; i < X25519_BYTES; i++)
    {
        printf("%02x", *pub_key + i);
    }
    printf("\n");
    */

    swapEndianness(pri_key, X25519_BYTES);
    swapEndianness(pub_key, X25519_BYTES);

    //////////////////////////////////////////////////////////////
    // WRITING ON DEVICE
    //////////////////////////////////////////////////////////////

    //-- INITIALIZATION: General/Interface Reset & Select Operation
    x25519_init(interface);

    //-- Write Scalar and Input Point
    x25519_write(X25519_SCALAR, X25519_BYTES / AXI_BYTES, pri_key, X25519_RST_ON, interface);
    x25519_write(X25519_POINT_IN, X25519_BYTES / AXI_BYTES, pub_key, X25519_RST_ON, interface);

    //-- Start Execution
    x25519_start(interface);

    //-- Detect when finish
    int count = 0;

    while (count < X25519_WAIT_TIME)
    {
        read_INTF(interface, &info, END_OP, AXI_BYTES);

        if (info & 0x1) break;

        count++;
    }
    
    if (count == X25519_WAIT_TIME) printf("X25519 FAIL!: TIMEOUT \t%d\n", count);

    count = 0;

    //////////////////////////////////////////////////////////////
    // RESULTS
    //////////////////////////////////////////////////////////////

    x25519_read(X25519_POINT_OUT, X25519_BYTES / AXI_BYTES, *shared_secret, interface);
    
    /*
    printf("Point_out = 0x");
    for (int i = 0; i < SHA_BYTES; i++)
    {
        printf("%02x", *(point_out + i));
    }
    printf("\n");
    */
    
    swapEndianness(pri_key, X25519_BYTES);
    swapEndianness(pub_key, X25519_BYTES);
    swapEndianness(*shared_secret, X25519_BYTES);
}

