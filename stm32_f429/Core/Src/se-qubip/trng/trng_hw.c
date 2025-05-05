/**
  * @file  trng_hw.c
  * @brief TRNG Test File
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


#include "../../se-qubip/trng/trng_hw.h"

/////////////////////////////////////////////////////////////////////////////////////////////
// INTERFACE INIT/START & READ/WRITE
/////////////////////////////////////////////////////////////////////////////////////////////

void trng_init(INTF interface)
{
    unsigned long long control;

    //-- General and Interface Reset
    control = (ADD_TRNG << 32) + TRNG_INTF_RST + TRNG_RST_ON;
    write_INTF(interface, &control, CONTROL, AXI_BYTES);
    control = (ADD_TRNG << 32) + TRNG_INTF_OPER + TRNG_RST_ON;
    write_INTF(interface, &control, CONTROL, AXI_BYTES);
	
	////////
	/* control = (ADD_TRNG << 32) + TRNG_INTF_LOAD + TRNG_RST_ON;
    unsigned long long addr = 0;

	write_INTF(interface, &control, CONTROL, AXI_BYTES);
	write_INTF(interface, &addr, ADDRESS, AXI_BYTES);
	
	unsigned long long in_data = 0;	
	write_INTF(interface, &in_data, DATA_IN, AXI_BYTES); */
}

void trng_start(unsigned int bytes, INTF interface)
{
    unsigned long long control = (ADD_TRNG << 32) + TRNG_INTF_LOAD + TRNG_RST_OFF;
	unsigned long long addr = 0;
	
    write_INTF(interface, &control, CONTROL, AXI_BYTES);
	write_INTF(interface, &addr, ADDRESS, AXI_BYTES);
	
	//unsigned long long in_data = ((bytes) << 5) + 1;
	unsigned long long in_data = ((bytes/8) << 5) + 1;
	
	write_INTF(interface, &in_data, DATA_IN, AXI_BYTES);
	
	control = (ADD_TRNG << 32) + TRNG_INTF_OPER + TRNG_RST_OFF;
    write_INTF(interface, &control, CONTROL, AXI_BYTES);
}


void trng_read(unsigned char* out, unsigned int bytes, INTF interface)
{
    unsigned long long in_data;
	unsigned long long control;
	unsigned long long addr;
	
	int loop = (bytes % AXI_BYTES == 0) ? (bytes / AXI_BYTES) : (bytes / AXI_BYTES + 1); 
	
    for (int i = 0; i < loop; i++)
    {
        //in_data = (i << 18) + ((bytes) << 5) + 1;
		in_data = (i << 18) + ((bytes/8) << 5) + 1;
		control = (ADD_TRNG << 32) + TRNG_INTF_LOAD + TRNG_RST_OFF;
		addr = 0;
		
		write_INTF(interface, &control, CONTROL, AXI_BYTES);
		write_INTF(interface, &addr, ADDRESS, AXI_BYTES);
		write_INTF(interface, &in_data, DATA_IN, AXI_BYTES);
		
		control = (ADD_TRNG << 32) + TRNG_INTF_READ + TRNG_RST_OFF;
		addr = 1;
		write_INTF(interface, &control, CONTROL, AXI_BYTES);
		write_INTF(interface, &addr, ADDRESS, AXI_BYTES);
		
		read_INTF(interface, out + AXI_BYTES * i, DATA_OUT, AXI_BYTES);
		
		
    }
}

/////////////////////////////////////////////////////////////////////////////////////////////
// TRNG FUNCTION
/////////////////////////////////////////////////////////////////////////////////////////////

void trng_hw(unsigned char* out, unsigned int bytes, INTF interface){
	
	unsigned int block_num = 0; 
	unsigned int block_total = bytes / TRNG_MAX_BYTES;
	unsigned int last_bytes = (bytes % TRNG_MAX_BYTES);

	// printf("\n %d %d %d", bytes, block_total, last_bytes);

	unsigned char out_trng[TRNG_MAX_BYTES]; 

	/*
	if (bytes > TRNG_MAX_BYTES) {
		 printf("\nTRNG FAIL: Max bytes = %d\n ", TRNG_MAX_BYTES);
		 exit(1);
	}
	*/
	if (block_total != 0) { // blocks of TRNG_MAX_BYTES
		for (block_num = 0; block_num < block_total; block_num++) {
			trng_init(interface);

			trng_start(TRNG_MAX_BYTES, interface);

			//-- Detect when finish
			unsigned long long info;
			int count = 0;

			while (count < TRNG_WAIT_TIME)
			{
				read_INTF(interface, &info, END_OP, AXI_BYTES);

				if (info & 0x1) break;

				count++;
			}
			if (count == TRNG_WAIT_TIME)
				printf("\nTRNG FAIL!: TIMEOUT \t%d\n", count);

			count = 0;

			trng_read(out_trng, TRNG_MAX_BYTES, interface);

			memcpy(out + TRNG_MAX_BYTES * block_num, out_trng, TRNG_MAX_BYTES);

		}
	}

	// last one or block less than TRNG_MAX_BYTES
	if (last_bytes != 0) {

		trng_init(interface);

		trng_start(last_bytes, interface);

		//-- Detect when finish
		unsigned long long info;
		int count = 0;

		while (count < TRNG_WAIT_TIME)
		{
			read_INTF(interface, &info, END_OP, AXI_BYTES);

			if (info & 0x1) break;

			count++;
		}
		if (count == TRNG_WAIT_TIME)
			printf("\nTRNG FAIL!: TIMEOUT \t%d\n", count);

		count = 0;

		trng_read(out_trng, last_bytes, interface);

		memcpy(out + TRNG_MAX_BYTES * block_num, out_trng, last_bytes);
	
	}
}

