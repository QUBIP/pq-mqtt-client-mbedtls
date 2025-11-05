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

#include "trng_hw.h"

/////////////////////////////////////////////////////////////////////////////////////////////
// TRNG FUNCTION
/////////////////////////////////////////////////////////////////////////////////////////////

void trng_hw(unsigned char* out, unsigned int bytes, INTF interface)
{
	//-- se_code = { {(32'b) 64-bit data_packages}, {10'b0}, {k = 4, k = 3, k = 2, DEC, ENC, KEY_GEN}, {(16'b)MLKEM} }
	uint64_t next_block = 0;
	uint64_t control 	= 0;
    while (control != CMD_SE_CODE)
    {
        picorv32_control(interface, &control);
    }
    const uint8_t trng_code = TRNG_SE_CODE;
	uint32_t data_packages 	= (bytes + AXI_BYTES - 1) / AXI_BYTES;

    uint64_t se_code = ((uint64_t) data_packages << 32) | trng_code;
    write_INTF(interface, &se_code, PICORV32_DATA_IN, AXI_BYTES);

	uint32_t data_blocks 	= data_packages / (FIFO_OUT_DEPTH - 2);
	uint32_t data_rem 		= data_packages % (FIFO_OUT_DEPTH - 2);

	//-- Read Random Data
	uint32_t packages_read = 0;
	for (uint32_t i = 0; i < data_blocks; i++)
	{
		while (control != CMD_SE_READ)
    	{
    	    picorv32_control(interface, &control);
    	}

		for (uint32_t j = 0; j < FIFO_IN_DEPTH - 2; j++)
		{
			read_INTF(interface, out + (j + packages_read) * AXI_BYTES, PICORV32_DATA_OUT, AXI_BYTES);
		}
		packages_read += FIFO_OUT_DEPTH - 2;

		while (control != CMD_SE_WAIT)
    	{
    	    picorv32_control(interface, &control);
			if (control == CMD_SE_WAIT) read_INTF(interface, &next_block, PICORV32_DATA_OUT, AXI_BYTES); // Send a read signal to continue
    	}
	}

	while (control != CMD_SE_READ)
    {
        picorv32_control(interface, &control);
    }

	for (uint32_t i = 0; i < data_rem; i++)
	{
		read_INTF(interface, out + (i + packages_read) * AXI_BYTES, PICORV32_DATA_OUT, AXI_BYTES);
	}

	while (control != CMD_SE_CODE)
    {
        picorv32_control(interface, &control);
    }
}



