/**
  * @file demo_trng.c
  * @brief Validation Test for TRNG Code
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

#include "demo.h"
#include "test_func.h"

void demo_trng_hw(unsigned int bits, unsigned verb, INTF interface) {

    unsigned int bytes = (int)(bits / 8);
    unsigned char* random; 
    random = malloc(bytes);

    unsigned char buf[20]; sprintf(buf, "%d bits", bits); 
    memset(random, 0, bytes);

    trng_hw(random, bytes, interface);

    if (verb >= 1) {
        printf("\n TRNG Random %d bits: ", bits);  show_array(random, bytes, 32);
    }

    print_result_double_valid("TRNG", buf, test_random(random, bytes));
    /*
    memset(random, 0, bytes);

    ctr_drbg(random, bytes);

    if (verb >= 1) {
        printf("\n CTR-DRBG Random %d bits: ", bits);  show_array(random, bytes, 32);
    }

    print_result_double_valid("CTR-DRBG", buf, test_random(random, bytes));

    memset(random, 0, bytes);

    hash_drbg(random, bytes);

    if (verb >= 1) {
        printf("\n HASH-DRBG Random %d bits: ", bits);  show_array(random, bytes, 32);
    }

    print_result_double_valid("HASH-DRBG", buf, test_random(random, bytes));
    */
}