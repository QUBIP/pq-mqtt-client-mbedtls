/**
  * @file demo_trng.c
  * @brief Validation test for Random Number Generator code
  *
  * @section License
  *
  * MIT License
  *
  * Copyright (c) 2024 Eros Camacho
  *
  * Permission is hereby granted, free of charge, to any person obtaining a copy
  * of this software and associated documentation files (the "Software"), to deal
  * in the Software without restriction, including without limitation the rights
  * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  * copies of the Software, and to permit persons to whom the Software is
  * furnished to do so, subject to the following conditions:
  *
  * The above copyright notice and this permission notice shall be included in all
  * copies or substantial portions of the Software.
  *
  * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  * SOFTWARE.
  *
  *
  *
  * @author Eros Camacho-Ruiz (camacho@imse-cnm.csic.es)
  * @version 5.0
  **/ 

#include "demo.h"
#include "test_func.h"

void demo_trng(unsigned int bits, unsigned verb) {

    unsigned int bytes = (int)(bits / 8);
    unsigned char* random; 
    random = malloc(bytes);

    unsigned char buf[20]; sprintf(buf, "%d bits", bits); 
    memset(random, 0, bytes);

    trng(random, bytes);

    if (verb >= 1) {
        printf("\n TRNG Random %d bits: ", bits);  show_array(random, bytes, 32);
    }

    print_result_double_valid("TRNG", buf, test_random(random, bytes));

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

}