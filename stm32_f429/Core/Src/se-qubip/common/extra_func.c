/**
  * @file  extra_func.c
  * @brief SEQUBIP Extra Function
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
#include "../../se-qubip/common/extra_func.h"

void swapEndianness(unsigned char *data, size_t size)
{
    size_t i;
    unsigned char temp;

    for (i = 0; i < size / 2; ++i)
    {
        temp = data[i];
        data[i] = data[size - 1 - i];
        data[size - 1 - i] = temp;
    }
}

void seed_rng()
{
    srand((unsigned int)time(NULL)); // Initialization, should only be called once.
}

void gen_priv_key(unsigned char *priv_key, unsigned int priv_len)
{
    unsigned int r;    // Returns a pseudo-random integer between 0 and RAND_MAX.

    for (int i = 0; i < priv_len / sizeof(int); i++)
    {
        r = rand();
        // printf("r = 0x%08X\n", r);

        memcpy(priv_key + i*sizeof(int), &r, sizeof(int));
    }

    /*
    printf("priv_key = 0x");

    for (int i = 0; i < priv_len; i++)
    {
        printf("%02X", *(priv_key + i));
    }
    printf("\n");
    */
}

void print_progress_bar(int percentage, float ETA_time)
{
    const char *color;
    if (percentage < 33)
    {
        color = "\033[1;31m"; // Red
    }
    else if (percentage < 66)
    {
        color = "\033[1;33m"; // Yellow
    }
    else
    {
        color = "\033[1;32m"; // Green
    }

    int pos = (percentage * BAR_WIDTH) / 100;

    // Save cursor position
    printf("\033[s");

    // Move cursor to bottom
    // printf("\033[%dB", EXTRA_LINES + 1);

    // Clear the line
    // printf("\033[2K");

    // Print the progress bar
    printf("%s[", color); // Set color
    for (int i = 0; i < BAR_WIDTH; ++i)
    {
        if (i < pos)
        {
            printf("#");
        }
        else if (i == pos)
        {
            printf(">");
        }
        else
        {
            printf(" ");
        }
    }
    printf("] %d%% | ETA: %4.2f s\033[0m", percentage, ETA_time); // Reset color and print percentage

    // Restore cursor position
    printf("\033[u");

    // printf("] %d%% | ETA: %4.2f s\033[0m\r", percentage, ETA_time);

    fflush(stdout);
}

unsigned long long Wtime() {
    struct timeval time_val;
    gettimeofday(&time_val, NULL);
    return time_val.tv_sec * 1000000 + time_val.tv_usec;
}