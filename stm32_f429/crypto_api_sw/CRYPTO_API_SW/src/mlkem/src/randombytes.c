#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "randombytes.h"


void randombytes_mlkem(uint8_t* out, size_t outlen) {

    srand(HAL_GetTick());

    for (int i = 0; i < outlen; i++) {
        out[i] = (uint8_t)rand();
    }
}
