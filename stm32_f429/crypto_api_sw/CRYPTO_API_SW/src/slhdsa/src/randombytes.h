#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#include <stddef.h>
#include <stdint.h>

void randombytes_slhdsa(uint8_t *out, size_t outlen);

#endif
