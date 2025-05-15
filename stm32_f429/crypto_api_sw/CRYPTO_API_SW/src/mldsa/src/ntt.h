#ifndef NTT_MLDSA_H
#define NTT_MLDSA_H

#include <stdint.h>
#include "params.h"

void ntt_mldsa(int32_t a[N_MLDSA]);

void invntt_tomont_mldsa(int32_t a[N_MLDSA]);

#endif
