#ifndef ROUNDING_H
#define ROUNDING_H

#include <stdint.h>
#include "params.h"

int32_t power2round(int32_t *a0, int32_t a);

int32_t decompose_44(int32_t *a0, int32_t a);
int32_t decompose_65(int32_t* a0, int32_t a);
int32_t decompose_87(int32_t* a0, int32_t a);

unsigned int make_hint_44(int32_t a0, int32_t a1);
unsigned int make_hint_65(int32_t a0, int32_t a1);
unsigned int make_hint_87(int32_t a0, int32_t a1);

int32_t use_hint_44(int32_t a, unsigned int hint);
int32_t use_hint_65(int32_t a, unsigned int hint);
int32_t use_hint_87(int32_t a, unsigned int hint);

#endif
