#ifndef CBD_H
#define CBD_H

#include <stdint.h>
#include "params.h"
#include "poly.h"

// void poly_cbd_eta1(poly *r, const uint8_t buf[KYBER_ETA1*KYBER_N/4]);

void poly_cbd_eta1_512(poly* r, const uint8_t buf[KYBER_ETA1_512 * KYBER_N / 4]);
void poly_cbd_eta1_768(poly* r, const uint8_t buf[KYBER_ETA1_768 * KYBER_N / 4]);
void poly_cbd_eta1_1024(poly* r, const uint8_t buf[KYBER_ETA1_1024 * KYBER_N / 4]);

void poly_cbd_eta2(poly *r, const uint8_t buf[KYBER_ETA2*KYBER_N/4]);

#endif
