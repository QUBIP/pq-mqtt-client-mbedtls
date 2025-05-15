#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "params.h"

/*
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*coeffs[2] + ... + X^{n-1}*coeffs[n-1]
 */
typedef struct{
  int16_t coeffs[KYBER_N];
} poly;

// void poly_compress(uint8_t r[KYBER_POLYCOMPRESSEDBYTES], const poly *a);

void poly_compress_512(uint8_t r[KYBER_POLYCOMPRESSEDBYTES_512], const poly* a);
void poly_compress_768(uint8_t r[KYBER_POLYCOMPRESSEDBYTES_768], const poly* a);
void poly_compress_1024(uint8_t r[KYBER_POLYCOMPRESSEDBYTES_1024], const poly* a);

// void poly_decompress(poly *r, const uint8_t a[KYBER_POLYCOMPRESSEDBYTES]);

void poly_decompress_512(poly* r, const uint8_t a[KYBER_POLYCOMPRESSEDBYTES_512]);
void poly_decompress_768(poly* r, const uint8_t a[KYBER_POLYCOMPRESSEDBYTES_768]);
void poly_decompress_1024(poly* r, const uint8_t a[KYBER_POLYCOMPRESSEDBYTES_1024]);

void poly_tobytes(uint8_t r[KYBER_POLYBYTES], const poly *a);
void poly_frombytes(poly *r, const uint8_t a[KYBER_POLYBYTES]);

void poly_frommsg(poly *r, const uint8_t msg[KYBER_INDCPA_MSGBYTES]);
void poly_tomsg(uint8_t msg[KYBER_INDCPA_MSGBYTES], const poly *r);

void poly_getnoise_eta1_512(poly* r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce);
void poly_getnoise_eta1_768(poly* r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce);
void poly_getnoise_eta1_1024(poly* r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce);

void poly_getnoise_eta2(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce);

void poly_ntt(poly *r);
void poly_invntt_tomont(poly *r);
void poly_basemul_montgomery(poly *r, const poly *a, const poly *b);
void poly_tomont(poly *r);

void poly_reduce(poly *r);

void poly_add(poly *r, const poly *a, const poly *b);
void poly_sub(poly *r, const poly *a, const poly *b);

#endif
