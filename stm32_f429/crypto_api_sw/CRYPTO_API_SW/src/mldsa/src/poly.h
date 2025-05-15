#ifndef POLY_MLDSA_H
#define POLY_MLDSA_H

#include <stdint.h>
#include "params.h"

typedef struct {
  int32_t coeffs[N_MLDSA];
} poly_mldsa;

void poly_reduce_mldsa(poly_mldsa *a);
void poly_caddq(poly_mldsa *a);

void poly_add_mldsa(poly_mldsa *c, const poly_mldsa *a, const poly_mldsa *b);
void poly_sub_mldsa(poly_mldsa *c, const poly_mldsa *a, const poly_mldsa *b);
void poly_shiftl(poly_mldsa *a);

void poly_ntt_mldsa(poly_mldsa *a);
void poly_invntt_tomont_mldsa(poly_mldsa *a);
void poly_pointwise_montgomery(poly_mldsa *c, const poly_mldsa *a, const poly_mldsa *b);

void poly_power2round(poly_mldsa *a1, poly_mldsa *a0, const poly_mldsa *a);

void poly_decompose_44(poly_mldsa *a1, poly_mldsa *a0, const poly_mldsa *a);
void poly_decompose_65(poly_mldsa* a1, poly_mldsa* a0, const poly_mldsa* a);
void poly_decompose_87(poly_mldsa* a1, poly_mldsa* a0, const poly_mldsa* a);

unsigned int poly_make_hint_44(poly_mldsa *h, const poly_mldsa *a0, const poly_mldsa *a1);
unsigned int poly_make_hint_65(poly_mldsa* h, const poly_mldsa* a0, const poly_mldsa* a1);
unsigned int poly_make_hint_87(poly_mldsa* h, const poly_mldsa* a0, const poly_mldsa* a1);

void poly_use_hint_44(poly_mldsa *b, const poly_mldsa *a, const poly_mldsa *h);
void poly_use_hint_65(poly_mldsa* b, const poly_mldsa* a, const poly_mldsa* h);
void poly_use_hint_87(poly_mldsa* b, const poly_mldsa* a, const poly_mldsa* h);

int poly_chknorm(const poly_mldsa *a, int32_t B);
void poly_uniform(poly_mldsa *a, const uint8_t seed[SEEDBYTES], uint16_t nonce);

void poly_uniform_eta_44(poly_mldsa *a, const uint8_t seed[CRHBYTES], uint16_t nonce);
void poly_uniform_eta_65(poly_mldsa* a, const uint8_t seed[CRHBYTES], uint16_t nonce);
void poly_uniform_eta_87(poly_mldsa* a, const uint8_t seed[CRHBYTES], uint16_t nonce);

void poly_uniform_gamma1_44(poly_mldsa *a, const uint8_t seed[CRHBYTES], uint16_t nonce);
void poly_uniform_gamma1_65(poly_mldsa* a, const uint8_t seed[CRHBYTES], uint16_t nonce);
void poly_uniform_gamma1_87(poly_mldsa* a, const uint8_t seed[CRHBYTES], uint16_t nonce);

void poly_challenge_44(poly_mldsa *c, const uint8_t seed[CTILDEBYTES_44]);
void poly_challenge_65(poly_mldsa* c, const uint8_t seed[CTILDEBYTES_65]);
void poly_challenge_87(poly_mldsa* c, const uint8_t seed[CTILDEBYTES_87]);

void polyeta_pack_44(uint8_t *r, const poly_mldsa *a);
void polyeta_pack_65(uint8_t* r, const poly_mldsa* a);
void polyeta_pack_87(uint8_t* r, const poly_mldsa* a);

void polyeta_unpack_44(poly_mldsa *r, const uint8_t *a);
void polyeta_unpack_65(poly_mldsa* r, const uint8_t* a);
void polyeta_unpack_87(poly_mldsa* r, const uint8_t* a);

void polyt1_pack(uint8_t *r, const poly_mldsa *a);
void polyt1_unpack(poly_mldsa *r, const uint8_t *a);

void polyt0_pack(uint8_t *r, const poly_mldsa *a);
void polyt0_unpack(poly_mldsa *r, const uint8_t *a);

void polyz_pack_44(uint8_t *r, const poly_mldsa *a);
void polyz_pack_65(uint8_t* r, const poly_mldsa* a);
void polyz_pack_87(uint8_t* r, const poly_mldsa* a);

void polyz_unpack_44(poly_mldsa *r, const uint8_t *a);
void polyz_unpack_65(poly_mldsa* r, const uint8_t* a);
void polyz_unpack_87(poly_mldsa* r, const uint8_t* a);

void polyw1_pack_44(uint8_t *r, const poly_mldsa *a);
void polyw1_pack_65(uint8_t* r, const poly_mldsa* a);
void polyw1_pack_87(uint8_t* r, const poly_mldsa* a);

#endif
