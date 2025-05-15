#ifndef POLYVEC_MLDSA_H
#define POLYVEC_MLDSA_H

#include <stdint.h>
#include "params.h"
#include "poly.h"

/* Vectors of polynomials of length L */
typedef struct {
  poly_mldsa vec[L_44];
} polyvecl_44;
typedef struct {
   poly_mldsa vec[L_65];
} polyvecl_65;
typedef struct {
   poly_mldsa vec[L_87];
} polyvecl_87;

/* Vectors of polynomials of length K */
typedef struct {
   poly_mldsa vec[K_44];
} polyveck_44;
typedef struct {
   poly_mldsa vec[K_65];
} polyveck_65;
typedef struct {
   poly_mldsa vec[K_87];
} polyveck_87;

// void polyvecl_uniform_eta(polyvecl *v, const uint8_t seed[CRHBYTES], uint16_t nonce);
void polyvecl_uniform_eta_44(polyvecl_44* v, const uint8_t seed[CRHBYTES], uint16_t nonce);
void polyvecl_uniform_eta_65(polyvecl_65* v, const uint8_t seed[CRHBYTES], uint16_t nonce);
void polyvecl_uniform_eta_87(polyvecl_87* v, const uint8_t seed[CRHBYTES], uint16_t nonce);

// void polyvecl_uniform_gamma1(polyvecl *v, const uint8_t seed[CRHBYTES], uint16_t nonce);
void polyvecl_uniform_gamma1_44(polyvecl_44* v, const uint8_t seed[CRHBYTES], uint16_t nonce);
void polyvecl_uniform_gamma1_65(polyvecl_65* v, const uint8_t seed[CRHBYTES], uint16_t nonce);
void polyvecl_uniform_gamma1_87(polyvecl_87* v, const uint8_t seed[CRHBYTES], uint16_t nonce);

// void polyvecl_reduce(polyvecl *v);
void polyvecl_reduce_44(polyvecl_44* v);
void polyvecl_reduce_65(polyvecl_65* v);
void polyvecl_reduce_87(polyvecl_87* v);

// void polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v);
void polyvecl_add_44(polyvecl_44* w, const polyvecl_44* u, const polyvecl_44* v);
void polyvecl_add_65(polyvecl_65* w, const polyvecl_65* u, const polyvecl_65* v);
void polyvecl_add_87(polyvecl_87* w, const polyvecl_87* u, const polyvecl_87* v);

// void polyvecl_ntt(polyvecl *v);
void polyvecl_ntt_44(polyvecl_44* v);
void polyvecl_ntt_65(polyvecl_65* v);
void polyvecl_ntt_87(polyvecl_87* v);

// void polyvecl_invntt_tomont(polyvecl *v);
void polyvecl_invntt_tomont_44(polyvecl_44* v);
void polyvecl_invntt_tomont_65(polyvecl_65* v);
void polyvecl_invntt_tomont_87(polyvecl_87* v);

// void polyvecl_pointwise_poly_montgomery(polyvecl *r, constpoly_mldsa *a, const polyvecl *v);
void polyvecl_pointwise_poly_montgomery_44(polyvecl_44* r, const poly_mldsa* a, const polyvecl_44* v);
void polyvecl_pointwise_poly_montgomery_65(polyvecl_65* r, const poly_mldsa* a, const polyvecl_65* v);
void polyvecl_pointwise_poly_montgomery_87(polyvecl_87* r, const poly_mldsa* a, const polyvecl_87* v);

// void polyvecl_pointwise_acc_montgomery(poly *w, const polyvecl *u, const polyvecl *v);
void polyvecl_pointwise_acc_montgomery_44(poly_mldsa* w, const polyvecl_44* u, const polyvecl_44* v);
void polyvecl_pointwise_acc_montgomery_65(poly_mldsa* w, const polyvecl_65* u, const polyvecl_65* v);
void polyvecl_pointwise_acc_montgomery_87(poly_mldsa* w, const polyvecl_87* u, const polyvecl_87* v);

// int polyvecl_chknorm(const polyvecl *v, int32_t B);
int polyvecl_chknorm_44(const polyvecl_44* v, int32_t B);
int polyvecl_chknorm_65(const polyvecl_65* v, int32_t B);
int polyvecl_chknorm_87(const polyvecl_87* v, int32_t B);

// void polyveck_uniform_eta(polyveck *v, const uint8_t seed[CRHBYTES], uint16_t nonce);
void polyveck_uniform_eta_44(polyveck_44* v, const uint8_t seed[CRHBYTES], uint16_t nonce);
void polyveck_uniform_eta_65(polyveck_65* v, const uint8_t seed[CRHBYTES], uint16_t nonce);
void polyveck_uniform_eta_87(polyveck_87* v, const uint8_t seed[CRHBYTES], uint16_t nonce);

// void polyveck_reduce(polyveck *v);
void polyveck_reduce_44(polyveck_44* v);
void polyveck_reduce_65(polyveck_65* v);
void polyveck_reduce_87(polyveck_87* v);

// void polyveck_caddq(polyveck *v);
void polyveck_caddq_44(polyveck_44* v);
void polyveck_caddq_65(polyveck_65* v);
void polyveck_caddq_87(polyveck_87* v);

// void polyveck_add(polyveck *w, const polyveck *u, const polyveck *v);
void polyveck_add_44(polyveck_44* w, const polyveck_44* u, const polyveck_44* v);
void polyveck_add_65(polyveck_65* w, const polyveck_65* u, const polyveck_65* v);
void polyveck_add_87(polyveck_87* w, const polyveck_87* u, const polyveck_87* v);

// void polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v);
void polyveck_sub_44(polyveck_44* w, const polyveck_44* u, const polyveck_44* v);
void polyveck_sub_65(polyveck_65* w, const polyveck_65* u, const polyveck_65* v);
void polyveck_sub_87(polyveck_87* w, const polyveck_87* u, const polyveck_87* v);

// void polyveck_shiftl(polyveck *v);
void polyveck_shiftl_44(polyveck_44* v);
void polyveck_shiftl_65(polyveck_65* v);
void polyveck_shiftl_87(polyveck_87* v);

// void polyveck_ntt(polyveck *v);
void polyveck_ntt_44(polyveck_44* v);
void polyveck_ntt_65(polyveck_65* v);
void polyveck_ntt_87(polyveck_87* v);

// void polyveck_invntt_tomont(polyveck *v);
void polyveck_invntt_tomont_44(polyveck_44* v);
void polyveck_invntt_tomont_65(polyveck_65* v);
void polyveck_invntt_tomont_87(polyveck_87* v);

// void polyveck_pointwise_poly_montgomery(polyveck *r, constpoly_mldsa *a, const polyveck *v);
void polyveck_pointwise_poly_montgomery_44(polyveck_44* r, const poly_mldsa* a, const polyveck_44* v);
void polyveck_pointwise_poly_montgomery_65(polyveck_65* r, const poly_mldsa* a, const polyveck_65* v);
void polyveck_pointwise_poly_montgomery_87(polyveck_87* r, const poly_mldsa* a, const polyveck_87* v);

// int polyveck_chknorm(const polyveck *v, int32_t B);
int polyveck_chknorm_44(const polyveck_44* v, int32_t B);
int polyveck_chknorm_65(const polyveck_65* v, int32_t B);
int polyveck_chknorm_87(const polyveck_87* v, int32_t B);

// void polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v);
void polyveck_power2round_44(polyveck_44* v1, polyveck_44* v0, const polyveck_44* v);
void polyveck_power2round_65(polyveck_65* v1, polyveck_65* v0, const polyveck_65* v);
void polyveck_power2round_87(polyveck_87* v1, polyveck_87* v0, const polyveck_87* v);

// void polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v);
void polyveck_decompose_44(polyveck_44* v1, polyveck_44* v0, const polyveck_44* v);
void polyveck_decompose_65(polyveck_65* v1, polyveck_65* v0, const polyveck_65* v);
void polyveck_decompose_87(polyveck_87* v1, polyveck_87* v0, const polyveck_87* v);

// unsigned int polyveck_make_hint(polyveck *h, const polyveck *v0, const polyveck *v1);
unsigned int polyveck_make_hint_44(polyveck_44* h, const polyveck_44* v0, const polyveck_44* v1);
unsigned int polyveck_make_hint_65(polyveck_65* h, const polyveck_65* v0, const polyveck_65* v1);
unsigned int polyveck_make_hint_87(polyveck_87* h, const polyveck_87* v0, const polyveck_87* v1);

// void polyveck_use_hint(polyveck *w, const polyveck *v, const polyveck *h);
void polyveck_use_hint_44(polyveck_44* w, const polyveck_44* v, const polyveck_44* h);
void polyveck_use_hint_65(polyveck_65* w, const polyveck_65* v, const polyveck_65* h);
void polyveck_use_hint_87(polyveck_87* w, const polyveck_87* v, const polyveck_87* h);

// void polyveck_pack_w1(uint8_t r[K*POLYW1_PACKEDBYTES], const polyveck *w1);
void polyveck_pack_w1_44(uint8_t r[K_44 * POLYW1_PACKEDBYTES_44], const polyveck_44* w1);
void polyveck_pack_w1_65(uint8_t r[K_65 * POLYW1_PACKEDBYTES_65], const polyveck_65* w1);
void polyveck_pack_w1_87(uint8_t r[K_87 * POLYW1_PACKEDBYTES_87], const polyveck_87* w1);

// void polyvec_matrix_expand(polyvecl mat[K], const uint8_t rho[SEEDBYTES]);
void polyvec_matrix_expand_44(polyvecl_44 mat[K_44], const uint8_t rho[SEEDBYTES]);
void polyvec_matrix_expand_65(polyvecl_65 mat[K_65], const uint8_t rho[SEEDBYTES]);
void polyvec_matrix_expand_87(polyvecl_87 mat[K_87], const uint8_t rho[SEEDBYTES]);

// void polyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[K], const polyvecl *v);
void polyvec_matrix_pointwise_montgomery_44(polyveck_44* t, const polyvecl_44 mat[K_44], const polyvecl_44* v);
void polyvec_matrix_pointwise_montgomery_65(polyveck_65* t, const polyvecl_65 mat[K_65], const polyvecl_65* v);
void polyvec_matrix_pointwise_montgomery_87(polyveck_87* t, const polyvecl_87 mat[K_87], const polyvecl_87* v);

#endif
