#include <stdint.h>
#include "params.h"
#include "polyvec.h"
#include "poly.h"

/*************************************************
* Name:        expand_mat
*
* Description: Implementation of ExpandA. Generates matrix A with uniformly
*              random coefficients a_{i,j} by performing rejection
*              sampling on the output stream of SHAKE128(rho|j|i)
*
* Arguments:   - polyvecl mat[K]: output matrix
*              - const uint8_t rho[]: byte array containing seed rho
**************************************************/
void polyvec_matrix_expand_44(polyvecl_44 mat[K_44], const uint8_t rho[SEEDBYTES]) {
    unsigned int i, j;

    for (i = 0; i < K_44; ++i)
        for (j = 0; j < L_44; ++j)
            poly_uniform(&mat[i].vec[j], rho, (i << 8) + j);
}
void polyvec_matrix_expand_65(polyvecl_65 mat[K_65], const uint8_t rho[SEEDBYTES]) {
    unsigned int i, j;

    for (i = 0; i < K_65; ++i)
        for (j = 0; j < L_65; ++j)
            poly_uniform(&mat[i].vec[j], rho, (i << 8) + j);
}
void polyvec_matrix_expand_87(polyvecl_87 mat[K_87], const uint8_t rho[SEEDBYTES]) {
    unsigned int i, j;

    for (i = 0; i < K_87; ++i)
        for (j = 0; j < L_87; ++j)
            poly_uniform(&mat[i].vec[j], rho, (i << 8) + j);
}


void polyvec_matrix_pointwise_montgomery_44(polyveck_44* t, const polyvecl_44 mat[K_44], const polyvecl_44* v) {
    unsigned int i;

    for (i = 0; i < K_44; ++i)
        polyvecl_pointwise_acc_montgomery_44(&t->vec[i], &mat[i], v);
}
void polyvec_matrix_pointwise_montgomery_65(polyveck_65* t, const polyvecl_65 mat[K_65], const polyvecl_65* v) {
    unsigned int i;

    for (i = 0; i < K_65; ++i)
        polyvecl_pointwise_acc_montgomery_65(&t->vec[i], &mat[i], v);
}
void polyvec_matrix_pointwise_montgomery_87(polyveck_87* t, const polyvecl_87 mat[K_87], const polyvecl_87* v) {
    unsigned int i;

    for (i = 0; i < K_87; ++i)
        polyvecl_pointwise_acc_montgomery_87(&t->vec[i], &mat[i], v);
}

/**************************************************************/
/************ Vectors of polynomials of length L **************/
/**************************************************************/

void polyvecl_uniform_eta_44(polyvecl_44* v, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    unsigned int i;

    for (i = 0; i < L_44; ++i)
        poly_uniform_eta_44(&v->vec[i], seed, nonce++);
}
void polyvecl_uniform_eta_65(polyvecl_65* v, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    unsigned int i;

    for (i = 0; i < L_65; ++i)
        poly_uniform_eta_65(&v->vec[i], seed, nonce++);
}
void polyvecl_uniform_eta_87(polyvecl_87* v, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    unsigned int i;

    for (i = 0; i < L_87; ++i)
        poly_uniform_eta_87(&v->vec[i], seed, nonce++);
}


void polyvecl_uniform_gamma1_44(polyvecl_44* v, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    unsigned int i;

    for (i = 0; i < L_44; ++i)
        poly_uniform_gamma1_44(&v->vec[i], seed, L_44 * nonce + i);
}
void polyvecl_uniform_gamma1_65(polyvecl_65* v, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    unsigned int i;

    for (i = 0; i < L_65; ++i)
        poly_uniform_gamma1_65(&v->vec[i], seed, L_65 * nonce + i);
}
void polyvecl_uniform_gamma1_87(polyvecl_87* v, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    unsigned int i;

    for (i = 0; i < L_87; ++i)
        poly_uniform_gamma1_87(&v->vec[i], seed, L_87 * nonce + i);
}


void polyvecl_reduce_44(polyvecl_44* v) {
    unsigned int i;

    for (i = 0; i < L_44; ++i)
        poly_reduce_mldsa(&v->vec[i]);
}
void polyvecl_reduce_65(polyvecl_65* v) {
    unsigned int i;

    for (i = 0; i < L_65; ++i)
        poly_reduce_mldsa(&v->vec[i]);
}
void polyvecl_reduce_87(polyvecl_87* v) {
    unsigned int i;

    for (i = 0; i < L_87; ++i)
        poly_reduce_mldsa(&v->vec[i]);
}

/*************************************************
* Name:        polyvecl_add
*
* Description: Add vectors of polynomials of length L.
*              No modular reduction is performed.
*
* Arguments:   - polyvecl *w: pointer to output vector
*              - const polyvecl *u: pointer to first summand
*              - const polyvecl *v: pointer to second summand
**************************************************/

void polyvecl_add_44(polyvecl_44* w, const polyvecl_44* u, const polyvecl_44* v) {
    unsigned int i;

    for (i = 0; i < L_44; ++i)
        poly_add_mldsa(&w->vec[i], &u->vec[i], &v->vec[i]);
}
void polyvecl_add_65(polyvecl_65* w, const polyvecl_65* u, const polyvecl_65* v) {
    unsigned int i;

    for (i = 0; i < L_65; ++i)
        poly_add_mldsa(&w->vec[i], &u->vec[i], &v->vec[i]);
}
void polyvecl_add_87(polyvecl_87* w, const polyvecl_87* u, const polyvecl_87* v) {
    unsigned int i;

    for (i = 0; i < L_87; ++i)
        poly_add_mldsa(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        polyvecl_ntt
*
* Description: Forward NTT of all polynomials in vector of length L. Output
*              coefficients can be up to 16*Q larger than input coefficients.
*
* Arguments:   - polyvecl *v: pointer to input/output vector
**************************************************/
void polyvecl_ntt_44(polyvecl_44* v) {
    unsigned int i;

    for (i = 0; i < L_44; ++i)
        poly_ntt_mldsa(&v->vec[i]);
}
void polyvecl_ntt_65(polyvecl_65* v) {
    unsigned int i;

    for (i = 0; i < L_65; ++i)
        poly_ntt_mldsa(&v->vec[i]);
}
void polyvecl_ntt_87(polyvecl_87* v) {
    unsigned int i;

    for (i = 0; i < L_87; ++i)
        poly_ntt_mldsa(&v->vec[i]);
}


void polyvecl_invntt_tomont_44(polyvecl_44* v) {
    unsigned int i;

    for (i = 0; i < L_44; ++i)
        poly_invntt_tomont_mldsa(&v->vec[i]);
}
void polyvecl_invntt_tomont_65(polyvecl_65* v) {
    unsigned int i;

    for (i = 0; i < L_65; ++i)
        poly_invntt_tomont_mldsa(&v->vec[i]);
}
void polyvecl_invntt_tomont_87(polyvecl_87* v) {
    unsigned int i;

    for (i = 0; i < L_87; ++i)
        poly_invntt_tomont_mldsa(&v->vec[i]);
}


void polyvecl_pointwise_poly_montgomery_44(polyvecl_44* r, const poly_mldsa* a, const polyvecl_44* v) {
    unsigned int i;

    for (i = 0; i < L_44; ++i)
        poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}
void polyvecl_pointwise_poly_montgomery_65(polyvecl_65* r, const poly_mldsa* a, const polyvecl_65* v) {
    unsigned int i;

    for (i = 0; i < L_65; ++i)
        poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}
void polyvecl_pointwise_poly_montgomery_87(polyvecl_87* r, const poly_mldsa* a, const polyvecl_87* v) {
    unsigned int i;

    for (i = 0; i < L_87; ++i)
        poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}

/*************************************************
* Name:        polyvecl_pointwise_acc_montgomery
*
* Description: Pointwise multiply vectors of polynomials of length L, multiply
*              resulting vector by 2^{-32} and add (accumulate) polynomials
*              in it. Input/output vectors are in NTT domain representation.
*
* Arguments:   - poly_mldsa *w: output polynomial
*              - const polyvecl *u: pointer to first input vector
*              - const polyvecl *v: pointer to second input vector
**************************************************/

void polyvecl_pointwise_acc_montgomery_44(poly_mldsa* w,
    const polyvecl_44* u,
    const polyvecl_44* v)
{
    unsigned int i;
    poly_mldsa t;

    poly_pointwise_montgomery(w, &u->vec[0], &v->vec[0]);
    for (i = 1; i < L_44; ++i) {
        poly_pointwise_montgomery(&t, &u->vec[i], &v->vec[i]);
        poly_add_mldsa(w, w, &t);
    }
}

void polyvecl_pointwise_acc_montgomery_65(poly_mldsa* w,
    const polyvecl_65* u,
    const polyvecl_65* v)
{
    unsigned int i;
    poly_mldsa t;

    poly_pointwise_montgomery(w, &u->vec[0], &v->vec[0]);
    for (i = 1; i < L_65; ++i) {
        poly_pointwise_montgomery(&t, &u->vec[i], &v->vec[i]);
        poly_add_mldsa(w, w, &t);
    }
}

void polyvecl_pointwise_acc_montgomery_87(poly_mldsa* w,
    const polyvecl_87* u,
    const polyvecl_87* v)
{
    unsigned int i;
    poly_mldsa t;

    poly_pointwise_montgomery(w, &u->vec[0], &v->vec[0]);
    for (i = 1; i < L_87; ++i) {
        poly_pointwise_montgomery(&t, &u->vec[i], &v->vec[i]);
        poly_add_mldsa(w, w, &t);
    }
}

/*************************************************
* Name:        polyvecl_chknorm
*
* Description: Check infinity norm of polynomials in vector of length L.
*              Assumes input polyvecl to be reduced by polyvecl_reduce().
*
* Arguments:   - const polyvecl *v: pointer to vector
*              - int32_t B: norm bound
*
* Returns 0 if norm of all polynomials is strictly smaller than B <= (Q-1)/8
* and 1 otherwise.
**************************************************/

int polyvecl_chknorm_44(const polyvecl_44* v, int32_t bound) {
    unsigned int i;

    for (i = 0; i < L_44; ++i)
        if (poly_chknorm(&v->vec[i], bound))
            return 1;

    return 0;
}
int polyvecl_chknorm_65(const polyvecl_65* v, int32_t bound) {
    unsigned int i;

    for (i = 0; i < L_65; ++i)
        if (poly_chknorm(&v->vec[i], bound))
            return 1;

    return 0;
}
int polyvecl_chknorm_87(const polyvecl_87* v, int32_t bound) {
    unsigned int i;

    for (i = 0; i < L_87; ++i)
        if (poly_chknorm(&v->vec[i], bound))
            return 1;

    return 0;
}


/**************************************************************/
/************ Vectors of polynomials of length K **************/
/**************************************************************/

void polyveck_uniform_eta_44(polyveck_44* v, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    unsigned int i;

    for (i = 0; i < K_44; ++i)
        poly_uniform_eta_44(&v->vec[i], seed, nonce++);
}
void polyveck_uniform_eta_65(polyveck_65* v, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    unsigned int i;

    for (i = 0; i < K_65; ++i)
        poly_uniform_eta_65(&v->vec[i], seed, nonce++);
}
void polyveck_uniform_eta_87(polyveck_87* v, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    unsigned int i;

    for (i = 0; i < K_87; ++i)
        poly_uniform_eta_87(&v->vec[i], seed, nonce++);
}

/*************************************************
* Name:        polyveck_reduce
*
* Description: Reduce coefficients of polynomials in vector of length K
*              to representatives in [-6283008,6283008].
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/

void polyveck_reduce_44(polyveck_44* v) {
    unsigned int i;

    for (i = 0; i < K_44; ++i)
        poly_reduce_mldsa(&v->vec[i]);
}
void polyveck_reduce_65(polyveck_65* v) {
    unsigned int i;

    for (i = 0; i < K_65; ++i)
        poly_reduce_mldsa(&v->vec[i]);
}
void polyveck_reduce_87(polyveck_87* v) {
    unsigned int i;

    for (i = 0; i < K_87; ++i)
        poly_reduce_mldsa(&v->vec[i]);
}

/*************************************************
* Name:        polyveck_caddq
*
* Description: For all coefficients of polynomials in vector of length K
*              add Q if coefficient is negative.
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/
void polyveck_caddq_44(polyveck_44* v) {
    unsigned int i;

    for (i = 0; i < K_44; ++i)
        poly_caddq(&v->vec[i]);
}
void polyveck_caddq_65(polyveck_65* v) {
    unsigned int i;

    for (i = 0; i < K_65; ++i)
        poly_caddq(&v->vec[i]);
}
void polyveck_caddq_87(polyveck_87* v) {
    unsigned int i;

    for (i = 0; i < K_87; ++i)
        poly_caddq(&v->vec[i]);
}


/*************************************************
* Name:        polyveck_add
*
* Description: Add vectors of polynomials of length K.
*              No modular reduction is performed.
*
* Arguments:   - polyveck *w: pointer to output vector
*              - const polyveck *u: pointer to first summand
*              - const polyveck *v: pointer to second summand
**************************************************/

void polyveck_add_44(polyveck_44* w, const polyveck_44* u, const polyveck_44* v) {
    unsigned int i;

    for (i = 0; i < K_44; ++i)
        poly_add_mldsa(&w->vec[i], &u->vec[i], &v->vec[i]);
}
void polyveck_add_65(polyveck_65* w, const polyveck_65* u, const polyveck_65* v) {
    unsigned int i;

    for (i = 0; i < K_65; ++i)
        poly_add_mldsa(&w->vec[i], &u->vec[i], &v->vec[i]);
}
void polyveck_add_87(polyveck_87* w, const polyveck_87* u, const polyveck_87* v) {
    unsigned int i;

    for (i = 0; i < K_87; ++i)
        poly_add_mldsa(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        polyveck_sub
*
* Description: Subtract vectors of polynomials of length K.
*              No modular reduction is performed.
*
* Arguments:   - polyveck *w: pointer to output vector
*              - const polyveck *u: pointer to first input vector
*              - const polyveck *v: pointer to second input vector to be
*                                   subtracted from first input vector
**************************************************/

void polyveck_sub_44(polyveck_44* w, const polyveck_44* u, const polyveck_44* v) {
    unsigned int i;

    for (i = 0; i < K_44; ++i)
        poly_sub_mldsa(&w->vec[i], &u->vec[i], &v->vec[i]);
}
void polyveck_sub_65(polyveck_65* w, const polyveck_65* u, const polyveck_65* v) {
    unsigned int i;

    for (i = 0; i < K_65; ++i)
        poly_sub_mldsa(&w->vec[i], &u->vec[i], &v->vec[i]);
}
void polyveck_sub_87(polyveck_87* w, const polyveck_87* u, const polyveck_87* v) {
    unsigned int i;

    for (i = 0; i < K_87; ++i)
        poly_sub_mldsa(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        polyveck_shiftl
*
* Description: Multiply vector of polynomials of Length K by 2^D without modular
*              reduction. Assumes input coefficients to be less than 2^{31-D}.
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/

void polyveck_shiftl_44(polyveck_44* v) {
    unsigned int i;

    for (i = 0; i < K_44; ++i)
        poly_shiftl(&v->vec[i]);
}
void polyveck_shiftl_65(polyveck_65* v) {
    unsigned int i;

    for (i = 0; i < K_65; ++i)
        poly_shiftl(&v->vec[i]);
}
void polyveck_shiftl_87(polyveck_87* v) {
    unsigned int i;

    for (i = 0; i < K_87; ++i)
        poly_shiftl(&v->vec[i]);
}
/*************************************************
* Name:        polyveck_ntt
*
* Description: Forward NTT of all polynomials in vector of length K. Output
*              coefficients can be up to 16*Q larger than input coefficients.
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/

void polyveck_ntt_44(polyveck_44* v) {
    unsigned int i;

    for (i = 0; i < K_44; ++i)
        poly_ntt_mldsa(&v->vec[i]);
}
void polyveck_ntt_65(polyveck_65* v) {
    unsigned int i;

    for (i = 0; i < K_65; ++i)
        poly_ntt_mldsa(&v->vec[i]);
}
void polyveck_ntt_87(polyveck_87* v) {
    unsigned int i;

    for (i = 0; i < K_87; ++i)
        poly_ntt_mldsa(&v->vec[i]);
}

/*************************************************
* Name:        polyveck_invntt_tomont
*
* Description: Inverse NTT and multiplication by 2^{32} of polynomials
*              in vector of length K. Input coefficients need to be less
*              than 2*Q.
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/
void polyveck_invntt_tomont_44(polyveck_44*v) {
  unsigned int i;

  for(i = 0; i < K_44; ++i)
    poly_invntt_tomont_mldsa(&v->vec[i]);
}
void polyveck_invntt_tomont_65(polyveck_65* v) {
    unsigned int i;

    for (i = 0; i < K_65; ++i)
        poly_invntt_tomont_mldsa(&v->vec[i]);
}
void polyveck_invntt_tomont_87(polyveck_87* v) {
    unsigned int i;

    for (i = 0; i < K_87; ++i)
        poly_invntt_tomont_mldsa(&v->vec[i]);
}


void polyveck_pointwise_poly_montgomery_44(polyveck_44*r, const poly_mldsa *a, const polyveck_44*v) {
  unsigned int i;

  for(i = 0; i < K_44; ++i)
    poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}
void polyveck_pointwise_poly_montgomery_65(polyveck_65* r, const poly_mldsa* a, const polyveck_65* v) {
    unsigned int i;

    for (i = 0; i < K_65; ++i)
        poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}
void polyveck_pointwise_poly_montgomery_87(polyveck_87* r, const poly_mldsa* a, const polyveck_87* v) {
    unsigned int i;

    for (i = 0; i < K_87; ++i)
        poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}

/*************************************************
* Name:        polyveck_chknorm
*
* Description: Check infinity norm of polynomials in vector of length K.
*              Assumes input polyveck to be reduced by polyveck_reduce().
*
* Arguments:   - const polyveck *v: pointer to vector
*              - int32_t B: norm bound
*
* Returns 0 if norm of all polynomials are strictly smaller than B <= (Q-1)/8
* and 1 otherwise.
**************************************************/
int polyveck_chknorm_44(const polyveck_44 *v, int32_t bound) {
  unsigned int i;

  for(i = 0; i < K_44; ++i)
    if(poly_chknorm(&v->vec[i], bound))
      return 1;

  return 0;
}
int polyveck_chknorm_65(const polyveck_65* v, int32_t bound) {
    unsigned int i;

    for (i = 0; i < K_65; ++i)
        if (poly_chknorm(&v->vec[i], bound))
            return 1;

    return 0;
}
int polyveck_chknorm_87(const polyveck_87* v, int32_t bound) {
    unsigned int i;

    for (i = 0; i < K_87; ++i)
        if (poly_chknorm(&v->vec[i], bound))
            return 1;

    return 0;
}

/*************************************************
* Name:        polyveck_power2round
*
* Description: For all coefficients a of polynomials in vector of length K,
*              compute a0, a1 such that a mod^+ Q = a1*2^D + a0
*              with -2^{D-1} < a0 <= 2^{D-1}. Assumes coefficients to be
*              standard representatives.
*
* Arguments:   - polyveck *v1: pointer to output vector of polynomials with
*                              coefficients a1
*              - polyveck *v0: pointer to output vector of polynomials with
*                              coefficients a0
*              - const polyveck *v: pointer to input vector
**************************************************/
void polyveck_power2round_44(polyveck_44*v1, polyveck_44*v0, const polyveck_44*v) {
  unsigned int i;

  for(i = 0; i < K_44; ++i)
    poly_power2round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}
void polyveck_power2round_65(polyveck_65* v1, polyveck_65* v0, const polyveck_65* v) {
    unsigned int i;

    for (i = 0; i < K_65; ++i)
        poly_power2round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}
void polyveck_power2round_87(polyveck_87* v1, polyveck_87* v0, const polyveck_87* v) {
    unsigned int i;

    for (i = 0; i < K_87; ++i)
        poly_power2round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        polyveck_decompose
*
* Description: For all coefficients a of polynomials in vector of length K,
*              compute high and low bits a0, a1 such a mod^+ Q = a1*ALPHA + a0
*              with -ALPHA/2 < a0 <= ALPHA/2 except a1 = (Q-1)/ALPHA where we
*              set a1 = 0 and -ALPHA/2 <= a0 = a mod Q - Q < 0.
*              Assumes coefficients to be standard representatives.
*
* Arguments:   - polyveck *v1: pointer to output vector of polynomials with
*                              coefficients a1
*              - polyveck *v0: pointer to output vector of polynomials with
*                              coefficients a0
*              - const polyveck *v: pointer to input vector
**************************************************/
void polyveck_decompose_44(polyveck_44 *v1, polyveck_44 *v0, const polyveck_44 *v) {
  unsigned int i;

      for(i = 0; i < K_44; ++i)
        poly_decompose_44(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}
void polyveck_decompose_65(polyveck_65* v1, polyveck_65* v0, const polyveck_65* v) {
    unsigned int i;

    for (i = 0; i < K_65; ++i)
        poly_decompose_65(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}
void polyveck_decompose_87(polyveck_87* v1, polyveck_87* v0, const polyveck_87* v) {
    unsigned int i;

    for (i = 0; i < K_87; ++i)
        poly_decompose_87(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        polyveck_make_hint
*
* Description: Compute hint vector.
*
* Arguments:   - polyveck *h: pointer to output vector
*              - const polyveck *v0: pointer to low part of input vector
*              - const polyveck *v1: pointer to high part of input vector
*
* Returns number of 1 bits.
**************************************************/
unsigned int polyveck_make_hint_44(polyveck_44 *h,
                                const polyveck_44 *v0,
                                const polyveck_44 *v1)
{
  unsigned int i, s = 0;

  for(i = 0; i < K_44; ++i)
    s += poly_make_hint_44(&h->vec[i], &v0->vec[i], &v1->vec[i]);

  return s;
}
unsigned int polyveck_make_hint_65(polyveck_65* h,
    const polyveck_65* v0,
    const polyveck_65* v1)
{
    unsigned int i, s = 0;

    for (i = 0; i < K_65; ++i)
        s += poly_make_hint_65(&h->vec[i], &v0->vec[i], &v1->vec[i]);

    return s;
}
unsigned int polyveck_make_hint_87(polyveck_87* h,
    const polyveck_87* v0,
    const polyveck_87* v1)
{
    unsigned int i, s = 0;

    for (i = 0; i < K_87; ++i)
        s += poly_make_hint_87(&h->vec[i], &v0->vec[i], &v1->vec[i]);

    return s;
}

/*************************************************
* Name:        polyveck_use_hint
*
* Description: Use hint vector to correct the high bits of input vector.
*
* Arguments:   - polyveck *w: pointer to output vector of polynomials with
*                             corrected high bits
*              - const polyveck *u: pointer to input vector
*              - const polyveck *h: pointer to input hint vector
**************************************************/
void polyveck_use_hint_44(polyveck_44 *w, const polyveck_44 *u, const polyveck_44 *h) {
  unsigned int i;

  for(i = 0; i < K_44; ++i)
    poly_use_hint_44(&w->vec[i], &u->vec[i], &h->vec[i]);
}
void polyveck_use_hint_65(polyveck_65* w, const polyveck_65* u, const polyveck_65* h) {
    unsigned int i;

    for (i = 0; i < K_65; ++i)
        poly_use_hint_65(&w->vec[i], &u->vec[i], &h->vec[i]);
}
void polyveck_use_hint_87(polyveck_87* w, const polyveck_87* u, const polyveck_87* h) {
    unsigned int i;

    for (i = 0; i < K_87; ++i)
        poly_use_hint_87(&w->vec[i], &u->vec[i], &h->vec[i]);
}

void polyveck_pack_w1_44(uint8_t r[K_44 * POLYW1_PACKEDBYTES_44], const polyveck_44 *w1) {
  unsigned int i;

  for(i = 0; i < K_44; ++i)
    polyw1_pack_44(&r[i*POLYW1_PACKEDBYTES_44], &w1->vec[i]);
}
void polyveck_pack_w1_65(uint8_t r[K_65 * POLYW1_PACKEDBYTES_65], const polyveck_65 *w1) {
    unsigned int i;

    for (i = 0; i < K_65; ++i)
        polyw1_pack_65(&r[i * POLYW1_PACKEDBYTES_65], &w1->vec[i]);
}

void polyveck_pack_w1_87(uint8_t r[K_87 * POLYW1_PACKEDBYTES_87], const polyveck_87 *w1) {
    unsigned int i;

    for (i = 0; i < K_87; ++i)
        polyw1_pack_87(&r[i * POLYW1_PACKEDBYTES_87], &w1->vec[i]);
}

