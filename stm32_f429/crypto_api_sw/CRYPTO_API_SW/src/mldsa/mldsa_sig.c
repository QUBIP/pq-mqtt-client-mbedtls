/**
  * @file mldsa_sig.c
  * @brief ML-DSA Signature code
  *
  * @section License
  *
  * MIT License
  *
  * Copyright (c) 2024 Eros Camacho
  *
  * Permission is hereby granted, free of charge, to any person obtaining a copy
  * of this software and associated documentation files (the "Software"), to deal
  * in the Software without restriction, including without limitation the rights
  * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  * copies of the Software, and to permit persons to whom the Software is
  * furnished to do so, subject to the following conditions:
  *
  * The above copyright notice and this permission notice shall be included in all
  * copies or substantial portions of the Software.
  *
  * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  * SOFTWARE.
  *
  *
  *
  * @author Eros Camacho-Ruiz (camacho@imse-cnm.csic.es)
  * @version 5.0
  **/

#include "mldsa.h"

int crypto_sign_signature_44(uint8_t* sig,
    size_t* siglen,
    const uint8_t* m,
    size_t mlen,
    const uint8_t* pre,
    size_t prelen,
    const uint8_t rnd[RNDBYTES],
    const uint8_t* sk)
{
    unsigned int n;
    uint8_t seedbuf[2 * SEEDBYTES + TRBYTES + 2 * CRHBYTES];
    uint8_t* rho, * tr, * key, * mu, * rhoprime;
    uint16_t nonce = 0;
    polyvecl_44 mat[K_44], s1, y, z;
    polyveck_44 t0, s2, w1, w0, h;
    poly_mldsa cp;
    keccak_state state;

    rho = seedbuf;
    tr = rho + SEEDBYTES;
    key = tr + TRBYTES;
    mu = key + SEEDBYTES;
    rhoprime = mu + CRHBYTES;
    unpack_sk_44(rho, tr, key, &t0, &s1, &s2, sk);

    /* Compute mu = CRH(tr, pre, msg) */
    shake256_init_mldsa(&state);
    shake256_absorb_mldsa(&state, tr, TRBYTES);
    shake256_absorb_mldsa(&state, pre, prelen);
    shake256_absorb_mldsa(&state, m, mlen);
    shake256_finalize_mldsa(&state);
    shake256_squeeze_mldsa(mu, CRHBYTES, &state);

    /* Compute rhoprime = CRH(key, rnd, mu) */
    shake256_init_mldsa(&state);
    shake256_absorb_mldsa(&state, key, SEEDBYTES);
    shake256_absorb_mldsa(&state, rnd, RNDBYTES);
    shake256_absorb_mldsa(&state, mu, CRHBYTES);
    shake256_finalize_mldsa(&state);
    shake256_squeeze_mldsa(rhoprime, CRHBYTES, &state);

    /* Expand matrix and transform vectors */
    polyvec_matrix_expand_44(mat, rho);
    polyvecl_ntt_44(&s1);
    polyveck_ntt_44(&s2);
    polyveck_ntt_44(&t0);

rej:
    /* Sample intermediate vector y */
    polyvecl_uniform_gamma1_44(&y, rhoprime, nonce++);

    /* Matrix-vector multiplication */
    z = y;
    polyvecl_ntt_44(&z);
    polyvec_matrix_pointwise_montgomery_44(&w1, mat, &z);
    polyveck_reduce_44(&w1);
    polyveck_invntt_tomont_44(&w1);

    /* Decompose w and call the random oracle */
    polyveck_caddq_44(&w1);
    polyveck_decompose_44(&w1, &w0, &w1);
    polyveck_pack_w1_44(sig, &w1);

    shake256_init_mldsa(&state);
    shake256_absorb_mldsa(&state, mu, CRHBYTES);
    shake256_absorb_mldsa(&state, sig, K_44 * POLYW1_PACKEDBYTES_44);
    shake256_finalize_mldsa(&state);
    shake256_squeeze_mldsa(sig, CTILDEBYTES_44, &state);
    poly_challenge_44(&cp, sig);
    poly_ntt_mldsa(&cp);

    /* Compute z, reject if it reveals secret */
    polyvecl_pointwise_poly_montgomery_44(&z, &cp, &s1);
    polyvecl_invntt_tomont_44(&z);
    polyvecl_add_44(&z, &z, &y);
    polyvecl_reduce_44(&z);
    if (polyvecl_chknorm_44(&z, GAMMA1_44 - BETA_44))
        goto rej;

    /* Check that subtracting cs2 does not change high bits of w and low bits
     * do not reveal secret information */
    polyveck_pointwise_poly_montgomery_44(&h, &cp, &s2);
    polyveck_invntt_tomont_44(&h);
    polyveck_sub_44(&w0, &w0, &h);
    polyveck_reduce_44(&w0);
    if (polyveck_chknorm_44(&w0, GAMMA2_44 - BETA_44))
        goto rej;

    /* Compute hints for w1 */
    polyveck_pointwise_poly_montgomery_44(&h, &cp, &t0);
    polyveck_invntt_tomont_44(&h);
    polyveck_reduce_44(&h);
    if (polyveck_chknorm_44(&h, GAMMA2_44))
        goto rej;

    polyveck_add_44(&w0, &w0, &h);
    n = polyveck_make_hint_44(&h, &w0, &w1);
    if (n > OMEGA_44)
        goto rej;

    /* Write signature */
    pack_sig_44(sig, sig, &z, &h);
    *siglen = CRYPTO_BYTES_44;
    return 0;
}

int crypto_sign_signature_65(uint8_t* sig,
    size_t* siglen,
    const uint8_t* m,
    size_t mlen,
    const uint8_t* pre,
    size_t prelen,
    const uint8_t rnd[RNDBYTES],
    const uint8_t* sk)
{
    unsigned int n;
    uint8_t seedbuf[2 * SEEDBYTES + TRBYTES + 2 * CRHBYTES];
    uint8_t* rho, * tr, * key, * mu, * rhoprime;
    uint16_t nonce = 0;
    polyvecl_65 mat[K_65], s1, y, z;
    polyveck_65 t0, s2, w1, w0, h;
    poly_mldsa cp;
    keccak_state state;

    rho = seedbuf;
    tr = rho + SEEDBYTES;
    key = tr + TRBYTES;
    mu = key + SEEDBYTES;
    rhoprime = mu + CRHBYTES;
    unpack_sk_65(rho, tr, key, &t0, &s1, &s2, sk);

    /* Compute mu = CRH(tr, pre, msg) */
    shake256_init_mldsa(&state);
    shake256_absorb_mldsa(&state, tr, TRBYTES);
    shake256_absorb_mldsa(&state, pre, prelen);
    shake256_absorb_mldsa(&state, m, mlen);
    shake256_finalize_mldsa(&state);
    shake256_squeeze_mldsa(mu, CRHBYTES, &state);

    /* Compute rhoprime = CRH(key, rnd, mu) */
    shake256_init_mldsa(&state);
    shake256_absorb_mldsa(&state, key, SEEDBYTES);
    shake256_absorb_mldsa(&state, rnd, RNDBYTES);
    shake256_absorb_mldsa(&state, mu, CRHBYTES);
    shake256_finalize_mldsa(&state);
    shake256_squeeze_mldsa(rhoprime, CRHBYTES, &state);

    /* Expand matrix and transform vectors */
    polyvec_matrix_expand_65(mat, rho);
    polyvecl_ntt_65(&s1);
    polyveck_ntt_65(&s2);
    polyveck_ntt_65(&t0);

rej:
    /* Sample intermediate vector y */
    polyvecl_uniform_gamma1_65(&y, rhoprime, nonce++);

    /* Matrix-vector multiplication */
    z = y;
    polyvecl_ntt_65(&z);
    polyvec_matrix_pointwise_montgomery_65(&w1, mat, &z);
    polyveck_reduce_65(&w1);
    polyveck_invntt_tomont_65(&w1);

    /* Decompose w and call the random oracle */
    polyveck_caddq_65(&w1);
    polyveck_decompose_65(&w1, &w0, &w1);
    polyveck_pack_w1_65(sig, &w1);

    shake256_init_mldsa(&state);
    shake256_absorb_mldsa(&state, mu, CRHBYTES);
    shake256_absorb_mldsa(&state, sig, K_65 * POLYW1_PACKEDBYTES_65);
    shake256_finalize_mldsa(&state);
    shake256_squeeze_mldsa(sig, CTILDEBYTES_65, &state);
    poly_challenge_65(&cp, sig);
    poly_ntt_mldsa(&cp);

    /* Compute z, reject if it reveals secret */
    polyvecl_pointwise_poly_montgomery_65(&z, &cp, &s1);
    polyvecl_invntt_tomont_65(&z);
    polyvecl_add_65(&z, &z, &y);
    polyvecl_reduce_65(&z);
    if (polyvecl_chknorm_65(&z, GAMMA1_65 - BETA_65))
        goto rej;

    /* Check that subtracting cs2 does not change high bits of w and low bits
     * do not reveal secret information */
    polyveck_pointwise_poly_montgomery_65(&h, &cp, &s2);
    polyveck_invntt_tomont_65(&h);
    polyveck_sub_65(&w0, &w0, &h);
    polyveck_reduce_65(&w0);
    if (polyveck_chknorm_65(&w0, GAMMA2_65 - BETA_65))
        goto rej;

    /* Compute hints for w1 */
    polyveck_pointwise_poly_montgomery_65(&h, &cp, &t0);
    polyveck_invntt_tomont_65(&h);
    polyveck_reduce_65(&h);
    if (polyveck_chknorm_65(&h, GAMMA2_65))
        goto rej;

    polyveck_add_65(&w0, &w0, &h);
    n = polyveck_make_hint_65(&h, &w0, &w1);
    if (n > OMEGA_65)
        goto rej;

    /* Write signature */
    pack_sig_65(sig, sig, &z, &h);
    *siglen = CRYPTO_BYTES_65;
    return 0;
}

int crypto_sign_signature_87(uint8_t* sig,
    size_t* siglen,
    const uint8_t* m,
    size_t mlen,
    const uint8_t* pre,
    size_t prelen,
    const uint8_t rnd[RNDBYTES],
    const uint8_t* sk)
{
    unsigned int n;
    uint8_t seedbuf[2 * SEEDBYTES + TRBYTES + 2 * CRHBYTES];
    uint8_t* rho, * tr, * key, * mu, * rhoprime;
    uint16_t nonce = 0;
    polyvecl_87 mat[K_87], s1, y, z;
    polyveck_87 t0, s2, w1, w0, h;
    poly_mldsa cp;
    keccak_state state;

    rho = seedbuf;
    tr = rho + SEEDBYTES;
    key = tr + TRBYTES;
    mu = key + SEEDBYTES;
    rhoprime = mu + CRHBYTES;
    unpack_sk_87(rho, tr, key, &t0, &s1, &s2, sk);

    /* Compute mu = CRH(tr, pre, msg) */
    shake256_init_mldsa(&state);
    shake256_absorb_mldsa(&state, tr, TRBYTES);
    shake256_absorb_mldsa(&state, pre, prelen);
    shake256_absorb_mldsa(&state, m, mlen);
    shake256_finalize_mldsa(&state);
    shake256_squeeze_mldsa(mu, CRHBYTES, &state);

    /* Compute rhoprime = CRH(key, rnd, mu) */
    shake256_init_mldsa(&state);
    shake256_absorb_mldsa(&state, key, SEEDBYTES);
    shake256_absorb_mldsa(&state, rnd, RNDBYTES);
    shake256_absorb_mldsa(&state, mu, CRHBYTES);
    shake256_finalize_mldsa(&state);
    shake256_squeeze_mldsa(rhoprime, CRHBYTES, &state);

    /* Expand matrix and transform vectors */
    polyvec_matrix_expand_87(mat, rho);
    polyvecl_ntt_87(&s1);
    polyveck_ntt_87(&s2);
    polyveck_ntt_87(&t0);

rej:
    /* Sample intermediate vector y */
    polyvecl_uniform_gamma1_87(&y, rhoprime, nonce++);

    /* Matrix-vector multiplication */
    z = y;
    polyvecl_ntt_87(&z);
    polyvec_matrix_pointwise_montgomery_87(&w1, mat, &z);
    polyveck_reduce_87(&w1);
    polyveck_invntt_tomont_87(&w1);

    /* Decompose w and call the random oracle */
    polyveck_caddq_87(&w1);
    polyveck_decompose_87(&w1, &w0, &w1);
    polyveck_pack_w1_87(sig, &w1);

    shake256_init_mldsa(&state);
    shake256_absorb_mldsa(&state, mu, CRHBYTES);
    shake256_absorb_mldsa(&state, sig, K_87 * POLYW1_PACKEDBYTES_87);
    shake256_finalize_mldsa(&state);
    shake256_squeeze_mldsa(sig, CTILDEBYTES_87, &state);
    poly_challenge_87(&cp, sig);
    poly_ntt_mldsa(&cp);

    /* Compute z, reject if it reveals secret */
    polyvecl_pointwise_poly_montgomery_87(&z, &cp, &s1);
    polyvecl_invntt_tomont_87(&z);
    polyvecl_add_87(&z, &z, &y);
    polyvecl_reduce_87(&z);
    if (polyvecl_chknorm_87(&z, GAMMA1_87 - BETA_87))
        goto rej;

    /* Check that subtracting cs2 does not change high bits of w and low bits
     * do not reveal secret information */
    polyveck_pointwise_poly_montgomery_87(&h, &cp, &s2);
    polyveck_invntt_tomont_87(&h);
    polyveck_sub_87(&w0, &w0, &h);
    polyveck_reduce_87(&w0);
    if (polyveck_chknorm_87(&w0, GAMMA2_87 - BETA_87))
        goto rej;

    /* Compute hints for w1 */
    polyveck_pointwise_poly_montgomery_87(&h, &cp, &t0);
    polyveck_invntt_tomont_87(&h);
    polyveck_reduce_87(&h);
    if (polyveck_chknorm_87(&h, GAMMA2_87))
        goto rej;

    polyveck_add_87(&w0, &w0, &h);
    n = polyveck_make_hint_87(&h, &w0, &w1);
    if (n > OMEGA_87)
        goto rej;

    /* Write signature */
    pack_sig_87(sig, sig, &z, &h);
    *siglen = CRYPTO_BYTES_87;
    return 0;
}

static int crypto_sign_44(int8_t* sig,
    size_t* siglen,
    const uint8_t* m,
    size_t mlen,
    const uint8_t* ctx,
    size_t ctxlen,
    const uint8_t* sk)
{
    int ret;
    size_t i;
    uint8_t pre[257];
    uint8_t rnd[RNDBYTES];

    if (ctxlen > 255)
        return -1;

    /* Prepare pre = (0, ctxlen, ctx) */
    pre[0] = 0;
    pre[1] = ctxlen;
    for (i = 0; i < ctxlen; i++)
        pre[2 + i] = ctx[i];

    // randombytes_mldsa(rnd, RNDBYTES);
    for (i = 0; i < RNDBYTES; i++)
        rnd[i] = 0;

    ret = crypto_sign_signature_44(sig, siglen, m, mlen, pre, 2 + ctxlen, rnd, sk);
    return ret;
}

static int crypto_sign_65(uint8_t* sig,
    size_t* siglen,
    const uint8_t* m,
    size_t mlen,
    const uint8_t* ctx,
    size_t ctxlen,
    const uint8_t* sk)
{
    int ret;
    size_t i;
    uint8_t pre[257];
    uint8_t rnd[RNDBYTES];

    if (ctxlen > 255)
        return -1;

    /* Prepare pre = (0, ctxlen, ctx) */
    pre[0] = 0;
    pre[1] = ctxlen;
    for (i = 0; i < ctxlen; i++)
        pre[2 + i] = ctx[i];

    // randombytes_mldsa(rnd, RNDBYTES);
    for (i = 0; i < RNDBYTES; i++)
        rnd[i] = 0;
    
    ret = crypto_sign_signature_65(sig, siglen, m, mlen, pre, 2 + ctxlen, rnd, sk);

    return ret;
}

static int crypto_sign_87(uint8_t* sig,
    size_t* siglen,
    const uint8_t* m,
    size_t mlen,
    const uint8_t* ctx,
    size_t ctxlen,
    const uint8_t* sk)
{
    int ret;
    size_t i;
    uint8_t pre[257];
    uint8_t rnd[RNDBYTES];

    if (ctxlen > 255)
        return -1;

    /* Prepare pre = (0, ctxlen, ctx) */
    pre[0] = 0;
    pre[1] = ctxlen;
    for (i = 0; i < ctxlen; i++)
        pre[2 + i] = ctx[i];

    // randombytes_mldsa(rnd, RNDBYTES);
    for (i = 0; i < RNDBYTES; i++)
        rnd[i] = 0;

    ret = crypto_sign_signature_87(sig, siglen, m, mlen, pre, 2 + ctxlen, rnd, sk);

    return ret;
}


void MLDSA_44_SIGN(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pri_key, unsigned char* sig, unsigned int* sig_len, unsigned char* ctx, unsigned int ctxlen) {
    
    crypto_sign_44(sig, (size_t*)sig_len, msg, msg_len, ctx, ctxlen, pri_key);

}

void MLDSA_65_SIGN(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pri_key, unsigned char* sig, unsigned int* sig_len, unsigned char* ctx, unsigned int ctxlen) {

    crypto_sign_65(sig, (size_t*)sig_len, msg, msg_len, ctx, ctxlen, pri_key);

}

void MLDSA_87_SIGN(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pri_key, unsigned char* sig, unsigned int* sig_len, unsigned char* ctx, unsigned int ctxlen) {

    crypto_sign_87(sig, (size_t*)sig_len, msg, msg_len, ctx, ctxlen, pri_key);

}
