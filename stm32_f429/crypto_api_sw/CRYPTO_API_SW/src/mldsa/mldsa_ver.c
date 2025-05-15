/**
  * @file mldsa_ver.c
  * @brief ML-DSA Verification code
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

static int crypto_sign_verify_44(const uint8_t* sig,
    size_t siglen,
    const uint8_t* m,
    size_t mlen,
    const uint8_t* pre,
    size_t prelen,
    const uint8_t* pk)
{
    unsigned int i;
    uint8_t buf[K_44 * POLYW1_PACKEDBYTES_44];
    uint8_t rho[SEEDBYTES];
    uint8_t mu[CRHBYTES];
    uint8_t c[CTILDEBYTES_44];
    uint8_t c2[CTILDEBYTES_44];
    poly_mldsa cp;
    polyvecl_44 mat[K_44], z;
    polyveck_44 t1, w1, h;
    keccak_state state;

    if (siglen != CRYPTO_BYTES_44)
        return -1;

    unpack_pk_44(rho, &t1, pk);
    if (unpack_sig_44(c, &z, &h, sig))
        return -1;
    if (polyvecl_chknorm_44(&z, GAMMA1_44 - BETA_44))
        return -1;

    /* Compute CRH(H(rho, t1), msg) */
    shake256_mldsa(mu, TRBYTES, pk, CRYPTO_PUBLICKEYBYTES_44);
    shake256_init_mldsa(&state);
    shake256_absorb_mldsa(&state, mu, TRBYTES);
    shake256_absorb_mldsa(&state, pre, prelen);
    shake256_absorb_mldsa(&state, m, mlen);
    shake256_finalize_mldsa(&state);
    shake256_squeeze_mldsa(mu, CRHBYTES, &state);

    /* Matrix-vector multiplication; compute Az - c2^dt1 */
    poly_challenge_44(&cp, c);
    polyvec_matrix_expand_44(mat, rho);

    polyvecl_ntt_44(&z);
    polyvec_matrix_pointwise_montgomery_44(&w1, mat, &z);

    poly_ntt_mldsa(&cp);
    polyveck_shiftl_44(&t1);
    polyveck_ntt_44(&t1);
    polyveck_pointwise_poly_montgomery_44(&t1, &cp, &t1);

    polyveck_sub_44(&w1, &w1, &t1);
    polyveck_reduce_44(&w1);
    polyveck_invntt_tomont_44(&w1);

    /* Reconstruct w1 */
    polyveck_caddq_44(&w1);
    polyveck_use_hint_44(&w1, &w1, &h);
    polyveck_pack_w1_44(buf, &w1);

    /* Call random oracle and verify challenge */
    shake256_init_mldsa(&state);
    shake256_absorb_mldsa(&state, mu, CRHBYTES);
    shake256_absorb_mldsa(&state, buf, K_44 * POLYW1_PACKEDBYTES_44);
    shake256_finalize_mldsa(&state);
    shake256_squeeze_mldsa(c2, CTILDEBYTES_44, &state);
    for (i = 0; i < CTILDEBYTES_44; ++i)
        if (c[i] != c2[i])
            return -1;

    return 0;
}

static int crypto_sign_verify_65(const uint8_t* sig,
    size_t siglen,
    const uint8_t* m,
    size_t mlen,
    const uint8_t* pre,
    size_t prelen,
    const uint8_t* pk)
{
    unsigned int i;
    uint8_t buf[K_65 * POLYW1_PACKEDBYTES_65];
    uint8_t rho[SEEDBYTES];
    uint8_t mu[CRHBYTES];
    uint8_t c[CTILDEBYTES_65];
    uint8_t c2[CTILDEBYTES_65];
    poly_mldsa cp;
    polyvecl_65 mat[K_65], z;
    polyveck_65 t1, w1, h;
    keccak_state state;

    if (siglen != CRYPTO_BYTES_65)
        return -1;

    unpack_pk_65(rho, &t1, pk);
    if (unpack_sig_65(c, &z, &h, sig))
        return -1;
    if (polyvecl_chknorm_65(&z, GAMMA1_65 - BETA_65))
        return -1;

    /* Compute CRH(H(rho, t1), msg) */
    shake256_mldsa(mu, TRBYTES, pk, CRYPTO_PUBLICKEYBYTES_65);
    shake256_init_mldsa(&state);
    shake256_absorb_mldsa(&state, mu, TRBYTES);
    shake256_absorb_mldsa(&state, pre, prelen);
    shake256_absorb_mldsa(&state, m, mlen);
    shake256_finalize_mldsa(&state);
    shake256_squeeze_mldsa(mu, CRHBYTES, &state);

    /* Matrix-vector multiplication; compute Az - c2^dt1 */
    poly_challenge_65(&cp, c);
    polyvec_matrix_expand_65(mat, rho);

    polyvecl_ntt_65(&z);
    polyvec_matrix_pointwise_montgomery_65(&w1, mat, &z);

    poly_ntt_mldsa(&cp);
    polyveck_shiftl_65(&t1);
    polyveck_ntt_65(&t1);
    polyveck_pointwise_poly_montgomery_65(&t1, &cp, &t1);

    polyveck_sub_65(&w1, &w1, &t1);
    polyveck_reduce_65(&w1);
    polyveck_invntt_tomont_65(&w1);

    /* Reconstruct w1 */
    polyveck_caddq_65(&w1);
    polyveck_use_hint_65(&w1, &w1, &h);
    polyveck_pack_w1_65(buf, &w1);

    /* Call random oracle and verify challenge */
    shake256_init_mldsa(&state);
    shake256_absorb_mldsa(&state, mu, CRHBYTES);
    shake256_absorb_mldsa(&state, buf, K_65 * POLYW1_PACKEDBYTES_65);
    shake256_finalize_mldsa(&state);
    shake256_squeeze_mldsa(c2, CTILDEBYTES_65, &state);
    for (i = 0; i < CTILDEBYTES_65; ++i)
        if (c[i] != c2[i])
            return -1;

    return 0;
}

static int crypto_sign_verify_87(const uint8_t* sig,
    size_t siglen,
    const uint8_t* m,
    size_t mlen,
    const uint8_t* pre,
    size_t prelen,
    const uint8_t* pk)
{
    unsigned int i;
    uint8_t buf[K_87 * POLYW1_PACKEDBYTES_87];
    uint8_t rho[SEEDBYTES];
    uint8_t mu[CRHBYTES];
    uint8_t c[CTILDEBYTES_87];
    uint8_t c2[CTILDEBYTES_87];
    poly_mldsa cp;
    polyvecl_87 mat[K_87], z;
    polyveck_87 t1, w1, h;
    keccak_state state;

    if (siglen != CRYPTO_BYTES_87)
        return -1;

    unpack_pk_87(rho, &t1, pk);
    if (unpack_sig_87(c, &z, &h, sig))
        return -1;
    if (polyvecl_chknorm_87(&z, GAMMA1_87 - BETA_87))
        return -1;

    /* Compute CRH(H(rho, t1), msg) */
    shake256_mldsa(mu, TRBYTES, pk, CRYPTO_PUBLICKEYBYTES_87);
    shake256_init_mldsa(&state);
    shake256_absorb_mldsa(&state, mu, TRBYTES);
    shake256_absorb_mldsa(&state, pre, prelen);
    shake256_absorb_mldsa(&state, m, mlen);
    shake256_finalize_mldsa(&state);
    shake256_squeeze_mldsa(mu, CRHBYTES, &state);

    /* Matrix-vector multiplication; compute Az - c2^dt1 */
    poly_challenge_87(&cp, c);
    polyvec_matrix_expand_87(mat, rho);

    polyvecl_ntt_87(&z);
    polyvec_matrix_pointwise_montgomery_87(&w1, mat, &z);

    poly_ntt_mldsa(&cp);
    polyveck_shiftl_87(&t1);
    polyveck_ntt_87(&t1);
    polyveck_pointwise_poly_montgomery_87(&t1, &cp, &t1);

    polyveck_sub_87(&w1, &w1, &t1);
    polyveck_reduce_87(&w1);
    polyveck_invntt_tomont_87(&w1);

    /* Reconstruct w1 */
    polyveck_caddq_87(&w1);
    polyveck_use_hint_87(&w1, &w1, &h);
    polyveck_pack_w1_87(buf, &w1);

    /* Call random oracle and verify challenge */
    shake256_init_mldsa(&state);
    shake256_absorb_mldsa(&state, mu, CRHBYTES);
    shake256_absorb_mldsa(&state, buf, K_87 * POLYW1_PACKEDBYTES_87);
    shake256_finalize_mldsa(&state);
    shake256_squeeze_mldsa(c2, CTILDEBYTES_87, &state);
    for (i = 0; i < CTILDEBYTES_87; ++i)
        if (c[i] != c2[i])
            return -1;

    return 0;
}

static int crypto_verify_44(const uint8_t* sig,
    size_t siglen,
    const uint8_t* m,
    size_t mlen,
    const uint8_t* ctx,
    size_t ctxlen,
    const uint8_t* pk)
{
    size_t i;
    uint8_t pre[257];

    if (ctxlen > 255)
        return -1;

    pre[0] = 0;
    pre[1] = ctxlen;
    for (i = 0; i < ctxlen; i++)
        pre[2 + i] = ctx[i];

    return crypto_sign_verify_44(sig, siglen, m, mlen, pre, 2 + ctxlen, pk);
}

static int crypto_verify_65(const uint8_t* sig,
    size_t siglen,
    const uint8_t* m,
    size_t mlen,
    const uint8_t* ctx,
    size_t ctxlen,
    const uint8_t* pk)
{
    size_t i;
    uint8_t pre[257];

    if (ctxlen > 255)
        return -1;

    pre[0] = 0;
    pre[1] = ctxlen;
    for (i = 0; i < ctxlen; i++)
        pre[2 + i] = ctx[i];

    return crypto_sign_verify_65(sig, siglen, m, mlen, pre, 2 + ctxlen, pk);
}

static int crypto_verify_87(const uint8_t* sig,
    size_t siglen,
    const uint8_t* m,
    size_t mlen,
    const uint8_t* ctx,
    size_t ctxlen,
    const uint8_t* pk)
{
    size_t i;
    uint8_t pre[257];

    if (ctxlen > 255)
        return -1;

    pre[0] = 0;
    pre[1] = ctxlen;
    for (i = 0; i < ctxlen; i++)
        pre[2 + i] = ctx[i];

    return crypto_sign_verify_87(sig, siglen, m, mlen, pre, 2 + ctxlen, pk);

}

void MLDSA_44_VERIFY(const unsigned char* msg, unsigned int msg_len, const unsigned char* pub_key, const unsigned char* sig, unsigned int sig_len, unsigned int* result, const unsigned char* ctx, unsigned int ctxlen) {

    *result = crypto_verify_44(sig, sig_len, msg, msg_len, ctx, ctxlen, pub_key);

}

void MLDSA_65_VERIFY(const unsigned char* msg, unsigned int msg_len, const unsigned char* pub_key, const unsigned char* sig, unsigned int sig_len, unsigned int* result, const unsigned char* ctx, unsigned int ctxlen) {

    *result = crypto_verify_65(sig, sig_len, msg, msg_len, ctx, ctxlen, pub_key);

}

void MLDSA_87_VERIFY(const unsigned char* msg, unsigned int msg_len, const unsigned char* pub_key, const unsigned char* sig, unsigned int sig_len, unsigned int* result, const unsigned char* ctx, unsigned int ctxlen) {

    *result = crypto_verify_87(sig, sig_len, msg, msg_len, ctx, ctxlen, pub_key);

}