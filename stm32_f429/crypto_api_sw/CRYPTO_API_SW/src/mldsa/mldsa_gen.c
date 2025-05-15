/**
  * @file mldsa_gen.c
  * @brief ML-DSA Key Generation code
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


static int crypto_sign_keypair_44(uint8_t* pk, uint8_t* sk) {
    uint8_t seedbuf[2 * SEEDBYTES + CRHBYTES];
    uint8_t tr[TRBYTES];
    const uint8_t* rho, * rhoprime, * key;
    polyvecl_44 mat[K_44];
    polyvecl_44 s1, s1hat;
    polyveck_44 s2, t1, t0;

    /* Get randomness for rho, rhoprime and key */
    randombytes_mldsa(seedbuf, SEEDBYTES);
    seedbuf[SEEDBYTES + 0] = K_44;
    seedbuf[SEEDBYTES + 1] = L_44;
    shake256_mldsa(seedbuf, 2 * SEEDBYTES + CRHBYTES, seedbuf, SEEDBYTES + 2);
    rho = seedbuf;
    rhoprime = rho + SEEDBYTES;
    key = rhoprime + CRHBYTES;

    /* Expand matrix */
    polyvec_matrix_expand_44(mat, rho);

    /* Sample short vectors s1 and s2 */
    polyvecl_uniform_eta_44(&s1, rhoprime, 0);
    polyveck_uniform_eta_44(&s2, rhoprime, L_44);

    /* Matrix-vector multiplication */
    s1hat = s1;
    polyvecl_ntt_44(&s1hat);
    polyvec_matrix_pointwise_montgomery_44(&t1, mat, &s1hat);
    polyveck_reduce_44(&t1);
    polyveck_invntt_tomont_44(&t1);

    /* Add error vector s2 */
    polyveck_add_44(&t1, &t1, &s2);

    /* Extract t1 and write public key */
    polyveck_caddq_44(&t1);
    polyveck_power2round_44(&t1, &t0, &t1);
    pack_pk_44(pk, rho, &t1);

    /* Compute H(rho, t1) and write secret key */
    shake256_mldsa(tr, TRBYTES, pk, CRYPTO_PUBLICKEYBYTES_44);
    pack_sk_44(sk, rho, tr, key, &t0, &s1, &s2);

    return 0;
}

static int crypto_sign_keypair_65(uint8_t* pk, uint8_t* sk) {
    uint8_t seedbuf[2 * SEEDBYTES + CRHBYTES];
    uint8_t tr[TRBYTES];
    const uint8_t* rho, * rhoprime, * key;
    polyvecl_65 mat[K_65];
    polyvecl_65 s1, s1hat;
    polyveck_65 s2, t1, t0;

    /* Get randomness for rho, rhoprime and key */
    randombytes_mldsa(seedbuf, SEEDBYTES);
    seedbuf[SEEDBYTES + 0] = K_65;
    seedbuf[SEEDBYTES + 1] = L_65;
    shake256_mldsa(seedbuf, 2 * SEEDBYTES + CRHBYTES, seedbuf, SEEDBYTES + 2);
    rho = seedbuf;
    rhoprime = rho + SEEDBYTES;
    key = rhoprime + CRHBYTES;

    /* Expand matrix */
    polyvec_matrix_expand_65(mat, rho);

    /* Sample short vectors s1 and s2 */
    polyvecl_uniform_eta_65(&s1, rhoprime, 0);
    polyveck_uniform_eta_65(&s2, rhoprime, L_65);

    /* Matrix-vector multiplication */
    s1hat = s1;
    polyvecl_ntt_65(&s1hat);
    polyvec_matrix_pointwise_montgomery_65(&t1, mat, &s1hat);
    polyveck_reduce_65(&t1);
    polyveck_invntt_tomont_65(&t1);

    /* Add error vector s2 */
    polyveck_add_65(&t1, &t1, &s2);

    /* Extract t1 and write public key */
    polyveck_caddq_65(&t1);
    polyveck_power2round_65(&t1, &t0, &t1);
    pack_pk_65(pk, rho, &t1);

    /* Compute H(rho, t1) and write secret key */
    shake256_mldsa(tr, TRBYTES, pk, CRYPTO_PUBLICKEYBYTES_65);
    pack_sk_65(sk, rho, tr, key, &t0, &s1, &s2);

    return 0;
}

static int crypto_sign_keypair_87(uint8_t* pk, uint8_t* sk) {
    uint8_t seedbuf[2 * SEEDBYTES + CRHBYTES];
    uint8_t tr[TRBYTES];
    const uint8_t* rho, * rhoprime, * key;
    polyvecl_87 mat[K_87];
    polyvecl_87 s1, s1hat;
    polyveck_87 s2, t1, t0;

    /* Get randomness for rho, rhoprime and key */
    randombytes_mldsa(seedbuf, SEEDBYTES);
    seedbuf[SEEDBYTES + 0] = K_87;
    seedbuf[SEEDBYTES + 1] = L_87;
    shake256_mldsa(seedbuf, 2 * SEEDBYTES + CRHBYTES, seedbuf, SEEDBYTES + 2);
    rho = seedbuf;
    rhoprime = rho + SEEDBYTES;
    key = rhoprime + CRHBYTES;

    /* Expand matrix */
    polyvec_matrix_expand_87(mat, rho);

    /* Sample short vectors s1 and s2 */
    polyvecl_uniform_eta_87(&s1, rhoprime, 0);
    polyveck_uniform_eta_87(&s2, rhoprime, L_87);

    /* Matrix-vector multiplication */
    s1hat = s1;
    polyvecl_ntt_87(&s1hat);
    polyvec_matrix_pointwise_montgomery_87(&t1, mat, &s1hat);
    polyveck_reduce_87(&t1);
    polyveck_invntt_tomont_87(&t1);

    /* Add error vector s2 */
    polyveck_add_87(&t1, &t1, &s2);

    /* Extract t1 and write public key */
    polyveck_caddq_87(&t1);
    polyveck_power2round_87(&t1, &t0, &t1);
    pack_pk_87(pk, rho, &t1);

    /* Compute H(rho, t1) and write secret key */
    shake256_mldsa(tr, TRBYTES, pk, CRYPTO_PUBLICKEYBYTES_87);
    pack_sk_87(sk, rho, tr, key, &t0, &s1, &s2);

    return 0;
}

void MLDSA_44_GEN_KEYS(unsigned char* pri_key, unsigned char* pub_key) {
    
    crypto_sign_keypair_44(pub_key, pri_key);
}

void MLDSA_65_GEN_KEYS(unsigned char* pri_key, unsigned char* pub_key) {

    crypto_sign_keypair_65(pub_key, pri_key);
}

void MLDSA_87_GEN_KEYS(unsigned char* pri_key, unsigned char* pub_key) {

    crypto_sign_keypair_87(pub_key, pri_key);
}
