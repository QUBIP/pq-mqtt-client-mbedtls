#include "params.h"
#include "packing.h"
#include "polyvec.h"
#include "poly.h"

/*************************************************
* Name:        pack_pk
*
* Description: Bit-pack public key pk = (rho, t1).
*
* Arguments:   - uint8_t pk[]: output byte array
*              - const uint8_t rho[]: byte array containing rho
*              - const polyveck *t1: pointer to vector t1
**************************************************/

void pack_pk_44(uint8_t pk[CRYPTO_PUBLICKEYBYTES_44],
    const uint8_t rho[SEEDBYTES],
    const polyveck_44* t1)
{
    unsigned int i;

    for (i = 0; i < SEEDBYTES; ++i)
        pk[i] = rho[i];
    pk += SEEDBYTES;

    for (i = 0; i < K_44; ++i)
        polyt1_pack(pk + i * POLYT1_PACKEDBYTES, &t1->vec[i]);
}
void pack_pk_65(uint8_t pk[CRYPTO_PUBLICKEYBYTES_65],
    const uint8_t rho[SEEDBYTES],
    const polyveck_65* t1)
{
    unsigned int i;

    for (i = 0; i < SEEDBYTES; ++i)
        pk[i] = rho[i];
    pk += SEEDBYTES;

    for (i = 0; i < K_65; ++i)
        polyt1_pack(pk + i * POLYT1_PACKEDBYTES, &t1->vec[i]);
}
void pack_pk_87(uint8_t pk[CRYPTO_PUBLICKEYBYTES_87],
    const uint8_t rho[SEEDBYTES],
    const polyveck_87* t1)
{
    unsigned int i;

    for (i = 0; i < SEEDBYTES; ++i)
        pk[i] = rho[i];
    pk += SEEDBYTES;

    for (i = 0; i < K_87; ++i)
        polyt1_pack(pk + i * POLYT1_PACKEDBYTES, &t1->vec[i]);
}
/*************************************************
* Name:        unpack_pk
*
* Description: Unpack public key pk = (rho, t1).
*
* Arguments:   - const uint8_t rho[]: output byte array for rho
*              - const polyveck *t1: pointer to output vector t1
*              - uint8_t pk[]: byte array containing bit-packed pk
**************************************************/
void unpack_pk_44(uint8_t rho[SEEDBYTES],
    polyveck_44* t1,
    const uint8_t pk[CRYPTO_PUBLICKEYBYTES_44])
{
    unsigned int i;

    for (i = 0; i < SEEDBYTES; ++i)
        rho[i] = pk[i];
    pk += SEEDBYTES;

    for (i = 0; i < K_44; ++i)
        polyt1_unpack(&t1->vec[i], pk + i * POLYT1_PACKEDBYTES);
}
void unpack_pk_65(uint8_t rho[SEEDBYTES],
    polyveck_65* t1,
    const uint8_t pk[CRYPTO_PUBLICKEYBYTES_65])
{
    unsigned int i;

    for (i = 0; i < SEEDBYTES; ++i)
        rho[i] = pk[i];
    pk += SEEDBYTES;

    for (i = 0; i < K_65; ++i)
        polyt1_unpack(&t1->vec[i], pk + i * POLYT1_PACKEDBYTES);
}
void unpack_pk_87(uint8_t rho[SEEDBYTES],
    polyveck_87* t1,
    const uint8_t pk[CRYPTO_PUBLICKEYBYTES_87])
{
    unsigned int i;

    for (i = 0; i < SEEDBYTES; ++i)
        rho[i] = pk[i];
    pk += SEEDBYTES;

    for (i = 0; i < K_87; ++i)
        polyt1_unpack(&t1->vec[i], pk + i * POLYT1_PACKEDBYTES);
}


/*************************************************
* Name:        pack_sk
*
* Description: Bit-pack secret key sk = (rho, tr, key, t0, s1, s2).
*
* Arguments:   - uint8_t sk[]: output byte array
*              - const uint8_t rho[]: byte array containing rho
*              - const uint8_t tr[]: byte array containing tr
*              - const uint8_t key[]: byte array containing key
*              - const polyveck *t0: pointer to vector t0
*              - const polyvecl *s1: pointer to vector s1
*              - const polyveck *s2: pointer to vector s2
**************************************************/

void pack_sk_44(uint8_t sk[CRYPTO_SECRETKEYBYTES_44],
    const uint8_t rho[SEEDBYTES],
    const uint8_t tr[TRBYTES],
    const uint8_t key[SEEDBYTES],
    const polyveck_44* t0,
    const polyvecl_44* s1,
    const polyveck_44* s2)
{
    unsigned int i;

    for (i = 0; i < SEEDBYTES; ++i)
        sk[i] = rho[i];
    sk += SEEDBYTES;

    for (i = 0; i < SEEDBYTES; ++i)
        sk[i] = key[i];
    sk += SEEDBYTES;

    for (i = 0; i < TRBYTES; ++i)
        sk[i] = tr[i];
    sk += TRBYTES;

    for (i = 0; i < L_44; ++i)
        polyeta_pack_44(sk + i * POLYETA_PACKEDBYTES_44, &s1->vec[i]);
    sk += L_44 * POLYETA_PACKEDBYTES_44;

    for (i = 0; i < K_44; ++i)
        polyeta_pack_44(sk + i * POLYETA_PACKEDBYTES_44, &s2->vec[i]);
    sk += K_44 * POLYETA_PACKEDBYTES_44;

    for (i = 0; i < K_44; ++i)
        polyt0_pack(sk + i * POLYT0_PACKEDBYTES, &t0->vec[i]);
}
void pack_sk_65(uint8_t sk[CRYPTO_SECRETKEYBYTES_65],
    const uint8_t rho[SEEDBYTES],
    const uint8_t tr[TRBYTES],
    const uint8_t key[SEEDBYTES],
    const polyveck_65* t0,
    const polyvecl_65* s1,
    const polyveck_65* s2)
{
    unsigned int i;

    for (i = 0; i < SEEDBYTES; ++i)
        sk[i] = rho[i];
    sk += SEEDBYTES;

    for (i = 0; i < SEEDBYTES; ++i)
        sk[i] = key[i];
    sk += SEEDBYTES;

    for (i = 0; i < TRBYTES; ++i)
        sk[i] = tr[i];
    sk += TRBYTES;

    for (i = 0; i < L_65; ++i)
        polyeta_pack_65(sk + i * POLYETA_PACKEDBYTES_65, &s1->vec[i]);
    sk += L_65 * POLYETA_PACKEDBYTES_65;

    for (i = 0; i < K_65; ++i)
        polyeta_pack_65(sk + i * POLYETA_PACKEDBYTES_65, &s2->vec[i]);
    sk += K_65 * POLYETA_PACKEDBYTES_65;

    for (i = 0; i < K_65; ++i)
        polyt0_pack(sk + i * POLYT0_PACKEDBYTES, &t0->vec[i]);
}
void pack_sk_87(uint8_t sk[CRYPTO_SECRETKEYBYTES_87],
    const uint8_t rho[SEEDBYTES],
    const uint8_t tr[TRBYTES],
    const uint8_t key[SEEDBYTES],
    const polyveck_87* t0,
    const polyvecl_87* s1,
    const polyveck_87* s2)
{
    unsigned int i;

    for (i = 0; i < SEEDBYTES; ++i)
        sk[i] = rho[i];
    sk += SEEDBYTES;

    for (i = 0; i < SEEDBYTES; ++i)
        sk[i] = key[i];
    sk += SEEDBYTES;

    for (i = 0; i < TRBYTES; ++i)
        sk[i] = tr[i];
    sk += TRBYTES;

    for (i = 0; i < L_87; ++i)
        polyeta_pack_87(sk + i * POLYETA_PACKEDBYTES_87, &s1->vec[i]);
    sk += L_87 * POLYETA_PACKEDBYTES_87;

    for (i = 0; i < K_87; ++i)
        polyeta_pack_87(sk + i * POLYETA_PACKEDBYTES_87, &s2->vec[i]);
    sk += K_87 * POLYETA_PACKEDBYTES_87;

    for (i = 0; i < K_87; ++i)
        polyt0_pack(sk + i * POLYT0_PACKEDBYTES, &t0->vec[i]);
}

/*************************************************
* Name:        unpack_sk
*
* Description: Unpack secret key sk = (rho, tr, key, t0, s1, s2).
*
* Arguments:   - const uint8_t rho[]: output byte array for rho
*              - const uint8_t tr[]: output byte array for tr
*              - const uint8_t key[]: output byte array for key
*              - const polyveck *t0: pointer to output vector t0
*              - const polyvecl *s1: pointer to output vector s1
*              - const polyveck *s2: pointer to output vector s2
*              - uint8_t sk[]: byte array containing bit-packed sk
**************************************************/
void unpack_sk_44(uint8_t rho[SEEDBYTES],
    uint8_t tr[TRBYTES],
    uint8_t key[SEEDBYTES],
    polyveck_44* t0,
    polyvecl_44* s1,
    polyveck_44* s2,
    const uint8_t sk[CRYPTO_SECRETKEYBYTES_44])
{
    unsigned int i;

    for (i = 0; i < SEEDBYTES; ++i)
        rho[i] = sk[i];
    sk += SEEDBYTES;

    for (i = 0; i < SEEDBYTES; ++i)
        key[i] = sk[i];
    sk += SEEDBYTES;

    for (i = 0; i < TRBYTES; ++i)
        tr[i] = sk[i];
    sk += TRBYTES;

    for (i = 0; i < L_44; ++i)
        polyeta_unpack_44(&s1->vec[i], sk + i * POLYETA_PACKEDBYTES_44);
    sk += L_44 * POLYETA_PACKEDBYTES_44;

    for (i = 0; i < K_44; ++i)
        polyeta_unpack_44(&s2->vec[i], sk + i * POLYETA_PACKEDBYTES_44);
    sk += K_44 * POLYETA_PACKEDBYTES_44;

    for (i = 0; i < K_44; ++i)
        polyt0_unpack(&t0->vec[i], sk + i * POLYT0_PACKEDBYTES);
}
void unpack_sk_65(uint8_t rho[SEEDBYTES],
    uint8_t tr[TRBYTES],
    uint8_t key[SEEDBYTES],
    polyveck_65* t0,
    polyvecl_65* s1,
    polyveck_65* s2,
    const uint8_t sk[CRYPTO_SECRETKEYBYTES_65])
{
    unsigned int i;

    for (i = 0; i < SEEDBYTES; ++i)
        rho[i] = sk[i];
    sk += SEEDBYTES;

    for (i = 0; i < SEEDBYTES; ++i)
        key[i] = sk[i];
    sk += SEEDBYTES;

    for (i = 0; i < TRBYTES; ++i)
        tr[i] = sk[i];
    sk += TRBYTES;

    for (i = 0; i < L_65; ++i)
        polyeta_unpack_65(&s1->vec[i], sk + i * POLYETA_PACKEDBYTES_65);
    sk += L_65 * POLYETA_PACKEDBYTES_65;

    for (i = 0; i < K_65; ++i)
        polyeta_unpack_65(&s2->vec[i], sk + i * POLYETA_PACKEDBYTES_65);
    sk += K_65 * POLYETA_PACKEDBYTES_65;

    for (i = 0; i < K_65; ++i)
        polyt0_unpack(&t0->vec[i], sk + i * POLYT0_PACKEDBYTES);
}
void unpack_sk_87(uint8_t rho[SEEDBYTES],
    uint8_t tr[TRBYTES],
    uint8_t key[SEEDBYTES],
    polyveck_87* t0,
    polyvecl_87* s1,
    polyveck_87* s2,
    const uint8_t sk[CRYPTO_SECRETKEYBYTES_87])
{
    unsigned int i;

    for (i = 0; i < SEEDBYTES; ++i)
        rho[i] = sk[i];
    sk += SEEDBYTES;

    for (i = 0; i < SEEDBYTES; ++i)
        key[i] = sk[i];
    sk += SEEDBYTES;

    for (i = 0; i < TRBYTES; ++i)
        tr[i] = sk[i];
    sk += TRBYTES;

    for (i = 0; i < L_87; ++i)
        polyeta_unpack_87(&s1->vec[i], sk + i * POLYETA_PACKEDBYTES_87);
    sk += L_87 * POLYETA_PACKEDBYTES_87;

    for (i = 0; i < K_87; ++i)
        polyeta_unpack_87(&s2->vec[i], sk + i * POLYETA_PACKEDBYTES_87);
    sk += K_87 * POLYETA_PACKEDBYTES_87;

    for (i = 0; i < K_87; ++i)
        polyt0_unpack(&t0->vec[i], sk + i * POLYT0_PACKEDBYTES);
}

/*************************************************
* Name:        pack_sig
*
* Description: Bit-pack signature sig = (c, z, h).
*
* Arguments:   - uint8_t sig[]: output byte array
*              - const uint8_t *c: pointer to challenge hash length SEEDBYTES
*              - const polyvecl *z: pointer to vector z
*              - const polyveck *h: pointer to hint vector h
**************************************************/

void pack_sig_44(uint8_t sig[CRYPTO_BYTES_44],
    const uint8_t c[CTILDEBYTES_44],
    const polyvecl_44* z,
    const polyveck_44* h)
{
    unsigned int i, j, k;

    for (i = 0; i < CTILDEBYTES_44; ++i)
        sig[i] = c[i];
    sig += CTILDEBYTES_44;

    for (i = 0; i < L_44; ++i)
        polyz_pack_44(sig + i * POLYZ_PACKEDBYTES_44, &z->vec[i]);
    sig += L_44 * POLYZ_PACKEDBYTES_44;

    /* Encode h */
    for (i = 0; i < OMEGA_44 + K_44; ++i)
        sig[i] = 0;

    k = 0;
    for (i = 0; i < K_44; ++i) {
        for (j = 0; j < N_MLDSA; ++j)
            if (h->vec[i].coeffs[j] != 0)
                sig[k++] = j;

        sig[OMEGA_44 + i] = k;
    }
}
void pack_sig_65(uint8_t sig[CRYPTO_BYTES_65],
    const uint8_t c[CTILDEBYTES_65],
    const polyvecl_65* z,
    const polyveck_65* h)
{
    unsigned int i, j, k;

    for (i = 0; i < CTILDEBYTES_65; ++i)
        sig[i] = c[i];
    sig += CTILDEBYTES_65;

    for (i = 0; i < L_65; ++i)
        polyz_pack_65(sig + i * POLYZ_PACKEDBYTES_65, &z->vec[i]);
    sig += L_65 * POLYZ_PACKEDBYTES_65;

    /* Encode h */
    for (i = 0; i < OMEGA_65 + K_65; ++i)
        sig[i] = 0;

    k = 0;
    for (i = 0; i < K_65; ++i) {
        for (j = 0; j < N_MLDSA; ++j)
            if (h->vec[i].coeffs[j] != 0)
                sig[k++] = j;

        sig[OMEGA_65 + i] = k;
    }
}
void pack_sig_87(uint8_t sig[CRYPTO_BYTES_87],
    const uint8_t c[CTILDEBYTES_87],
    const polyvecl_87* z,
    const polyveck_87* h)
{
    unsigned int i, j, k;

    for (i = 0; i < CTILDEBYTES_87; ++i)
        sig[i] = c[i];
    sig += CTILDEBYTES_87;

    for (i = 0; i < L_87; ++i)
        polyz_pack_87(sig + i * POLYZ_PACKEDBYTES_87, &z->vec[i]);
    sig += L_87 * POLYZ_PACKEDBYTES_87;

    /* Encode h */
    for (i = 0; i < OMEGA_87 + K_87; ++i)
        sig[i] = 0;

    k = 0;
    for (i = 0; i < K_87; ++i) {
        for (j = 0; j < N_MLDSA; ++j)
            if (h->vec[i].coeffs[j] != 0)
                sig[k++] = j;

        sig[OMEGA_87 + i] = k;
    }
}

/*************************************************
* Name:        unpack_sig
*
* Description: Unpack signature sig = (c, z, h).
*
* Arguments:   - uint8_t *c: pointer to output challenge hash
*              - polyvecl *z: pointer to output vector z
*              - polyveck *h: pointer to output hint vector h
*              - const uint8_t sig[]: byte array containing
*                bit-packed signature
*
* Returns 1 in case of malformed signature; otherwise 0.
**************************************************/

int unpack_sig_44(uint8_t c[CTILDEBYTES_44],
    polyvecl_44* z,
    polyveck_44* h,
    const uint8_t sig[CRYPTO_BYTES_44])
{
    unsigned int i, j, k;

    for (i = 0; i < CTILDEBYTES_44; ++i)
        c[i] = sig[i];
    sig += CTILDEBYTES_44;

    for (i = 0; i < L_44; ++i)
        polyz_unpack_44(&z->vec[i], sig + i * POLYZ_PACKEDBYTES_44);
    sig += L_44 * POLYZ_PACKEDBYTES_44;

    /* Decode h */
    k = 0;
    for (i = 0; i < K_44; ++i) {
        for (j = 0; j < N_MLDSA; ++j)
            h->vec[i].coeffs[j] = 0;

        if (sig[OMEGA_44 + i] < k || sig[OMEGA_44 + i] > OMEGA_44)
            return 1;

        for (j = k; j < sig[OMEGA_44 + i]; ++j) {
            /* Coefficients are ordered for strong unforgeability */
            if (j > k && sig[j] <= sig[j - 1]) return 1;
            h->vec[i].coeffs[sig[j]] = 1;
        }

        k = sig[OMEGA_44 + i];
    }

    /* Extra indices are zero for strong unforgeability */
    for (j = k; j < OMEGA_44; ++j)
        if (sig[j])
            return 1;

    return 0;
}
int unpack_sig_65(uint8_t c[CTILDEBYTES_65],
    polyvecl_65* z,
    polyveck_65* h,
    const uint8_t sig[CRYPTO_BYTES_65])
{
    unsigned int i, j, k;

    for (i = 0; i < CTILDEBYTES_65; ++i)
        c[i] = sig[i];
    sig += CTILDEBYTES_65;

    for (i = 0; i < L_65; ++i)
        polyz_unpack_65(&z->vec[i], sig + i * POLYZ_PACKEDBYTES_65);
    sig += L_65 * POLYZ_PACKEDBYTES_65;

    /* Decode h */
    k = 0;
    for (i = 0; i < K_65; ++i) {
        for (j = 0; j < N_MLDSA; ++j)
            h->vec[i].coeffs[j] = 0;

        if (sig[OMEGA_65 + i] < k || sig[OMEGA_65 + i] > OMEGA_65)
            return 1;

        for (j = k; j < sig[OMEGA_65 + i]; ++j) {
            /* Coefficients are ordered for strong unforgeability */
            if (j > k && sig[j] <= sig[j - 1]) return 1;
            h->vec[i].coeffs[sig[j]] = 1;
        }

        k = sig[OMEGA_65 + i];
    }

    /* Extra indices are zero for strong unforgeability */
    for (j = k; j < OMEGA_65; ++j)
        if (sig[j])
            return 1;

    return 0;
}
int unpack_sig_87(uint8_t c[CTILDEBYTES_87],
    polyvecl_87* z,
    polyveck_87* h,
    const uint8_t sig[CRYPTO_BYTES_87])
{
    unsigned int i, j, k;

    for (i = 0; i < CTILDEBYTES_87; ++i)
        c[i] = sig[i];
    sig += CTILDEBYTES_87;

    for (i = 0; i < L_87; ++i)
        polyz_unpack_87(&z->vec[i], sig + i * POLYZ_PACKEDBYTES_87);
    sig += L_87 * POLYZ_PACKEDBYTES_87;

    /* Decode h */
    k = 0;
    for (i = 0; i < K_87; ++i) {
        for (j = 0; j < N_MLDSA; ++j)
            h->vec[i].coeffs[j] = 0;

        if (sig[OMEGA_87 + i] < k || sig[OMEGA_87 + i] > OMEGA_87)
            return 1;

        for (j = k; j < sig[OMEGA_87 + i]; ++j) {
            /* Coefficients are ordered for strong unforgeability */
            if (j > k && sig[j] <= sig[j - 1]) return 1;
            h->vec[i].coeffs[sig[j]] = 1;
        }

        k = sig[OMEGA_87 + i];
    }

    /* Extra indices are zero for strong unforgeability */
    for (j = k; j < OMEGA_87; ++j)
        if (sig[j])
            return 1;

    return 0;
}