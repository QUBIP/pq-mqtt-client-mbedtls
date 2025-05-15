#ifndef PACKING_H
#define PACKING_H

#include <stdint.h>
#include "params.h"
#include "polyvec.h"

// #define pack_pk DILITHIUM_NAMESPACE(pack_pk)
void pack_pk_44(uint8_t pk[CRYPTO_PUBLICKEYBYTES_44], const uint8_t rho[SEEDBYTES], const polyveck_44 *t1);
void pack_pk_65(uint8_t pk[CRYPTO_PUBLICKEYBYTES_65], const uint8_t rho[SEEDBYTES], const polyveck_65* t1);
void pack_pk_87(uint8_t pk[CRYPTO_PUBLICKEYBYTES_87], const uint8_t rho[SEEDBYTES], const polyveck_87* t1);

// void pack_sk(uint8_t sk[CRYPTO_SECRETKEYBYTES], const uint8_t rho[SEEDBYTES], const uint8_t tr[TRBYTES], const uint8_t key[SEEDBYTES], const polyveck *t0, const polyvecl *s1, const polyveck *s2);
void pack_sk_44(uint8_t sk[CRYPTO_SECRETKEYBYTES_44], const uint8_t rho[SEEDBYTES], const uint8_t tr[TRBYTES], const uint8_t key[SEEDBYTES], const polyveck_44* t0, const polyvecl_44* s1, const polyveck_44* s2);
void pack_sk_65(uint8_t sk[CRYPTO_SECRETKEYBYTES_65], const uint8_t rho[SEEDBYTES], const uint8_t tr[TRBYTES], const uint8_t key[SEEDBYTES], const polyveck_65* t0, const polyvecl_65* s1, const polyveck_65* s2);
void pack_sk_87(uint8_t sk[CRYPTO_SECRETKEYBYTES_87], const uint8_t rho[SEEDBYTES], const uint8_t tr[TRBYTES], const uint8_t key[SEEDBYTES], const polyveck_87* t0, const polyvecl_87* s1, const polyveck_87* s2);

// void pack_sig(uint8_t sig[CRYPTO_BYTES], const uint8_t c[CTILDEBYTES], const polyvecl *z, const polyveck *h);
void pack_sig_44(uint8_t sig[CRYPTO_BYTES_44], const uint8_t c[CTILDEBYTES_44], const polyvecl_44* z, const polyveck_44* h);
void pack_sig_65(uint8_t sig[CRYPTO_BYTES_65], const uint8_t c[CTILDEBYTES_65], const polyvecl_65* z, const polyveck_65* h);
void pack_sig_87(uint8_t sig[CRYPTO_BYTES_87], const uint8_t c[CTILDEBYTES_87], const polyvecl_87* z, const polyveck_87* h);

// void unpack_pk(uint8_t rho[SEEDBYTES], polyveck *t1, const uint8_t pk[CRYPTO_PUBLICKEYBYTES]);
void unpack_pk_44(uint8_t rho[SEEDBYTES], polyveck_44* t1, const uint8_t pk[CRYPTO_PUBLICKEYBYTES_44]);
void unpack_pk_65(uint8_t rho[SEEDBYTES], polyveck_65* t1, const uint8_t pk[CRYPTO_PUBLICKEYBYTES_65]);
void unpack_pk_87(uint8_t rho[SEEDBYTES], polyveck_87* t1, const uint8_t pk[CRYPTO_PUBLICKEYBYTES_87]);

// void unpack_sk(uint8_t rho[SEEDBYTES], uint8_t tr[TRBYTES],uint8_t key[SEEDBYTES], polyveck *t0, polyvecl *s1, polyveck *s2, const uint8_t sk[CRYPTO_SECRETKEYBYTES]);
void unpack_sk_44(uint8_t rho[SEEDBYTES], uint8_t tr[TRBYTES], uint8_t key[SEEDBYTES], polyveck_44* t0, polyvecl_44* s1, polyveck_44* s2, const uint8_t sk[CRYPTO_SECRETKEYBYTES_44]);
void unpack_sk_65(uint8_t rho[SEEDBYTES], uint8_t tr[TRBYTES], uint8_t key[SEEDBYTES], polyveck_65* t0, polyvecl_65* s1, polyveck_65* s2, const uint8_t sk[CRYPTO_SECRETKEYBYTES_65]);
void unpack_sk_87(uint8_t rho[SEEDBYTES], uint8_t tr[TRBYTES], uint8_t key[SEEDBYTES], polyveck_87* t0, polyvecl_87* s1, polyveck_87* s2, const uint8_t sk[CRYPTO_SECRETKEYBYTES_87]);

// int unpack_sig(uint8_t c[CTILDEBYTES], polyvecl *z, polyveck *h, const uint8_t sig[CRYPTO_BYTES]);
int unpack_sig_44(uint8_t c[CTILDEBYTES_44], polyvecl_44* z, polyveck_44* h, const uint8_t sig[CRYPTO_BYTES_44]);
int unpack_sig_65(uint8_t c[CTILDEBYTES_65], polyvecl_65* z, polyveck_65* h, const uint8_t sig[CRYPTO_BYTES_65]);
int unpack_sig_87(uint8_t c[CTILDEBYTES_87], polyvecl_87* z, polyveck_87* h, const uint8_t sig[CRYPTO_BYTES_87]);

#endif
