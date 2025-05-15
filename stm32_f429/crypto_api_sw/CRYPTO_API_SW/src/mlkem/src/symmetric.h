#ifndef SYMMETRIC_H
#define SYMMETRIC_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"

#include "fips202.h"

typedef keccak_state xof_state;

void kyber_shake128_absorb(keccak_state *s,
                           const uint8_t seed[KYBER_SYMBYTES],
                           uint8_t x,
                           uint8_t y);

void kyber_shake256_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce);

void kyber_shake256_rkprf_512(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES_512]);
void kyber_shake256_rkprf_768(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES_768]);
void kyber_shake256_rkprf_1024(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES_1024]);

#define XOF_BLOCKBYTES SHAKE128_RATE

#define hash_h(OUT, IN, INBYTES) sha3_256_mlkem(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha3_512_mlkem(OUT, IN, INBYTES)
#define xof_absorb(STATE, SEED, X, Y) kyber_shake128_absorb(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) shake128_squeezeblocks_mlkem(OUT, OUTBLOCKS, STATE)
#define prf(OUT, OUTBYTES, KEY, NONCE) kyber_shake256_prf(OUT, OUTBYTES, KEY, NONCE)
#define kdf(OUT, IN, INBYTES) shake256_mlkem(OUT, KYBER_SSBYTES, IN, INBYTES)

#define rkprf_512(OUT, KEY, IN) kyber_shake256_rkprf_512(OUT, KEY, IN)
#define rkprf_768(OUT, KEY, IN) kyber_shake256_rkprf_768(OUT, KEY, IN)
#define rkprf_1024(OUT, KEY, IN) kyber_shake256_rkprf_1024(OUT, KEY, IN)

#endif /* SYMMETRIC_H */
