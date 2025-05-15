#ifndef FIPS202_H
#define FIPS202_H

#include <stddef.h>
#include <stdint.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

typedef struct {
  uint64_t s[25];
  unsigned int pos;
} keccak_state;

void shake128_init_mldsa(keccak_state *state);
void shake128_absorb_mldsa(keccak_state *state, const uint8_t *in, size_t inlen);
void shake128_finalize_mldsa(keccak_state *state);
void shake128_squeeze_mldsa(uint8_t *out, size_t outlen, keccak_state *state);
void shake128_absorb_once_mldsa(keccak_state *state, const uint8_t *in, size_t inlen);
void shake128_squeezeblocks_mldsa(uint8_t *out, size_t nblocks, keccak_state *state);

void shake256_init_mldsa(keccak_state *state);
void shake256_absorb_mldsa(keccak_state *state, const uint8_t *in, size_t inlen);
void shake256_finalize_mldsa(keccak_state *state);
void shake256_squeeze_mldsa(uint8_t *out, size_t outlen, keccak_state *state);
void shake256_absorb_once_mldsa(keccak_state *state, const uint8_t *in, size_t inlen);
void shake256_squeezeblocks_mldsa(uint8_t *out, size_t nblocks,  keccak_state *state);

void shake128_mldsa(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
void shake256_mldsa(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
void sha3_256_mldsa(uint8_t h[32], const uint8_t *in, size_t inlen);
void sha3_512_mldsa(uint8_t h[64], const uint8_t *in, size_t inlen);

#endif
