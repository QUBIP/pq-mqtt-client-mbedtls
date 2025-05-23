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
} keccak_state;

void shake128_absorb_slhdsa(keccak_state* state, const uint8_t* in, size_t inlen);
void shake128_squeezeblocks_slhdsa(uint8_t* out, size_t nblocks, keccak_state* state);

void shake256_absorb_slhdsa(keccak_state* state, const uint8_t* in, size_t inlen);
void shake256_squeezeblocks_slhdsa(uint8_t* out, size_t nblocks, keccak_state* state);

void shake128_slhdsa(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen);
void shake256_slhdsa(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen);
void sha3_256_slhdsa(uint8_t h[32], const uint8_t* in, size_t inlen);
void sha3_512_slhdsa(uint8_t h[64], const uint8_t* in, size_t inlen);

#endif
