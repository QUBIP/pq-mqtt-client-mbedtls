#include <stdint.h>
#include "params.h"
#include "symmetric.h"
#include "fips202.h"

void dilithium_shake128_stream_init(keccak_state *state, const uint8_t seed[SEEDBYTES], uint16_t nonce)
{
  uint8_t t[2];
  t[0] = nonce;
  t[1] = nonce >> 8;

  shake128_init_mldsa(state);
  shake128_absorb_mldsa(state, seed, SEEDBYTES);
  shake128_absorb_mldsa(state, t, 2);
  shake128_finalize_mldsa(state);
}

void dilithium_shake256_stream_init(keccak_state *state, const uint8_t seed[CRHBYTES], uint16_t nonce)
{
  uint8_t t[2];
  t[0] = nonce;
  t[1] = nonce >> 8;

  shake256_init_mldsa(state);
  shake256_absorb_mldsa(state, seed, CRHBYTES);
  shake256_absorb_mldsa(state, t, 2);
  shake256_finalize_mldsa(state);
}
