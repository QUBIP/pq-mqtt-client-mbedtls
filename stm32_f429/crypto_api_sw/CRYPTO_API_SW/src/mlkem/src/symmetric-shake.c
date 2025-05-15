#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "params.h"
#include "symmetric.h"
#include "fips202.h"

/*************************************************
* Name:        kyber_shake128_absorb
*
* Description: Absorb step of the SHAKE128 specialized for the Kyber context.
*
* Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak state
*              - const uint8_t *seed: pointer to KYBER_SYMBYTES input to be absorbed into state
*              - uint8_t i: additional byte of input
*              - uint8_t j: additional byte of input
**************************************************/
void kyber_shake128_absorb(keccak_state *state,
                           const uint8_t seed[KYBER_SYMBYTES],
                           uint8_t x,
                           uint8_t y)
{
  uint8_t extseed[KYBER_SYMBYTES+2];

  memcpy(extseed, seed, KYBER_SYMBYTES);
  extseed[KYBER_SYMBYTES+0] = x;
  extseed[KYBER_SYMBYTES+1] = y;

  shake128_absorb_once_mlkem(state, extseed, sizeof(extseed));
}

/*************************************************
* Name:        kyber_shake256_prf
*
* Description: Usage of SHAKE256 as a PRF, concatenates secret and public input
*              and then generates outlen bytes of SHAKE256 output
*
* Arguments:   - uint8_t *out: pointer to output
*              - size_t outlen: number of requested output bytes
*              - const uint8_t *key: pointer to the key (of length KYBER_SYMBYTES)
*              - uint8_t nonce: single-byte nonce (public PRF input)
**************************************************/
void kyber_shake256_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce)
{
  uint8_t extkey[KYBER_SYMBYTES+1];

  memcpy(extkey, key, KYBER_SYMBYTES);
  extkey[KYBER_SYMBYTES] = nonce;

  shake256_mlkem(out, outlen, extkey, sizeof(extkey));
}

/*************************************************
* Name:        kyber_shake256_prf
*
* Description: Usage of SHAKE256 as a PRF, concatenates secret and public input
*              and then generates outlen bytes of SHAKE256 output
*
* Arguments:   - uint8_t *out: pointer to output
*              - size_t outlen: number of requested output bytes
*              - const uint8_t *key: pointer to the key (of length KYBER_SYMBYTES)
*              - uint8_t nonce: single-byte nonce (public PRF input)
**************************************************/

void kyber_shake256_rkprf_512(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES_512])
{
    unsigned char* buf;
    buf = malloc(KYBER_SYMBYTES + KYBER_CIPHERTEXTBYTES_512);

    memcpy(buf, key, KYBER_SYMBYTES);
    memcpy(buf + KYBER_SYMBYTES, input, KYBER_CIPHERTEXTBYTES_512);

    shake256_mlkem(out, KYBER_SSBYTES, buf, sizeof(buf));

    free(buf);
}

void kyber_shake256_rkprf_768(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES_768])
{
    unsigned char* buf;
    buf = malloc(KYBER_SYMBYTES + KYBER_CIPHERTEXTBYTES_768);

    memcpy(buf, key, KYBER_SYMBYTES);
    memcpy(buf + KYBER_SYMBYTES, input, KYBER_CIPHERTEXTBYTES_768);

    shake256_mlkem(out, KYBER_SSBYTES, buf, sizeof(buf));

    free(buf);
}

void kyber_shake256_rkprf_1024(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES_1024])
{
    unsigned char* buf;
    buf = malloc(KYBER_SYMBYTES + KYBER_CIPHERTEXTBYTES_1024);

    memcpy(buf, key, KYBER_SYMBYTES);
    memcpy(buf + KYBER_SYMBYTES, input, KYBER_CIPHERTEXTBYTES_1024);

    shake256_mlkem(out, KYBER_SSBYTES, buf, sizeof(buf));

    free(buf);
}