#ifndef SPX_API_H
#define SPX_API_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"

#define CRYPTO_ALGNAME "SPHINCS+"

#define CRYPTO_SECRETKEYBYTES_SHAKE_128_F   SPX_SK_BYTES_SHAKE_128_F
#define CRYPTO_PUBLICKEYBYTES_SHAKE_128_F   SPX_PK_BYTES_SHAKE_128_F
#define CRYPTO_BYTES_SHAKE_128_F            SPX_BYTES_SHAKE_128_F
#define CRYPTO_SEEDBYTES_SHAKE_128_F        (3*SPX_N_SHAKE_128_F)

#define CRYPTO_SECRETKEYBYTES_SHAKE_128_S   SPX_SK_BYTES_SHAKE_128_S
#define CRYPTO_PUBLICKEYBYTES_SHAKE_128_S   SPX_PK_BYTES_SHAKE_128_S
#define CRYPTO_BYTES_SHAKE_128_S            SPX_BYTES_SHAKE_128_S
#define CRYPTO_SEEDBYTES_SHAKE_128_S        (3*SPX_N_SHAKE_128_S)

#define CRYPTO_SECRETKEYBYTES_SHAKE_192_F   SPX_SK_BYTES_SHAKE_192_F
#define CRYPTO_PUBLICKEYBYTES_SHAKE_192_F   SPX_PK_BYTES_SHAKE_192_F
#define CRYPTO_BYTES_SHAKE_192_F            SPX_BYTES_SHAKE_192_F
#define CRYPTO_SEEDBYTES_SHAKE_192_F        (3*SPX_N_SHAKE_192_F)

#define CRYPTO_SECRETKEYBYTES_SHAKE_192_S   SPX_SK_BYTES_SHAKE_192_S
#define CRYPTO_PUBLICKEYBYTES_SHAKE_192_S   SPX_PK_BYTES_SHAKE_192_S
#define CRYPTO_BYTES_SHAKE_192_S            SPX_BYTES_SHAKE_192_S
#define CRYPTO_SEEDBYTES_SHAKE_192_S        (3*SPX_N_SHAKE_192_S)

#define CRYPTO_SECRETKEYBYTES_SHAKE_256_F   SPX_SK_BYTES_SHAKE_256_F
#define CRYPTO_PUBLICKEYBYTES_SHAKE_256_F   SPX_PK_BYTES_SHAKE_256_F
#define CRYPTO_BYTES_SHAKE_256_F            SPX_BYTES_SHAKE_256_F
#define CRYPTO_SEEDBYTES_SHAKE_256_F        (3*SPX_N_SHAKE_256_F)

#define CRYPTO_SECRETKEYBYTES_SHAKE_256_S   SPX_SK_BYTES_SHAKE_256_S
#define CRYPTO_PUBLICKEYBYTES_SHAKE_256_S   SPX_PK_BYTES_SHAKE_256_S
#define CRYPTO_BYTES_SHAKE_256_S            SPX_BYTES_SHAKE_256_S
#define CRYPTO_SEEDBYTES_SHAKE_256_S        (3*SPX_N_SHAKE_256_S)


/*
 * Generates a SPHINCS+ key pair given a seed.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED]
 */
int crypto_sign_seed_keypair_shake_128_f(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
int crypto_sign_seed_keypair_shake_128_s(uint8_t* pk, uint8_t* sk, const uint8_t* seed);
int crypto_sign_seed_keypair_shake_192_f(uint8_t* pk, uint8_t* sk, const uint8_t* seed);
int crypto_sign_seed_keypair_shake_192_s(uint8_t* pk, uint8_t* sk, const uint8_t* seed);
int crypto_sign_seed_keypair_shake_256_f(uint8_t* pk, uint8_t* sk, const uint8_t* seed);
int crypto_sign_seed_keypair_shake_256_s(uint8_t* pk, uint8_t* sk, const uint8_t* seed);


/**
 * Returns an array containing a detached signature.
 */
int crypto_sign_signature_shake_128_f(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
int crypto_sign_signature_shake_128_s(uint8_t* sig, size_t* siglen, const uint8_t* m, size_t mlen, const uint8_t* sk);
int crypto_sign_signature_shake_192_f(uint8_t* sig, size_t* siglen, const uint8_t* m, size_t mlen, const uint8_t* sk);
int crypto_sign_signature_shake_192_s(uint8_t* sig, size_t* siglen, const uint8_t* m, size_t mlen, const uint8_t* sk);
int crypto_sign_signature_shake_256_f(uint8_t* sig, size_t* siglen, const uint8_t* m, size_t mlen, const uint8_t* sk);
int crypto_sign_signature_shake_256_s(uint8_t* sig, size_t* siglen, const uint8_t* m, size_t mlen, const uint8_t* sk);

/**
 * Verifies a detached signature and message under a given public key.
 */
int crypto_sign_verify_shake_128_f(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
int crypto_sign_verify_shake_128_s(const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, const uint8_t* pk);
int crypto_sign_verify_shake_192_f(const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, const uint8_t* pk);
int crypto_sign_verify_shake_192_s(const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, const uint8_t* pk);
int crypto_sign_verify_shake_256_f(const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, const uint8_t* pk);
int crypto_sign_verify_shake_256_s(const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, const uint8_t* pk);

#endif
