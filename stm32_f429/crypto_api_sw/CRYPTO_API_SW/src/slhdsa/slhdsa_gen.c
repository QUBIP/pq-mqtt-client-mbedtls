#include "slhdsa.h"

void SLHDSA_SHAKE_128_F_GEN_KEYS(unsigned char* pri_key, unsigned char* pub_key) {

    uint8_t seed[CRYPTO_SEEDBYTES_SHAKE_128_F];
    randombytes_slhdsa(seed, CRYPTO_SEEDBYTES_SHAKE_128_F);
    crypto_sign_seed_keypair_shake_128_f(pub_key, pri_key, seed);

}

void SLHDSA_SHAKE_128_S_GEN_KEYS(unsigned char* pri_key, unsigned char* pub_key) {

    uint8_t seed[CRYPTO_SEEDBYTES_SHAKE_128_S];
    randombytes_slhdsa(seed, CRYPTO_SEEDBYTES_SHAKE_128_S);
    crypto_sign_seed_keypair_shake_128_s(pub_key, pri_key, seed);

}

void SLHDSA_SHAKE_192_F_GEN_KEYS(unsigned char* pri_key, unsigned char* pub_key) {

    uint8_t seed[CRYPTO_SEEDBYTES_SHAKE_192_F];
    randombytes_slhdsa(seed, CRYPTO_SEEDBYTES_SHAKE_192_F);
    crypto_sign_seed_keypair_shake_192_f(pub_key, pri_key, seed);

}

void SLHDSA_SHAKE_192_S_GEN_KEYS(unsigned char* pri_key, unsigned char* pub_key) {

    uint8_t seed[CRYPTO_SEEDBYTES_SHAKE_192_S];
    randombytes_slhdsa(seed, CRYPTO_SEEDBYTES_SHAKE_192_S);
    crypto_sign_seed_keypair_shake_192_s(pub_key, pri_key, seed);

}

void SLHDSA_SHAKE_256_F_GEN_KEYS(unsigned char* pri_key, unsigned char* pub_key) {

    uint8_t seed[CRYPTO_SEEDBYTES_SHAKE_256_F];
    randombytes_slhdsa(seed, CRYPTO_SEEDBYTES_SHAKE_256_F);
    crypto_sign_seed_keypair_shake_256_f(pub_key, pri_key, seed);

}

void SLHDSA_SHAKE_256_S_GEN_KEYS(unsigned char* pri_key, unsigned char* pub_key) {

    uint8_t seed[CRYPTO_SEEDBYTES_SHAKE_256_S];
    randombytes_slhdsa(seed, CRYPTO_SEEDBYTES_SHAKE_256_S);
    crypto_sign_seed_keypair_shake_256_s(pub_key, pri_key, seed);

}