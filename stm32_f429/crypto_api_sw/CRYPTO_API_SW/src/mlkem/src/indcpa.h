#ifndef INDCPA_H
#define INDCPA_H

#include <stdint.h>
#include "params.h"
#include "polyvec.h"

void gen_matrix(polyvec* a, const uint8_t seed[KYBER_SYMBYTES], int transposed, int kyber_k);

/*
#define indcpa_keypair KYBER_NAMESPACE(indcpa_keypair)
void indcpa_keypair(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]);
*/

void indcpa_keypair_512(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES_512],
    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES_512], const uint8_t coins[KYBER_SYMBYTES]);
void indcpa_keypair_768(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES_768],
    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES_768], const uint8_t coins[KYBER_SYMBYTES]);
void indcpa_keypair_1024(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES_1024],
    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES_1024], const uint8_t coins[KYBER_SYMBYTES]);

void indcpa_enc_512(uint8_t c[KYBER_INDCPA_BYTES_512],
    const uint8_t m[KYBER_INDCPA_MSGBYTES],
    const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES_512],
    const uint8_t coins[KYBER_SYMBYTES]);
void indcpa_enc_768(uint8_t c[KYBER_INDCPA_BYTES_768],
    const uint8_t m[KYBER_INDCPA_MSGBYTES],
    const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES_768],
    const uint8_t coins[KYBER_SYMBYTES]);
void indcpa_enc_1024(uint8_t c[KYBER_INDCPA_BYTES_1024],
    const uint8_t m[KYBER_INDCPA_MSGBYTES],
    const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES_1024],
    const uint8_t coins[KYBER_SYMBYTES]);

void indcpa_dec_512(uint8_t m[KYBER_INDCPA_MSGBYTES],
    const uint8_t c[KYBER_INDCPA_BYTES_512],
    const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES_512]);
void indcpa_dec_768(uint8_t m[KYBER_INDCPA_MSGBYTES],
    const uint8_t c[KYBER_INDCPA_BYTES_768],
    const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES_768]);
void indcpa_dec_1024(uint8_t m[KYBER_INDCPA_MSGBYTES],
    const uint8_t c[KYBER_INDCPA_BYTES_1024],
    const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES_1024]);
/*
#define indcpa_enc KYBER_NAMESPACE(indcpa_enc)
void indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES]);

#define indcpa_enc_DBG KYBER_NAMESPACE(indcpa_enc_DBG)
void indcpa_enc_DBG(uint8_t c[KYBER_INDCPA_BYTES],
    const uint8_t m[KYBER_INDCPA_MSGBYTES],
    const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
    const uint8_t coins[KYBER_SYMBYTES],
    int DBG);

#define indcpa_dec KYBER_NAMESPACE(indcpa_dec)
void indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]);
*/

#endif
