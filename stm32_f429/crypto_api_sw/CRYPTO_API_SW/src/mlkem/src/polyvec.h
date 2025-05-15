#ifndef POLYVEC_H
#define POLYVEC_H

#include <stdint.h>
#include "params.h"
#include "poly.h"

typedef struct{
  poly vec[4];
} polyvec;

// void polyvec_compress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES], const polyvec *a);

void polyvec_compress_512(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES_512], const polyvec* a);
void polyvec_compress_768(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES_768], const polyvec* a);
void polyvec_compress_1024(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES_1024], const polyvec* a);

// void polyvec_decompress(polyvec *r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES]);

void polyvec_decompress_512(polyvec* r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES_512]);
void polyvec_decompress_768(polyvec* r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES_768]);
void polyvec_decompress_1024(polyvec* r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES_1024]);

// void polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES], const polyvec *a);

void polyvec_tobytes_512(uint8_t r[KYBER_POLYVECBYTES_512], const polyvec* a);
void polyvec_tobytes_768(uint8_t r[KYBER_POLYVECBYTES_768], const polyvec* a);
void polyvec_tobytes_1024(uint8_t r[KYBER_POLYVECBYTES_1024], const polyvec* a);

// void polyvec_frombytes(polyvec *r, const uint8_t a[KYBER_POLYVECBYTES]);

void polyvec_frombytes_512(polyvec* r, const uint8_t a[KYBER_POLYVECBYTES_512]);
void polyvec_frombytes_768(polyvec* r, const uint8_t a[KYBER_POLYVECBYTES_768]);
void polyvec_frombytes_1024(polyvec* r, const uint8_t a[KYBER_POLYVECBYTES_1024]);

// void polyvec_ntt(polyvec *r);

void polyvec_ntt_512(polyvec* r);
void polyvec_ntt_768(polyvec* r);
void polyvec_ntt_1024(polyvec* r);


// void polyvec_invntt_tomont(polyvec *r);

void polyvec_invntt_tomont_512(polyvec* r);
void polyvec_invntt_tomont_768(polyvec* r);
void polyvec_invntt_tomont_1024(polyvec* r);

// void polyvec_basemul_acc_montgomery(poly *r, const polyvec *a, const polyvec *b);

void polyvec_basemul_acc_montgomery_512(poly* r, const polyvec* a, const polyvec* b);
void polyvec_basemul_acc_montgomery_768(poly* r, const polyvec* a, const polyvec* b);
void polyvec_basemul_acc_montgomery_1024(poly* r, const polyvec* a, const polyvec* b);

// void polyvec_reduce(polyvec *r);

void polyvec_reduce_512(polyvec* r);
void polyvec_reduce_768(polyvec* r);
void polyvec_reduce_1024(polyvec* r);

// void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b);

void polyvec_add_512(polyvec* r, const polyvec* a, const polyvec* b);
void polyvec_add_768(polyvec* r, const polyvec* a, const polyvec* b);
void polyvec_add_1024(polyvec* r, const polyvec* a, const polyvec* b);

#endif
