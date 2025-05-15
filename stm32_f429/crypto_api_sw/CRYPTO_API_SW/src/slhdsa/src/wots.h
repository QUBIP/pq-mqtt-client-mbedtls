#ifndef SPX_WOTS_H
#define SPX_WOTS_H

#include <stdint.h>

#include "context.h"
#include "params.h"

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
void wots_pk_from_sig_shake_128_f(unsigned char *pk,
    const unsigned char *sig, const unsigned char *msg,
    const spx_ctx_shake_128_f *ctx, uint32_t addr[8]);
void wots_pk_from_sig_shake_128_s(unsigned char* pk,
    const unsigned char* sig, const unsigned char* msg,
    const spx_ctx_shake_128_s* ctx, uint32_t addr[8]);
void wots_pk_from_sig_shake_192_f(unsigned char* pk,
    const unsigned char* sig, const unsigned char* msg,
    const spx_ctx_shake_192_f* ctx, uint32_t addr[8]);
void wots_pk_from_sig_shake_192_s(unsigned char* pk,
    const unsigned char* sig, const unsigned char* msg,
    const spx_ctx_shake_192_s* ctx, uint32_t addr[8]);
void wots_pk_from_sig_shake_256_f(unsigned char* pk,
    const unsigned char* sig, const unsigned char* msg,
    const spx_ctx_shake_256_f* ctx, uint32_t addr[8]);
void wots_pk_from_sig_shake_256_s(unsigned char* pk,
    const unsigned char* sig, const unsigned char* msg,
    const spx_ctx_shake_256_s* ctx, uint32_t addr[8]);

/*
 * Compute the chain lengths needed for a given message hash
 */
void chain_lengths_shake_128_f(uint32_t *lengths, const unsigned char *msg);
void chain_lengths_shake_128_s(uint32_t* lengths, const unsigned char* msg);
void chain_lengths_shake_192_f(uint32_t* lengths, const unsigned char* msg);
void chain_lengths_shake_192_s(uint32_t* lengths, const unsigned char* msg);
void chain_lengths_shake_256_f(uint32_t* lengths, const unsigned char* msg);
void chain_lengths_shake_256_s(uint32_t* lengths, const unsigned char* msg);

#endif
