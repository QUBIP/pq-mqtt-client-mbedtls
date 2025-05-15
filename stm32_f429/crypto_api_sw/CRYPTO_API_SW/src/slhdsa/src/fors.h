#ifndef SPX_FORS_H
#define SPX_FORS_H

#include <stdint.h>

#include "context.h"
#include "params.h"

/**
 * Signs a message m, deriving the secret key from sk_seed and the FTS address.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 */
void fors_sign_shake_128_f(unsigned char *sig, unsigned char *pk,
    const unsigned char *m,
    const spx_ctx_shake_128_f *ctx,
    const uint32_t fors_addr[8]);
void fors_sign_shake_128_s(unsigned char* sig, unsigned char* pk,
    const unsigned char* m,
    const spx_ctx_shake_128_s* ctx,
    const uint32_t fors_addr[8]);
void fors_sign_shake_192_f(unsigned char* sig, unsigned char* pk,
    const unsigned char* m,
    const spx_ctx_shake_192_f* ctx,
    const uint32_t fors_addr[8]);
void fors_sign_shake_192_s(unsigned char* sig, unsigned char* pk,
    const unsigned char* m,
    const spx_ctx_shake_192_s* ctx,
    const uint32_t fors_addr[8]);
void fors_sign_shake_256_f(unsigned char* sig, unsigned char* pk,
    const unsigned char* m,
    const spx_ctx_shake_256_f* ctx,
    const uint32_t fors_addr[8]);
void fors_sign_shake_256_s(unsigned char* sig, unsigned char* pk,
    const unsigned char* m,
    const spx_ctx_shake_256_s* ctx,
    const uint32_t fors_addr[8]);


/**
 * Derives the FORS public key from a signature.
 * This can be used for verification by comparing to a known public key, or to
 * subsequently verify a signature on the derived public key. The latter is the
 * typical use-case when used as an FTS below an OTS in a hypertree.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 */

void fors_pk_from_sig_shake_128_s(unsigned char *pk,
    const unsigned char *sig, const unsigned char *m,
    const spx_ctx_shake_128_s *ctx,
    const uint32_t fors_addr[8]);
void fors_pk_from_sig_shake_128_f(unsigned char* pk,
    const unsigned char* sig, const unsigned char* m,
    const spx_ctx_shake_128_f* ctx,
    const uint32_t fors_addr[8]);
void fors_pk_from_sig_shake_192_s(unsigned char* pk,
    const unsigned char* sig, const unsigned char* m,
    const spx_ctx_shake_192_s* ctx,
    const uint32_t fors_addr[8]);
void fors_pk_from_sig_shake_192_f(unsigned char* pk,
    const unsigned char* sig, const unsigned char* m,
    const spx_ctx_shake_192_f* ctx,
    const uint32_t fors_addr[8]);
void fors_pk_from_sig_shake_256_s(unsigned char* pk,
    const unsigned char* sig, const unsigned char* m,
    const spx_ctx_shake_256_s* ctx,
    const uint32_t fors_addr[8]);
void fors_pk_from_sig_shake_256_f(unsigned char* pk,
    const unsigned char* sig, const unsigned char* m,
    const spx_ctx_shake_256_f* ctx,
    const uint32_t fors_addr[8]);

#endif
