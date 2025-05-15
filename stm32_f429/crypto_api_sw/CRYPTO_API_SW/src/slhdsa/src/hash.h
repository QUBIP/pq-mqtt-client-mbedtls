#ifndef SPX_HASH_H
#define SPX_HASH_H

#include <stddef.h>
#include <stdint.h>

#include "context.h"
#include "params.h"

void prf_addr_shake_128_f(unsigned char *out, const spx_ctx_shake_128_f *ctx,
    const uint32_t addr[8]);
void prf_addr_shake_128_s(unsigned char* out, const spx_ctx_shake_128_s* ctx,
    const uint32_t addr[8]);
void prf_addr_shake_192_f(unsigned char* out, const spx_ctx_shake_192_f* ctx,
    const uint32_t addr[8]);
void prf_addr_shake_192_s(unsigned char* out, const spx_ctx_shake_192_s* ctx,
    const uint32_t addr[8]);
void prf_addr_shake_256_f(unsigned char* out, const spx_ctx_shake_256_f* ctx,
    const uint32_t addr[8]);
void prf_addr_shake_256_s(unsigned char* out, const spx_ctx_shake_256_s* ctx,
    const uint32_t addr[8]);

void gen_message_random_shake_128_f(unsigned char *R, const unsigned char *sk_prf,
    const unsigned char *optrand,
    const unsigned char *m, size_t mlen,
    const spx_ctx_shake_128_f *ctx);
void gen_message_random_shake_128_s(unsigned char* R, const unsigned char* sk_prf,
    const unsigned char* optrand,
    const unsigned char* m, size_t mlen,
    const spx_ctx_shake_128_s* ctx);
void gen_message_random_shake_192_f(unsigned char* R, const unsigned char* sk_prf,
    const unsigned char* optrand,
    const unsigned char* m, size_t mlen,
    const spx_ctx_shake_192_f* ctx);
void gen_message_random_shake_192_s(unsigned char* R, const unsigned char* sk_prf,
    const unsigned char* optrand,
    const unsigned char* m, size_t mlen,
    const spx_ctx_shake_192_s* ctx);
void gen_message_random_shake_256_f(unsigned char* R, const unsigned char* sk_prf,
    const unsigned char* optrand,
    const unsigned char* m, size_t mlen,
    const spx_ctx_shake_256_f* ctx);
void gen_message_random_shake_256_s(unsigned char* R, const unsigned char* sk_prf,
    const unsigned char* optrand,
    const unsigned char* m, size_t mlen,
    const spx_ctx_shake_256_s* ctx);

void hash_message_shake_128_f(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
    const unsigned char *R, const unsigned char *pk,
    const unsigned char *m, size_t mlen,
    const spx_ctx_shake_128_f *ctx);
void hash_message_shake_128_s(unsigned char* digest, uint64_t* tree, uint32_t* leaf_idx,
    const unsigned char* R, const unsigned char* pk,
    const unsigned char* m, size_t mlen,
    const spx_ctx_shake_128_s* ctx);
void hash_message_shake_192_f(unsigned char* digest, uint64_t* tree, uint32_t* leaf_idx,
    const unsigned char* R, const unsigned char* pk,
    const unsigned char* m, size_t mlen,
    const spx_ctx_shake_192_f* ctx);
void hash_message_shake_192_s(unsigned char* digest, uint64_t* tree, uint32_t* leaf_idx,
    const unsigned char* R, const unsigned char* pk,
    const unsigned char* m, size_t mlen,
    const spx_ctx_shake_192_s* ctx);
void hash_message_shake_256_f(unsigned char* digest, uint64_t* tree, uint32_t* leaf_idx,
    const unsigned char* R, const unsigned char* pk,
    const unsigned char* m, size_t mlen,
    const spx_ctx_shake_256_f* ctx);
void hash_message_shake_256_s(unsigned char* digest, uint64_t* tree, uint32_t* leaf_idx,
    const unsigned char* R, const unsigned char* pk,
    const unsigned char* m, size_t mlen,
    const spx_ctx_shake_256_s* ctx);

#endif
