#ifndef MERKLE_H_
#define MERKLE_H_

#include <stdint.h>

#include "context.h"
#include "params.h"

/* Generate a Merkle signature (WOTS signature followed by the Merkle */
/* authentication path) */
void merkle_sign_shake_128_f(uint8_t *sig, unsigned char *root,
    const spx_ctx_shake_128_f *ctx,
    uint32_t wots_addr[8], uint32_t tree_addr[8],
    uint32_t idx_leaf);
void merkle_sign_shake_128_s(uint8_t* sig, unsigned char* root,
    const spx_ctx_shake_128_s* ctx,
    uint32_t wots_addr[8], uint32_t tree_addr[8],
    uint32_t idx_leaf);
void merkle_sign_shake_192_f(uint8_t* sig, unsigned char* root,
    const spx_ctx_shake_192_f* ctx,
    uint32_t wots_addr[8], uint32_t tree_addr[8],
    uint32_t idx_leaf);
void merkle_sign_shake_192_s(uint8_t* sig, unsigned char* root,
    const spx_ctx_shake_192_s* ctx,
    uint32_t wots_addr[8], uint32_t tree_addr[8],
    uint32_t idx_leaf);
void merkle_sign_shake_256_f(uint8_t* sig, unsigned char* root,
    const spx_ctx_shake_256_f* ctx,
    uint32_t wots_addr[8], uint32_t tree_addr[8],
    uint32_t idx_leaf);
void merkle_sign_shake_256_s(uint8_t* sig, unsigned char* root,
    const spx_ctx_shake_256_s* ctx,
    uint32_t wots_addr[8], uint32_t tree_addr[8],
    uint32_t idx_leaf);

/* Compute the root node of the top-most subtree. */
void merkle_gen_root_shake_128_f(unsigned char *root, const spx_ctx_shake_128_f *ctx);
void merkle_gen_root_shake_128_s(unsigned char* root, const spx_ctx_shake_128_s* ctx);
void merkle_gen_root_shake_192_f(unsigned char* root, const spx_ctx_shake_192_f* ctx);
void merkle_gen_root_shake_192_s(unsigned char* root, const spx_ctx_shake_192_s* ctx);
void merkle_gen_root_shake_256_f(unsigned char* root, const spx_ctx_shake_256_f* ctx);
void merkle_gen_root_shake_256_s(unsigned char* root, const spx_ctx_shake_256_s* ctx);

#endif /* MERKLE_H_ */
