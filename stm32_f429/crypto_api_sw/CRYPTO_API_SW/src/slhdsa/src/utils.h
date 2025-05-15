#ifndef SPX_UTILS_H
#define SPX_UTILS_H

#include <stdint.h>

#include "compat.h"
#include "context.h"
#include "params.h"

/* To support MSVC use alloca() instead of VLAs. See #20. */

/**
 * Converts the value of 'in' to 'outlen' bytes in big-endian byte order.
 */
void ull_to_bytes(unsigned char *out, unsigned int outlen,
                  unsigned long long in);
void u32_to_bytes(unsigned char *out, uint32_t in);

/**
 * Converts the inlen bytes in 'in' from big-endian byte order to an integer.
 */
unsigned long long bytes_to_ull(const unsigned char *in, unsigned int inlen);

/**
 * Computes a root node given a leaf and an auth path.
 * Expects address to be complete other than the tree_height and tree_index.
 */
void compute_root_shake_128_f(unsigned char *root, const unsigned char *leaf,
    uint32_t leaf_idx, uint32_t idx_offset,
    const unsigned char *auth_path, uint32_t tree_height,
    const spx_ctx_shake_128_f *ctx, uint32_t addr[8]);
void compute_root_shake_128_s(unsigned char* root, const unsigned char* leaf,
    uint32_t leaf_idx, uint32_t idx_offset,
    const unsigned char* auth_path, uint32_t tree_height,
    const spx_ctx_shake_128_s* ctx, uint32_t addr[8]);
void compute_root_shake_192_f(unsigned char* root, const unsigned char* leaf,
    uint32_t leaf_idx, uint32_t idx_offset,
    const unsigned char* auth_path, uint32_t tree_height,
    const spx_ctx_shake_192_f* ctx, uint32_t addr[8]);
void compute_root_shake_192_s(unsigned char* root, const unsigned char* leaf,
    uint32_t leaf_idx, uint32_t idx_offset,
    const unsigned char* auth_path, uint32_t tree_height,
    const spx_ctx_shake_192_s* ctx, uint32_t addr[8]);
void compute_root_shake_256_f(unsigned char* root, const unsigned char* leaf,
    uint32_t leaf_idx, uint32_t idx_offset,
    const unsigned char* auth_path, uint32_t tree_height,
    const spx_ctx_shake_256_f* ctx, uint32_t addr[8]);
void compute_root_shake_256_s(unsigned char* root, const unsigned char* leaf,
    uint32_t leaf_idx, uint32_t idx_offset,
    const unsigned char* auth_path, uint32_t tree_height,
    const spx_ctx_shake_256_s* ctx, uint32_t addr[8]);

/**
 * For a given leaf index, computes the authentication path and the resulting
 * root node using Merkle's TreeHash algorithm.
 * Expects the layer and tree parts of the tree_addr to be set, as well as the
 * tree type (i.e. SPX_ADDR_TYPE_HASHTREE or SPX_ADDR_TYPE_FORSTREE).
 * Applies the offset idx_offset to indices before building addresses, so that
 * it is possible to continue counting indices across trees.
 */
void treehash_shake_128_f(unsigned char *root, unsigned char *auth_path,
              const spx_ctx_shake_128_f* ctx,
              uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
              void (*gen_leaf)(
                  unsigned char * /* leaf */,
                  const spx_ctx_shake_128_f* /* ctx */,
                  uint32_t /* addr_idx */, const uint32_t[8] /* tree_addr */),
              uint32_t tree_addr[8]);
void treehash_shake_128_s(unsigned char* root, unsigned char* auth_path,
    const spx_ctx_shake_128_s* ctx,
    uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
    void (*gen_leaf)(
        unsigned char* /* leaf */,
        const spx_ctx_shake_128_s* /* ctx */,
        uint32_t /* addr_idx */, const uint32_t[8] /* tree_addr */),
    uint32_t tree_addr[8]);

void treehash_shake_192_f(unsigned char* root, unsigned char* auth_path,
    const spx_ctx_shake_192_f* ctx,
    uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
    void (*gen_leaf)(
        unsigned char* /* leaf */,
        const spx_ctx_shake_192_f* /* ctx */,
        uint32_t /* addr_idx */, const uint32_t[8] /* tree_addr */),
    uint32_t tree_addr[8]);
void treehash_shake_192_s(unsigned char* root, unsigned char* auth_path,
    const spx_ctx_shake_192_s* ctx,
    uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
    void (*gen_leaf)(
        unsigned char* /* leaf */,
        const spx_ctx_shake_192_s* /* ctx */,
        uint32_t /* addr_idx */, const uint32_t[8] /* tree_addr */),
    uint32_t tree_addr[8]);

void treehash_shake_256_f(unsigned char* root, unsigned char* auth_path,
    const spx_ctx_shake_256_f* ctx,
    uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
    void (*gen_leaf)(
        unsigned char* /* leaf */,
        const spx_ctx_shake_256_f* /* ctx */,
        uint32_t /* addr_idx */, const uint32_t[8] /* tree_addr */),
    uint32_t tree_addr[8]);
void treehash_shake_256_s(unsigned char* root, unsigned char* auth_path,
    const spx_ctx_shake_256_s* ctx,
    uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
    void (*gen_leaf)(
        unsigned char* /* leaf */,
        const spx_ctx_shake_256_s* /* ctx */,
        uint32_t /* addr_idx */, const uint32_t[8] /* tree_addr */),
    uint32_t tree_addr[8]);

#endif
