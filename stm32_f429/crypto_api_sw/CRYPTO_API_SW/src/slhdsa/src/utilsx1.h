#ifndef SPX_UTILSX4_H
#define SPX_UTILSX4_H

#include <stdint.h>

#include "context.h"
#include "params.h"

/**
 * For a given leaf index, computes the authentication path and the resulting
 * root node using Merkle's TreeHash algorithm.
 * Expects the layer and tree parts of the tree_addr to be set, as well as the
 * tree type (i.e. SPX_ADDR_TYPE_HASHTREE or SPX_ADDR_TYPE_FORSTREE).
 * Applies the offset idx_offset to indices before building addresses, so that
 * it is possible to continue counting indices across trees.
 */

void treehashx1_shake_128_f(unsigned char *root, unsigned char *auth_path,
                const spx_ctx_shake_128_f *ctx,
                uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
                void (*gen_leaf)(
                    unsigned char * /* Where to write the leaf */,
                    const spx_ctx_shake_128_f * /* ctx */,
                    uint32_t addr_idx, void *info),
                uint32_t tree_addrx4[8], void *info);
void treehashx1_shake_128_s(unsigned char* root, unsigned char* auth_path,
    const spx_ctx_shake_128_s* ctx,
    uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
    void (*gen_leaf)(
        unsigned char* /* Where to write the leaf */,
        const spx_ctx_shake_128_s* /* ctx */,
        uint32_t addr_idx, void* info),
    uint32_t tree_addrx4[8], void* info);

void treehashx1_shake_192_f(unsigned char* root, unsigned char* auth_path,
    const spx_ctx_shake_192_f* ctx,
    uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
    void (*gen_leaf)(
        unsigned char* /* Where to write the leaf */,
        const spx_ctx_shake_192_f* /* ctx */,
        uint32_t addr_idx, void* info),
    uint32_t tree_addrx4[8], void* info);
void treehashx1_shake_192_s(unsigned char* root, unsigned char* auth_path,
    const spx_ctx_shake_192_s* ctx,
    uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
    void (*gen_leaf)(
        unsigned char* /* Where to write the leaf */,
        const spx_ctx_shake_192_s* /* ctx */,
        uint32_t addr_idx, void* info),
    uint32_t tree_addrx4[8], void* info);

void treehashx1_shake_256_f(unsigned char* root, unsigned char* auth_path,
    const spx_ctx_shake_256_f* ctx,
    uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
    void (*gen_leaf)(
        unsigned char* /* Where to write the leaf */,
        const spx_ctx_shake_256_f* /* ctx */,
        uint32_t addr_idx, void* info),
    uint32_t tree_addrx4[8], void* info);
void treehashx1_shake_256_s(unsigned char* root, unsigned char* auth_path,
    const spx_ctx_shake_256_s* ctx,
    uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
    void (*gen_leaf)(
        unsigned char* /* Where to write the leaf */,
        const spx_ctx_shake_256_s* /* ctx */,
        uint32_t addr_idx, void* info),
    uint32_t tree_addrx4[8], void* info);

#endif
