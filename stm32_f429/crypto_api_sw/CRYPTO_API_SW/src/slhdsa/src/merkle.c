#include <stdint.h>
#include <string.h>

#include "address.h"
#include "merkle.h"
#include "params.h"
#include "utils.h"
#include "utilsx1.h"
#include "wots.h"
#include "wotsx1.h"

/*
 * This generates a Merkle signature (WOTS signature followed by the Merkle
 * authentication path).  This is in this file because most of the complexity
 * is involved with the WOTS signature; the Merkle authentication path logic
 * is mostly hidden in treehashx4
 */
void merkle_sign_shake_128_f(uint8_t *sig, unsigned char *root,
    const spx_ctx_shake_128_f *ctx,
    uint32_t wots_addr[8], uint32_t tree_addr[8],
    uint32_t idx_leaf) {
    unsigned char *auth_path = sig + SPX_WOTS_BYTES_SHAKE_128_F;
    struct leaf_info_x1 info = { 0 };
    uint32_t steps[ SPX_WOTS_LEN_SHAKE_128_F ];

    info.wots_sig = sig;
    chain_lengths_shake_128_f(steps, root);
    info.wots_steps = steps;

    set_type(&tree_addr[0], SPX_ADDR_TYPE_HASHTREE);
    set_type(&info.pk_addr[0], SPX_ADDR_TYPE_WOTSPK);
    copy_subtree_addr(&info.leaf_addr[0], wots_addr);
    copy_subtree_addr(&info.pk_addr[0], wots_addr);

    info.wots_sign_leaf = idx_leaf;

    treehashx1_shake_128_f(root, auth_path, ctx,
               idx_leaf, 0,
               SPX_TREE_HEIGHT_SHAKE_128_F,
               wots_gen_leafx1_shake_128_f,
               tree_addr, &info);
}
void merkle_sign_shake_128_s(uint8_t* sig, unsigned char* root,
    const spx_ctx_shake_128_s* ctx,
    uint32_t wots_addr[8], uint32_t tree_addr[8],
    uint32_t idx_leaf) {
    unsigned char* auth_path = sig + SPX_WOTS_BYTES_SHAKE_128_S;
    struct leaf_info_x1 info = { 0 };
    uint32_t steps[SPX_WOTS_LEN_SHAKE_128_S];

    info.wots_sig = sig;
    chain_lengths_shake_128_s(steps, root);
    info.wots_steps = steps;

    set_type(&tree_addr[0], SPX_ADDR_TYPE_HASHTREE);
    set_type(&info.pk_addr[0], SPX_ADDR_TYPE_WOTSPK);
    copy_subtree_addr(&info.leaf_addr[0], wots_addr);
    copy_subtree_addr(&info.pk_addr[0], wots_addr);

    info.wots_sign_leaf = idx_leaf;

    treehashx1_shake_128_s(root, auth_path, ctx,
        idx_leaf, 0,
        SPX_TREE_HEIGHT_SHAKE_128_S,
        wots_gen_leafx1_shake_128_s,
        tree_addr, &info);
}

void merkle_sign_shake_192_f(uint8_t* sig, unsigned char* root,
    const spx_ctx_shake_192_f* ctx,
    uint32_t wots_addr[8], uint32_t tree_addr[8],
    uint32_t idx_leaf) {
    unsigned char* auth_path = sig + SPX_WOTS_BYTES_SHAKE_192_F;
    struct leaf_info_x1 info = { 0 };
    uint32_t steps[SPX_WOTS_LEN_SHAKE_192_F];

    info.wots_sig = sig;
    chain_lengths_shake_192_f(steps, root);
    info.wots_steps = steps;

    set_type(&tree_addr[0], SPX_ADDR_TYPE_HASHTREE);
    set_type(&info.pk_addr[0], SPX_ADDR_TYPE_WOTSPK);
    copy_subtree_addr(&info.leaf_addr[0], wots_addr);
    copy_subtree_addr(&info.pk_addr[0], wots_addr);

    info.wots_sign_leaf = idx_leaf;

    treehashx1_shake_192_f(root, auth_path, ctx,
        idx_leaf, 0,
        SPX_TREE_HEIGHT_SHAKE_192_F,
        wots_gen_leafx1_shake_192_f,
        tree_addr, &info);
}
void merkle_sign_shake_192_s(uint8_t* sig, unsigned char* root,
    const spx_ctx_shake_192_s* ctx,
    uint32_t wots_addr[8], uint32_t tree_addr[8],
    uint32_t idx_leaf) {
    unsigned char* auth_path = sig + SPX_WOTS_BYTES_SHAKE_192_S;
    struct leaf_info_x1 info = { 0 };
    uint32_t steps[SPX_WOTS_LEN_SHAKE_192_S];

    info.wots_sig = sig;
    chain_lengths_shake_192_s(steps, root);
    info.wots_steps = steps;

    set_type(&tree_addr[0], SPX_ADDR_TYPE_HASHTREE);
    set_type(&info.pk_addr[0], SPX_ADDR_TYPE_WOTSPK);
    copy_subtree_addr(&info.leaf_addr[0], wots_addr);
    copy_subtree_addr(&info.pk_addr[0], wots_addr);

    info.wots_sign_leaf = idx_leaf;

    treehashx1_shake_192_s(root, auth_path, ctx,
        idx_leaf, 0,
        SPX_TREE_HEIGHT_SHAKE_192_S,
        wots_gen_leafx1_shake_192_s,
        tree_addr, &info);
}

void merkle_sign_shake_256_f(uint8_t* sig, unsigned char* root,
    const spx_ctx_shake_256_f* ctx,
    uint32_t wots_addr[8], uint32_t tree_addr[8],
    uint32_t idx_leaf) {
    unsigned char* auth_path = sig + SPX_WOTS_BYTES_SHAKE_256_F;
    struct leaf_info_x1 info = { 0 };
    uint32_t steps[SPX_WOTS_LEN_SHAKE_256_F];

    info.wots_sig = sig;
    chain_lengths_shake_256_f(steps, root);
    info.wots_steps = steps;

    set_type(&tree_addr[0], SPX_ADDR_TYPE_HASHTREE);
    set_type(&info.pk_addr[0], SPX_ADDR_TYPE_WOTSPK);
    copy_subtree_addr(&info.leaf_addr[0], wots_addr);
    copy_subtree_addr(&info.pk_addr[0], wots_addr);

    info.wots_sign_leaf = idx_leaf;

    treehashx1_shake_256_f(root, auth_path, ctx,
        idx_leaf, 0,
        SPX_TREE_HEIGHT_SHAKE_256_F,
        wots_gen_leafx1_shake_256_f,
        tree_addr, &info);
}
void merkle_sign_shake_256_s(uint8_t* sig, unsigned char* root,
    const spx_ctx_shake_256_s* ctx,
    uint32_t wots_addr[8], uint32_t tree_addr[8],
    uint32_t idx_leaf) {
    unsigned char* auth_path = sig + SPX_WOTS_BYTES_SHAKE_256_S;
    struct leaf_info_x1 info = { 0 };
    uint32_t steps[SPX_WOTS_LEN_SHAKE_256_S];

    info.wots_sig = sig;
    chain_lengths_shake_256_s(steps, root);
    info.wots_steps = steps;

    set_type(&tree_addr[0], SPX_ADDR_TYPE_HASHTREE);
    set_type(&info.pk_addr[0], SPX_ADDR_TYPE_WOTSPK);
    copy_subtree_addr(&info.leaf_addr[0], wots_addr);
    copy_subtree_addr(&info.pk_addr[0], wots_addr);

    info.wots_sign_leaf = idx_leaf;

    treehashx1_shake_256_s(root, auth_path, ctx,
        idx_leaf, 0,
        SPX_TREE_HEIGHT_SHAKE_256_S,
        wots_gen_leafx1_shake_256_s,
        tree_addr, &info);
}


/* Compute root node of the top-most subtree. */
void merkle_gen_root_shake_128_f(unsigned char *root, const spx_ctx_shake_128_f *ctx) {
    /* We do not need the auth path in key generation, but it simplifies the
       code to have just one treehash routine that computes both root and path
       in one function. */
    unsigned char auth_path[SPX_TREE_HEIGHT_SHAKE_128_F * SPX_N_SHAKE_128_F + SPX_WOTS_BYTES_SHAKE_128_F];
    uint32_t top_tree_addr[8] = {0};
    uint32_t wots_addr[8] = {0};

    set_layer_addr(top_tree_addr, SPX_D_SHAKE_128_F - 1);
    set_layer_addr(wots_addr, SPX_D_SHAKE_128_F - 1);

    merkle_sign_shake_128_f(auth_path, root, ctx,
                wots_addr, top_tree_addr,
                ~0U /* ~0 means "don't bother generating an auth path */ );
}
void merkle_gen_root_shake_128_s(unsigned char* root, const spx_ctx_shake_128_s* ctx) {
    /* We do not need the auth path in key generation, but it simplifies the
       code to have just one treehash routine that computes both root and path
       in one function. */
    unsigned char auth_path[SPX_TREE_HEIGHT_SHAKE_128_S * SPX_N_SHAKE_128_S + SPX_WOTS_BYTES_SHAKE_128_S];
    uint32_t top_tree_addr[8] = { 0 };
    uint32_t wots_addr[8] = { 0 };

    set_layer_addr(top_tree_addr, SPX_D_SHAKE_128_S - 1);
    set_layer_addr(wots_addr, SPX_D_SHAKE_128_S - 1);

    merkle_sign_shake_128_s(auth_path, root, ctx,
        wots_addr, top_tree_addr,
        ~0U /* ~0 means "don't bother generating an auth path */);
}

void merkle_gen_root_shake_192_f(unsigned char* root, const spx_ctx_shake_192_f* ctx) {
    /* We do not need the auth path in key generation, but it simplifies the
       code to have just one treehash routine that computes both root and path
       in one function. */
    unsigned char auth_path[SPX_TREE_HEIGHT_SHAKE_192_F * SPX_N_SHAKE_192_F + SPX_WOTS_BYTES_SHAKE_192_F];
    uint32_t top_tree_addr[8] = { 0 };
    uint32_t wots_addr[8] = { 0 };

    set_layer_addr(top_tree_addr, SPX_D_SHAKE_192_F - 1);
    set_layer_addr(wots_addr, SPX_D_SHAKE_192_F - 1);

    merkle_sign_shake_192_f(auth_path, root, ctx,
        wots_addr, top_tree_addr,
        ~0U /* ~0 means "don't bother generating an auth path */);
}
void merkle_gen_root_shake_192_s(unsigned char* root, const spx_ctx_shake_192_s* ctx) {
    /* We do not need the auth path in key generation, but it simplifies the
       code to have just one treehash routine that computes both root and path
       in one function. */
    unsigned char auth_path[SPX_TREE_HEIGHT_SHAKE_192_S * SPX_N_SHAKE_192_S + SPX_WOTS_BYTES_SHAKE_192_S];
    uint32_t top_tree_addr[8] = { 0 };
    uint32_t wots_addr[8] = { 0 };

    set_layer_addr(top_tree_addr, SPX_D_SHAKE_192_S - 1);
    set_layer_addr(wots_addr, SPX_D_SHAKE_192_S - 1);

    merkle_sign_shake_192_s(auth_path, root, ctx,
        wots_addr, top_tree_addr,
        ~0U /* ~0 means "don't bother generating an auth path */);
}

void merkle_gen_root_shake_256_f(unsigned char* root, const spx_ctx_shake_256_f* ctx) {
    /* We do not need the auth path in key generation, but it simplifies the
       code to have just one treehash routine that computes both root and path
       in one function. */
    unsigned char auth_path[SPX_TREE_HEIGHT_SHAKE_256_F * SPX_N_SHAKE_256_F + SPX_WOTS_BYTES_SHAKE_256_F];
    uint32_t top_tree_addr[8] = { 0 };
    uint32_t wots_addr[8] = { 0 };

    set_layer_addr(top_tree_addr, SPX_D_SHAKE_256_F - 1);
    set_layer_addr(wots_addr, SPX_D_SHAKE_256_F - 1);

    merkle_sign_shake_256_f(auth_path, root, ctx,
        wots_addr, top_tree_addr,
        ~0U /* ~0 means "don't bother generating an auth path */);
}
void merkle_gen_root_shake_256_s(unsigned char* root, const spx_ctx_shake_256_s* ctx) {
    /* We do not need the auth path in key generation, but it simplifies the
       code to have just one treehash routine that computes both root and path
       in one function. */
    unsigned char auth_path[SPX_TREE_HEIGHT_SHAKE_256_S * SPX_N_SHAKE_256_S + SPX_WOTS_BYTES_SHAKE_256_S];
    uint32_t top_tree_addr[8] = { 0 };
    uint32_t wots_addr[8] = { 0 };

    set_layer_addr(top_tree_addr, SPX_D_SHAKE_256_S - 1);
    set_layer_addr(wots_addr, SPX_D_SHAKE_256_S - 1);

    merkle_sign_shake_256_s(auth_path, root, ctx,
        wots_addr, top_tree_addr,
        ~0U /* ~0 means "don't bother generating an auth path */);
}
