#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "fors.h"

#include "address.h"
#include "hash.h"
#include "thash.h"
#include "utils.h"
#include "utilsx1.h"

static void fors_gen_sk_shake_128_f(unsigned char *sk, const spx_ctx_shake_128_f *ctx,
    uint32_t fors_leaf_addr[8]) {
    prf_addr_shake_128_f(sk, ctx, fors_leaf_addr);
}
static void fors_gen_sk_shake_128_s(unsigned char* sk, const spx_ctx_shake_128_s* ctx,
    uint32_t fors_leaf_addr[8]) {
    prf_addr_shake_128_s(sk, ctx, fors_leaf_addr);
}
static void fors_gen_sk_shake_192_f(unsigned char* sk, const spx_ctx_shake_192_f* ctx,
    uint32_t fors_leaf_addr[8]) {
    prf_addr_shake_192_f(sk, ctx, fors_leaf_addr);
}
static void fors_gen_sk_shake_192_s(unsigned char* sk, const spx_ctx_shake_192_s* ctx,
    uint32_t fors_leaf_addr[8]) {
    prf_addr_shake_192_s(sk, ctx, fors_leaf_addr);
}
static void fors_gen_sk_shake_256_f(unsigned char* sk, const spx_ctx_shake_256_f* ctx,
    uint32_t fors_leaf_addr[8]) {
    prf_addr_shake_256_f(sk, ctx, fors_leaf_addr);
}
static void fors_gen_sk_shake_256_s(unsigned char* sk, const spx_ctx_shake_256_s* ctx,
    uint32_t fors_leaf_addr[8]) {
    prf_addr_shake_256_s(sk, ctx, fors_leaf_addr);
}

static void fors_sk_to_leaf_shake_128_f(unsigned char *leaf, const unsigned char *sk,
    const spx_ctx_shake_128_f *ctx,
    uint32_t fors_leaf_addr[8]) {
    thash_shake_128_f(leaf, sk, 1, ctx, fors_leaf_addr);
}
static void fors_sk_to_leaf_shake_128_s(unsigned char* leaf, const unsigned char* sk,
    const spx_ctx_shake_128_s* ctx,
    uint32_t fors_leaf_addr[8]) {
    thash_shake_128_s(leaf, sk, 1, ctx, fors_leaf_addr);
}
static void fors_sk_to_leaf_shake_192_f(unsigned char* leaf, const unsigned char* sk,
    const spx_ctx_shake_192_f* ctx,
    uint32_t fors_leaf_addr[8]) {
    thash_shake_192_f(leaf, sk, 1, ctx, fors_leaf_addr);
}
static void fors_sk_to_leaf_shake_192_s(unsigned char* leaf, const unsigned char* sk,
    const spx_ctx_shake_192_s* ctx,
    uint32_t fors_leaf_addr[8]) {
    thash_shake_192_s(leaf, sk, 1, ctx, fors_leaf_addr);
}
static void fors_sk_to_leaf_shake_256_f(unsigned char* leaf, const unsigned char* sk,
    const spx_ctx_shake_256_f* ctx,
    uint32_t fors_leaf_addr[8]) {
    thash_shake_256_f(leaf, sk, 1, ctx, fors_leaf_addr);
}
static void fors_sk_to_leaf_shake_256_s(unsigned char* leaf, const unsigned char* sk,
    const spx_ctx_shake_256_s* ctx,
    uint32_t fors_leaf_addr[8]) {
    thash_shake_256_s(leaf, sk, 1, ctx, fors_leaf_addr);
}


struct fors_gen_leaf_info {
    uint32_t leaf_addrx[8];
};

static void fors_gen_leafx1_shake_128_f(unsigned char *leaf,
    const spx_ctx_shake_128_f*ctx,
    uint32_t addr_idx, void *info) {
    struct fors_gen_leaf_info *fors_info = info;
    uint32_t *fors_leaf_addr = fors_info->leaf_addrx;

    /* Only set the parts that the caller doesn't set */
    set_tree_index(fors_leaf_addr, addr_idx);
    set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSPRF);
    fors_gen_sk_shake_128_f(leaf, ctx, fors_leaf_addr);

    set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSTREE);
    fors_sk_to_leaf_shake_128_f(leaf, leaf,
                    ctx, fors_leaf_addr);
}
static void fors_gen_leafx1_shake_128_s(unsigned char* leaf,
    const spx_ctx_shake_128_s* ctx,
    uint32_t addr_idx, void* info) {
    struct fors_gen_leaf_info* fors_info = info;
    uint32_t* fors_leaf_addr = fors_info->leaf_addrx;

    /* Only set the parts that the caller doesn't set */
    set_tree_index(fors_leaf_addr, addr_idx);
    set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSPRF);
    fors_gen_sk_shake_128_s(leaf, ctx, fors_leaf_addr);

    set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSTREE);
    fors_sk_to_leaf_shake_128_s(leaf, leaf,
        ctx, fors_leaf_addr);
}

static void fors_gen_leafx1_shake_192_f(unsigned char* leaf,
    const spx_ctx_shake_192_f* ctx,
    uint32_t addr_idx, void* info) {
    struct fors_gen_leaf_info* fors_info = info;
    uint32_t* fors_leaf_addr = fors_info->leaf_addrx;

    /* Only set the parts that the caller doesn't set */
    set_tree_index(fors_leaf_addr, addr_idx);
    set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSPRF);
    fors_gen_sk_shake_192_f(leaf, ctx, fors_leaf_addr);

    set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSTREE);
    fors_sk_to_leaf_shake_192_f(leaf, leaf,
        ctx, fors_leaf_addr);
}
static void fors_gen_leafx1_shake_192_s(unsigned char* leaf,
    const spx_ctx_shake_192_s* ctx,
    uint32_t addr_idx, void* info) {
    struct fors_gen_leaf_info* fors_info = info;
    uint32_t* fors_leaf_addr = fors_info->leaf_addrx;

    /* Only set the parts that the caller doesn't set */
    set_tree_index(fors_leaf_addr, addr_idx);
    set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSPRF);
    fors_gen_sk_shake_192_s(leaf, ctx, fors_leaf_addr);

    set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSTREE);
    fors_sk_to_leaf_shake_192_s(leaf, leaf,
        ctx, fors_leaf_addr);
}

static void fors_gen_leafx1_shake_256_f(unsigned char* leaf,
    const spx_ctx_shake_256_f* ctx,
    uint32_t addr_idx, void* info) {
    struct fors_gen_leaf_info* fors_info = info;
    uint32_t* fors_leaf_addr = fors_info->leaf_addrx;

    /* Only set the parts that the caller doesn't set */
    set_tree_index(fors_leaf_addr, addr_idx);
    set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSPRF);
    fors_gen_sk_shake_256_f(leaf, ctx, fors_leaf_addr);

    set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSTREE);
    fors_sk_to_leaf_shake_256_f(leaf, leaf,
        ctx, fors_leaf_addr);
}
static void fors_gen_leafx1_shake_256_s(unsigned char* leaf,
    const spx_ctx_shake_256_s* ctx,
    uint32_t addr_idx, void* info) {
    struct fors_gen_leaf_info* fors_info = info;
    uint32_t* fors_leaf_addr = fors_info->leaf_addrx;

    /* Only set the parts that the caller doesn't set */
    set_tree_index(fors_leaf_addr, addr_idx);
    set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSPRF);
    fors_gen_sk_shake_256_s(leaf, ctx, fors_leaf_addr);

    set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSTREE);
    fors_sk_to_leaf_shake_256_s(leaf, leaf,
        ctx, fors_leaf_addr);
}

/**
 * Interprets m as SPX_FORS_HEIGHT-bit unsigned integers.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 * Assumes indices has space for SPX_FORS_TREES integers.
 */
static void message_to_indices_shake_128_f(uint32_t *indices, const unsigned char *m) {
    unsigned int i, j;
    unsigned int offset = 0;

    for (i = 0; i < SPX_FORS_TREES_SHAKE_128_F; i++) {
        indices[i] = 0;
        for (j = 0; j < SPX_FORS_HEIGHT_SHAKE_128_F; j++) {
            indices[i] ^= (uint32_t)(((m[offset >> 3] >> (offset & 0x7)) & 0x1) << j);
            offset++;
        }
    }
}
static void message_to_indices_shake_128_s(uint32_t* indices, const unsigned char* m) {
    unsigned int i, j;
    unsigned int offset = 0;

    for (i = 0; i < SPX_FORS_TREES_SHAKE_128_S; i++) {
        indices[i] = 0;
        for (j = 0; j < SPX_FORS_HEIGHT_SHAKE_128_S; j++) {
            indices[i] ^= (uint32_t)(((m[offset >> 3] >> (offset & 0x7)) & 0x1) << j);
            offset++;
        }
    }
}
static void message_to_indices_shake_192_f(uint32_t* indices, const unsigned char* m) {
    unsigned int i, j;
    unsigned int offset = 0;

    for (i = 0; i < SPX_FORS_TREES_SHAKE_192_F; i++) {
        indices[i] = 0;
        for (j = 0; j < SPX_FORS_HEIGHT_SHAKE_192_F; j++) {
            indices[i] ^= (uint32_t)(((m[offset >> 3] >> (offset & 0x7)) & 0x1) << j);
            offset++;
        }
    }
}
static void message_to_indices_shake_192_s(uint32_t* indices, const unsigned char* m) {
    unsigned int i, j;
    unsigned int offset = 0;

    for (i = 0; i < SPX_FORS_TREES_SHAKE_192_S; i++) {
        indices[i] = 0;
        for (j = 0; j < SPX_FORS_HEIGHT_SHAKE_192_S; j++) {
            indices[i] ^= (uint32_t)(((m[offset >> 3] >> (offset & 0x7)) & 0x1) << j);
            offset++;
        }
    }
}
static void message_to_indices_shake_256_f(uint32_t* indices, const unsigned char* m) {
    unsigned int i, j;
    unsigned int offset = 0;

    for (i = 0; i < SPX_FORS_TREES_SHAKE_256_F; i++) {
        indices[i] = 0;
        for (j = 0; j < SPX_FORS_HEIGHT_SHAKE_256_F; j++) {
            indices[i] ^= (uint32_t)(((m[offset >> 3] >> (offset & 0x7)) & 0x1) << j);
            offset++;
        }
    }
}
static void message_to_indices_shake_256_s(uint32_t* indices, const unsigned char* m) {
    unsigned int i, j;
    unsigned int offset = 0;

    for (i = 0; i < SPX_FORS_TREES_SHAKE_256_S; i++) {
        indices[i] = 0;
        for (j = 0; j < SPX_FORS_HEIGHT_SHAKE_256_S; j++) {
            indices[i] ^= (uint32_t)(((m[offset >> 3] >> (offset & 0x7)) & 0x1) << j);
            offset++;
        }
    }
}

/**
 * Signs a message m, deriving the secret key from sk_seed and the FTS address.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 */
void fors_sign_shake_128_f(unsigned char *sig, unsigned char *pk,
               const unsigned char *m,
               const spx_ctx_shake_128_f *ctx,
               const uint32_t fors_addr[8]) {
    uint32_t indices[SPX_FORS_TREES_SHAKE_128_F];
    unsigned char roots[SPX_FORS_TREES_SHAKE_128_F * SPX_N_SHAKE_128_F];
    uint32_t fors_tree_addr[8] = {0};
    struct fors_gen_leaf_info fors_info = {0};
    uint32_t *fors_leaf_addr = fors_info.leaf_addrx;
    uint32_t fors_pk_addr[8] = {0};
    uint32_t idx_offset;
    unsigned int i;

    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_leaf_addr, fors_addr);

    copy_keypair_addr(fors_pk_addr, fors_addr);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices_shake_128_f(indices, m);

    for (i = 0; i < SPX_FORS_TREES_SHAKE_128_F; i++) {
        idx_offset = i * (1 << SPX_FORS_HEIGHT_SHAKE_128_F);

        set_tree_height(fors_tree_addr, 0);
        set_tree_index(fors_tree_addr, indices[i] + idx_offset);
        set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSPRF);

        /* Include the secret key part that produces the selected leaf node. */
        fors_gen_sk_shake_128_f(sig, ctx, fors_tree_addr);
        set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
        sig += SPX_N_SHAKE_128_F;

        /* Compute the authentication path for this leaf node. */
        treehashx1_shake_128_f(roots + i * SPX_N_SHAKE_128_F, sig, ctx,
                   indices[i], idx_offset, SPX_FORS_HEIGHT_SHAKE_128_F, fors_gen_leafx1_shake_128_f,
                   fors_tree_addr, &fors_info);

        sig += SPX_N_SHAKE_128_F * SPX_FORS_HEIGHT_SHAKE_128_F;
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    thash_shake_128_f(pk, roots, SPX_FORS_TREES_SHAKE_128_F, ctx, fors_pk_addr);
}

void fors_sign_shake_128_s(unsigned char* sig, unsigned char* pk,
    const unsigned char* m,
    const spx_ctx_shake_128_s* ctx,
    const uint32_t fors_addr[8]) {
    uint32_t indices[SPX_FORS_TREES_SHAKE_128_S];
    unsigned char roots[SPX_FORS_TREES_SHAKE_128_S * SPX_N_SHAKE_128_S];
    uint32_t fors_tree_addr[8] = { 0 };
    struct fors_gen_leaf_info fors_info = { 0 };
    uint32_t* fors_leaf_addr = fors_info.leaf_addrx;
    uint32_t fors_pk_addr[8] = { 0 };
    uint32_t idx_offset;
    unsigned int i;

    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_leaf_addr, fors_addr);

    copy_keypair_addr(fors_pk_addr, fors_addr);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices_shake_128_s(indices, m);

    for (i = 0; i < SPX_FORS_TREES_SHAKE_128_S; i++) {
        idx_offset = i * (1 << SPX_FORS_HEIGHT_SHAKE_128_S);

        set_tree_height(fors_tree_addr, 0);
        set_tree_index(fors_tree_addr, indices[i] + idx_offset);
        set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSPRF);

        /* Include the secret key part that produces the selected leaf node. */
        fors_gen_sk_shake_128_s(sig, ctx, fors_tree_addr);
        set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
        sig += SPX_N_SHAKE_128_S;

        /* Compute the authentication path for this leaf node. */
        treehashx1_shake_128_s(roots + i * SPX_N_SHAKE_128_S, sig, ctx,
            indices[i], idx_offset, SPX_FORS_HEIGHT_SHAKE_128_S, fors_gen_leafx1_shake_128_s,
            fors_tree_addr, &fors_info);

        sig += SPX_N_SHAKE_128_S * SPX_FORS_HEIGHT_SHAKE_128_S;
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    thash_shake_128_s(pk, roots, SPX_FORS_TREES_SHAKE_128_S, ctx, fors_pk_addr);
}

void fors_sign_shake_192_f(unsigned char* sig, unsigned char* pk,
    const unsigned char* m,
    const spx_ctx_shake_192_f* ctx,
    const uint32_t fors_addr[8]) {
    uint32_t indices[SPX_FORS_TREES_SHAKE_192_F];
    unsigned char roots[SPX_FORS_TREES_SHAKE_192_F * SPX_N_SHAKE_192_F];
    uint32_t fors_tree_addr[8] = { 0 };
    struct fors_gen_leaf_info fors_info = { 0 };
    uint32_t* fors_leaf_addr = fors_info.leaf_addrx;
    uint32_t fors_pk_addr[8] = { 0 };
    uint32_t idx_offset;
    unsigned int i;

    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_leaf_addr, fors_addr);

    copy_keypair_addr(fors_pk_addr, fors_addr);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices_shake_192_f(indices, m);

    for (i = 0; i < SPX_FORS_TREES_SHAKE_192_F; i++) {
        idx_offset = i * (1 << SPX_FORS_HEIGHT_SHAKE_192_F);

        set_tree_height(fors_tree_addr, 0);
        set_tree_index(fors_tree_addr, indices[i] + idx_offset);
        set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSPRF);

        /* Include the secret key part that produces the selected leaf node. */
        fors_gen_sk_shake_192_f(sig, ctx, fors_tree_addr);
        set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
        sig += SPX_N_SHAKE_192_F;

        /* Compute the authentication path for this leaf node. */
        treehashx1_shake_192_f(roots + i * SPX_N_SHAKE_192_F, sig, ctx,
            indices[i], idx_offset, SPX_FORS_HEIGHT_SHAKE_192_F, fors_gen_leafx1_shake_192_f,
            fors_tree_addr, &fors_info);

        sig += SPX_N_SHAKE_192_F * SPX_FORS_HEIGHT_SHAKE_192_F;
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    thash_shake_192_f(pk, roots, SPX_FORS_TREES_SHAKE_192_F, ctx, fors_pk_addr);
}

void fors_sign_shake_192_s(unsigned char* sig, unsigned char* pk,
    const unsigned char* m,
    const spx_ctx_shake_192_s* ctx,
    const uint32_t fors_addr[8]) {
    uint32_t indices[SPX_FORS_TREES_SHAKE_192_S];
    unsigned char roots[SPX_FORS_TREES_SHAKE_192_S * SPX_N_SHAKE_192_S];
    uint32_t fors_tree_addr[8] = { 0 };
    struct fors_gen_leaf_info fors_info = { 0 };
    uint32_t* fors_leaf_addr = fors_info.leaf_addrx;
    uint32_t fors_pk_addr[8] = { 0 };
    uint32_t idx_offset;
    unsigned int i;

    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_leaf_addr, fors_addr);

    copy_keypair_addr(fors_pk_addr, fors_addr);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices_shake_192_s(indices, m);

    for (i = 0; i < SPX_FORS_TREES_SHAKE_192_S; i++) {
        idx_offset = i * (1 << SPX_FORS_HEIGHT_SHAKE_192_S);

        set_tree_height(fors_tree_addr, 0);
        set_tree_index(fors_tree_addr, indices[i] + idx_offset);
        set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSPRF);

        /* Include the secret key part that produces the selected leaf node. */
        fors_gen_sk_shake_192_s(sig, ctx, fors_tree_addr);
        set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
        sig += SPX_N_SHAKE_192_S;

        /* Compute the authentication path for this leaf node. */
        treehashx1_shake_192_s(roots + i * SPX_N_SHAKE_192_S, sig, ctx,
            indices[i], idx_offset, SPX_FORS_HEIGHT_SHAKE_192_S, fors_gen_leafx1_shake_192_s,
            fors_tree_addr, &fors_info);

        sig += SPX_N_SHAKE_192_S * SPX_FORS_HEIGHT_SHAKE_192_S;
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    thash_shake_192_s(pk, roots, SPX_FORS_TREES_SHAKE_192_S, ctx, fors_pk_addr);
}

void fors_sign_shake_256_f(unsigned char* sig, unsigned char* pk,
    const unsigned char* m,
    const spx_ctx_shake_256_f* ctx,
    const uint32_t fors_addr[8]) {
    uint32_t indices[SPX_FORS_TREES_SHAKE_256_F];
    unsigned char roots[SPX_FORS_TREES_SHAKE_256_F * SPX_N_SHAKE_256_F];
    uint32_t fors_tree_addr[8] = { 0 };
    struct fors_gen_leaf_info fors_info = { 0 };
    uint32_t* fors_leaf_addr = fors_info.leaf_addrx;
    uint32_t fors_pk_addr[8] = { 0 };
    uint32_t idx_offset;
    unsigned int i;

    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_leaf_addr, fors_addr);

    copy_keypair_addr(fors_pk_addr, fors_addr);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices_shake_256_f(indices, m);

    for (i = 0; i < SPX_FORS_TREES_SHAKE_256_F; i++) {
        idx_offset = i * (1 << SPX_FORS_HEIGHT_SHAKE_256_F);

        set_tree_height(fors_tree_addr, 0);
        set_tree_index(fors_tree_addr, indices[i] + idx_offset);
        set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSPRF);

        /* Include the secret key part that produces the selected leaf node. */
        fors_gen_sk_shake_256_f(sig, ctx, fors_tree_addr);
        set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
        sig += SPX_N_SHAKE_256_F;

        /* Compute the authentication path for this leaf node. */
        treehashx1_shake_256_f(roots + i * SPX_N_SHAKE_256_F, sig, ctx,
            indices[i], idx_offset, SPX_FORS_HEIGHT_SHAKE_256_F, fors_gen_leafx1_shake_256_f,
            fors_tree_addr, &fors_info);

        sig += SPX_N_SHAKE_256_F * SPX_FORS_HEIGHT_SHAKE_256_F;
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    thash_shake_256_f(pk, roots, SPX_FORS_TREES_SHAKE_256_F, ctx, fors_pk_addr);
}

void fors_sign_shake_256_s(unsigned char* sig, unsigned char* pk,
    const unsigned char* m,
    const spx_ctx_shake_256_s* ctx,
    const uint32_t fors_addr[8]) {
    uint32_t indices[SPX_FORS_TREES_SHAKE_256_S];
    unsigned char roots[SPX_FORS_TREES_SHAKE_256_S * SPX_N_SHAKE_256_S];
    uint32_t fors_tree_addr[8] = { 0 };
    struct fors_gen_leaf_info fors_info = { 0 };
    uint32_t* fors_leaf_addr = fors_info.leaf_addrx;
    uint32_t fors_pk_addr[8] = { 0 };
    uint32_t idx_offset;
    unsigned int i;

    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_leaf_addr, fors_addr);

    copy_keypair_addr(fors_pk_addr, fors_addr);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices_shake_256_s(indices, m);

    for (i = 0; i < SPX_FORS_TREES_SHAKE_256_S; i++) {
        idx_offset = i * (1 << SPX_FORS_HEIGHT_SHAKE_256_S);

        set_tree_height(fors_tree_addr, 0);
        set_tree_index(fors_tree_addr, indices[i] + idx_offset);
        set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSPRF);

        /* Include the secret key part that produces the selected leaf node. */
        fors_gen_sk_shake_256_s(sig, ctx, fors_tree_addr);
        set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
        sig += SPX_N_SHAKE_256_S;

        /* Compute the authentication path for this leaf node. */
        treehashx1_shake_256_s(roots + i * SPX_N_SHAKE_256_S, sig, ctx,
            indices[i], idx_offset, SPX_FORS_HEIGHT_SHAKE_256_S, fors_gen_leafx1_shake_256_s,
            fors_tree_addr, &fors_info);

        sig += SPX_N_SHAKE_256_S * SPX_FORS_HEIGHT_SHAKE_256_S;
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    thash_shake_256_s(pk, roots, SPX_FORS_TREES_SHAKE_256_S, ctx, fors_pk_addr);
}

/**
 * Derives the FORS public key from a signature.
 * This can be used for verification by comparing to a known public key, or to
 * subsequently verify a signature on the derived public key. The latter is the
 * typical use-case when used as an FTS below an OTS in a hypertree.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 */
void fors_pk_from_sig_shake_128_f(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *m,
                      const spx_ctx_shake_128_f*ctx,
                      const uint32_t fors_addr[8]) {
    uint32_t indices[SPX_FORS_TREES_SHAKE_128_F];
    unsigned char roots[SPX_FORS_TREES_SHAKE_128_F * SPX_N_SHAKE_128_F];
    unsigned char leaf[SPX_N_SHAKE_128_F];
    uint32_t fors_tree_addr[8] = {0};
    uint32_t fors_pk_addr[8] = {0};
    uint32_t idx_offset;
    unsigned int i;

    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_pk_addr, fors_addr);

    set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices_shake_128_f(indices, m);

    for (i = 0; i < SPX_FORS_TREES_SHAKE_128_F; i++) {
        idx_offset = i * (1 << SPX_FORS_HEIGHT_SHAKE_128_F);

        set_tree_height(fors_tree_addr, 0);
        set_tree_index(fors_tree_addr, indices[i] + idx_offset);

        /* Derive the leaf from the included secret key part. */
        fors_sk_to_leaf_shake_128_f(leaf, sig, ctx, fors_tree_addr);
        sig += SPX_N_SHAKE_128_F;

        /* Derive the corresponding root node of this tree. */
        compute_root_shake_128_f(roots + i * SPX_N_SHAKE_128_F, leaf, indices[i], idx_offset,
                     sig, SPX_FORS_HEIGHT_SHAKE_128_F, ctx, fors_tree_addr);
        sig += SPX_N_SHAKE_128_F * SPX_FORS_HEIGHT_SHAKE_128_F;
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    thash_shake_128_f(pk, roots, SPX_FORS_TREES_SHAKE_128_F, ctx, fors_pk_addr);
}

void fors_pk_from_sig_shake_128_s(unsigned char* pk,
    const unsigned char* sig, const unsigned char* m,
    const spx_ctx_shake_128_s* ctx,
    const uint32_t fors_addr[8]) {
    uint32_t indices[SPX_FORS_TREES_SHAKE_128_S];
    unsigned char roots[SPX_FORS_TREES_SHAKE_128_S * SPX_N_SHAKE_128_S];
    unsigned char leaf[SPX_N_SHAKE_128_S];
    uint32_t fors_tree_addr[8] = { 0 };
    uint32_t fors_pk_addr[8] = { 0 };
    uint32_t idx_offset;
    unsigned int i;

    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_pk_addr, fors_addr);

    set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices_shake_128_s(indices, m);

    for (i = 0; i < SPX_FORS_TREES_SHAKE_128_S; i++) {
        idx_offset = i * (1 << SPX_FORS_HEIGHT_SHAKE_128_S);

        set_tree_height(fors_tree_addr, 0);
        set_tree_index(fors_tree_addr, indices[i] + idx_offset);

        /* Derive the leaf from the included secret key part. */
        fors_sk_to_leaf_shake_128_s(leaf, sig, ctx, fors_tree_addr);
        sig += SPX_N_SHAKE_128_S;

        /* Derive the corresponding root node of this tree. */
        compute_root_shake_128_s(roots + i * SPX_N_SHAKE_128_S, leaf, indices[i], idx_offset,
            sig, SPX_FORS_HEIGHT_SHAKE_128_S, ctx, fors_tree_addr);
        sig += SPX_N_SHAKE_128_S * SPX_FORS_HEIGHT_SHAKE_128_S;
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    thash_shake_128_s(pk, roots, SPX_FORS_TREES_SHAKE_128_S, ctx, fors_pk_addr);
}

void fors_pk_from_sig_shake_192_f(unsigned char* pk,
    const unsigned char* sig, const unsigned char* m,
    const spx_ctx_shake_192_f* ctx,
    const uint32_t fors_addr[8]) {
    uint32_t indices[SPX_FORS_TREES_SHAKE_192_F];
    unsigned char roots[SPX_FORS_TREES_SHAKE_192_F * SPX_N_SHAKE_192_F];
    unsigned char leaf[SPX_N_SHAKE_192_F];
    uint32_t fors_tree_addr[8] = { 0 };
    uint32_t fors_pk_addr[8] = { 0 };
    uint32_t idx_offset;
    unsigned int i;

    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_pk_addr, fors_addr);

    set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices_shake_192_f(indices, m);

    for (i = 0; i < SPX_FORS_TREES_SHAKE_192_F; i++) {
        idx_offset = i * (1 << SPX_FORS_HEIGHT_SHAKE_192_F);

        set_tree_height(fors_tree_addr, 0);
        set_tree_index(fors_tree_addr, indices[i] + idx_offset);

        /* Derive the leaf from the included secret key part. */
        fors_sk_to_leaf_shake_192_f(leaf, sig, ctx, fors_tree_addr);
        sig += SPX_N_SHAKE_192_F;

        /* Derive the corresponding root node of this tree. */
        compute_root_shake_192_f(roots + i * SPX_N_SHAKE_192_F, leaf, indices[i], idx_offset,
            sig, SPX_FORS_HEIGHT_SHAKE_192_F, ctx, fors_tree_addr);
        sig += SPX_N_SHAKE_192_F * SPX_FORS_HEIGHT_SHAKE_192_F;
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    thash_shake_192_f(pk, roots, SPX_FORS_TREES_SHAKE_192_F, ctx, fors_pk_addr);
}

void fors_pk_from_sig_shake_192_s(unsigned char* pk,
    const unsigned char* sig, const unsigned char* m,
    const spx_ctx_shake_192_s* ctx,
    const uint32_t fors_addr[8]) {
    uint32_t indices[SPX_FORS_TREES_SHAKE_192_S];
    unsigned char roots[SPX_FORS_TREES_SHAKE_192_S * SPX_N_SHAKE_192_S];
    unsigned char leaf[SPX_N_SHAKE_192_S];
    uint32_t fors_tree_addr[8] = { 0 };
    uint32_t fors_pk_addr[8] = { 0 };
    uint32_t idx_offset;
    unsigned int i;

    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_pk_addr, fors_addr);

    set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices_shake_192_s(indices, m);

    for (i = 0; i < SPX_FORS_TREES_SHAKE_192_S; i++) {
        idx_offset = i * (1 << SPX_FORS_HEIGHT_SHAKE_192_S);

        set_tree_height(fors_tree_addr, 0);
        set_tree_index(fors_tree_addr, indices[i] + idx_offset);

        /* Derive the leaf from the included secret key part. */
        fors_sk_to_leaf_shake_192_s(leaf, sig, ctx, fors_tree_addr);
        sig += SPX_N_SHAKE_192_S;

        /* Derive the corresponding root node of this tree. */
        compute_root_shake_192_s(roots + i * SPX_N_SHAKE_192_S, leaf, indices[i], idx_offset,
            sig, SPX_FORS_HEIGHT_SHAKE_192_S, ctx, fors_tree_addr);
        sig += SPX_N_SHAKE_192_S * SPX_FORS_HEIGHT_SHAKE_192_S;
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    thash_shake_192_s(pk, roots, SPX_FORS_TREES_SHAKE_192_S, ctx, fors_pk_addr);
}

void fors_pk_from_sig_shake_256_f(unsigned char* pk,
    const unsigned char* sig, const unsigned char* m,
    const spx_ctx_shake_256_f* ctx,
    const uint32_t fors_addr[8]) {
    uint32_t indices[SPX_FORS_TREES_SHAKE_256_F];
    unsigned char roots[SPX_FORS_TREES_SHAKE_256_F * SPX_N_SHAKE_256_F];
    unsigned char leaf[SPX_N_SHAKE_256_F];
    uint32_t fors_tree_addr[8] = { 0 };
    uint32_t fors_pk_addr[8] = { 0 };
    uint32_t idx_offset;
    unsigned int i;

    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_pk_addr, fors_addr);

    set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices_shake_256_f(indices, m);

    for (i = 0; i < SPX_FORS_TREES_SHAKE_256_F; i++) {
        idx_offset = i * (1 << SPX_FORS_HEIGHT_SHAKE_256_F);

        set_tree_height(fors_tree_addr, 0);
        set_tree_index(fors_tree_addr, indices[i] + idx_offset);

        /* Derive the leaf from the included secret key part. */
        fors_sk_to_leaf_shake_256_f(leaf, sig, ctx, fors_tree_addr);
        sig += SPX_N_SHAKE_256_F;

        /* Derive the corresponding root node of this tree. */
        compute_root_shake_256_f(roots + i * SPX_N_SHAKE_256_F, leaf, indices[i], idx_offset,
            sig, SPX_FORS_HEIGHT_SHAKE_256_F, ctx, fors_tree_addr);
        sig += SPX_N_SHAKE_256_F * SPX_FORS_HEIGHT_SHAKE_256_F;
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    thash_shake_256_f(pk, roots, SPX_FORS_TREES_SHAKE_256_F, ctx, fors_pk_addr);
}

void fors_pk_from_sig_shake_256_s(unsigned char* pk,
    const unsigned char* sig, const unsigned char* m,
    const spx_ctx_shake_256_s* ctx,
    const uint32_t fors_addr[8]) {
    uint32_t indices[SPX_FORS_TREES_SHAKE_256_S];
    unsigned char roots[SPX_FORS_TREES_SHAKE_256_S * SPX_N_SHAKE_256_S];
    unsigned char leaf[SPX_N_SHAKE_256_S];
    uint32_t fors_tree_addr[8] = { 0 };
    uint32_t fors_pk_addr[8] = { 0 };
    uint32_t idx_offset;
    unsigned int i;

    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_pk_addr, fors_addr);

    set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices_shake_256_s(indices, m);

    for (i = 0; i < SPX_FORS_TREES_SHAKE_256_S; i++) {
        idx_offset = i * (1 << SPX_FORS_HEIGHT_SHAKE_256_S);

        set_tree_height(fors_tree_addr, 0);
        set_tree_index(fors_tree_addr, indices[i] + idx_offset);

        /* Derive the leaf from the included secret key part. */
        fors_sk_to_leaf_shake_256_s(leaf, sig, ctx, fors_tree_addr);
        sig += SPX_N_SHAKE_256_S;

        /* Derive the corresponding root node of this tree. */
        compute_root_shake_256_s(roots + i * SPX_N_SHAKE_256_S, leaf, indices[i], idx_offset,
            sig, SPX_FORS_HEIGHT_SHAKE_256_S, ctx, fors_tree_addr);
        sig += SPX_N_SHAKE_256_S * SPX_FORS_HEIGHT_SHAKE_256_S;
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    thash_shake_256_s(pk, roots, SPX_FORS_TREES_SHAKE_256_S, ctx, fors_pk_addr);
}