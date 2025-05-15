#include <stdint.h>
#include <string.h>

#include "wots.h"
#include "wotsx1.h"

#include "address.h"
#include "hash.h"
#include "params.h"
#include "thash.h"
#include "utils.h"

/*
 * This generates a WOTS public key
 * It also generates the WOTS signature if leaf_info indicates
 * that we're signing with this WOTS key
 */
void wots_gen_leafx1_shake_128_f(unsigned char *dest,
                     const spx_ctx_shake_128_f *ctx,
                     uint32_t leaf_idx, void *v_info) {
    struct leaf_info_x1 *info = v_info;
    uint32_t *leaf_addr = info->leaf_addr;
    uint32_t *pk_addr = info->pk_addr;
    uint32_t i, k;
    unsigned char pk_buffer[ SPX_WOTS_BYTES_SHAKE_128_F ];
    unsigned char *buffer;
    uint32_t wots_k_mask;

    if (leaf_idx == info->wots_sign_leaf) {
        /* We're traversing the leaf that's signing; generate the WOTS */
        /* signature */
        wots_k_mask = 0;
    } else {
        /* Nope, we're just generating pk's; turn off the signature logic */
        wots_k_mask = (uint32_t)~0;
    }

    set_keypair_addr( leaf_addr, leaf_idx );
    set_keypair_addr( pk_addr, leaf_idx );

    for (i = 0, buffer = pk_buffer; i < SPX_WOTS_LEN_SHAKE_128_F; i++, buffer += SPX_N_SHAKE_128_F) {
        uint32_t wots_k = info->wots_steps[i] | wots_k_mask; /* Set wots_k to */
        /* the step if we're generating a signature, ~0 if we're not */

        /* Start with the secret seed */
        set_chain_addr(leaf_addr, i);
        set_hash_addr(leaf_addr, 0);
        set_type(leaf_addr, SPX_ADDR_TYPE_WOTSPRF);

        prf_addr_shake_128_f(buffer, ctx, leaf_addr);

        set_type(leaf_addr, SPX_ADDR_TYPE_WOTS);

        /* Iterate down the WOTS chain */
        for (k = 0;; k++) {
            /* Check if this is the value that needs to be saved as a */
            /* part of the WOTS signature */
            if (k == wots_k) {
                memcpy( info->wots_sig + i * SPX_N_SHAKE_128_F, buffer, SPX_N_SHAKE_128_F);
            }

            /* Check if we hit the top of the chain */
            if (k == SPX_WOTS_W_SHAKE_128_F - 1) {
                break;
            }

            /* Iterate one step on the chain */
            set_hash_addr(leaf_addr, k);

            thash_shake_128_f(buffer, buffer, 1, ctx, leaf_addr);
        }
    }

    /* Do the final thash to generate the public keys */
    thash_shake_128_f(dest, pk_buffer, SPX_WOTS_LEN_SHAKE_128_F, ctx, pk_addr);
}
void wots_gen_leafx1_shake_128_s(unsigned char* dest,
    const spx_ctx_shake_128_s* ctx,
    uint32_t leaf_idx, void* v_info) {
    struct leaf_info_x1* info = v_info;
    uint32_t* leaf_addr = info->leaf_addr;
    uint32_t* pk_addr = info->pk_addr;
    uint32_t i, k;
    unsigned char pk_buffer[SPX_WOTS_BYTES_SHAKE_128_S];
    unsigned char* buffer;
    uint32_t wots_k_mask;

    if (leaf_idx == info->wots_sign_leaf) {
        /* We're traversing the leaf that's signing; generate the WOTS */
        /* signature */
        wots_k_mask = 0;
    }
    else {
        /* Nope, we're just generating pk's; turn off the signature logic */
        wots_k_mask = (uint32_t)~0;
    }

    set_keypair_addr(leaf_addr, leaf_idx);
    set_keypair_addr(pk_addr, leaf_idx);

    for (i = 0, buffer = pk_buffer; i < SPX_WOTS_LEN_SHAKE_128_S; i++, buffer += SPX_N_SHAKE_128_S) {
        uint32_t wots_k = info->wots_steps[i] | wots_k_mask; /* Set wots_k to */
        /* the step if we're generating a signature, ~0 if we're not */

        /* Start with the secret seed */
        set_chain_addr(leaf_addr, i);
        set_hash_addr(leaf_addr, 0);
        set_type(leaf_addr, SPX_ADDR_TYPE_WOTSPRF);

        prf_addr_shake_128_s(buffer, ctx, leaf_addr);

        set_type(leaf_addr, SPX_ADDR_TYPE_WOTS);

        /* Iterate down the WOTS chain */
        for (k = 0;; k++) {
            /* Check if this is the value that needs to be saved as a */
            /* part of the WOTS signature */
            if (k == wots_k) {
                memcpy(info->wots_sig + i * SPX_N_SHAKE_128_S, buffer, SPX_N_SHAKE_128_S);
            }

            /* Check if we hit the top of the chain */
            if (k == SPX_WOTS_W_SHAKE_128_S - 1) {
                break;
            }

            /* Iterate one step on the chain */
            set_hash_addr(leaf_addr, k);

            thash_shake_128_s(buffer, buffer, 1, ctx, leaf_addr);
        }
    }

    /* Do the final thash to generate the public keys */
    thash_shake_128_s(dest, pk_buffer, SPX_WOTS_LEN_SHAKE_128_S, ctx, pk_addr);
}

void wots_gen_leafx1_shake_192_f(unsigned char* dest,
    const spx_ctx_shake_192_f* ctx,
    uint32_t leaf_idx, void* v_info) {
    struct leaf_info_x1* info = v_info;
    uint32_t* leaf_addr = info->leaf_addr;
    uint32_t* pk_addr = info->pk_addr;
    uint32_t i, k;
    unsigned char pk_buffer[SPX_WOTS_BYTES_SHAKE_192_F];
    unsigned char* buffer;
    uint32_t wots_k_mask;

    if (leaf_idx == info->wots_sign_leaf) {
        /* We're traversing the leaf that's signing; generate the WOTS */
        /* signature */
        wots_k_mask = 0;
    }
    else {
        /* Nope, we're just generating pk's; turn off the signature logic */
        wots_k_mask = (uint32_t)~0;
    }

    set_keypair_addr(leaf_addr, leaf_idx);
    set_keypair_addr(pk_addr, leaf_idx);

    for (i = 0, buffer = pk_buffer; i < SPX_WOTS_LEN_SHAKE_192_F; i++, buffer += SPX_N_SHAKE_192_F) {
        uint32_t wots_k = info->wots_steps[i] | wots_k_mask; /* Set wots_k to */
        /* the step if we're generating a signature, ~0 if we're not */

        /* Start with the secret seed */
        set_chain_addr(leaf_addr, i);
        set_hash_addr(leaf_addr, 0);
        set_type(leaf_addr, SPX_ADDR_TYPE_WOTSPRF);

        prf_addr_shake_192_f(buffer, ctx, leaf_addr);

        set_type(leaf_addr, SPX_ADDR_TYPE_WOTS);

        /* Iterate down the WOTS chain */
        for (k = 0;; k++) {
            /* Check if this is the value that needs to be saved as a */
            /* part of the WOTS signature */
            if (k == wots_k) {
                memcpy(info->wots_sig + i * SPX_N_SHAKE_192_F, buffer, SPX_N_SHAKE_192_F);
            }

            /* Check if we hit the top of the chain */
            if (k == SPX_WOTS_W_SHAKE_192_F - 1) {
                break;
            }

            /* Iterate one step on the chain */
            set_hash_addr(leaf_addr, k);

            thash_shake_192_f(buffer, buffer, 1, ctx, leaf_addr);
        }
    }

    /* Do the final thash to generate the public keys */
    thash_shake_192_f(dest, pk_buffer, SPX_WOTS_LEN_SHAKE_192_F, ctx, pk_addr);
}
void wots_gen_leafx1_shake_192_s(unsigned char* dest,
    const spx_ctx_shake_192_s* ctx,
    uint32_t leaf_idx, void* v_info) {
    struct leaf_info_x1* info = v_info;
    uint32_t* leaf_addr = info->leaf_addr;
    uint32_t* pk_addr = info->pk_addr;
    uint32_t i, k;
    unsigned char pk_buffer[SPX_WOTS_BYTES_SHAKE_192_S];
    unsigned char* buffer;
    uint32_t wots_k_mask;

    if (leaf_idx == info->wots_sign_leaf) {
        /* We're traversing the leaf that's signing; generate the WOTS */
        /* signature */
        wots_k_mask = 0;
    }
    else {
        /* Nope, we're just generating pk's; turn off the signature logic */
        wots_k_mask = (uint32_t)~0;
    }

    set_keypair_addr(leaf_addr, leaf_idx);
    set_keypair_addr(pk_addr, leaf_idx);

    for (i = 0, buffer = pk_buffer; i < SPX_WOTS_LEN_SHAKE_192_S; i++, buffer += SPX_N_SHAKE_192_S) {
        uint32_t wots_k = info->wots_steps[i] | wots_k_mask; /* Set wots_k to */
        /* the step if we're generating a signature, ~0 if we're not */

        /* Start with the secret seed */
        set_chain_addr(leaf_addr, i);
        set_hash_addr(leaf_addr, 0);
        set_type(leaf_addr, SPX_ADDR_TYPE_WOTSPRF);

        prf_addr_shake_192_s(buffer, ctx, leaf_addr);

        set_type(leaf_addr, SPX_ADDR_TYPE_WOTS);

        /* Iterate down the WOTS chain */
        for (k = 0;; k++) {
            /* Check if this is the value that needs to be saved as a */
            /* part of the WOTS signature */
            if (k == wots_k) {
                memcpy(info->wots_sig + i * SPX_N_SHAKE_192_S, buffer, SPX_N_SHAKE_192_S);
            }

            /* Check if we hit the top of the chain */
            if (k == SPX_WOTS_W_SHAKE_192_S - 1) {
                break;
            }

            /* Iterate one step on the chain */
            set_hash_addr(leaf_addr, k);

            thash_shake_192_s(buffer, buffer, 1, ctx, leaf_addr);
        }
    }

    /* Do the final thash to generate the public keys */
    thash_shake_192_s(dest, pk_buffer, SPX_WOTS_LEN_SHAKE_192_S, ctx, pk_addr);
}

void wots_gen_leafx1_shake_256_f(unsigned char* dest,
    const spx_ctx_shake_256_f* ctx,
    uint32_t leaf_idx, void* v_info) {
    struct leaf_info_x1* info = v_info;
    uint32_t* leaf_addr = info->leaf_addr;
    uint32_t* pk_addr = info->pk_addr;
    uint32_t i, k;
    unsigned char pk_buffer[SPX_WOTS_BYTES_SHAKE_256_F];
    unsigned char* buffer;
    uint32_t wots_k_mask;

    if (leaf_idx == info->wots_sign_leaf) {
        /* We're traversing the leaf that's signing; generate the WOTS */
        /* signature */
        wots_k_mask = 0;
    }
    else {
        /* Nope, we're just generating pk's; turn off the signature logic */
        wots_k_mask = (uint32_t)~0;
    }

    set_keypair_addr(leaf_addr, leaf_idx);
    set_keypair_addr(pk_addr, leaf_idx);

    for (i = 0, buffer = pk_buffer; i < SPX_WOTS_LEN_SHAKE_256_F; i++, buffer += SPX_N_SHAKE_256_F) {
        uint32_t wots_k = info->wots_steps[i] | wots_k_mask; /* Set wots_k to */
        /* the step if we're generating a signature, ~0 if we're not */

        /* Start with the secret seed */
        set_chain_addr(leaf_addr, i);
        set_hash_addr(leaf_addr, 0);
        set_type(leaf_addr, SPX_ADDR_TYPE_WOTSPRF);

        prf_addr_shake_256_f(buffer, ctx, leaf_addr);

        set_type(leaf_addr, SPX_ADDR_TYPE_WOTS);

        /* Iterate down the WOTS chain */
        for (k = 0;; k++) {
            /* Check if this is the value that needs to be saved as a */
            /* part of the WOTS signature */
            if (k == wots_k) {
                memcpy(info->wots_sig + i * SPX_N_SHAKE_256_F, buffer, SPX_N_SHAKE_256_F);
            }

            /* Check if we hit the top of the chain */
            if (k == SPX_WOTS_W_SHAKE_256_F - 1) {
                break;
            }

            /* Iterate one step on the chain */
            set_hash_addr(leaf_addr, k);

            thash_shake_256_f(buffer, buffer, 1, ctx, leaf_addr);
        }
    }

    /* Do the final thash to generate the public keys */
    thash_shake_256_f(dest, pk_buffer, SPX_WOTS_LEN_SHAKE_256_F, ctx, pk_addr);
}
void wots_gen_leafx1_shake_256_s(unsigned char* dest,
    const spx_ctx_shake_256_s* ctx,
    uint32_t leaf_idx, void* v_info) {
    struct leaf_info_x1* info = v_info;
    uint32_t* leaf_addr = info->leaf_addr;
    uint32_t* pk_addr = info->pk_addr;
    uint32_t i, k;
    unsigned char pk_buffer[SPX_WOTS_BYTES_SHAKE_256_S];
    unsigned char* buffer;
    uint32_t wots_k_mask;

    if (leaf_idx == info->wots_sign_leaf) {
        /* We're traversing the leaf that's signing; generate the WOTS */
        /* signature */
        wots_k_mask = 0;
    }
    else {
        /* Nope, we're just generating pk's; turn off the signature logic */
        wots_k_mask = (uint32_t)~0;
    }

    set_keypair_addr(leaf_addr, leaf_idx);
    set_keypair_addr(pk_addr, leaf_idx);

    for (i = 0, buffer = pk_buffer; i < SPX_WOTS_LEN_SHAKE_256_S; i++, buffer += SPX_N_SHAKE_256_S) {
        uint32_t wots_k = info->wots_steps[i] | wots_k_mask; /* Set wots_k to */
        /* the step if we're generating a signature, ~0 if we're not */

        /* Start with the secret seed */
        set_chain_addr(leaf_addr, i);
        set_hash_addr(leaf_addr, 0);
        set_type(leaf_addr, SPX_ADDR_TYPE_WOTSPRF);

        prf_addr_shake_256_s(buffer, ctx, leaf_addr);

        set_type(leaf_addr, SPX_ADDR_TYPE_WOTS);

        /* Iterate down the WOTS chain */
        for (k = 0;; k++) {
            /* Check if this is the value that needs to be saved as a */
            /* part of the WOTS signature */
            if (k == wots_k) {
                memcpy(info->wots_sig + i * SPX_N_SHAKE_256_S, buffer, SPX_N_SHAKE_256_S);
            }

            /* Check if we hit the top of the chain */
            if (k == SPX_WOTS_W_SHAKE_256_S - 1) {
                break;
            }

            /* Iterate one step on the chain */
            set_hash_addr(leaf_addr, k);

            thash_shake_256_s(buffer, buffer, 1, ctx, leaf_addr);
        }
    }

    /* Do the final thash to generate the public keys */
    thash_shake_256_s(dest, pk_buffer, SPX_WOTS_LEN_SHAKE_256_S, ctx, pk_addr);
}
