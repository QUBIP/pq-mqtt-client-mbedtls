#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "address.h"
#include "context.h"
#include "fors.h"
#include "hash.h"
#include "merkle.h"
#include "nistapi.h"
#include "params.h"
#include "randombytes.h"
#include "thash.h"
#include "utils.h"
#include "wots.h"

/*
 * Generates an SPX key pair given a seed of length
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 */
int crypto_sign_seed_keypair_shake_128_f(uint8_t *pk, uint8_t *sk,
                             const uint8_t *seed) {
    spx_ctx_shake_128_f ctx;

    /* Initialize SK_SEED, SK_PRF and PUB_SEED from seed. */
    memcpy(sk, seed, CRYPTO_SEEDBYTES_SHAKE_128_F);

    memcpy(pk, sk + 2 * SPX_N_SHAKE_128_F, SPX_N_SHAKE_128_F);

    memcpy(ctx.pub_seed, pk, SPX_N_SHAKE_128_F);
    memcpy(ctx.sk_seed, sk, SPX_N_SHAKE_128_F);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function_shake_128_f(&ctx);

    /* Compute root node of the top-most subtree. */
    merkle_gen_root_shake_128_f(sk + 3 * SPX_N_SHAKE_128_F, &ctx);

    // cleanup
    free_hash_function_shake_128_f(&ctx);

    memcpy(pk + SPX_N_SHAKE_128_F, sk + 3 * SPX_N_SHAKE_128_F, SPX_N_SHAKE_128_F);

    return 0;
}
int crypto_sign_seed_keypair_shake_128_s(uint8_t* pk, uint8_t* sk,
    const uint8_t* seed) {
    spx_ctx_shake_128_s ctx;

    /* Initialize SK_SEED, SK_PRF and PUB_SEED from seed. */
    memcpy(sk, seed, CRYPTO_SEEDBYTES_SHAKE_128_S);

    memcpy(pk, sk + 2 * SPX_N_SHAKE_128_S, SPX_N_SHAKE_128_S);

    memcpy(ctx.pub_seed, pk, SPX_N_SHAKE_128_S);
    memcpy(ctx.sk_seed, sk, SPX_N_SHAKE_128_S);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function_shake_128_s(&ctx);

    /* Compute root node of the top-most subtree. */
    merkle_gen_root_shake_128_s(sk + 3 * SPX_N_SHAKE_128_S, &ctx);

    // cleanup
    free_hash_function_shake_128_s(&ctx);

    memcpy(pk + SPX_N_SHAKE_128_S, sk + 3 * SPX_N_SHAKE_128_S, SPX_N_SHAKE_128_S);

    return 0;
}

int crypto_sign_seed_keypair_shake_192_f(uint8_t* pk, uint8_t* sk,
    const uint8_t* seed) {
    spx_ctx_shake_192_f ctx;

    /* Initialize SK_SEED, SK_PRF and PUB_SEED from seed. */
    memcpy(sk, seed, CRYPTO_SEEDBYTES_SHAKE_192_F);

    memcpy(pk, sk + 2 * SPX_N_SHAKE_192_F, SPX_N_SHAKE_192_F);

    memcpy(ctx.pub_seed, pk, SPX_N_SHAKE_192_F);
    memcpy(ctx.sk_seed, sk, SPX_N_SHAKE_192_F);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function_shake_192_f(&ctx);

    /* Compute root node of the top-most subtree. */
    merkle_gen_root_shake_192_f(sk + 3 * SPX_N_SHAKE_192_F, &ctx);

    // cleanup
    free_hash_function_shake_192_f(&ctx);

    memcpy(pk + SPX_N_SHAKE_192_F, sk + 3 * SPX_N_SHAKE_192_F, SPX_N_SHAKE_192_F);

    return 0;
}
int crypto_sign_seed_keypair_shake_192_s(uint8_t* pk, uint8_t* sk,
    const uint8_t* seed) {
    spx_ctx_shake_192_s ctx;

    /* Initialize SK_SEED, SK_PRF and PUB_SEED from seed. */
    memcpy(sk, seed, CRYPTO_SEEDBYTES_SHAKE_192_S);

    memcpy(pk, sk + 2 * SPX_N_SHAKE_192_S, SPX_N_SHAKE_192_S);

    memcpy(ctx.pub_seed, pk, SPX_N_SHAKE_192_S);
    memcpy(ctx.sk_seed, sk, SPX_N_SHAKE_192_S);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function_shake_192_s(&ctx);

    /* Compute root node of the top-most subtree. */
    merkle_gen_root_shake_192_s(sk + 3 * SPX_N_SHAKE_192_S, &ctx);

    // cleanup
    free_hash_function_shake_192_s(&ctx);

    memcpy(pk + SPX_N_SHAKE_192_S, sk + 3 * SPX_N_SHAKE_192_S, SPX_N_SHAKE_192_S);

    return 0;
}

int crypto_sign_seed_keypair_shake_256_f(uint8_t* pk, uint8_t* sk,
    const uint8_t* seed) {
    spx_ctx_shake_256_f ctx;

    /* Initialize SK_SEED, SK_PRF and PUB_SEED from seed. */
    memcpy(sk, seed, CRYPTO_SEEDBYTES_SHAKE_256_F);

    memcpy(pk, sk + 2 * SPX_N_SHAKE_256_F, SPX_N_SHAKE_256_F);

    memcpy(ctx.pub_seed, pk, SPX_N_SHAKE_256_F);
    memcpy(ctx.sk_seed, sk, SPX_N_SHAKE_256_F);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function_shake_256_f(&ctx);

    /* Compute root node of the top-most subtree. */
    merkle_gen_root_shake_256_f(sk + 3 * SPX_N_SHAKE_256_F, &ctx);

    // cleanup
    free_hash_function_shake_256_f(&ctx);

    memcpy(pk + SPX_N_SHAKE_256_F, sk + 3 * SPX_N_SHAKE_256_F, SPX_N_SHAKE_256_F);

    return 0;
}
int crypto_sign_seed_keypair_shake_256_s(uint8_t* pk, uint8_t* sk,
    const uint8_t* seed) {
    spx_ctx_shake_256_s ctx;

    /* Initialize SK_SEED, SK_PRF and PUB_SEED from seed. */
    memcpy(sk, seed, CRYPTO_SEEDBYTES_SHAKE_256_S);

    memcpy(pk, sk + 2 * SPX_N_SHAKE_256_S, SPX_N_SHAKE_256_S);

    memcpy(ctx.pub_seed, pk, SPX_N_SHAKE_256_S);
    memcpy(ctx.sk_seed, sk, SPX_N_SHAKE_256_S);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function_shake_256_s(&ctx);

    /* Compute root node of the top-most subtree. */
    merkle_gen_root_shake_256_s(sk + 3 * SPX_N_SHAKE_256_S, &ctx);

    // cleanup
    free_hash_function_shake_256_s(&ctx);

    memcpy(pk + SPX_N_SHAKE_256_S, sk + 3 * SPX_N_SHAKE_256_S, SPX_N_SHAKE_256_S);

    return 0;
}

/**
 * Returns an array containing a detached signature.
 */
int crypto_sign_signature_shake_128_f(uint8_t *sig, size_t *siglen,
    const uint8_t *m, size_t mlen, const uint8_t *sk) {
    spx_ctx_shake_128_f ctx;

    const uint8_t *sk_prf = sk + SPX_N_SHAKE_128_F;
    const uint8_t *pk = sk + 2 * SPX_N_SHAKE_128_F;

    uint8_t optrand[SPX_N_SHAKE_128_F];
    uint8_t mhash[SPX_FORS_MSG_BYTES_SHAKE_128_F];
    uint8_t root[SPX_N_SHAKE_128_F];
    uint32_t i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};

    memcpy(ctx.sk_seed, sk, SPX_N_SHAKE_128_F);
    memcpy(ctx.pub_seed, pk, SPX_N_SHAKE_128_F);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function_shake_128_f(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    /* Optionally, signing can be made non-deterministic using optrand.
       This can help counter side-channel attacks that would benefit from
       getting a large number of traces when the signer uses the same nodes. */
    randombytes_slhdsa(optrand, SPX_N_SHAKE_128_F);
    /* Compute the digest randomization value. */
    gen_message_random_shake_128_f(sig, sk_prf, optrand, m, mlen, &ctx);

    /* Derive the message digest and leaf index from R, PK and M. */
    hash_message_shake_128_f(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    sig += SPX_N_SHAKE_128_F;

    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    /* Sign the message hash using FORS. */
    fors_sign_shake_128_f(sig, root, mhash, &ctx, wots_addr);
    sig += SPX_FORS_BYTES_SHAKE_128_F;

    for (i = 0; i < SPX_D_SHAKE_128_F; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        merkle_sign_shake_128_f(sig, root, &ctx, wots_addr, tree_addr, idx_leaf);
        sig += SPX_WOTS_BYTES_SHAKE_128_F + SPX_TREE_HEIGHT_SHAKE_128_F * SPX_N_SHAKE_128_F;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT_SHAKE_128_F) - 1));
        tree = tree >> SPX_TREE_HEIGHT_SHAKE_128_F;
    }

    free_hash_function_shake_128_f(&ctx);

    *siglen = SPX_BYTES_SHAKE_128_F;

    return 0;
}
int crypto_sign_signature_shake_128_s(uint8_t* sig, size_t* siglen,
    const uint8_t* m, size_t mlen, const uint8_t* sk) {
    spx_ctx_shake_128_s ctx;

    const uint8_t* sk_prf = sk + SPX_N_SHAKE_128_S;
    const uint8_t* pk = sk + 2 * SPX_N_SHAKE_128_S;

    uint8_t optrand[SPX_N_SHAKE_128_S];
    uint8_t mhash[SPX_FORS_MSG_BYTES_SHAKE_128_S];
    uint8_t root[SPX_N_SHAKE_128_S];
    uint32_t i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = { 0 };
    uint32_t tree_addr[8] = { 0 };

    memcpy(ctx.sk_seed, sk, SPX_N_SHAKE_128_S);
    memcpy(ctx.pub_seed, pk, SPX_N_SHAKE_128_S);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function_shake_128_s(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    /* Optionally, signing can be made non-deterministic using optrand.
       This can help counter side-channel attacks that would benefit from
       getting a large number of traces when the signer uses the same nodes. */
    randombytes_slhdsa(optrand, SPX_N_SHAKE_128_S);
    /* Compute the digest randomization value. */
    gen_message_random_shake_128_s(sig, sk_prf, optrand, m, mlen, &ctx);

    /* Derive the message digest and leaf index from R, PK and M. */
    hash_message_shake_128_s(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    sig += SPX_N_SHAKE_128_S;

    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    /* Sign the message hash using FORS. */
    fors_sign_shake_128_s(sig, root, mhash, &ctx, wots_addr);
    sig += SPX_FORS_BYTES_SHAKE_128_S;

    for (i = 0; i < SPX_D_SHAKE_128_S; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        merkle_sign_shake_128_s(sig, root, &ctx, wots_addr, tree_addr, idx_leaf);
        sig += SPX_WOTS_BYTES_SHAKE_128_S + SPX_TREE_HEIGHT_SHAKE_128_S * SPX_N_SHAKE_128_S;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT_SHAKE_128_S) - 1));
        tree = tree >> SPX_TREE_HEIGHT_SHAKE_128_S;
    }

    free_hash_function_shake_128_s(&ctx);

    *siglen = SPX_BYTES_SHAKE_128_S;

    return 0;
}

int crypto_sign_signature_shake_192_f(uint8_t* sig, size_t* siglen,
    const uint8_t* m, size_t mlen, const uint8_t* sk) {
    spx_ctx_shake_192_f ctx;

    const uint8_t* sk_prf = sk + SPX_N_SHAKE_192_F;
    const uint8_t* pk = sk + 2 * SPX_N_SHAKE_192_F;

    uint8_t optrand[SPX_N_SHAKE_192_F];
    uint8_t mhash[SPX_FORS_MSG_BYTES_SHAKE_192_F];
    uint8_t root[SPX_N_SHAKE_192_F];
    uint32_t i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = { 0 };
    uint32_t tree_addr[8] = { 0 };

    memcpy(ctx.sk_seed, sk, SPX_N_SHAKE_192_F);
    memcpy(ctx.pub_seed, pk, SPX_N_SHAKE_192_F);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function_shake_192_f(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    /* Optionally, signing can be made non-deterministic using optrand.
       This can help counter side-channel attacks that would benefit from
       getting a large number of traces when the signer uses the same nodes. */
    randombytes_slhdsa(optrand, SPX_N_SHAKE_192_F);
    /* Compute the digest randomization value. */
    gen_message_random_shake_192_f(sig, sk_prf, optrand, m, mlen, &ctx);

    /* Derive the message digest and leaf index from R, PK and M. */
    hash_message_shake_192_f(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    sig += SPX_N_SHAKE_192_F;

    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    /* Sign the message hash using FORS. */
    fors_sign_shake_192_f(sig, root, mhash, &ctx, wots_addr);
    sig += SPX_FORS_BYTES_SHAKE_192_F;

    for (i = 0; i < SPX_D_SHAKE_192_F; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        merkle_sign_shake_192_f(sig, root, &ctx, wots_addr, tree_addr, idx_leaf);
        sig += SPX_WOTS_BYTES_SHAKE_192_F + SPX_TREE_HEIGHT_SHAKE_192_F * SPX_N_SHAKE_192_F;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT_SHAKE_192_F) - 1));
        tree = tree >> SPX_TREE_HEIGHT_SHAKE_192_F;
    }

    free_hash_function_shake_192_f(&ctx);

    *siglen = SPX_BYTES_SHAKE_192_F;

    return 0;
}
int crypto_sign_signature_shake_192_s(uint8_t* sig, size_t* siglen,
    const uint8_t* m, size_t mlen, const uint8_t* sk) {
    spx_ctx_shake_192_s ctx;

    const uint8_t* sk_prf = sk + SPX_N_SHAKE_192_S;
    const uint8_t* pk = sk + 2 * SPX_N_SHAKE_192_S;

    uint8_t optrand[SPX_N_SHAKE_192_S];
    uint8_t mhash[SPX_FORS_MSG_BYTES_SHAKE_192_S];
    uint8_t root[SPX_N_SHAKE_192_S];
    uint32_t i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = { 0 };
    uint32_t tree_addr[8] = { 0 };

    memcpy(ctx.sk_seed, sk, SPX_N_SHAKE_192_S);
    memcpy(ctx.pub_seed, pk, SPX_N_SHAKE_192_S);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function_shake_192_s(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    /* Optionally, signing can be made non-deterministic using optrand.
       This can help counter side-channel attacks that would benefit from
       getting a large number of traces when the signer uses the same nodes. */
    randombytes_slhdsa(optrand, SPX_N_SHAKE_192_S);
    /* Compute the digest randomization value. */
    gen_message_random_shake_192_s(sig, sk_prf, optrand, m, mlen, &ctx);

    /* Derive the message digest and leaf index from R, PK and M. */
    hash_message_shake_192_s(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    sig += SPX_N_SHAKE_192_S;

    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    /* Sign the message hash using FORS. */
    fors_sign_shake_192_s(sig, root, mhash, &ctx, wots_addr);
    sig += SPX_FORS_BYTES_SHAKE_192_S;

    for (i = 0; i < SPX_D_SHAKE_192_S; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        merkle_sign_shake_192_s(sig, root, &ctx, wots_addr, tree_addr, idx_leaf);
        sig += SPX_WOTS_BYTES_SHAKE_192_S + SPX_TREE_HEIGHT_SHAKE_192_S * SPX_N_SHAKE_192_S;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT_SHAKE_192_S) - 1));
        tree = tree >> SPX_TREE_HEIGHT_SHAKE_192_S;
    }

    free_hash_function_shake_192_s(&ctx);

    *siglen = SPX_BYTES_SHAKE_192_S;

    return 0;
}

int crypto_sign_signature_shake_256_f(uint8_t* sig, size_t* siglen,
    const uint8_t* m, size_t mlen, const uint8_t* sk) {
    spx_ctx_shake_256_f ctx;

    const uint8_t* sk_prf = sk + SPX_N_SHAKE_256_F;
    const uint8_t* pk = sk + 2 * SPX_N_SHAKE_256_F;

    uint8_t optrand[SPX_N_SHAKE_256_F];
    uint8_t mhash[SPX_FORS_MSG_BYTES_SHAKE_256_F];
    uint8_t root[SPX_N_SHAKE_256_F];
    uint32_t i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = { 0 };
    uint32_t tree_addr[8] = { 0 };

    memcpy(ctx.sk_seed, sk, SPX_N_SHAKE_256_F);
    memcpy(ctx.pub_seed, pk, SPX_N_SHAKE_256_F);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function_shake_256_f(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    /* Optionally, signing can be made non-deterministic using optrand.
       This can help counter side-channel attacks that would benefit from
       getting a large number of traces when the signer uses the same nodes. */
    randombytes_slhdsa(optrand, SPX_N_SHAKE_256_F);
    /* Compute the digest randomization value. */
    gen_message_random_shake_256_f(sig, sk_prf, optrand, m, mlen, &ctx);

    /* Derive the message digest and leaf index from R, PK and M. */
    hash_message_shake_256_f(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    sig += SPX_N_SHAKE_256_F;

    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    /* Sign the message hash using FORS. */
    fors_sign_shake_256_f(sig, root, mhash, &ctx, wots_addr);
    sig += SPX_FORS_BYTES_SHAKE_256_F;

    for (i = 0; i < SPX_D_SHAKE_256_F; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        merkle_sign_shake_256_f(sig, root, &ctx, wots_addr, tree_addr, idx_leaf);
        sig += SPX_WOTS_BYTES_SHAKE_256_F + SPX_TREE_HEIGHT_SHAKE_256_F * SPX_N_SHAKE_256_F;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT_SHAKE_256_F) - 1));
        tree = tree >> SPX_TREE_HEIGHT_SHAKE_256_F;
    }

    free_hash_function_shake_256_f(&ctx);

    *siglen = SPX_BYTES_SHAKE_256_F;

    return 0;
}
int crypto_sign_signature_shake_256_s(uint8_t* sig, size_t* siglen,
    const uint8_t* m, size_t mlen, const uint8_t* sk) {
    spx_ctx_shake_256_s ctx;

    const uint8_t* sk_prf = sk + SPX_N_SHAKE_256_S;
    const uint8_t* pk = sk + 2 * SPX_N_SHAKE_256_S;

    uint8_t optrand[SPX_N_SHAKE_256_S];
    uint8_t mhash[SPX_FORS_MSG_BYTES_SHAKE_256_S];
    uint8_t root[SPX_N_SHAKE_256_S];
    uint32_t i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = { 0 };
    uint32_t tree_addr[8] = { 0 };

    memcpy(ctx.sk_seed, sk, SPX_N_SHAKE_256_S);
    memcpy(ctx.pub_seed, pk, SPX_N_SHAKE_256_S);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function_shake_256_s(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    /* Optionally, signing can be made non-deterministic using optrand.
       This can help counter side-channel attacks that would benefit from
       getting a large number of traces when the signer uses the same nodes. */
    randombytes_slhdsa(optrand, SPX_N_SHAKE_256_S);
    /* Compute the digest randomization value. */
    gen_message_random_shake_256_s(sig, sk_prf, optrand, m, mlen, &ctx);

    /* Derive the message digest and leaf index from R, PK and M. */
    hash_message_shake_256_s(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    sig += SPX_N_SHAKE_256_S;

    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    /* Sign the message hash using FORS. */
    fors_sign_shake_256_s(sig, root, mhash, &ctx, wots_addr);
    sig += SPX_FORS_BYTES_SHAKE_256_S;

    for (i = 0; i < SPX_D_SHAKE_256_S; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        merkle_sign_shake_256_s(sig, root, &ctx, wots_addr, tree_addr, idx_leaf);
        sig += SPX_WOTS_BYTES_SHAKE_256_S + SPX_TREE_HEIGHT_SHAKE_256_S * SPX_N_SHAKE_256_S;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT_SHAKE_256_S) - 1));
        tree = tree >> SPX_TREE_HEIGHT_SHAKE_256_S;
    }

    free_hash_function_shake_256_s(&ctx);

    *siglen = SPX_BYTES_SHAKE_256_S;

    return 0;
}

/**
 * Verifies a detached signature and message under a given public key.
 */
int crypto_sign_verify_shake_128_f(const uint8_t *sig, size_t siglen,
    const uint8_t *m, size_t mlen, const uint8_t *pk) {
    spx_ctx_shake_128_f ctx;
    const uint8_t *pub_root = pk + SPX_N_SHAKE_128_F;
    uint8_t mhash[SPX_FORS_MSG_BYTES_SHAKE_128_F];
    uint8_t wots_pk[SPX_WOTS_BYTES_SHAKE_128_F];
    uint8_t root[SPX_N_SHAKE_128_F];
    uint8_t leaf[SPX_N_SHAKE_128_F];
    unsigned int i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};
    uint32_t wots_pk_addr[8] = {0};

    if (siglen != SPX_BYTES_SHAKE_128_F) {
        return -1;
    }

    memcpy(ctx.pub_seed, pk, SPX_N_SHAKE_128_F);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function_shake_128_f(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
    set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    /* Derive the message digest and leaf index from R || PK || M. */
    /* The additional SPX_N is a result of the hash domain separator. */
    hash_message_shake_128_f(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    sig += SPX_N_SHAKE_128_F;

    /* Layer correctly defaults to 0, so no need to set_layer_addr */
    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    fors_pk_from_sig_shake_128_f(root, sig, mhash, &ctx, wots_addr);
    sig += SPX_FORS_BYTES_SHAKE_128_F;

    /* For each subtree.. */
    for (i = 0; i < SPX_D_SHAKE_128_F; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        copy_keypair_addr(wots_pk_addr, wots_addr);

        /* The WOTS public key is only correct if the signature was correct. */
        /* Initially, root is the FORS pk, but on subsequent iterations it is
           the root of the subtree below the currently processed subtree. */
        wots_pk_from_sig_shake_128_f(wots_pk, sig, root, &ctx, wots_addr);
        sig += SPX_WOTS_BYTES_SHAKE_128_F;

        /* Compute the leaf node using the WOTS public key. */
        thash_shake_128_f(leaf, wots_pk, SPX_WOTS_LEN_SHAKE_128_F, &ctx, wots_pk_addr);

        /* Compute the root node of this subtree. */
        compute_root_shake_128_f(root, leaf, idx_leaf, 0, sig, SPX_TREE_HEIGHT_SHAKE_128_F,
                     &ctx, tree_addr);
        sig += SPX_TREE_HEIGHT_SHAKE_128_F * SPX_N_SHAKE_128_F;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT_SHAKE_128_F) - 1));
        tree = tree >> SPX_TREE_HEIGHT_SHAKE_128_F;
    }

    // cleanup
    free_hash_function_shake_128_f(&ctx);

    /* Check if the root node equals the root node in the public key. */
    if (memcmp(root, pub_root, SPX_N_SHAKE_128_F) != 0) {
        return -1;
    }

    return 0;
}
int crypto_sign_verify_shake_128_s(const uint8_t* sig, size_t siglen,
    const uint8_t* m, size_t mlen, const uint8_t* pk) {
    spx_ctx_shake_128_s ctx;
    const uint8_t* pub_root = pk + SPX_N_SHAKE_128_S;
    uint8_t mhash[SPX_FORS_MSG_BYTES_SHAKE_128_S];
    uint8_t wots_pk[SPX_WOTS_BYTES_SHAKE_128_S];
    uint8_t root[SPX_N_SHAKE_128_S];
    uint8_t leaf[SPX_N_SHAKE_128_S];
    unsigned int i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = { 0 };
    uint32_t tree_addr[8] = { 0 };
    uint32_t wots_pk_addr[8] = { 0 };

    if (siglen != SPX_BYTES_SHAKE_128_S) {
        return -1;
    }

    memcpy(ctx.pub_seed, pk, SPX_N_SHAKE_128_S);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function_shake_128_s(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
    set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    /* Derive the message digest and leaf index from R || PK || M. */
    /* The additional SPX_N is a result of the hash domain separator. */
    hash_message_shake_128_s(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    sig += SPX_N_SHAKE_128_S;

    /* Layer correctly defaults to 0, so no need to set_layer_addr */
    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    fors_pk_from_sig_shake_128_s(root, sig, mhash, &ctx, wots_addr);
    sig += SPX_FORS_BYTES_SHAKE_128_S;

    /* For each subtree.. */
    for (i = 0; i < SPX_D_SHAKE_128_S; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        copy_keypair_addr(wots_pk_addr, wots_addr);

        /* The WOTS public key is only correct if the signature was correct. */
        /* Initially, root is the FORS pk, but on subsequent iterations it is
           the root of the subtree below the currently processed subtree. */
        wots_pk_from_sig_shake_128_s(wots_pk, sig, root, &ctx, wots_addr);
        sig += SPX_WOTS_BYTES_SHAKE_128_S;

        /* Compute the leaf node using the WOTS public key. */
        thash_shake_128_s(leaf, wots_pk, SPX_WOTS_LEN_SHAKE_128_S, &ctx, wots_pk_addr);

        /* Compute the root node of this subtree. */
        compute_root_shake_128_s(root, leaf, idx_leaf, 0, sig, SPX_TREE_HEIGHT_SHAKE_128_S,
            &ctx, tree_addr);
        sig += SPX_TREE_HEIGHT_SHAKE_128_S * SPX_N_SHAKE_128_S;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT_SHAKE_128_S) - 1));
        tree = tree >> SPX_TREE_HEIGHT_SHAKE_128_S;
    }

    // cleanup
    free_hash_function_shake_128_s(&ctx);

    /* Check if the root node equals the root node in the public key. */
    if (memcmp(root, pub_root, SPX_N_SHAKE_128_S) != 0) {
        return -1;
    }

    return 0;
}

int crypto_sign_verify_shake_192_f(const uint8_t* sig, size_t siglen,
    const uint8_t* m, size_t mlen, const uint8_t* pk) {
    spx_ctx_shake_192_f ctx;
    const uint8_t* pub_root = pk + SPX_N_SHAKE_192_F;
    uint8_t mhash[SPX_FORS_MSG_BYTES_SHAKE_192_F];
    uint8_t wots_pk[SPX_WOTS_BYTES_SHAKE_192_F];
    uint8_t root[SPX_N_SHAKE_192_F];
    uint8_t leaf[SPX_N_SHAKE_192_F];
    unsigned int i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = { 0 };
    uint32_t tree_addr[8] = { 0 };
    uint32_t wots_pk_addr[8] = { 0 };

    if (siglen != SPX_BYTES_SHAKE_192_F) {
        return -1;
    }

    memcpy(ctx.pub_seed, pk, SPX_N_SHAKE_192_F);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function_shake_192_f(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
    set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    /* Derive the message digest and leaf index from R || PK || M. */
    /* The additional SPX_N is a result of the hash domain separator. */
    hash_message_shake_192_f(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    sig += SPX_N_SHAKE_192_F;

    /* Layer correctly defaults to 0, so no need to set_layer_addr */
    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    fors_pk_from_sig_shake_192_f(root, sig, mhash, &ctx, wots_addr);
    sig += SPX_FORS_BYTES_SHAKE_192_F;

    /* For each subtree.. */
    for (i = 0; i < SPX_D_SHAKE_192_F; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        copy_keypair_addr(wots_pk_addr, wots_addr);

        /* The WOTS public key is only correct if the signature was correct. */
        /* Initially, root is the FORS pk, but on subsequent iterations it is
           the root of the subtree below the currently processed subtree. */
        wots_pk_from_sig_shake_192_f(wots_pk, sig, root, &ctx, wots_addr);
        sig += SPX_WOTS_BYTES_SHAKE_192_F;

        /* Compute the leaf node using the WOTS public key. */
        thash_shake_192_f(leaf, wots_pk, SPX_WOTS_LEN_SHAKE_192_F, &ctx, wots_pk_addr);

        /* Compute the root node of this subtree. */
        compute_root_shake_192_f(root, leaf, idx_leaf, 0, sig, SPX_TREE_HEIGHT_SHAKE_192_F,
            &ctx, tree_addr);
        sig += SPX_TREE_HEIGHT_SHAKE_192_F * SPX_N_SHAKE_192_F;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT_SHAKE_192_F) - 1));
        tree = tree >> SPX_TREE_HEIGHT_SHAKE_192_F;
    }

    // cleanup
    free_hash_function_shake_192_f(&ctx);

    /* Check if the root node equals the root node in the public key. */
    if (memcmp(root, pub_root, SPX_N_SHAKE_192_F) != 0) {
        return -1;
    }

    return 0;
}
int crypto_sign_verify_shake_192_s(const uint8_t* sig, size_t siglen,
    const uint8_t* m, size_t mlen, const uint8_t* pk) {
    spx_ctx_shake_192_s ctx;
    const uint8_t* pub_root = pk + SPX_N_SHAKE_192_S;
    uint8_t mhash[SPX_FORS_MSG_BYTES_SHAKE_192_S];
    uint8_t wots_pk[SPX_WOTS_BYTES_SHAKE_192_S];
    uint8_t root[SPX_N_SHAKE_192_S];
    uint8_t leaf[SPX_N_SHAKE_192_S];
    unsigned int i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = { 0 };
    uint32_t tree_addr[8] = { 0 };
    uint32_t wots_pk_addr[8] = { 0 };

    if (siglen != SPX_BYTES_SHAKE_192_S) {
        return -1;
    }

    memcpy(ctx.pub_seed, pk, SPX_N_SHAKE_192_S);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function_shake_192_s(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
    set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    /* Derive the message digest and leaf index from R || PK || M. */
    /* The additional SPX_N is a result of the hash domain separator. */
    hash_message_shake_192_s(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    sig += SPX_N_SHAKE_192_S;

    /* Layer correctly defaults to 0, so no need to set_layer_addr */
    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    fors_pk_from_sig_shake_192_s(root, sig, mhash, &ctx, wots_addr);
    sig += SPX_FORS_BYTES_SHAKE_192_S;

    /* For each subtree.. */
    for (i = 0; i < SPX_D_SHAKE_192_S; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        copy_keypair_addr(wots_pk_addr, wots_addr);

        /* The WOTS public key is only correct if the signature was correct. */
        /* Initially, root is the FORS pk, but on subsequent iterations it is
           the root of the subtree below the currently processed subtree. */
        wots_pk_from_sig_shake_192_s(wots_pk, sig, root, &ctx, wots_addr);
        sig += SPX_WOTS_BYTES_SHAKE_192_S;

        /* Compute the leaf node using the WOTS public key. */
        thash_shake_192_s(leaf, wots_pk, SPX_WOTS_LEN_SHAKE_192_S, &ctx, wots_pk_addr);

        /* Compute the root node of this subtree. */
        compute_root_shake_192_s(root, leaf, idx_leaf, 0, sig, SPX_TREE_HEIGHT_SHAKE_192_S,
            &ctx, tree_addr);
        sig += SPX_TREE_HEIGHT_SHAKE_192_S * SPX_N_SHAKE_192_S;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT_SHAKE_192_S) - 1));
        tree = tree >> SPX_TREE_HEIGHT_SHAKE_192_S;
    }

    // cleanup
    free_hash_function_shake_192_s(&ctx);

    /* Check if the root node equals the root node in the public key. */
    if (memcmp(root, pub_root, SPX_N_SHAKE_192_S) != 0) {
        return -1;
    }

    return 0;
}

int crypto_sign_verify_shake_256_f(const uint8_t* sig, size_t siglen,
    const uint8_t* m, size_t mlen, const uint8_t* pk) {
    spx_ctx_shake_256_f ctx;
    const uint8_t* pub_root = pk + SPX_N_SHAKE_256_F;
    uint8_t mhash[SPX_FORS_MSG_BYTES_SHAKE_256_F];
    uint8_t wots_pk[SPX_WOTS_BYTES_SHAKE_256_F];
    uint8_t root[SPX_N_SHAKE_256_F];
    uint8_t leaf[SPX_N_SHAKE_256_F];
    unsigned int i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = { 0 };
    uint32_t tree_addr[8] = { 0 };
    uint32_t wots_pk_addr[8] = { 0 };

    if (siglen != SPX_BYTES_SHAKE_256_F) {
        return -1;
    }

    memcpy(ctx.pub_seed, pk, SPX_N_SHAKE_256_F);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function_shake_256_f(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
    set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    /* Derive the message digest and leaf index from R || PK || M. */
    /* The additional SPX_N is a result of the hash domain separator. */
    hash_message_shake_256_f(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    sig += SPX_N_SHAKE_256_F;

    /* Layer correctly defaults to 0, so no need to set_layer_addr */
    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    fors_pk_from_sig_shake_256_f(root, sig, mhash, &ctx, wots_addr);
    sig += SPX_FORS_BYTES_SHAKE_256_F;

    /* For each subtree.. */
    for (i = 0; i < SPX_D_SHAKE_256_F; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        copy_keypair_addr(wots_pk_addr, wots_addr);

        /* The WOTS public key is only correct if the signature was correct. */
        /* Initially, root is the FORS pk, but on subsequent iterations it is
           the root of the subtree below the currently processed subtree. */
        wots_pk_from_sig_shake_256_f(wots_pk, sig, root, &ctx, wots_addr);
        sig += SPX_WOTS_BYTES_SHAKE_256_F;

        /* Compute the leaf node using the WOTS public key. */
        thash_shake_256_f(leaf, wots_pk, SPX_WOTS_LEN_SHAKE_256_F, &ctx, wots_pk_addr);

        /* Compute the root node of this subtree. */
        compute_root_shake_256_f(root, leaf, idx_leaf, 0, sig, SPX_TREE_HEIGHT_SHAKE_256_F,
            &ctx, tree_addr);
        sig += SPX_TREE_HEIGHT_SHAKE_256_F * SPX_N_SHAKE_256_F;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT_SHAKE_256_F) - 1));
        tree = tree >> SPX_TREE_HEIGHT_SHAKE_256_F;
    }

    // cleanup
    free_hash_function_shake_256_f(&ctx);

    /* Check if the root node equals the root node in the public key. */
    if (memcmp(root, pub_root, SPX_N_SHAKE_256_F) != 0) {
        return -1;
    }

    return 0;
}
int crypto_sign_verify_shake_256_s(const uint8_t* sig, size_t siglen,
    const uint8_t* m, size_t mlen, const uint8_t* pk) {
    spx_ctx_shake_256_s ctx;
    const uint8_t* pub_root = pk + SPX_N_SHAKE_256_S;
    uint8_t mhash[SPX_FORS_MSG_BYTES_SHAKE_256_S];
    uint8_t wots_pk[SPX_WOTS_BYTES_SHAKE_256_S];
    uint8_t root[SPX_N_SHAKE_256_S];
    uint8_t leaf[SPX_N_SHAKE_256_S];
    unsigned int i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = { 0 };
    uint32_t tree_addr[8] = { 0 };
    uint32_t wots_pk_addr[8] = { 0 };

    if (siglen != SPX_BYTES_SHAKE_256_S) {
        return -1;
    }

    memcpy(ctx.pub_seed, pk, SPX_N_SHAKE_256_S);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function_shake_256_s(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
    set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    /* Derive the message digest and leaf index from R || PK || M. */
    /* The additional SPX_N is a result of the hash domain separator. */
    hash_message_shake_256_s(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    sig += SPX_N_SHAKE_256_S;

    /* Layer correctly defaults to 0, so no need to set_layer_addr */
    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    fors_pk_from_sig_shake_256_s(root, sig, mhash, &ctx, wots_addr);
    sig += SPX_FORS_BYTES_SHAKE_256_S;

    /* For each subtree.. */
    for (i = 0; i < SPX_D_SHAKE_256_S; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        copy_keypair_addr(wots_pk_addr, wots_addr);

        /* The WOTS public key is only correct if the signature was correct. */
        /* Initially, root is the FORS pk, but on subsequent iterations it is
           the root of the subtree below the currently processed subtree. */
        wots_pk_from_sig_shake_256_s(wots_pk, sig, root, &ctx, wots_addr);
        sig += SPX_WOTS_BYTES_SHAKE_256_S;

        /* Compute the leaf node using the WOTS public key. */
        thash_shake_256_s(leaf, wots_pk, SPX_WOTS_LEN_SHAKE_256_S, &ctx, wots_pk_addr);

        /* Compute the root node of this subtree. */
        compute_root_shake_256_s(root, leaf, idx_leaf, 0, sig, SPX_TREE_HEIGHT_SHAKE_256_S,
            &ctx, tree_addr);
        sig += SPX_TREE_HEIGHT_SHAKE_256_S * SPX_N_SHAKE_256_S;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT_SHAKE_256_S) - 1));
        tree = tree >> SPX_TREE_HEIGHT_SHAKE_256_S;
    }

    // cleanup
    free_hash_function_shake_256_s(&ctx);

    /* Check if the root node equals the root node in the public key. */
    if (memcmp(root, pub_root, SPX_N_SHAKE_256_S) != 0) {
        return -1;
    }

    return 0;
}
