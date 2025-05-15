#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "hash.h"

#include "address.h"
#include "fips202.h"
#include "params.h"
#include "utils.h"

/*
 * Computes PRF(pk_seed, sk_seed, addr)
 */
void prf_addr_shake_128_f(unsigned char *out, const spx_ctx_shake_128_f *ctx,
              const uint32_t addr[8]) {
    unsigned char buf[2 * SPX_N_SHAKE_128_F + SPX_ADDR_BYTES];

    memcpy(buf, ctx->pub_seed, SPX_N_SHAKE_128_F);
    memcpy(buf + SPX_N_SHAKE_128_F, addr, SPX_ADDR_BYTES);
    memcpy(buf + SPX_N_SHAKE_128_F + SPX_ADDR_BYTES, ctx->sk_seed, SPX_N_SHAKE_128_F);

    shake256_slhdsa(out, SPX_N_SHAKE_128_F, buf, 2 * SPX_N_SHAKE_128_F + SPX_ADDR_BYTES);
}
void prf_addr_shake_128_s(unsigned char* out, const spx_ctx_shake_128_s* ctx,
    const uint32_t addr[8]) {
    unsigned char buf[2 * SPX_N_SHAKE_128_S + SPX_ADDR_BYTES];

    memcpy(buf, ctx->pub_seed, SPX_N_SHAKE_128_S);
    memcpy(buf + SPX_N_SHAKE_128_S, addr, SPX_ADDR_BYTES);
    memcpy(buf + SPX_N_SHAKE_128_S + SPX_ADDR_BYTES, ctx->sk_seed, SPX_N_SHAKE_128_S);

    shake256_slhdsa(out, SPX_N_SHAKE_128_S, buf, 2 * SPX_N_SHAKE_128_S + SPX_ADDR_BYTES);
}

void prf_addr_shake_192_f(unsigned char* out, const spx_ctx_shake_192_f* ctx,
    const uint32_t addr[8]) {
    unsigned char buf[2 * SPX_N_SHAKE_192_F + SPX_ADDR_BYTES];

    memcpy(buf, ctx->pub_seed, SPX_N_SHAKE_192_F);
    memcpy(buf + SPX_N_SHAKE_192_F, addr, SPX_ADDR_BYTES);
    memcpy(buf + SPX_N_SHAKE_192_F + SPX_ADDR_BYTES, ctx->sk_seed, SPX_N_SHAKE_192_F);

    shake256_slhdsa(out, SPX_N_SHAKE_192_F, buf, 2 * SPX_N_SHAKE_192_F + SPX_ADDR_BYTES);
}
void prf_addr_shake_192_s(unsigned char* out, const spx_ctx_shake_192_s* ctx,
    const uint32_t addr[8]) {
    unsigned char buf[2 * SPX_N_SHAKE_192_S + SPX_ADDR_BYTES];

    memcpy(buf, ctx->pub_seed, SPX_N_SHAKE_192_S);
    memcpy(buf + SPX_N_SHAKE_192_S, addr, SPX_ADDR_BYTES);
    memcpy(buf + SPX_N_SHAKE_192_S + SPX_ADDR_BYTES, ctx->sk_seed, SPX_N_SHAKE_192_S);

    shake256_slhdsa(out, SPX_N_SHAKE_192_S, buf, 2 * SPX_N_SHAKE_192_S + SPX_ADDR_BYTES);
}

void prf_addr_shake_256_f(unsigned char* out, const spx_ctx_shake_256_f* ctx,
    const uint32_t addr[8]) {
    unsigned char buf[2 * SPX_N_SHAKE_256_F + SPX_ADDR_BYTES];

    memcpy(buf, ctx->pub_seed, SPX_N_SHAKE_256_F);
    memcpy(buf + SPX_N_SHAKE_256_F, addr, SPX_ADDR_BYTES);
    memcpy(buf + SPX_N_SHAKE_256_F + SPX_ADDR_BYTES, ctx->sk_seed, SPX_N_SHAKE_256_F);

    shake256_slhdsa(out, SPX_N_SHAKE_256_F, buf, 2 * SPX_N_SHAKE_256_F + SPX_ADDR_BYTES);
}
void prf_addr_shake_256_s(unsigned char* out, const spx_ctx_shake_256_s* ctx,
    const uint32_t addr[8]) {
    unsigned char buf[2 * SPX_N_SHAKE_256_S + SPX_ADDR_BYTES];

    memcpy(buf, ctx->pub_seed, SPX_N_SHAKE_256_S);
    memcpy(buf + SPX_N_SHAKE_256_S, addr, SPX_ADDR_BYTES);
    memcpy(buf + SPX_N_SHAKE_256_S + SPX_ADDR_BYTES, ctx->sk_seed, SPX_N_SHAKE_256_S);

    shake256_slhdsa(out, SPX_N_SHAKE_256_S, buf, 2 * SPX_N_SHAKE_256_S + SPX_ADDR_BYTES);
}

/**
 * Computes the message-dependent randomness R, using a secret seed and an
 * optional randomization value as well as the message.
 */

void gen_message_random_shake_128_f(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, size_t mlen,
                        const spx_ctx_shake_128_f *ctx) {
    (void)ctx;
    /*
    shake256incctx s_inc;

    shake256_inc_init(&s_inc);
    shake256_inc_absorb(&s_inc, sk_prf, SPX_N);
    shake256_inc_absorb(&s_inc, optrand, SPX_N);
    shake256_inc_absorb(&s_inc, m, mlen);
    shake256_inc_finalize(&s_inc);
    shake256_inc_squeeze(R, SPX_N, &s_inc);
    shake256_inc_ctx_release(&s_inc);
    */

    keccak_state state;
    shake256_absorb_slhdsa(&state, sk_prf, SPX_N_SHAKE_128_F);
    shake256_absorb_slhdsa(&state, optrand, SPX_N_SHAKE_128_F);
    shake256_absorb_slhdsa(&state, m, mlen);
    uint8_t buf[SHAKE256_RATE];
    shake256_squeezeblocks_slhdsa(buf, 1, &state);
    memcpy(R, buf, SPX_N_SHAKE_128_F);
}

void gen_message_random_shake_128_s(unsigned char* R, const unsigned char* sk_prf,
    const unsigned char* optrand,
    const unsigned char* m, size_t mlen,
    const spx_ctx_shake_128_s* ctx) {
    (void)ctx;
    /*
    shake256incctx s_inc;

    shake256_inc_init(&s_inc);
    shake256_inc_absorb(&s_inc, sk_prf, SPX_N);
    shake256_inc_absorb(&s_inc, optrand, SPX_N);
    shake256_inc_absorb(&s_inc, m, mlen);
    shake256_inc_finalize(&s_inc);
    shake256_inc_squeeze(R, SPX_N, &s_inc);
    shake256_inc_ctx_release(&s_inc);
    */

    keccak_state state;
    shake256_absorb_slhdsa(&state, sk_prf, SPX_N_SHAKE_128_S);
    shake256_absorb_slhdsa(&state, optrand, SPX_N_SHAKE_128_S);
    shake256_absorb_slhdsa(&state, m, mlen);
    uint8_t buf[SHAKE256_RATE];
    shake256_squeezeblocks_slhdsa(buf, 1, &state);
    memcpy(R, buf, SPX_N_SHAKE_128_S);
}

void gen_message_random_shake_192_f(unsigned char* R, const unsigned char* sk_prf,
    const unsigned char* optrand,
    const unsigned char* m, size_t mlen,
    const spx_ctx_shake_192_f* ctx) {
    (void)ctx;
    /*
    shake256incctx s_inc;

    shake256_inc_init(&s_inc);
    shake256_inc_absorb(&s_inc, sk_prf, SPX_N);
    shake256_inc_absorb(&s_inc, optrand, SPX_N);
    shake256_inc_absorb(&s_inc, m, mlen);
    shake256_inc_finalize(&s_inc);
    shake256_inc_squeeze(R, SPX_N, &s_inc);
    shake256_inc_ctx_release(&s_inc);
    */

    keccak_state state;
    shake256_absorb_slhdsa(&state, sk_prf, SPX_N_SHAKE_192_F);
    shake256_absorb_slhdsa(&state, optrand, SPX_N_SHAKE_192_F);
    shake256_absorb_slhdsa(&state, m, mlen);
    uint8_t buf[SHAKE256_RATE];
    shake256_squeezeblocks_slhdsa(buf, 1, &state);
    memcpy(R, buf, SPX_N_SHAKE_192_F);
}

void gen_message_random_shake_192_s(unsigned char* R, const unsigned char* sk_prf,
    const unsigned char* optrand,
    const unsigned char* m, size_t mlen,
    const spx_ctx_shake_192_s* ctx) {
    (void)ctx;
    /*
    shake256incctx s_inc;

    shake256_inc_init(&s_inc);
    shake256_inc_absorb(&s_inc, sk_prf, SPX_N);
    shake256_inc_absorb(&s_inc, optrand, SPX_N);
    shake256_inc_absorb(&s_inc, m, mlen);
    shake256_inc_finalize(&s_inc);
    shake256_inc_squeeze(R, SPX_N, &s_inc);
    shake256_inc_ctx_release(&s_inc);
    */

    keccak_state state;
    shake256_absorb_slhdsa(&state, sk_prf, SPX_N_SHAKE_192_S);
    shake256_absorb_slhdsa(&state, optrand, SPX_N_SHAKE_192_S);
    shake256_absorb_slhdsa(&state, m, mlen);
    uint8_t buf[SHAKE256_RATE];
    shake256_squeezeblocks_slhdsa(buf, 1, &state);
    memcpy(R, buf, SPX_N_SHAKE_192_S);
}

void gen_message_random_shake_256_f(unsigned char* R, const unsigned char* sk_prf,
    const unsigned char* optrand,
    const unsigned char* m, size_t mlen,
    const spx_ctx_shake_256_f* ctx) {
    (void)ctx;
    /*
    shake256incctx s_inc;

    shake256_inc_init(&s_inc);
    shake256_inc_absorb(&s_inc, sk_prf, SPX_N);
    shake256_inc_absorb(&s_inc, optrand, SPX_N);
    shake256_inc_absorb(&s_inc, m, mlen);
    shake256_inc_finalize(&s_inc);
    shake256_inc_squeeze(R, SPX_N, &s_inc);
    shake256_inc_ctx_release(&s_inc);
    */

    keccak_state state;
    shake256_absorb_slhdsa(&state, sk_prf, SPX_N_SHAKE_256_F);
    shake256_absorb_slhdsa(&state, optrand, SPX_N_SHAKE_256_F);
    shake256_absorb_slhdsa(&state, m, mlen);
    uint8_t buf[SHAKE256_RATE];
    shake256_squeezeblocks_slhdsa(buf, 1, &state);
    memcpy(R, buf, SPX_N_SHAKE_256_F);
}

void gen_message_random_shake_256_s(unsigned char* R, const unsigned char* sk_prf,
    const unsigned char* optrand,
    const unsigned char* m, size_t mlen,
    const spx_ctx_shake_256_s* ctx) {
    (void)ctx;
    /*
    shake256incctx s_inc;

    shake256_inc_init(&s_inc);
    shake256_inc_absorb(&s_inc, sk_prf, SPX_N);
    shake256_inc_absorb(&s_inc, optrand, SPX_N);
    shake256_inc_absorb(&s_inc, m, mlen);
    shake256_inc_finalize(&s_inc);
    shake256_inc_squeeze(R, SPX_N, &s_inc);
    shake256_inc_ctx_release(&s_inc);
    */

    keccak_state state;
    shake256_absorb_slhdsa(&state, sk_prf, SPX_N_SHAKE_256_S);
    shake256_absorb_slhdsa(&state, optrand, SPX_N_SHAKE_256_S);
    shake256_absorb_slhdsa(&state, m, mlen);
    uint8_t buf[SHAKE256_RATE];
    shake256_squeezeblocks_slhdsa(buf, 1, &state);
    memcpy(R, buf, SPX_N_SHAKE_256_S);
}

/**
 * Computes the message hash using R, the public key, and the message.
 * Outputs the message digest and the index of the leaf. The index is split in
 * the tree index and the leaf index, for convenient copying to an address.
 */
#define SPX_TREE_BITS_SHAKE_128_F   (SPX_TREE_HEIGHT_SHAKE_128_F * (SPX_D_SHAKE_128_F - 1))
#define SPX_TREE_BYTES_SHAKE_128_F  ((SPX_TREE_BITS_SHAKE_128_F + 7) / 8)
#define SPX_LEAF_BITS_SHAKE_128_F   SPX_TREE_HEIGHT_SHAKE_128_F
#define SPX_LEAF_BYTES_SHAKE_128_F  ((SPX_LEAF_BITS_SHAKE_128_F + 7) / 8)
#define SPX_DGST_BYTES_SHAKE_128_F  (SPX_FORS_MSG_BYTES_SHAKE_128_F + SPX_TREE_BYTES_SHAKE_128_F + SPX_LEAF_BYTES_SHAKE_128_F)

#define SPX_TREE_BITS_SHAKE_128_S   (SPX_TREE_HEIGHT_SHAKE_128_S * (SPX_D_SHAKE_128_S - 1))
#define SPX_TREE_BYTES_SHAKE_128_S  ((SPX_TREE_BITS_SHAKE_128_S + 7) / 8)
#define SPX_LEAF_BITS_SHAKE_128_S   SPX_TREE_HEIGHT_SHAKE_128_S
#define SPX_LEAF_BYTES_SHAKE_128_S  ((SPX_LEAF_BITS_SHAKE_128_S + 7) / 8)
#define SPX_DGST_BYTES_SHAKE_128_S  (SPX_FORS_MSG_BYTES_SHAKE_128_S + SPX_TREE_BYTES_SHAKE_128_S + SPX_LEAF_BYTES_SHAKE_128_S)

#define SPX_TREE_BITS_SHAKE_192_F   (SPX_TREE_HEIGHT_SHAKE_192_F * (SPX_D_SHAKE_192_F - 1))
#define SPX_TREE_BYTES_SHAKE_192_F  ((SPX_TREE_BITS_SHAKE_192_F + 7) / 8)
#define SPX_LEAF_BITS_SHAKE_192_F   SPX_TREE_HEIGHT_SHAKE_192_F
#define SPX_LEAF_BYTES_SHAKE_192_F  ((SPX_LEAF_BITS_SHAKE_192_F + 7) / 8)
#define SPX_DGST_BYTES_SHAKE_192_F  (SPX_FORS_MSG_BYTES_SHAKE_192_F + SPX_TREE_BYTES_SHAKE_192_F + SPX_LEAF_BYTES_SHAKE_192_F)

#define SPX_TREE_BITS_SHAKE_192_S   (SPX_TREE_HEIGHT_SHAKE_192_S * (SPX_D_SHAKE_192_S - 1))
#define SPX_TREE_BYTES_SHAKE_192_S  ((SPX_TREE_BITS_SHAKE_192_S + 7) / 8)
#define SPX_LEAF_BITS_SHAKE_192_S   SPX_TREE_HEIGHT_SHAKE_192_S
#define SPX_LEAF_BYTES_SHAKE_192_S  ((SPX_LEAF_BITS_SHAKE_192_S + 7) / 8)
#define SPX_DGST_BYTES_SHAKE_192_S  (SPX_FORS_MSG_BYTES_SHAKE_192_S + SPX_TREE_BYTES_SHAKE_192_S + SPX_LEAF_BYTES_SHAKE_192_S)

#define SPX_TREE_BITS_SHAKE_256_F   (SPX_TREE_HEIGHT_SHAKE_256_F * (SPX_D_SHAKE_256_F - 1))
#define SPX_TREE_BYTES_SHAKE_256_F  ((SPX_TREE_BITS_SHAKE_256_F + 7) / 8)
#define SPX_LEAF_BITS_SHAKE_256_F   SPX_TREE_HEIGHT_SHAKE_256_F
#define SPX_LEAF_BYTES_SHAKE_256_F  ((SPX_LEAF_BITS_SHAKE_256_F + 7) / 8)
#define SPX_DGST_BYTES_SHAKE_256_F  (SPX_FORS_MSG_BYTES_SHAKE_256_F + SPX_TREE_BYTES_SHAKE_256_F + SPX_LEAF_BYTES_SHAKE_256_F)

#define SPX_TREE_BITS_SHAKE_256_S   (SPX_TREE_HEIGHT_SHAKE_256_S * (SPX_D_SHAKE_256_S - 1))
#define SPX_TREE_BYTES_SHAKE_256_S  ((SPX_TREE_BITS_SHAKE_256_S + 7) / 8)
#define SPX_LEAF_BITS_SHAKE_256_S   SPX_TREE_HEIGHT_SHAKE_256_S
#define SPX_LEAF_BYTES_SHAKE_256_S  ((SPX_LEAF_BITS_SHAKE_256_S + 7) / 8)
#define SPX_DGST_BYTES_SHAKE_256_S  (SPX_FORS_MSG_BYTES_SHAKE_256_S + SPX_TREE_BYTES_SHAKE_256_S + SPX_LEAF_BYTES_SHAKE_256_S)


void hash_message_shake_128_f(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, size_t mlen,
                  const spx_ctx_shake_128_f *ctx) {
    (void)ctx;

    unsigned char buf[SPX_DGST_BYTES_SHAKE_128_F];
    unsigned char *bufp = buf;
    /*
    shake256incctx s_inc;

    shake256_inc_init(&s_inc);
    shake256_inc_absorb(&s_inc, R, SPX_N);
    shake256_inc_absorb(&s_inc, pk, SPX_PK_BYTES);
    shake256_inc_absorb(&s_inc, m, mlen);
    shake256_inc_finalize(&s_inc);
    shake256_inc_squeeze(buf, SPX_DGST_BYTES, &s_inc);
    shake256_inc_ctx_release(&s_inc);
    */

    keccak_state state;
    shake256_absorb_slhdsa(&state, R, SPX_N_SHAKE_128_F);
    shake256_absorb_slhdsa(&state, pk, SPX_PK_BYTES_SHAKE_128_F);
    shake256_absorb_slhdsa(&state, m, mlen);
    uint8_t hbuf[SHAKE256_RATE];
    shake256_squeezeblocks_slhdsa(hbuf, 1, &state);
    memcpy(buf, hbuf, SPX_DGST_BYTES_SHAKE_128_F);


    memcpy(digest, bufp, SPX_FORS_MSG_BYTES_SHAKE_128_F);
    bufp += SPX_FORS_MSG_BYTES_SHAKE_128_F;

    *tree = bytes_to_ull(bufp, SPX_TREE_BYTES_SHAKE_128_F);
    *tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS_SHAKE_128_F);
    bufp += SPX_TREE_BYTES_SHAKE_128_F;

    *leaf_idx = (uint32_t)bytes_to_ull(bufp, SPX_LEAF_BYTES_SHAKE_128_F);
    *leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS_SHAKE_128_F);
}

void hash_message_shake_128_s(unsigned char* digest, uint64_t* tree, uint32_t* leaf_idx,
    const unsigned char* R, const unsigned char* pk,
    const unsigned char* m, size_t mlen,
    const spx_ctx_shake_128_s* ctx) {
    (void)ctx;

    unsigned char buf[SPX_DGST_BYTES_SHAKE_128_S];
    unsigned char* bufp = buf;
    /*
    shake256incctx s_inc;

    shake256_inc_init(&s_inc);
    shake256_inc_absorb(&s_inc, R, SPX_N);
    shake256_inc_absorb(&s_inc, pk, SPX_PK_BYTES);
    shake256_inc_absorb(&s_inc, m, mlen);
    shake256_inc_finalize(&s_inc);
    shake256_inc_squeeze(buf, SPX_DGST_BYTES, &s_inc);
    shake256_inc_ctx_release(&s_inc);
    */

    keccak_state state;
    shake256_absorb_slhdsa(&state, R, SPX_N_SHAKE_128_S);
    shake256_absorb_slhdsa(&state, pk, SPX_PK_BYTES_SHAKE_128_S);
    shake256_absorb_slhdsa(&state, m, mlen);
    uint8_t hbuf[SHAKE256_RATE];
    shake256_squeezeblocks_slhdsa(hbuf, 1, &state);
    memcpy(buf, hbuf, SPX_DGST_BYTES_SHAKE_128_S);


    memcpy(digest, bufp, SPX_FORS_MSG_BYTES_SHAKE_128_S);
    bufp += SPX_FORS_MSG_BYTES_SHAKE_128_S;

    *tree = bytes_to_ull(bufp, SPX_TREE_BYTES_SHAKE_128_S);
    *tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS_SHAKE_128_S);
    bufp += SPX_TREE_BYTES_SHAKE_128_S;

    *leaf_idx = (uint32_t)bytes_to_ull(bufp, SPX_LEAF_BYTES_SHAKE_128_S);
    *leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS_SHAKE_128_S);
}

void hash_message_shake_192_f(unsigned char* digest, uint64_t* tree, uint32_t* leaf_idx,
    const unsigned char* R, const unsigned char* pk,
    const unsigned char* m, size_t mlen,
    const spx_ctx_shake_192_f* ctx) {
    (void)ctx;

    unsigned char buf[SPX_DGST_BYTES_SHAKE_192_F];
    unsigned char* bufp = buf;
    /*
    shake256incctx s_inc;

    shake256_inc_init(&s_inc);
    shake256_inc_absorb(&s_inc, R, SPX_N);
    shake256_inc_absorb(&s_inc, pk, SPX_PK_BYTES);
    shake256_inc_absorb(&s_inc, m, mlen);
    shake256_inc_finalize(&s_inc);
    shake256_inc_squeeze(buf, SPX_DGST_BYTES, &s_inc);
    shake256_inc_ctx_release(&s_inc);
    */

    keccak_state state;
    shake256_absorb_slhdsa(&state, R, SPX_N_SHAKE_192_F);
    shake256_absorb_slhdsa(&state, pk, SPX_PK_BYTES_SHAKE_192_F);
    shake256_absorb_slhdsa(&state, m, mlen);
    uint8_t hbuf[SHAKE256_RATE];
    shake256_squeezeblocks_slhdsa(hbuf, 1, &state);
    memcpy(buf, hbuf, SPX_DGST_BYTES_SHAKE_192_F);


    memcpy(digest, bufp, SPX_FORS_MSG_BYTES_SHAKE_192_F);
    bufp += SPX_FORS_MSG_BYTES_SHAKE_192_F;

    *tree = bytes_to_ull(bufp, SPX_TREE_BYTES_SHAKE_192_F);
    *tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS_SHAKE_192_F);
    bufp += SPX_TREE_BYTES_SHAKE_192_F;

    *leaf_idx = (uint32_t)bytes_to_ull(bufp, SPX_LEAF_BYTES_SHAKE_192_F);
    *leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS_SHAKE_192_F);
}

void hash_message_shake_192_s(unsigned char* digest, uint64_t* tree, uint32_t* leaf_idx,
    const unsigned char* R, const unsigned char* pk,
    const unsigned char* m, size_t mlen,
    const spx_ctx_shake_192_s* ctx) {
    (void)ctx;

    unsigned char buf[SPX_DGST_BYTES_SHAKE_192_S];
    unsigned char* bufp = buf;
    /*
    shake256incctx s_inc;

    shake256_inc_init(&s_inc);
    shake256_inc_absorb(&s_inc, R, SPX_N);
    shake256_inc_absorb(&s_inc, pk, SPX_PK_BYTES);
    shake256_inc_absorb(&s_inc, m, mlen);
    shake256_inc_finalize(&s_inc);
    shake256_inc_squeeze(buf, SPX_DGST_BYTES, &s_inc);
    shake256_inc_ctx_release(&s_inc);
    */

    keccak_state state;
    shake256_absorb_slhdsa(&state, R, SPX_N_SHAKE_192_S);
    shake256_absorb_slhdsa(&state, pk, SPX_PK_BYTES_SHAKE_192_S);
    shake256_absorb_slhdsa(&state, m, mlen);
    uint8_t hbuf[SHAKE256_RATE];
    shake256_squeezeblocks_slhdsa(hbuf, 1, &state);
    memcpy(buf, hbuf, SPX_DGST_BYTES_SHAKE_192_S);


    memcpy(digest, bufp, SPX_FORS_MSG_BYTES_SHAKE_192_S);
    bufp += SPX_FORS_MSG_BYTES_SHAKE_192_S;

    *tree = bytes_to_ull(bufp, SPX_TREE_BYTES_SHAKE_192_S);
    *tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS_SHAKE_192_S);
    bufp += SPX_TREE_BYTES_SHAKE_192_S;

    *leaf_idx = (uint32_t)bytes_to_ull(bufp, SPX_LEAF_BYTES_SHAKE_192_S);
    *leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS_SHAKE_192_S);
}

void hash_message_shake_256_f(unsigned char* digest, uint64_t* tree, uint32_t* leaf_idx,
    const unsigned char* R, const unsigned char* pk,
    const unsigned char* m, size_t mlen,
    const spx_ctx_shake_256_f* ctx) {
    (void)ctx;

    unsigned char buf[SPX_DGST_BYTES_SHAKE_256_F];
    unsigned char* bufp = buf;
    /*
    shake256incctx s_inc;

    shake256_inc_init(&s_inc);
    shake256_inc_absorb(&s_inc, R, SPX_N);
    shake256_inc_absorb(&s_inc, pk, SPX_PK_BYTES);
    shake256_inc_absorb(&s_inc, m, mlen);
    shake256_inc_finalize(&s_inc);
    shake256_inc_squeeze(buf, SPX_DGST_BYTES, &s_inc);
    shake256_inc_ctx_release(&s_inc);
    */

    keccak_state state;
    shake256_absorb_slhdsa(&state, R, SPX_N_SHAKE_256_F);
    shake256_absorb_slhdsa(&state, pk, SPX_PK_BYTES_SHAKE_256_F);
    shake256_absorb_slhdsa(&state, m, mlen);
    uint8_t hbuf[SHAKE256_RATE];
    shake256_squeezeblocks_slhdsa(hbuf, 1, &state);
    memcpy(buf, hbuf, SPX_DGST_BYTES_SHAKE_256_F);


    memcpy(digest, bufp, SPX_FORS_MSG_BYTES_SHAKE_256_F);
    bufp += SPX_FORS_MSG_BYTES_SHAKE_256_F;

    *tree = bytes_to_ull(bufp, SPX_TREE_BYTES_SHAKE_256_F);
    *tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS_SHAKE_256_F);
    bufp += SPX_TREE_BYTES_SHAKE_256_F;

    *leaf_idx = (uint32_t)bytes_to_ull(bufp, SPX_LEAF_BYTES_SHAKE_256_F);
    *leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS_SHAKE_256_F);
}

void hash_message_shake_256_s(unsigned char* digest, uint64_t* tree, uint32_t* leaf_idx,
    const unsigned char* R, const unsigned char* pk,
    const unsigned char* m, size_t mlen,
    const spx_ctx_shake_256_s* ctx) {
    (void)ctx;

    unsigned char buf[SPX_DGST_BYTES_SHAKE_256_S];
    unsigned char* bufp = buf;
    /*
    shake256incctx s_inc;

    shake256_inc_init(&s_inc);
    shake256_inc_absorb(&s_inc, R, SPX_N);
    shake256_inc_absorb(&s_inc, pk, SPX_PK_BYTES);
    shake256_inc_absorb(&s_inc, m, mlen);
    shake256_inc_finalize(&s_inc);
    shake256_inc_squeeze(buf, SPX_DGST_BYTES, &s_inc);
    shake256_inc_ctx_release(&s_inc);
    */

    keccak_state state;
    shake256_absorb_slhdsa(&state, R, SPX_N_SHAKE_256_S);
    shake256_absorb_slhdsa(&state, pk, SPX_PK_BYTES_SHAKE_256_S);
    shake256_absorb_slhdsa(&state, m, mlen);
    uint8_t hbuf[SHAKE256_RATE];
    shake256_squeezeblocks_slhdsa(hbuf, 1, &state);
    memcpy(buf, hbuf, SPX_DGST_BYTES_SHAKE_256_S);


    memcpy(digest, bufp, SPX_FORS_MSG_BYTES_SHAKE_256_S);
    bufp += SPX_FORS_MSG_BYTES_SHAKE_256_S;

    *tree = bytes_to_ull(bufp, SPX_TREE_BYTES_SHAKE_256_S);
    *tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS_SHAKE_256_S);
    bufp += SPX_TREE_BYTES_SHAKE_256_S;

    *leaf_idx = (uint32_t)bytes_to_ull(bufp, SPX_LEAF_BYTES_SHAKE_256_S);
    *leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS_SHAKE_256_S);
}