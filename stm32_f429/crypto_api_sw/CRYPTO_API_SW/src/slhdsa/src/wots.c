#include <stdint.h>
#include <string.h>

#include "wots.h"
#include "wotsx1.h"

#include "address.h"
#include "hash.h"
#include "params.h"
#include "thash.h"
#include "utils.h"
#include "utilsx1.h"

// TODO clarify address expectations, and make them more uniform.
// TODO i.e. do we expect types to be set already?
// TODO and do we expect modifications or copies?

/**
 * Computes the chaining function.
 * out and in have to be n-byte arrays.
 *
 * Interprets in as start-th value of the chain.
 * addr has to contain the address of the chain.
 */
static void gen_chain_shake_128_f(unsigned char *out, const unsigned char *in,
    uint32_t start, uint32_t steps,
    const spx_ctx_shake_128_f *ctx, uint32_t addr[8]) {
    uint32_t i;

    /* Initialize out with the value at position 'start'. */
    memcpy(out, in, SPX_N_SHAKE_128_F);

    /* Iterate 'steps' calls to the hash function. */
    for (i = start; i < (start + steps) && i < SPX_WOTS_W_SHAKE_128_F; i++) {
        set_hash_addr(addr, i);
        thash_shake_128_f(out, out, 1, ctx, addr);
    }
}
static void gen_chain_shake_128_s(unsigned char* out, const unsigned char* in,
    uint32_t start, uint32_t steps,
    const spx_ctx_shake_128_s* ctx, uint32_t addr[8]) {
    uint32_t i;

    /* Initialize out with the value at position 'start'. */
    memcpy(out, in, SPX_N_SHAKE_128_S);

    /* Iterate 'steps' calls to the hash function. */
    for (i = start; i < (start + steps) && i < SPX_WOTS_W_SHAKE_128_S; i++) {
        set_hash_addr(addr, i);
        thash_shake_128_s(out, out, 1, ctx, addr);
    }
}

static void gen_chain_shake_192_f(unsigned char* out, const unsigned char* in,
    uint32_t start, uint32_t steps,
    const spx_ctx_shake_192_f* ctx, uint32_t addr[8]) {
    uint32_t i;

    /* Initialize out with the value at position 'start'. */
    memcpy(out, in, SPX_N_SHAKE_192_F);

    /* Iterate 'steps' calls to the hash function. */
    for (i = start; i < (start + steps) && i < SPX_WOTS_W_SHAKE_192_F; i++) {
        set_hash_addr(addr, i);
        thash_shake_192_f(out, out, 1, ctx, addr);
    }
}
static void gen_chain_shake_192_s(unsigned char* out, const unsigned char* in,
    uint32_t start, uint32_t steps,
    const spx_ctx_shake_192_s* ctx, uint32_t addr[8]) {
    uint32_t i;

    /* Initialize out with the value at position 'start'. */
    memcpy(out, in, SPX_N_SHAKE_192_S);

    /* Iterate 'steps' calls to the hash function. */
    for (i = start; i < (start + steps) && i < SPX_WOTS_W_SHAKE_192_S; i++) {
        set_hash_addr(addr, i);
        thash_shake_192_s(out, out, 1, ctx, addr);
    }
}

static void gen_chain_shake_256_f(unsigned char* out, const unsigned char* in,
    uint32_t start, uint32_t steps,
    const spx_ctx_shake_256_f* ctx, uint32_t addr[8]) {
    uint32_t i;

    /* Initialize out with the value at position 'start'. */
    memcpy(out, in, SPX_N_SHAKE_256_F);

    /* Iterate 'steps' calls to the hash function. */
    for (i = start; i < (start + steps) && i < SPX_WOTS_W_SHAKE_256_F; i++) {
        set_hash_addr(addr, i);
        thash_shake_256_f(out, out, 1, ctx, addr);
    }
}
static void gen_chain_shake_256_s(unsigned char* out, const unsigned char* in,
    uint32_t start, uint32_t steps,
    const spx_ctx_shake_256_s* ctx, uint32_t addr[8]) {
    uint32_t i;

    /* Initialize out with the value at position 'start'. */
    memcpy(out, in, SPX_N_SHAKE_256_S);

    /* Iterate 'steps' calls to the hash function. */
    for (i = start; i < (start + steps) && i < SPX_WOTS_W_SHAKE_256_S; i++) {
        set_hash_addr(addr, i);
        thash_shake_256_s(out, out, 1, ctx, addr);
    }
}

/**
 * base_w algorithm as described in draft.
 * Interprets an array of bytes as integers in base w.
 * This only works when log_w is a divisor of 8.
 */
static void base_w_shake_128_f(uint32_t *output, const int out_len,
                   const unsigned char *input) {
    int in = 0;
    int out = 0;
    unsigned char total = 0;
    int bits = 0;
    int consumed;

    for (consumed = 0; consumed < out_len; consumed++) {
        if (bits == 0) {
            total = input[in];
            in++;
            bits += 8;
        }
        bits -= SPX_WOTS_LOGW;
        output[out] = (total >> bits) & (SPX_WOTS_W_SHAKE_128_F - 1);
        out++;
    }
}
static void base_w_shake_128_s(uint32_t* output, const int out_len,
    const unsigned char* input) {
    int in = 0;
    int out = 0;
    unsigned char total = 0;
    int bits = 0;
    int consumed;

    for (consumed = 0; consumed < out_len; consumed++) {
        if (bits == 0) {
            total = input[in];
            in++;
            bits += 8;
        }
        bits -= SPX_WOTS_LOGW;
        output[out] = (total >> bits) & (SPX_WOTS_W_SHAKE_128_S - 1);
        out++;
    }
}

static void base_w_shake_192_f(uint32_t* output, const int out_len,
    const unsigned char* input) {
    int in = 0;
    int out = 0;
    unsigned char total = 0;
    int bits = 0;
    int consumed;

    for (consumed = 0; consumed < out_len; consumed++) {
        if (bits == 0) {
            total = input[in];
            in++;
            bits += 8;
        }
        bits -= SPX_WOTS_LOGW;
        output[out] = (total >> bits) & (SPX_WOTS_W_SHAKE_192_F - 1);
        out++;
    }
}
static void base_w_shake_192_s(uint32_t* output, const int out_len,
    const unsigned char* input) {
    int in = 0;
    int out = 0;
    unsigned char total = 0;
    int bits = 0;
    int consumed;

    for (consumed = 0; consumed < out_len; consumed++) {
        if (bits == 0) {
            total = input[in];
            in++;
            bits += 8;
        }
        bits -= SPX_WOTS_LOGW;
        output[out] = (total >> bits) & (SPX_WOTS_W_SHAKE_192_S - 1);
        out++;
    }
}

static void base_w_shake_256_f(uint32_t* output, const int out_len,
    const unsigned char* input) {
    int in = 0;
    int out = 0;
    unsigned char total = 0;
    int bits = 0;
    int consumed;

    for (consumed = 0; consumed < out_len; consumed++) {
        if (bits == 0) {
            total = input[in];
            in++;
            bits += 8;
        }
        bits -= SPX_WOTS_LOGW;
        output[out] = (total >> bits) & (SPX_WOTS_W_SHAKE_256_F - 1);
        out++;
    }
}
static void base_w_shake_256_s(uint32_t* output, const int out_len,
    const unsigned char* input) {
    int in = 0;
    int out = 0;
    unsigned char total = 0;
    int bits = 0;
    int consumed;

    for (consumed = 0; consumed < out_len; consumed++) {
        if (bits == 0) {
            total = input[in];
            in++;
            bits += 8;
        }
        bits -= SPX_WOTS_LOGW;
        output[out] = (total >> bits) & (SPX_WOTS_W_SHAKE_256_S - 1);
        out++;
    }
}

/* Computes the WOTS+ checksum over a message (in base_w). */
static void wots_checksum_shake_128_f(uint32_t *csum_base_w,
                          const uint32_t *msg_base_w) {
    uint32_t csum = 0;
    unsigned char csum_bytes[(SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8];
    uint32_t i;

    /* Compute checksum. */
    for (i = 0; i < SPX_WOTS_LEN1_SHAKE_128_F; i++) {
        csum += SPX_WOTS_W_SHAKE_128_F - 1 - msg_base_w[i];
    }

    /* Convert checksum to base_w. */
    /* Make sure expected empty zero bits are the least significant bits. */
    csum = csum << ((8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8)) % 8);
    ull_to_bytes(csum_bytes, sizeof(csum_bytes), csum);
    base_w_shake_128_f(csum_base_w, SPX_WOTS_LEN2, csum_bytes);
}
static void wots_checksum_shake_128_s(uint32_t* csum_base_w,
    const uint32_t* msg_base_w) {
    uint32_t csum = 0;
    unsigned char csum_bytes[(SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8];
    uint32_t i;

    /* Compute checksum. */
    for (i = 0; i < SPX_WOTS_LEN1_SHAKE_128_S; i++) {
        csum += SPX_WOTS_W_SHAKE_128_S - 1 - msg_base_w[i];
    }

    /* Convert checksum to base_w. */
    /* Make sure expected empty zero bits are the least significant bits. */
    csum = csum << ((8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8)) % 8);
    ull_to_bytes(csum_bytes, sizeof(csum_bytes), csum);
    base_w_shake_128_s(csum_base_w, SPX_WOTS_LEN2, csum_bytes);
}

static void wots_checksum_shake_192_f(uint32_t* csum_base_w,
    const uint32_t* msg_base_w) {
    uint32_t csum = 0;
    unsigned char csum_bytes[(SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8];
    uint32_t i;

    /* Compute checksum. */
    for (i = 0; i < SPX_WOTS_LEN1_SHAKE_192_F; i++) {
        csum += SPX_WOTS_W_SHAKE_192_F - 1 - msg_base_w[i];
    }

    /* Convert checksum to base_w. */
    /* Make sure expected empty zero bits are the least significant bits. */
    csum = csum << ((8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8)) % 8);
    ull_to_bytes(csum_bytes, sizeof(csum_bytes), csum);
    base_w_shake_192_f(csum_base_w, SPX_WOTS_LEN2, csum_bytes);
}
static void wots_checksum_shake_192_s(uint32_t* csum_base_w,
    const uint32_t* msg_base_w) {
    uint32_t csum = 0;
    unsigned char csum_bytes[(SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8];
    uint32_t i;

    /* Compute checksum. */
    for (i = 0; i < SPX_WOTS_LEN1_SHAKE_192_S; i++) {
        csum += SPX_WOTS_W_SHAKE_192_S - 1 - msg_base_w[i];
    }

    /* Convert checksum to base_w. */
    /* Make sure expected empty zero bits are the least significant bits. */
    csum = csum << ((8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8)) % 8);
    ull_to_bytes(csum_bytes, sizeof(csum_bytes), csum);
    base_w_shake_192_s(csum_base_w, SPX_WOTS_LEN2, csum_bytes);
}

static void wots_checksum_shake_256_f(uint32_t* csum_base_w,
    const uint32_t* msg_base_w) {
    uint32_t csum = 0;
    unsigned char csum_bytes[(SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8];
    uint32_t i;

    /* Compute checksum. */
    for (i = 0; i < SPX_WOTS_LEN1_SHAKE_256_F; i++) {
        csum += SPX_WOTS_W_SHAKE_256_F - 1 - msg_base_w[i];
    }

    /* Convert checksum to base_w. */
    /* Make sure expected empty zero bits are the least significant bits. */
    csum = csum << ((8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8)) % 8);
    ull_to_bytes(csum_bytes, sizeof(csum_bytes), csum);
    base_w_shake_256_f(csum_base_w, SPX_WOTS_LEN2, csum_bytes);
}
static void wots_checksum_shake_256_s(uint32_t* csum_base_w,
    const uint32_t* msg_base_w) {
    uint32_t csum = 0;
    unsigned char csum_bytes[(SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8];
    uint32_t i;

    /* Compute checksum. */
    for (i = 0; i < SPX_WOTS_LEN1_SHAKE_256_S; i++) {
        csum += SPX_WOTS_W_SHAKE_256_S - 1 - msg_base_w[i];
    }

    /* Convert checksum to base_w. */
    /* Make sure expected empty zero bits are the least significant bits. */
    csum = csum << ((8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8)) % 8);
    ull_to_bytes(csum_bytes, sizeof(csum_bytes), csum);
    base_w_shake_256_s(csum_base_w, SPX_WOTS_LEN2, csum_bytes);
}

/* Takes a message and derives the matching chain lengths. */
void chain_lengths_shake_128_f(uint32_t *lengths, const unsigned char *msg) {
    base_w_shake_128_f(lengths, SPX_WOTS_LEN1_SHAKE_128_F, msg);
    wots_checksum_shake_128_f(lengths + SPX_WOTS_LEN1_SHAKE_128_F, lengths);
}
void chain_lengths_shake_128_s(uint32_t* lengths, const unsigned char* msg) {
    base_w_shake_128_s(lengths, SPX_WOTS_LEN1_SHAKE_128_S, msg);
    wots_checksum_shake_128_s(lengths + SPX_WOTS_LEN1_SHAKE_128_S, lengths);
}

void chain_lengths_shake_192_f(uint32_t* lengths, const unsigned char* msg) {
    base_w_shake_192_f(lengths, SPX_WOTS_LEN1_SHAKE_192_F, msg);
    wots_checksum_shake_192_f(lengths + SPX_WOTS_LEN1_SHAKE_192_F, lengths);
}
void chain_lengths_shake_192_s(uint32_t* lengths, const unsigned char* msg) {
    base_w_shake_192_s(lengths, SPX_WOTS_LEN1_SHAKE_192_S, msg);
    wots_checksum_shake_192_s(lengths + SPX_WOTS_LEN1_SHAKE_192_S, lengths);
}

void chain_lengths_shake_256_f(uint32_t* lengths, const unsigned char* msg) {
    base_w_shake_256_f(lengths, SPX_WOTS_LEN1_SHAKE_256_F, msg);
    wots_checksum_shake_256_f(lengths + SPX_WOTS_LEN1_SHAKE_256_F, lengths);
}
void chain_lengths_shake_256_s(uint32_t* lengths, const unsigned char* msg) {
    base_w_shake_256_s(lengths, SPX_WOTS_LEN1_SHAKE_256_S, msg);
    wots_checksum_shake_256_s(lengths + SPX_WOTS_LEN1_SHAKE_256_S, lengths);
}

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
void wots_pk_from_sig_shake_128_f(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *msg,
                      const spx_ctx_shake_128_f *ctx, uint32_t addr[8]) {
    uint32_t lengths[SPX_WOTS_LEN_SHAKE_128_F];
    uint32_t i;

    chain_lengths_shake_128_f(lengths, msg);

    for (i = 0; i < SPX_WOTS_LEN_SHAKE_128_F; i++) {
        set_chain_addr(addr, i);
        gen_chain_shake_128_f(pk + i * SPX_N_SHAKE_128_F, sig + i * SPX_N_SHAKE_128_F,
                  lengths[i], SPX_WOTS_W_SHAKE_128_F - 1 - lengths[i], ctx, addr);
    }
}
void wots_pk_from_sig_shake_128_s(unsigned char* pk,
    const unsigned char* sig, const unsigned char* msg,
    const spx_ctx_shake_128_s* ctx, uint32_t addr[8]) {
    uint32_t lengths[SPX_WOTS_LEN_SHAKE_128_S];
    uint32_t i;

    chain_lengths_shake_128_s(lengths, msg);

    for (i = 0; i < SPX_WOTS_LEN_SHAKE_128_S; i++) {
        set_chain_addr(addr, i);
        gen_chain_shake_128_s(pk + i * SPX_N_SHAKE_128_S, sig + i * SPX_N_SHAKE_128_S,
            lengths[i], SPX_WOTS_W_SHAKE_128_S - 1 - lengths[i], ctx, addr);
    }
}

void wots_pk_from_sig_shake_192_f(unsigned char* pk,
    const unsigned char* sig, const unsigned char* msg,
    const spx_ctx_shake_192_f* ctx, uint32_t addr[8]) {
    uint32_t lengths[SPX_WOTS_LEN_SHAKE_192_F];
    uint32_t i;

    chain_lengths_shake_192_f(lengths, msg);

    for (i = 0; i < SPX_WOTS_LEN_SHAKE_192_F; i++) {
        set_chain_addr(addr, i);
        gen_chain_shake_192_f(pk + i * SPX_N_SHAKE_192_F, sig + i * SPX_N_SHAKE_192_F,
            lengths[i], SPX_WOTS_W_SHAKE_192_F - 1 - lengths[i], ctx, addr);
    }
}
void wots_pk_from_sig_shake_192_s(unsigned char* pk,
    const unsigned char* sig, const unsigned char* msg,
    const spx_ctx_shake_192_s* ctx, uint32_t addr[8]) {
    uint32_t lengths[SPX_WOTS_LEN_SHAKE_192_S];
    uint32_t i;

    chain_lengths_shake_192_s(lengths, msg);

    for (i = 0; i < SPX_WOTS_LEN_SHAKE_192_S; i++) {
        set_chain_addr(addr, i);
        gen_chain_shake_192_s(pk + i * SPX_N_SHAKE_192_S, sig + i * SPX_N_SHAKE_192_S,
            lengths[i], SPX_WOTS_W_SHAKE_192_S - 1 - lengths[i], ctx, addr);
    }
}

void wots_pk_from_sig_shake_256_f(unsigned char* pk,
    const unsigned char* sig, const unsigned char* msg,
    const spx_ctx_shake_256_f* ctx, uint32_t addr[8]) {
    uint32_t lengths[SPX_WOTS_LEN_SHAKE_256_F];
    uint32_t i;

    chain_lengths_shake_256_f(lengths, msg);

    for (i = 0; i < SPX_WOTS_LEN_SHAKE_256_F; i++) {
        set_chain_addr(addr, i);
        gen_chain_shake_256_f(pk + i * SPX_N_SHAKE_256_F, sig + i * SPX_N_SHAKE_256_F,
            lengths[i], SPX_WOTS_W_SHAKE_256_F - 1 - lengths[i], ctx, addr);
    }
}
void wots_pk_from_sig_shake_256_s(unsigned char* pk,
    const unsigned char* sig, const unsigned char* msg,
    const spx_ctx_shake_256_s* ctx, uint32_t addr[8]) {
    uint32_t lengths[SPX_WOTS_LEN_SHAKE_256_S];
    uint32_t i;

    chain_lengths_shake_256_s(lengths, msg);

    for (i = 0; i < SPX_WOTS_LEN_SHAKE_256_S; i++) {
        set_chain_addr(addr, i);
        gen_chain_shake_256_s(pk + i * SPX_N_SHAKE_256_S, sig + i * SPX_N_SHAKE_256_S,
            lengths[i], SPX_WOTS_W_SHAKE_256_S - 1 - lengths[i], ctx, addr);
    }
}