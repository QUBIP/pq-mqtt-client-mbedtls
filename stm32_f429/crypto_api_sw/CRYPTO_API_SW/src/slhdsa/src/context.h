#ifndef SPX_CONTEXT_H
#define SPX_CONTEXT_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"

// ----- SHAKE 128 F ----- //

typedef struct {
    uint8_t pub_seed[SPX_N_SHAKE_128_F];
    uint8_t sk_seed[SPX_N_SHAKE_128_F];
} spx_ctx_shake_128_f;

void initialize_hash_function_shake_128_f(spx_ctx_shake_128_f *ctx);
void free_hash_function_shake_128_f(spx_ctx_shake_128_f *ctx);

// ----- SHAKE 128 S ----- //

typedef struct {
    uint8_t pub_seed[SPX_N_SHAKE_128_S];
    uint8_t sk_seed[SPX_N_SHAKE_128_S];
} spx_ctx_shake_128_s;

void initialize_hash_function_shake_128_s(spx_ctx_shake_128_s* ctx);
void free_hash_function_shake_128_s(spx_ctx_shake_128_s* ctx);

// ----- SHAKE 192 F ----- //

typedef struct {
    uint8_t pub_seed[SPX_N_SHAKE_192_F];
    uint8_t sk_seed[SPX_N_SHAKE_192_F];
} spx_ctx_shake_192_f;

void initialize_hash_function_shake_192_f(spx_ctx_shake_192_f* ctx);
void free_hash_function_shake_192_f(spx_ctx_shake_192_f* ctx);

// ----- SHAKE 192 S ----- //

typedef struct {
    uint8_t pub_seed[SPX_N_SHAKE_192_S];
    uint8_t sk_seed[SPX_N_SHAKE_192_S];
} spx_ctx_shake_192_s;

void initialize_hash_function_shake_192_s(spx_ctx_shake_192_s* ctx);
void free_hash_function_shake_192_s(spx_ctx_shake_192_s* ctx);

// ----- SHAKE 256 F ----- //

typedef struct {
    uint8_t pub_seed[SPX_N_SHAKE_256_F];
    uint8_t sk_seed[SPX_N_SHAKE_256_F];
} spx_ctx_shake_256_f;

void initialize_hash_function_shake_256_f(spx_ctx_shake_256_f* ctx);
void free_hash_function_shake_256_f(spx_ctx_shake_256_f* ctx);

// ----- SHAKE 256 S ----- //

typedef struct {
    uint8_t pub_seed[SPX_N_SHAKE_256_S];
    uint8_t sk_seed[SPX_N_SHAKE_256_S];
} spx_ctx_shake_256_s;

void initialize_hash_function_shake_256_s(spx_ctx_shake_256_s* ctx);
void free_hash_function_shake_256_s(spx_ctx_shake_256_s* ctx);

#endif
