#include "context.h"

/* For SHAKE256, there is no immediate reason to initialize at the start,
   so this function is an empty operation. */
void initialize_hash_function_shake_128_s(spx_ctx_shake_128_s *ctx) {
    (void)ctx; 
}
void initialize_hash_function_shake_128_f(spx_ctx_shake_128_f* ctx) {
    (void)ctx;
}
void initialize_hash_function_shake_192_s(spx_ctx_shake_192_s* ctx) {
    (void)ctx;
}
void initialize_hash_function_shake_192_f(spx_ctx_shake_192_f* ctx) {
    (void)ctx;
}
void initialize_hash_function_shake_256_s(spx_ctx_shake_256_s* ctx) {
    (void)ctx;
}
void initialize_hash_function_shake_256_f(spx_ctx_shake_256_f* ctx) {
    (void)ctx;
}


// in case the hash function api is heap-based.
void free_hash_function_shake_128_s(spx_ctx_shake_128_s* ctx) {
    (void)ctx;
}
void free_hash_function_shake_128_f(spx_ctx_shake_128_f* ctx) {
    (void)ctx;
}
void free_hash_function_shake_192_s(spx_ctx_shake_192_s* ctx) {
    (void)ctx;
}
void free_hash_function_shake_192_f(spx_ctx_shake_192_f* ctx) {
    (void)ctx;
}
void free_hash_function_shake_256_s(spx_ctx_shake_256_s* ctx) {
    (void)ctx;
}
void free_hash_function_shake_256_f(spx_ctx_shake_256_f* ctx) {
    (void)ctx;
}
