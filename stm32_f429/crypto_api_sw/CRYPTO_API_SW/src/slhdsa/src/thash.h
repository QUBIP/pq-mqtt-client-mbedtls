#ifndef SPX_THASH_H
#define SPX_THASH_H

#include "context.h"
#include "params.h"

#include <stdint.h>

void thash_shake_128_f(unsigned char *out, const unsigned char *in, unsigned int inblocks,
    const spx_ctx_shake_128_f *ctx, uint32_t addr[8]);
void thash_shake_128_s(unsigned char* out, const unsigned char* in, unsigned int inblocks,
    const spx_ctx_shake_128_s* ctx, uint32_t addr[8]);
void thash_shake_192_f(unsigned char* out, const unsigned char* in, unsigned int inblocks,
    const spx_ctx_shake_192_f* ctx, uint32_t addr[8]);
void thash_shake_192_s(unsigned char* out, const unsigned char* in, unsigned int inblocks,
    const spx_ctx_shake_192_s* ctx, uint32_t addr[8]);
void thash_shake_256_f(unsigned char* out, const unsigned char* in, unsigned int inblocks,
    const spx_ctx_shake_256_f* ctx, uint32_t addr[8]);
void thash_shake_256_s(unsigned char* out, const unsigned char* in, unsigned int inblocks,
    const spx_ctx_shake_256_s* ctx, uint32_t addr[8]);

#endif
