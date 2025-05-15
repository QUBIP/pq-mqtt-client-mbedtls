#include <stdint.h>
#include <string.h>

#include "thash.h"

#include "address.h"
#include "params.h"
#include "utils.h"

#include "fips202.h"

/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
void thash_shake_128_f(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx_shake_128_f *ctx, uint32_t addr[8]) {
    PQCLEAN_VLA(uint8_t, buf, SPX_N_SHAKE_128_F + SPX_ADDR_BYTES + inblocks * SPX_N_SHAKE_128_F);

    memcpy(buf, ctx->pub_seed, SPX_N_SHAKE_128_F);
    memcpy(buf + SPX_N_SHAKE_128_F, addr, SPX_ADDR_BYTES);
    memcpy(buf + SPX_N_SHAKE_128_F + SPX_ADDR_BYTES, in, inblocks * SPX_N_SHAKE_128_F);

    shake256_slhdsa(out, SPX_N_SHAKE_128_F, buf, SPX_N_SHAKE_128_F + SPX_ADDR_BYTES + inblocks * SPX_N_SHAKE_128_F);
}
void thash_shake_128_s(unsigned char* out, const unsigned char* in, unsigned int inblocks,
    const spx_ctx_shake_128_s* ctx, uint32_t addr[8]) {
    PQCLEAN_VLA(uint8_t, buf, SPX_N_SHAKE_128_S + SPX_ADDR_BYTES + inblocks * SPX_N_SHAKE_128_S);

    memcpy(buf, ctx->pub_seed, SPX_N_SHAKE_128_S);
    memcpy(buf + SPX_N_SHAKE_128_S, addr, SPX_ADDR_BYTES);
    memcpy(buf + SPX_N_SHAKE_128_S + SPX_ADDR_BYTES, in, inblocks * SPX_N_SHAKE_128_S);

    shake256_slhdsa(out, SPX_N_SHAKE_128_S, buf, SPX_N_SHAKE_128_S + SPX_ADDR_BYTES + inblocks * SPX_N_SHAKE_128_S);
}

void thash_shake_192_f(unsigned char* out, const unsigned char* in, unsigned int inblocks,
    const spx_ctx_shake_192_f* ctx, uint32_t addr[8]) {
    PQCLEAN_VLA(uint8_t, buf, SPX_N_SHAKE_192_F + SPX_ADDR_BYTES + inblocks * SPX_N_SHAKE_192_F);

    memcpy(buf, ctx->pub_seed, SPX_N_SHAKE_192_F);
    memcpy(buf + SPX_N_SHAKE_192_F, addr, SPX_ADDR_BYTES);
    memcpy(buf + SPX_N_SHAKE_192_F + SPX_ADDR_BYTES, in, inblocks * SPX_N_SHAKE_192_F);

    shake256_slhdsa(out, SPX_N_SHAKE_192_F, buf, SPX_N_SHAKE_192_F + SPX_ADDR_BYTES + inblocks * SPX_N_SHAKE_192_F);
}
void thash_shake_192_s(unsigned char* out, const unsigned char* in, unsigned int inblocks,
    const spx_ctx_shake_192_s* ctx, uint32_t addr[8]) {
    PQCLEAN_VLA(uint8_t, buf, SPX_N_SHAKE_192_S + SPX_ADDR_BYTES + inblocks * SPX_N_SHAKE_192_S);

    memcpy(buf, ctx->pub_seed, SPX_N_SHAKE_192_S);
    memcpy(buf + SPX_N_SHAKE_192_S, addr, SPX_ADDR_BYTES);
    memcpy(buf + SPX_N_SHAKE_192_S + SPX_ADDR_BYTES, in, inblocks * SPX_N_SHAKE_192_S);

    shake256_slhdsa(out, SPX_N_SHAKE_192_S, buf, SPX_N_SHAKE_192_S + SPX_ADDR_BYTES + inblocks * SPX_N_SHAKE_192_S);
}

void thash_shake_256_f(unsigned char* out, const unsigned char* in, unsigned int inblocks,
    const spx_ctx_shake_256_f* ctx, uint32_t addr[8]) {
    PQCLEAN_VLA(uint8_t, buf, SPX_N_SHAKE_256_F + SPX_ADDR_BYTES + inblocks * SPX_N_SHAKE_256_F);

    memcpy(buf, ctx->pub_seed, SPX_N_SHAKE_256_F);
    memcpy(buf + SPX_N_SHAKE_256_F, addr, SPX_ADDR_BYTES);
    memcpy(buf + SPX_N_SHAKE_256_F + SPX_ADDR_BYTES, in, inblocks * SPX_N_SHAKE_256_F);

    shake256_slhdsa(out, SPX_N_SHAKE_256_F, buf, SPX_N_SHAKE_256_F + SPX_ADDR_BYTES + inblocks * SPX_N_SHAKE_256_F);
}
void thash_shake_256_s(unsigned char* out, const unsigned char* in, unsigned int inblocks,
    const spx_ctx_shake_256_s* ctx, uint32_t addr[8]) {
    PQCLEAN_VLA(uint8_t, buf, SPX_N_SHAKE_256_S + SPX_ADDR_BYTES + inblocks * SPX_N_SHAKE_256_S);

    memcpy(buf, ctx->pub_seed, SPX_N_SHAKE_256_S);
    memcpy(buf + SPX_N_SHAKE_256_S, addr, SPX_ADDR_BYTES);
    memcpy(buf + SPX_N_SHAKE_256_S + SPX_ADDR_BYTES, in, inblocks * SPX_N_SHAKE_256_S);

    shake256_slhdsa(out, SPX_N_SHAKE_256_S, buf, SPX_N_SHAKE_256_S + SPX_ADDR_BYTES + inblocks * SPX_N_SHAKE_256_S);
}
