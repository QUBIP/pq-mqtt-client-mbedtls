/*
 * eddsa_alt.c
 *
 *  Created on: Nov 14, 2024
 *      Author: vagrant
 */
#include "common.h"


#if defined(MBEDTLS_EDDSA_VERIFY_ALT)

#include "mbedtls/eddsa.h"
#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#if defined(MBEDTLS_ECP_DP_ED25519_ENABLED)
#include "mbedtls/sha512.h"
#endif

//void ed25519VerifySignature(const uint8_t *publicKey, const void *message,
//   size_t messageLen, const void *context, uint8_t contextLen, uint8_t flag,
//   const uint8_t *signature, uint8_t *ver)
// void EDDSA25519_VERIFY(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pub_key, const unsigned int pub_len, const unsigned char* sig, const unsigned int sig_len, unsigned int* result)
int mbedtls_eddsa_verify(mbedtls_ecp_group *grp,
                         const unsigned char *buf, size_t blen,
                         const mbedtls_ecp_point *Q, const mbedtls_mpi *r,
                         const mbedtls_mpi *s,
                         mbedtls_eddsa_id eddsa_id,
                         const unsigned char *ed_ctx, size_t ed_ctx_len)
{
    int ret = 0;
    if(grp->id != MBEDTLS_ECP_DP_ED25519){
    	return 1;
    }

    const unsigned char* sig = malloc(76);
    const unsigned char* pub_key = malloc(32);
    size_t plen = (grp->pbits + 1 + 7) >> 3;
    size_t sig_len = 2 * plen;

    if ((ret = mbedtls_mpi_write_binary_le(r, sig, 76)) != 0)
    		return ret;
    if ((ret = mbedtls_mpi_write_binary_le(s,sig+plen,76-plen)) != 0)
    		return ret;

	if((ret = mbedtls_ecp_point_write_binary(grp, Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &sig_len, pub_key, 32)) != 0)
		return ret;

	EDDSA25519_VERIFY(buf,blen,pub_key,32,sig,sig_len,&ret);

    free(sig);
    free(pub_key);
    return ret;
}
#endif
