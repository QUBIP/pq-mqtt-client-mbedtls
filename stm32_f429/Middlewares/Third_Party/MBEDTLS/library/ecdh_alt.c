/*
 * ecdh_alt.c
 *
 *  Created on: Nov 14, 2024
 *      Author: vagrant
 */
#include "common.h"

#if defined(MBEDTLS_ECDH_COMPUTE_SHARED_ALT)


#include "mbedtls/ecdh.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "crypto_api_sw.h"

#include <string.h>


static int ecdh_compute_shared_restartable(mbedtls_ecp_group *grp,
                                           mbedtls_mpi *z,
                                           const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
                                           int (*f_rng)(void *, unsigned char *, size_t),
                                           void *p_rng,
                                           mbedtls_ecp_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    mbedtls_ecp_point P;

    mbedtls_ecp_point_init(&P);

    MBEDTLS_MPI_CHK(mbedtls_ecp_mul_restartable(grp, &P, d, Q,
                                                f_rng, p_rng, rs_ctx));

    if (mbedtls_ecp_is_zero_ext(grp, &P)) {
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(z, &P.X));

cleanup:
    mbedtls_ecp_point_free(&P);

    return ret;
}

/*
 * Compute shared secret (SEC1 3.3.1)
 */
int custom_compute_shared(mbedtls_ecp_group *grp, mbedtls_mpi *z,
        const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
        int (*f_rng)(void *, unsigned char *, size_t),
        void *p_rng) {
	const unsigned char* pri_key = malloc(32);
	const unsigned char* pub_key = malloc(32);
	const unsigned char *shared_secret;
	int ret = 0;
	unsigned int ssize;
	size_t olen;

	if ((ret = mbedtls_mpi_write_binary_le(d, pri_key, 32)) != 0)
		return ret;

	if((ret = mbedtls_mpi_write_binary_le(&Q->X, pub_key,32)) != 0)
		return ret;

	X25519_SS_GEN(&shared_secret,&ssize,pub_key,32,pri_key,32);

	if((ret = mbedtls_mpi_read_binary_le(z, shared_secret, ssize)) != 0)
		return ret;


	free(pri_key);
	free(pub_key);
	free(shared_secret);

	return ret;
}
int mbedtls_ecdh_compute_shared(mbedtls_ecp_group *grp, mbedtls_mpi *z,
                                const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
                                int (*f_rng)(void *, unsigned char *, size_t),
                                void *p_rng)
{
	int ret;
	if(grp->id == MBEDTLS_ECP_DP_CURVE25519){
		return custom_compute_shared(grp, z, Q, d, f_rng, p_rng);
	} else {
		return ecdh_compute_shared_restartable(grp, z, Q, d,
                                           f_rng, p_rng, NULL);
	}
	//ret = ecdh_compute_shared_restartable(grp, z, Q, d,
	//                                           f_rng, p_rng, NULL);
	return ret;
}

#endif
