/*
 * eddsa_alt.c
 *
 *  Created on: Nov 14, 2024
 *      Author: vagrant
 */
#include "common.h"
#include "qubip.h"

#if defined(MBEDTLS_EDDSA_VERIFY_ALT)

#include "mbedtls/eddsa.h"
#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    pvPortCalloc
#define mbedtls_free       vPortFree
#endif

#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#if defined(MBEDTLS_ECP_DP_ED25519_ENABLED)
#include "mbedtls/sha512.h"
#endif

#ifdef MBEDTLS_ECP_DP_ED25519_ENABLED
static int mbedtls_eddsa_put_dom2_ctx(int flag, const unsigned char *ctx,
		size_t ctx_len, mbedtls_sha512_context *sha_ctx) {
	unsigned char ct_init_string[] = "SigEd25519 no Ed25519 collisions";
	unsigned char ct_flag = flag;
	unsigned char ct_ctx_len = ctx_len & 0xff;

	mbedtls_sha512_update(sha_ctx, ct_init_string, 32);
	mbedtls_sha512_update(sha_ctx, &ct_flag, 1);
	mbedtls_sha512_update(sha_ctx, &ct_ctx_len, 1);

	if (ctx && ctx_len > 0) {
		mbedtls_sha512_update(sha_ctx, ctx, ctx_len);
	}

	return 0;
}
#endif

void reverse32(unsigned char buf[32]) {
	for (size_t i = 0; i < 16; i++) {
		unsigned char tmp = buf[i];
		buf[i] = buf[31 - i];
		buf[31 - i] = tmp;
	}
}

//void ed25519VerifySignature(const uint8_t *publicKey, const void *message,
//   size_t messageLen, const void *context, uint8_t contextLen, uint8_t flag,
//   const uint8_t *signature, uint8_t *ver)
// void EDDSA25519_VERIFY(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pub_key, const unsigned int pub_len, const unsigned char* sig, const unsigned int sig_len, unsigned int* result)
int mbedtls_eddsa_sign_secpat(mbedtls_ecp_group *grp,
		mbedtls_ecp_keypair *key_pair, const unsigned char *buf, size_t blen,
		const mbedtls_mpi *d, const mbedtls_ecp_point *outQ,
		const mbedtls_mpi *r, const mbedtls_mpi *s, mbedtls_eddsa_id eddsa_id,
		const unsigned char *ed_ctx, size_t ed_ctx_len,
		int (*f_rng)(void*, unsigned char*, size_t), void *p_rng,
		const unsigned char *out_sig, unsigned int *out_sig_size) {

	int ret;
	mbedtls_ecp_point Q, R;
	mbedtls_mpi q, prefix, rq, h;

	/* EdDSA only should be used with Ed25519 curve  */
	if (!mbedtls_eddsa_can_do(grp->id) || grp->N.p == NULL) {
		return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
	}

#ifdef MBEDTLS_ECP_DP_ED25519_ENABLED
	if (grp->id == MBEDTLS_ECP_DP_ED25519 && eddsa_id != MBEDTLS_EDDSA_PURE
			&& eddsa_id != MBEDTLS_EDDSA_CTX
			&& eddsa_id != MBEDTLS_EDDSA_PREHASH) {
		return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
	}
#endif

	if (eddsa_id == MBEDTLS_EDDSA_PREHASH && blen != 64) {
		return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
	}

	mbedtls_ecp_point_init(&Q);
	mbedtls_ecp_point_init(&R);

	mbedtls_mpi_init(&q);
	mbedtls_mpi_init(&prefix);
	mbedtls_mpi_init(&rq);
	mbedtls_mpi_init(&h);

	/* Step 1 */
	MBEDTLS_MPI_CHK(mbedtls_ecp_expand_edwards(grp, d, &q, &prefix));

	MBEDTLS_MPI_CHK(mbedtls_ecp_mul(grp, &Q, &q, &grp->G, f_rng, p_rng));

	switch (grp->id) {
#ifdef MBEDTLS_ECP_DP_ED25519_ENABLED
	case MBEDTLS_ECP_DP_ED25519: {
		mbedtls_sha512_context sha_ctx;
		unsigned char sha_buf[64], tmp_buf[32];
		size_t olen = 0;

		/* r computation */
		mbedtls_sha512_init(&sha_ctx);
		mbedtls_sha512_starts(&sha_ctx, 0);

		/* Step 2 */
		if (eddsa_id == MBEDTLS_EDDSA_CTX) {
			MBEDTLS_MPI_CHK(
					mbedtls_eddsa_put_dom2_ctx(0, ed_ctx, ed_ctx_len,
							&sha_ctx));
		} else if (eddsa_id == MBEDTLS_EDDSA_PREHASH) {
			MBEDTLS_MPI_CHK(
					mbedtls_eddsa_put_dom2_ctx(1, ed_ctx, ed_ctx_len,
							&sha_ctx));
		}

		/* Update SHA with prefix */
		MBEDTLS_MPI_CHK(
				mbedtls_mpi_write_binary_le(&prefix, tmp_buf, sizeof(tmp_buf)));

		mbedtls_sha512_update(&sha_ctx, tmp_buf, sizeof(tmp_buf));

		mbedtls_platform_zeroize(tmp_buf, sizeof(tmp_buf));

		/* In EDDSA_PREHASH, buf should contain the SHA512 hash. It contains the whole message otherwise */
		mbedtls_sha512_update(&sha_ctx, buf, blen);

		mbedtls_sha512_finish(&sha_ctx, sha_buf);
		mbedtls_sha512_free(&sha_ctx);

		MBEDTLS_MPI_CHK(
				mbedtls_mpi_read_binary_le(&rq, sha_buf, sizeof(sha_buf)));

		mbedtls_platform_zeroize(sha_buf, sizeof(sha_buf));

		MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&rq, &rq, &grp->N));

		/* Step 3 */
		MBEDTLS_MPI_CHK(mbedtls_ecp_mul(grp, &R, &rq, &grp->G, f_rng, p_rng));

		/* We encode the R point to r */
		MBEDTLS_MPI_CHK(mbedtls_ecp_point_encode(grp, r, &R));

		/* s computation */
		mbedtls_sha512_init(&sha_ctx);
		mbedtls_sha512_starts(&sha_ctx, 0);

		/* Step 4 */
		if (eddsa_id == MBEDTLS_EDDSA_CTX) {
			MBEDTLS_MPI_CHK(
					mbedtls_eddsa_put_dom2_ctx(0, ed_ctx, ed_ctx_len,
							&sha_ctx));
		} else if (eddsa_id == MBEDTLS_EDDSA_PREHASH) {
			MBEDTLS_MPI_CHK(
					mbedtls_eddsa_put_dom2_ctx(1, ed_ctx, ed_ctx_len,
							&sha_ctx));
		}

		MBEDTLS_MPI_CHK(
				mbedtls_ecp_point_write_binary(grp, &R, MBEDTLS_ECP_PF_COMPRESSED, &olen, tmp_buf, sizeof(tmp_buf)));
		mbedtls_sha512_update(&sha_ctx, tmp_buf, sizeof(tmp_buf));

		MBEDTLS_MPI_CHK(
				mbedtls_ecp_point_write_binary(grp, &Q, MBEDTLS_ECP_PF_COMPRESSED, &olen, tmp_buf, sizeof(tmp_buf)));
		mbedtls_sha512_update(&sha_ctx, tmp_buf, sizeof(tmp_buf));

		mbedtls_platform_zeroize(tmp_buf, sizeof(tmp_buf));

		/* In EDDSA_PREHASH, buf should contain the SHA512 hash. It contains the whole message otherwise */
		mbedtls_sha512_update(&sha_ctx, buf, blen);

		mbedtls_sha512_finish(&sha_ctx, sha_buf);
		mbedtls_sha512_free(&sha_ctx);

		/* Step 5 */

		const unsigned char *pub_key = pvPortMalloc(32);
		const unsigned char *priv_key = pvPortMalloc(32);

		if ((ret = mbedtls_mpi_write_binary(&key_pair->d, priv_key, 32)) != 0)
			return ret;

		size_t plen = (grp->pbits + 1 + 7) >> 3;
		size_t sig_len = 2 * plen;

		if ((ret = mbedtls_ecp_point_write_binary(grp, &Q,
		MBEDTLS_ECP_PF_COMPRESSED, &sig_len, pub_key, 32)) != 0)
			return ret;

		//	void EDDSA25519_VERIFY(
		//  const unsigned char* msg, const unsigned int msg_len,
		//	const unsigned char* pub_key, const unsigned int pub_len,
		//	const unsigned char* sig, const unsigned int sig_len,
		//  unsigned int* result);

		printf("##########################################################\n");
		printf("Starting EDDSA25519 signature...\n");

		uint32_t end_time = 0;
		uint32_t start_time = micros();

#if	HW_IMPLEMENTATION==1

		uint8_t unused = 0;
		bool external_key = true;
		mbedtls_eddsa(grp, r, s, d, buf, blen, eddsa_id, ed_ctx,
				ed_ctx_len, f_rng, p_rng);
		/*
		 void eddsa25519_sign_hw(unsigned char *msg, unsigned int msg_len,
		 unsigned char *pri_key, unsigned int pri_len, unsigned char *pub_key,
		 unsigned int pub_len, unsigned char **sig, unsigned int *sig_len,
		 bool ext_key, uint8_t *key_id, INTF interface)
		 */
		unsigned char *out_sig_buf = (unsigned char*) pvPortMalloc(
				100 * sizeof(unsigned char));
		//reverse32(priv_key);
		start_time = micros();
		eddsa25519_sign_hw(sha_buf, 64, priv_key, 32, pub_key, 32, &out_sig_buf,
				out_sig_size, external_key, &unused, 0);
		end_time = micros();
		ed25519_sign_us = end_time - start_time;
		printf("HW EDDSA Signature - %lu us\t\t\t\033[1;32m\u2705\033[0m\n",
				ed25519_sign_us);

		memcpy(out_sig, out_sig_buf, 64);
		vPortFree(out_sig_buf);

#else

		/*
		 *void EDDSA25519_SIGN(const unsigned char* msg, const unsigned int msg_len,
		 *void const unsigned char* pri_key, const unsigned int pri_len,
		 *void unsigned char** sig, unsigned int* sig_len)
		 */
		start_time = micros();
		mbedtls_eddsa(grp, r, s, d, buf, blen, eddsa_id, ed_ctx, ed_ctx_len,
				f_rng, p_rng);
		end_time = micros();
		ed25519_sign_us = end_time - start_time;
		printf("SW EDDSA Signature - %lu us\t\t\t\033[1;32m\u2705\033[0m\n",
				ed25519_sign_us);
#endif

		printf("EDDSA25519 signature completed!\n");
		printf(
				"##########################################################\n\n");

		vPortFree(priv_key);
		vPortFree(pub_key);

		break;
	}
#endif
	default:
		break;
	}

	cleanup: mbedtls_mpi_free(&q);
	mbedtls_mpi_free(&prefix);
	mbedtls_mpi_free(&rq);
	mbedtls_mpi_free(&h);
	mbedtls_ecp_point_free(&Q);
	mbedtls_ecp_point_free(&R);

	return ret;
}

int mbedtls_eddsa_verify_secpat(mbedtls_ecp_group *grp,
		const unsigned char *buf, size_t blen, const mbedtls_ecp_point *Q,
		const mbedtls_mpi *r, const mbedtls_mpi *s, mbedtls_eddsa_id eddsa_id,
		const unsigned char *ed_ctx, size_t ed_ctx_len) {
	int ret = 0;
	if (grp->id != MBEDTLS_ECP_DP_ED25519) {
		return 1;
	}

	const unsigned char *sig = malloc(76);
	const unsigned char *pub_key = malloc(32);
	size_t plen = (grp->pbits + 1 + 7) >> 3;
	size_t sig_len = 2 * plen;

	if ((ret = mbedtls_mpi_write_binary_le(r, sig, 76)) != 0)
		return ret;
	if ((ret = mbedtls_mpi_write_binary_le(s, sig + plen, 76 - plen)) != 0)
		return ret;

	if ((ret = mbedtls_ecp_point_write_binary(grp, Q,
	MBEDTLS_ECP_PF_UNCOMPRESSED, &sig_len, pub_key, 32)) != 0)
		return ret;

	//	void EDDSA25519_VERIFY(
	//  const unsigned char* msg, const unsigned int msg_len,
	//	const unsigned char* pub_key, const unsigned int pub_len,
	//	const unsigned char* sig, const unsigned int sig_len,
	//  unsigned int* result);

	printf("##########################################################\n");
	printf("Starting EDDSA25519 verify...\n");
	uint32_t end_time = 0;
	uint32_t start_time = micros();

#if	HW_IMPLEMENTATION==1

	uint8_t unused = 0;
	bool external_key = true;
	/*
	 *
	 * void eddsa25519_verify_hw(unsigned char *msg, unsigned int msg_len,
	 unsigned char *pub_key, unsigned int pub_len,
	 unsigned char *sig, unsigned int sig_len,
	 unsigned int *result, bool ext_key,
	 uint8_t *key_id, INTF interface)
	 */
	start_time = micros();

	eddsa25519_verify_hw(buf, blen, pub_key, 32, sig, sig_len, &ret,
			external_key, &unused, 0);
	end_time = micros();
	ed25519_verify_us += (end_time - start_time);
	printf("HW EDDSA Verify - %lu us\t\t\t\033[1;32m\u2705\033[0m\n",
			ed25519_verify_us);

	ret = !ret;
#else

	/*
	 * void EDDSA25519_VERIFY(const unsigned char* msg, const unsigned int msg_len,
	 * const unsigned char* pub_key, const unsigned int pub_len,
	 * const unsigned char* sig, const unsigned int sig_len,
	 * unsigned int* result);
	 *
	 */
	start_time = micros();
	EDDSA25519_VERIFY(buf, blen, pub_key, 32, sig, sig_len, &ret);
	end_time = micros();
	ed25519_verify_us += (end_time - start_time);
	printf("SW EDDSA Verify - %lu us\t\t\t\033[1;32m\u2705\033[0m\n",
			ed25519_verify_us);
#endif
	printf("EDDSA25519 verify completed!\n");
	printf("##########################################################\n\n");
	free(sig);
	free(pub_key);
	return ret;
}
#endif
