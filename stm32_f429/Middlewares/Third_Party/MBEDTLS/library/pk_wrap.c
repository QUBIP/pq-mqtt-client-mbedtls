/*
 *  Public Key abstraction layer: wrapper functions
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#include "mbedtls/platform_util.h"

#if defined(MBEDTLS_PK_C)
#include "pk_wrap.h"
#include "pk_internal.h"
#include "mbedtls/error.h"
#include "mbedtls/psa_util.h"

/* Even if RSA not activated, for the sake of RSA-alt */
#include "mbedtls/rsa.h"

#if defined(MBEDTLS_ECP_C)
#include "mbedtls/ecp.h"
#endif

#if defined(MBEDTLS_ECDSA_C)
#include "mbedtls/ecdsa.h"
#endif

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#include "psa_util_internal.h"
#include "psa/crypto.h"
#include "mbedtls/psa_util.h"

#if defined(MBEDTLS_RSA_C)
#include "pkwrite.h"
#include "rsa_internal.h"
#endif

#if defined(MBEDTLS_PK_CAN_ECDSA_SOME)
#include "mbedtls/asn1write.h"
#include "mbedtls/asn1.h"
#endif
#endif  /* MBEDTLS_USE_PSA_CRYPTO */

#include "mbedtls/platform.h"
#include "crypto_api_sw.h"
#include "mbedtls/eddsa.h"

#include <limits.h>
#include <stdint.h>
#include <string.h>

#include <se-qubip.h>
#include <qubip.h>

#if defined(MBEDTLS_RSA_C)
static int rsa_can_do(mbedtls_pk_type_t type) {
	return type == MBEDTLS_PK_RSA || type == MBEDTLS_PK_RSASSA_PSS;
}

static size_t rsa_get_bitlen(mbedtls_pk_context *pk) {
	const mbedtls_rsa_context *rsa = (const mbedtls_rsa_context*) pk->pk_ctx;
	return mbedtls_rsa_get_bitlen(rsa);
}

#if defined(MBEDTLS_USE_PSA_CRYPTO)
static int rsa_verify_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
		const unsigned char *hash, size_t hash_len, const unsigned char *sig,
		size_t sig_len) {
	mbedtls_rsa_context *rsa = (mbedtls_rsa_context*) pk->pk_ctx;
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
	psa_status_t status;
	int key_len;
	unsigned char buf[MBEDTLS_PK_RSA_PUB_DER_MAX_BYTES];
	unsigned char *p = buf + sizeof(buf);
	psa_algorithm_t psa_alg_md;
	size_t rsa_len = mbedtls_rsa_get_len(rsa);

#if SIZE_MAX > UINT_MAX
    if (md_alg == MBEDTLS_MD_NONE && UINT_MAX < hash_len) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
#endif

	if (mbedtls_rsa_get_padding_mode(rsa) == MBEDTLS_RSA_PKCS_V21) {
		psa_alg_md = PSA_ALG_RSA_PSS(mbedtls_md_psa_alg_from_type(md_alg));
	} else {
		psa_alg_md = PSA_ALG_RSA_PKCS1V15_SIGN(
				mbedtls_md_psa_alg_from_type(md_alg));
	}

	if (sig_len < rsa_len) {
		return MBEDTLS_ERR_RSA_VERIFY_FAILED;
	}

	key_len = mbedtls_rsa_write_pubkey(rsa, buf, &p);
	if (key_len <= 0) {
		return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
	}

	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_HASH);
	psa_set_key_algorithm(&attributes, psa_alg_md);
	psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_PUBLIC_KEY);

	status = psa_import_key(&attributes, buf + sizeof(buf) - key_len, key_len,
			&key_id);
	if (status != PSA_SUCCESS) {
		ret = PSA_PK_TO_MBEDTLS_ERR(status);
		goto cleanup;
	}

	status = psa_verify_hash(key_id, psa_alg_md, hash, hash_len, sig, sig_len);
	if (status != PSA_SUCCESS) {
		ret = PSA_PK_RSA_TO_MBEDTLS_ERR(status);
		goto cleanup;
	}
	ret = 0;

	cleanup: status = psa_destroy_key(key_id);
	if (ret == 0 && status != PSA_SUCCESS) {
		ret = PSA_PK_TO_MBEDTLS_ERR(status);
	}

	return ret;
}
#else /* MBEDTLS_USE_PSA_CRYPTO */
static int rsa_verify_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                           const unsigned char *hash, size_t hash_len,
                           const unsigned char *sig, size_t sig_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_rsa_context *rsa = (mbedtls_rsa_context *) pk->pk_ctx;
    size_t rsa_len = mbedtls_rsa_get_len(rsa);

#if SIZE_MAX > UINT_MAX
    if (md_alg == MBEDTLS_MD_NONE && UINT_MAX < hash_len) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
#endif

    if (sig_len < rsa_len) {
        return MBEDTLS_ERR_RSA_VERIFY_FAILED;
    }

    if ((ret = mbedtls_rsa_pkcs1_verify(rsa, md_alg,
                                        (unsigned int) hash_len,
                                        hash, sig)) != 0) {
        return ret;
    }

    /* The buffer contains a valid signature followed by extra data.
     * We have a special error code for that so that so that callers can
     * use mbedtls_pk_verify() to check "Does the buffer start with a
     * valid signature?" and not just "Does the buffer contain a valid
     * signature?". */
    if (sig_len > rsa_len) {
        return MBEDTLS_ERR_PK_SIG_LEN_MISMATCH;
    }

    return 0;
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(MBEDTLS_USE_PSA_CRYPTO)
int mbedtls_pk_psa_rsa_sign_ext(psa_algorithm_t alg,
		mbedtls_rsa_context *rsa_ctx, const unsigned char *hash,
		size_t hash_len, unsigned char *sig, size_t sig_size, size_t *sig_len) {
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
	psa_status_t status;
	int key_len;
	unsigned char *buf = NULL;
	unsigned char *p;

	buf = mbedtls_calloc(1, MBEDTLS_PK_RSA_PRV_DER_MAX_BYTES);
	if (buf == NULL) {
		return MBEDTLS_ERR_PK_ALLOC_FAILED;
	}
	p = buf + MBEDTLS_PK_RSA_PRV_DER_MAX_BYTES;

	*sig_len = mbedtls_rsa_get_len(rsa_ctx);
	if (sig_size < *sig_len) {
		mbedtls_free(buf);
		return MBEDTLS_ERR_PK_BUFFER_TOO_SMALL;
	}

	key_len = mbedtls_rsa_write_key(rsa_ctx, buf, &p);
	if (key_len <= 0) {
		mbedtls_free(buf);
		return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
	}
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
	psa_set_key_algorithm(&attributes, alg);
	psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);

	status = psa_import_key(&attributes,
			buf + MBEDTLS_PK_RSA_PRV_DER_MAX_BYTES - key_len, key_len, &key_id);
	if (status != PSA_SUCCESS) {
		ret = PSA_PK_TO_MBEDTLS_ERR(status);
		goto cleanup;
	}
	status = psa_sign_hash(key_id, alg, hash, hash_len, sig, sig_size, sig_len);
	if (status != PSA_SUCCESS) {
		ret = PSA_PK_RSA_TO_MBEDTLS_ERR(status);
		goto cleanup;
	}

	ret = 0;

	cleanup: mbedtls_free(buf);
	status = psa_destroy_key(key_id);
	if (ret == 0 && status != PSA_SUCCESS) {
		ret = PSA_PK_TO_MBEDTLS_ERR(status);
	}
	return ret;
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(MBEDTLS_USE_PSA_CRYPTO)
static int rsa_sign_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
		const unsigned char *hash, size_t hash_len, unsigned char *sig,
		size_t sig_size, size_t *sig_len,
		int (*f_rng)(void*, unsigned char*, size_t), void *p_rng) {
	((void) f_rng);
	((void) p_rng);

	psa_algorithm_t psa_md_alg;
	psa_md_alg = mbedtls_md_psa_alg_from_type(md_alg);
	if (psa_md_alg == 0) {
		return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
	}
	psa_algorithm_t psa_alg;
	if (mbedtls_rsa_get_padding_mode(
			mbedtls_pk_rsa(*pk)) == MBEDTLS_RSA_PKCS_V21) {
		psa_alg = PSA_ALG_RSA_PSS(psa_md_alg);
	} else {
		psa_alg = PSA_ALG_RSA_PKCS1V15_SIGN(psa_md_alg);
	}

	return mbedtls_pk_psa_rsa_sign_ext(psa_alg, pk->pk_ctx, hash, hash_len, sig,
			sig_size, sig_len);
}
#else /* MBEDTLS_USE_PSA_CRYPTO */
static int rsa_sign_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                         const unsigned char *hash, size_t hash_len,
                         unsigned char *sig, size_t sig_size, size_t *sig_len,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    mbedtls_rsa_context *rsa = (mbedtls_rsa_context *) pk->pk_ctx;

#if SIZE_MAX > UINT_MAX
    if (md_alg == MBEDTLS_MD_NONE && UINT_MAX < hash_len) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
#endif

    *sig_len = mbedtls_rsa_get_len(rsa);
    if (sig_size < *sig_len) {
        return MBEDTLS_ERR_PK_BUFFER_TOO_SMALL;
    }

    return mbedtls_rsa_pkcs1_sign(rsa, f_rng, p_rng,
                                  md_alg, (unsigned int) hash_len,
                                  hash, sig);
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(MBEDTLS_USE_PSA_CRYPTO)
static int rsa_decrypt_wrap(mbedtls_pk_context *pk, const unsigned char *input,
		size_t ilen, unsigned char *output, size_t *olen, size_t osize,
		int (*f_rng)(void*, unsigned char*, size_t), void *p_rng) {
	mbedtls_rsa_context *rsa = (mbedtls_rsa_context*) pk->pk_ctx;
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
	psa_algorithm_t psa_md_alg,
	decrypt_alg;
	psa_status_t status;
	int key_len;
	unsigned char buf[MBEDTLS_PK_RSA_PRV_DER_MAX_BYTES];
	unsigned char *p = buf + sizeof(buf);

	((void) f_rng);
	((void) p_rng);

	if (ilen != mbedtls_rsa_get_len(rsa)) {
		return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
	}

	key_len = mbedtls_rsa_write_key(rsa, buf, &p);
	if (key_len <= 0) {
		return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
	}

	psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
	if (mbedtls_rsa_get_padding_mode(rsa) == MBEDTLS_RSA_PKCS_V21) {
		psa_md_alg = mbedtls_md_psa_alg_from_type(
				(mbedtls_md_type_t) mbedtls_rsa_get_md_alg(rsa));
		decrypt_alg = PSA_ALG_RSA_OAEP(psa_md_alg);
	} else {
		decrypt_alg = PSA_ALG_RSA_PKCS1V15_CRYPT;
	}
	psa_set_key_algorithm(&attributes, decrypt_alg);

	status = psa_import_key(&attributes, buf + sizeof(buf) - key_len, key_len,
			&key_id);
	if (status != PSA_SUCCESS) {
		ret = PSA_PK_TO_MBEDTLS_ERR(status);
		goto cleanup;
	}

	status = psa_asymmetric_decrypt(key_id, decrypt_alg, input, ilen,
	NULL, 0, output, osize, olen);
	if (status != PSA_SUCCESS) {
		ret = PSA_PK_RSA_TO_MBEDTLS_ERR(status);
		goto cleanup;
	}

	ret = 0;

	cleanup: mbedtls_platform_zeroize(buf, sizeof(buf));
	status = psa_destroy_key(key_id);
	if (ret == 0 && status != PSA_SUCCESS) {
		ret = PSA_PK_TO_MBEDTLS_ERR(status);
	}

	return ret;
}
#else /* MBEDTLS_USE_PSA_CRYPTO */
static int rsa_decrypt_wrap(mbedtls_pk_context *pk,
                            const unsigned char *input, size_t ilen,
                            unsigned char *output, size_t *olen, size_t osize,
                            int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    mbedtls_rsa_context *rsa = (mbedtls_rsa_context *) pk->pk_ctx;

    if (ilen != mbedtls_rsa_get_len(rsa)) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    return mbedtls_rsa_pkcs1_decrypt(rsa, f_rng, p_rng,
                                     olen, input, output, osize);
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(MBEDTLS_USE_PSA_CRYPTO)
static int rsa_encrypt_wrap(mbedtls_pk_context *pk, const unsigned char *input,
		size_t ilen, unsigned char *output, size_t *olen, size_t osize,
		int (*f_rng)(void*, unsigned char*, size_t), void *p_rng) {
	mbedtls_rsa_context *rsa = (mbedtls_rsa_context*) pk->pk_ctx;
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
	psa_algorithm_t psa_md_alg,
	psa_encrypt_alg;
	psa_status_t status;
	int key_len;
	unsigned char buf[MBEDTLS_PK_RSA_PUB_DER_MAX_BYTES];
	unsigned char *p = buf + sizeof(buf);

	((void) f_rng);
	((void) p_rng);

	if (mbedtls_rsa_get_len(rsa) > osize) {
		return MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE;
	}

	key_len = mbedtls_rsa_write_pubkey(rsa, buf, &p);
	if (key_len <= 0) {
		return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
	}

	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
	if (mbedtls_rsa_get_padding_mode(rsa) == MBEDTLS_RSA_PKCS_V21) {
		psa_md_alg = mbedtls_md_psa_alg_from_type(
				(mbedtls_md_type_t) mbedtls_rsa_get_md_alg(rsa));
		psa_encrypt_alg = PSA_ALG_RSA_OAEP(psa_md_alg);
	} else {
		psa_encrypt_alg = PSA_ALG_RSA_PKCS1V15_CRYPT;
	}
	psa_set_key_algorithm(&attributes, psa_encrypt_alg);
	psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_PUBLIC_KEY);

	status = psa_import_key(&attributes, buf + sizeof(buf) - key_len, key_len,
			&key_id);
	if (status != PSA_SUCCESS) {
		ret = PSA_PK_TO_MBEDTLS_ERR(status);
		goto cleanup;
	}

	status = psa_asymmetric_encrypt(key_id, psa_encrypt_alg, input, ilen,
	NULL, 0, output, osize, olen);
	if (status != PSA_SUCCESS) {
		ret = PSA_PK_RSA_TO_MBEDTLS_ERR(status);
		goto cleanup;
	}

	ret = 0;

	cleanup: status = psa_destroy_key(key_id);
	if (ret == 0 && status != PSA_SUCCESS) {
		ret = PSA_PK_TO_MBEDTLS_ERR(status);
	}

	return ret;
}
#else /* MBEDTLS_USE_PSA_CRYPTO */
static int rsa_encrypt_wrap(mbedtls_pk_context *pk,
                            const unsigned char *input, size_t ilen,
                            unsigned char *output, size_t *olen, size_t osize,
                            int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    mbedtls_rsa_context *rsa = (mbedtls_rsa_context *) pk->pk_ctx;
    *olen = mbedtls_rsa_get_len(rsa);

    if (*olen > osize) {
        return MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE;
    }

    return mbedtls_rsa_pkcs1_encrypt(rsa, f_rng, p_rng,
                                     ilen, input, output);
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */

static int rsa_check_pair_wrap(mbedtls_pk_context *pub, mbedtls_pk_context *prv,
		int (*f_rng)(void*, unsigned char*, size_t), void *p_rng) {
	(void) f_rng;
	(void) p_rng;
	return mbedtls_rsa_check_pub_priv((const mbedtls_rsa_context*) pub->pk_ctx,
			(const mbedtls_rsa_context*) prv->pk_ctx);
}

static void* rsa_alloc_wrap(void) {
	void *ctx = mbedtls_calloc(1, sizeof(mbedtls_rsa_context));

	if (ctx != NULL) {
		mbedtls_rsa_init((mbedtls_rsa_context*) ctx);
	}

	return ctx;
}

static void rsa_free_wrap(void *ctx) {
	mbedtls_rsa_free((mbedtls_rsa_context*) ctx);
	mbedtls_free(ctx);
}

static void rsa_debug(mbedtls_pk_context *pk, mbedtls_pk_debug_item *items) {
#if defined(MBEDTLS_RSA_ALT)
    /* Not supported */
    (void) pk;
    (void) items;
#else
	mbedtls_rsa_context *rsa = (mbedtls_rsa_context*) pk->pk_ctx;

	items->type = MBEDTLS_PK_DEBUG_MPI;
	items->name = "rsa.N";
	items->value = &(rsa->N);

	items++;

	items->type = MBEDTLS_PK_DEBUG_MPI;
	items->name = "rsa.E";
	items->value = &(rsa->E);
#endif
}

const mbedtls_pk_info_t mbedtls_rsa_info = { .type = MBEDTLS_PK_RSA, .name =
		"RSA", .get_bitlen = rsa_get_bitlen, .can_do = rsa_can_do,
		.verify_func = rsa_verify_wrap, .sign_func = rsa_sign_wrap,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    .verify_rs_func = NULL,
    .sign_rs_func = NULL,
    .rs_alloc_func = NULL,
    .rs_free_func = NULL,
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
		.decrypt_func = rsa_decrypt_wrap, .encrypt_func = rsa_encrypt_wrap,
		.check_pair_func = rsa_check_pair_wrap,
		.ctx_alloc_func = rsa_alloc_wrap, .ctx_free_func = rsa_free_wrap,
		.debug_func = rsa_debug, };
#endif /* MBEDTLS_RSA_C */

#if defined(MBEDTLS_PK_HAVE_ECC_KEYS)
/*
 * Generic EC key
 */
static int eckey_can_do(mbedtls_pk_type_t type) {
	return type == MBEDTLS_PK_ECKEY || type == MBEDTLS_PK_ECKEY_DH
			|| type == MBEDTLS_PK_ECDSA;
}

static size_t eckey_get_bitlen(mbedtls_pk_context *pk) {
#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
    return pk->ec_bits;
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
	mbedtls_ecp_keypair *ecp = (mbedtls_ecp_keypair*) pk->pk_ctx;
	return ecp->grp.pbits;
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */
}

#if defined(MBEDTLS_PK_CAN_ECDSA_VERIFY)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
/* Common helper for ECDSA verify using PSA functions. */
static int ecdsa_verify_psa(unsigned char *key, size_t key_len,
		psa_ecc_family_t curve, size_t curve_bits, const unsigned char *hash,
		size_t hash_len, const unsigned char *sig, size_t sig_len) {
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
	psa_algorithm_t psa_sig_md = PSA_ALG_ECDSA_ANY;
	size_t signature_len = PSA_ECDSA_SIGNATURE_SIZE(curve_bits);
	size_t converted_sig_len;
	unsigned char extracted_sig[PSA_VENDOR_ECDSA_SIGNATURE_MAX_SIZE];
	unsigned char *p;
	psa_status_t status;

	if (curve == 0) {
		return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
	}

	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(curve));
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_HASH);
	psa_set_key_algorithm(&attributes, psa_sig_md);

	status = psa_import_key(&attributes, key, key_len, &key_id);
	if (status != PSA_SUCCESS) {
		ret = PSA_PK_TO_MBEDTLS_ERR(status);
		goto cleanup;
	}

	if (signature_len > sizeof(extracted_sig)) {
		ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
		goto cleanup;
	}

	p = (unsigned char*) sig;
	ret = mbedtls_ecdsa_der_to_raw(curve_bits, p, sig_len, extracted_sig,
			sizeof(extracted_sig), &converted_sig_len);
	if (ret != 0) {
		goto cleanup;
	}

	if (converted_sig_len != signature_len) {
		ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
		goto cleanup;
	}

	status = psa_verify_hash(key_id, psa_sig_md, hash, hash_len, extracted_sig,
			signature_len);
	if (status != PSA_SUCCESS) {
		ret = PSA_PK_ECDSA_TO_MBEDTLS_ERR(status);
		goto cleanup;
	}

	ret = 0;

	cleanup: status = psa_destroy_key(key_id);
	if (ret == 0 && status != PSA_SUCCESS) {
		ret = PSA_PK_TO_MBEDTLS_ERR(status);
	}

	return ret;
}

static int ecdsa_opaque_verify_wrap(mbedtls_pk_context *pk,
		mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len,
		const unsigned char *sig, size_t sig_len) {
	(void) md_alg;
	unsigned char key[MBEDTLS_PK_MAX_EC_PUBKEY_RAW_LEN];
	size_t key_len;
	psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_ecc_family_t curve;
	size_t curve_bits;
	psa_status_t status;

	status = psa_get_key_attributes(pk->priv_id, &key_attr);
	if (status != PSA_SUCCESS) {
		return PSA_PK_ECDSA_TO_MBEDTLS_ERR(status);
	}
	curve = PSA_KEY_TYPE_ECC_GET_FAMILY(psa_get_key_type(&key_attr));
	curve_bits = psa_get_key_bits(&key_attr);
	psa_reset_key_attributes(&key_attr);

	status = psa_export_public_key(pk->priv_id, key, sizeof(key), &key_len);
	if (status != PSA_SUCCESS) {
		return PSA_PK_ECDSA_TO_MBEDTLS_ERR(status);
	}

	return ecdsa_verify_psa(key, key_len, curve, curve_bits, hash, hash_len,
			sig, sig_len);
}

#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
static int ecdsa_verify_wrap(mbedtls_pk_context *pk,
                             mbedtls_md_type_t md_alg,
                             const unsigned char *hash, size_t hash_len,
                             const unsigned char *sig, size_t sig_len)
{
    (void) md_alg;
    psa_ecc_family_t curve = pk->ec_family;
    size_t curve_bits = pk->ec_bits;

    return ecdsa_verify_psa(pk->pub_raw, pk->pub_raw_len, curve, curve_bits,
                            hash, hash_len, sig, sig_len);
}
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
static int ecdsa_verify_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
		const unsigned char *hash, size_t hash_len, const unsigned char *sig,
		size_t sig_len) {
	(void) md_alg;
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	mbedtls_ecp_keypair *ctx = pk->pk_ctx;
	unsigned char key[MBEDTLS_PSA_MAX_EC_PUBKEY_LENGTH];
	size_t key_len;
	size_t curve_bits;
	psa_ecc_family_t curve = mbedtls_ecc_group_to_psa(ctx->grp.id, &curve_bits);

	ret = mbedtls_ecp_point_write_binary(&ctx->grp, &ctx->Q,
	MBEDTLS_ECP_PF_UNCOMPRESSED, &key_len, key, sizeof(key));
	if (ret != 0) {
		return ret;
	}

	return ecdsa_verify_psa(key, key_len, curve, curve_bits, hash, hash_len,
			sig, sig_len);
}
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */
#else /* MBEDTLS_USE_PSA_CRYPTO */
static int ecdsa_verify_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                             const unsigned char *hash, size_t hash_len,
                             const unsigned char *sig, size_t sig_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ((void) md_alg);

    ret = mbedtls_ecdsa_read_signature((mbedtls_ecdsa_context *) pk->pk_ctx,
                                       hash, hash_len, sig, sig_len);

    if (ret == MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH) {
        return MBEDTLS_ERR_PK_SIG_LEN_MISMATCH;
    }

    return ret;
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */
#endif /* MBEDTLS_PK_CAN_ECDSA_VERIFY */

#if defined(MBEDTLS_PK_CAN_ECDSA_SIGN)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
/* Common helper for ECDSA sign using PSA functions.
 * Instead of extracting key's properties in order to check which kind of ECDSA
 * signature it supports, we try both deterministic and non-deterministic.
 */
static int ecdsa_sign_psa(mbedtls_svc_key_id_t key_id, mbedtls_md_type_t md_alg,
		const unsigned char *hash, size_t hash_len, unsigned char *sig,
		size_t sig_size, size_t *sig_len) {
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	psa_status_t status;
	psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
	size_t key_bits = 0;

	status = psa_get_key_attributes(key_id, &key_attr);
	if (status != PSA_SUCCESS) {
		return PSA_PK_ECDSA_TO_MBEDTLS_ERR(status);
	}
	key_bits = psa_get_key_bits(&key_attr);
	psa_reset_key_attributes(&key_attr);

	status = psa_sign_hash(key_id,
			PSA_ALG_DETERMINISTIC_ECDSA(mbedtls_md_psa_alg_from_type(md_alg)),
			hash, hash_len, sig, sig_size, sig_len);
	if (status == PSA_SUCCESS) {
		goto done;
	} else if (status != PSA_ERROR_NOT_PERMITTED) {
		return PSA_PK_ECDSA_TO_MBEDTLS_ERR(status);
	}

	status = psa_sign_hash(key_id,
			PSA_ALG_ECDSA(mbedtls_md_psa_alg_from_type(md_alg)), hash, hash_len,
			sig, sig_size, sig_len);
	if (status != PSA_SUCCESS) {
		return PSA_PK_ECDSA_TO_MBEDTLS_ERR(status);
	}

	done: ret = mbedtls_ecdsa_raw_to_der(key_bits, sig, *sig_len, sig, sig_size,
			sig_len);

	return ret;
}

static int ecdsa_opaque_sign_wrap(mbedtls_pk_context *pk,
		mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len,
		unsigned char *sig, size_t sig_size, size_t *sig_len,
		int (*f_rng)(void*, unsigned char*, size_t), void *p_rng) {
	((void) f_rng);
	((void) p_rng);

	return ecdsa_sign_psa(pk->priv_id, md_alg, hash, hash_len, sig, sig_size,
			sig_len);
}

#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
/* When PK_USE_PSA_EC_DATA is defined opaque and non-opaque keys end up
 * using the same function. */
#define ecdsa_sign_wrap     ecdsa_opaque_sign_wrap
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
static int ecdsa_sign_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
		const unsigned char *hash, size_t hash_len, unsigned char *sig,
		size_t sig_size, size_t *sig_len,
		int (*f_rng)(void*, unsigned char*, size_t), void *p_rng) {
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
	psa_status_t status;
	mbedtls_ecp_keypair *ctx = pk->pk_ctx;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	unsigned char buf[MBEDTLS_PSA_MAX_EC_KEY_PAIR_LENGTH];
	size_t curve_bits;
	psa_ecc_family_t curve = mbedtls_ecc_group_to_psa(ctx->grp.id, &curve_bits);
	size_t key_len = PSA_BITS_TO_BYTES(curve_bits);
	psa_algorithm_t psa_hash = mbedtls_md_psa_alg_from_type(md_alg);
	psa_algorithm_t psa_sig_md = MBEDTLS_PK_PSA_ALG_ECDSA_MAYBE_DET(psa_hash);
	((void) f_rng);
	((void) p_rng);

	if (curve == 0) {
		return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
	}

	if (key_len > sizeof(buf)) {
		return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	}
	ret = mbedtls_mpi_write_binary(&ctx->d, buf, key_len);
	if (ret != 0) {
		goto cleanup;
	}

	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(curve));
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
	psa_set_key_algorithm(&attributes, psa_sig_md);

	status = psa_import_key(&attributes, buf, key_len, &key_id);
	if (status != PSA_SUCCESS) {
		ret = PSA_PK_TO_MBEDTLS_ERR(status);
		goto cleanup;
	}

	ret = ecdsa_sign_psa(key_id, md_alg, hash, hash_len, sig, sig_size,
			sig_len);

	cleanup: mbedtls_platform_zeroize(buf, sizeof(buf));
	status = psa_destroy_key(key_id);
	if (ret == 0 && status != PSA_SUCCESS) {
		ret = PSA_PK_TO_MBEDTLS_ERR(status);
	}

	return ret;
}
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */
#else /* MBEDTLS_USE_PSA_CRYPTO */
static int ecdsa_sign_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                           const unsigned char *hash, size_t hash_len,
                           unsigned char *sig, size_t sig_size, size_t *sig_len,
                           int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    return mbedtls_ecdsa_write_signature((mbedtls_ecdsa_context *) pk->pk_ctx,
                                         md_alg, hash, hash_len,
                                         sig, sig_size, sig_len,
                                         f_rng, p_rng);
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */
#endif /* MBEDTLS_PK_CAN_ECDSA_SIGN */

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
/* Forward declarations */
static int ecdsa_verify_rs_wrap(mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
                                const unsigned char *hash, size_t hash_len,
                                const unsigned char *sig, size_t sig_len,
                                void *rs_ctx);

static int ecdsa_sign_rs_wrap(mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
                              const unsigned char *hash, size_t hash_len,
                              unsigned char *sig, size_t sig_size, size_t *sig_len,
                              int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                              void *rs_ctx);

/*
 * Restart context for ECDSA operations with ECKEY context
 *
 * We need to store an actual ECDSA context, as we need to pass the same to
 * the underlying ecdsa function, so we can't create it on the fly every time.
 */
typedef struct {
    mbedtls_ecdsa_restart_ctx ecdsa_rs;
    mbedtls_ecdsa_context ecdsa_ctx;
} eckey_restart_ctx;

static void *eckey_rs_alloc(void)
{
    eckey_restart_ctx *rs_ctx;

    void *ctx = mbedtls_calloc(1, sizeof(eckey_restart_ctx));

    if (ctx != NULL) {
        rs_ctx = ctx;
        mbedtls_ecdsa_restart_init(&rs_ctx->ecdsa_rs);
        mbedtls_ecdsa_init(&rs_ctx->ecdsa_ctx);
    }

    return ctx;
}

static void eckey_rs_free(void *ctx)
{
    eckey_restart_ctx *rs_ctx;

    if (ctx == NULL) {
        return;
    }

    rs_ctx = ctx;
    mbedtls_ecdsa_restart_free(&rs_ctx->ecdsa_rs);
    mbedtls_ecdsa_free(&rs_ctx->ecdsa_ctx);

    mbedtls_free(ctx);
}

static int eckey_verify_rs_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                                const unsigned char *hash, size_t hash_len,
                                const unsigned char *sig, size_t sig_len,
                                void *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    eckey_restart_ctx *rs = rs_ctx;

    /* Should never happen */
    if (rs == NULL) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    /* set up our own sub-context if needed (that is, on first run) */
    if (rs->ecdsa_ctx.grp.pbits == 0) {
        MBEDTLS_MPI_CHK(mbedtls_ecdsa_from_keypair(&rs->ecdsa_ctx, pk->pk_ctx));
    }

    MBEDTLS_MPI_CHK(ecdsa_verify_rs_wrap(pk,
                                         md_alg, hash, hash_len,
                                         sig, sig_len, &rs->ecdsa_rs));

cleanup:
    return ret;
}

static int eckey_sign_rs_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                              const unsigned char *hash, size_t hash_len,
                              unsigned char *sig, size_t sig_size, size_t *sig_len,
                              int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                              void *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    eckey_restart_ctx *rs = rs_ctx;

    /* Should never happen */
    if (rs == NULL) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    /* set up our own sub-context if needed (that is, on first run) */
    if (rs->ecdsa_ctx.grp.pbits == 0) {
        MBEDTLS_MPI_CHK(mbedtls_ecdsa_from_keypair(&rs->ecdsa_ctx, pk->pk_ctx));
    }

    MBEDTLS_MPI_CHK(ecdsa_sign_rs_wrap(pk, md_alg,
                                       hash, hash_len, sig, sig_size, sig_len,
                                       f_rng, p_rng, &rs->ecdsa_rs));

cleanup:
    return ret;
}
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
static int eckey_check_pair_psa(mbedtls_pk_context *pub, mbedtls_pk_context *prv)
{
    psa_status_t status;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    uint8_t prv_key_buf[MBEDTLS_PSA_MAX_EC_PUBKEY_LENGTH];
    size_t prv_key_len;
    mbedtls_svc_key_id_t key_id = prv->priv_id;

    status = psa_export_public_key(key_id, prv_key_buf, sizeof(prv_key_buf),
                                   &prv_key_len);
    ret = PSA_PK_TO_MBEDTLS_ERR(status);
    if (ret != 0) {
        return ret;
    }

    if (memcmp(prv_key_buf, pub->pub_raw, pub->pub_raw_len) != 0) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    return 0;
}
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
static int eckey_check_pair_psa(mbedtls_pk_context *pub,
		mbedtls_pk_context *prv) {
	psa_status_t status;
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	uint8_t prv_key_buf[MBEDTLS_PSA_MAX_EC_PUBKEY_LENGTH];
	size_t prv_key_len;
	psa_status_t destruction_status;
	mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
	psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
	uint8_t pub_key_buf[MBEDTLS_PSA_MAX_EC_PUBKEY_LENGTH];
	size_t pub_key_len;
	size_t curve_bits;
	const psa_ecc_family_t curve = mbedtls_ecc_group_to_psa(
			mbedtls_pk_ec_ro(*prv)->grp.id, &curve_bits);
	const size_t curve_bytes = PSA_BITS_TO_BYTES(curve_bits);

	if (curve == 0) {
		return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
	}

	psa_set_key_type(&key_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(curve));
	psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_EXPORT);

	ret = mbedtls_mpi_write_binary(&mbedtls_pk_ec_ro(*prv)->d, prv_key_buf,
			curve_bytes);
	if (ret != 0) {
		mbedtls_platform_zeroize(prv_key_buf, sizeof(prv_key_buf));
		return ret;
	}

	status = psa_import_key(&key_attr, prv_key_buf, curve_bytes, &key_id);
	mbedtls_platform_zeroize(prv_key_buf, sizeof(prv_key_buf));
	ret = PSA_PK_TO_MBEDTLS_ERR(status);
	if (ret != 0) {
		return ret;
	}

	// From now on prv_key_buf is used to store the public key of prv.
	status = psa_export_public_key(key_id, prv_key_buf, sizeof(prv_key_buf),
			&prv_key_len);
	ret = PSA_PK_TO_MBEDTLS_ERR(status);
	destruction_status = psa_destroy_key(key_id);
	if (ret != 0) {
		return ret;
	} else if (destruction_status != PSA_SUCCESS) {
		return PSA_PK_TO_MBEDTLS_ERR(destruction_status);
	}

	ret = mbedtls_ecp_point_write_binary(&mbedtls_pk_ec_rw(*pub)->grp,
			&mbedtls_pk_ec_rw(*pub)->Q,
			MBEDTLS_ECP_PF_UNCOMPRESSED, &pub_key_len, pub_key_buf,
			sizeof(pub_key_buf));
	if (ret != 0) {
		return ret;
	}

	if (memcmp(prv_key_buf, pub_key_buf, curve_bytes) != 0) {
		return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
	}

	return 0;
}
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */

static int eckey_check_pair_wrap(mbedtls_pk_context *pub,
		mbedtls_pk_context *prv, int (*f_rng)(void*, unsigned char*, size_t),
		void *p_rng) {
	(void) f_rng;
	(void) p_rng;
	return eckey_check_pair_psa(pub, prv);
}
#else /* MBEDTLS_USE_PSA_CRYPTO */
static int eckey_check_pair_wrap(mbedtls_pk_context *pub, mbedtls_pk_context *prv,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng)
{
    return mbedtls_ecp_check_pub_priv((const mbedtls_ecp_keypair *) pub->pk_ctx,
                                      (const mbedtls_ecp_keypair *) prv->pk_ctx,
                                      f_rng, p_rng);
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
/* When PK_USE_PSA_EC_DATA is defined opaque and non-opaque keys end up
 * using the same function. */
#define ecdsa_opaque_check_pair_wrap    eckey_check_pair_wrap
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
static int ecdsa_opaque_check_pair_wrap(mbedtls_pk_context *pub,
		mbedtls_pk_context *prv, int (*f_rng)(void*, unsigned char*, size_t),
		void *p_rng) {
	psa_status_t status;
	uint8_t exp_pub_key[MBEDTLS_PK_MAX_EC_PUBKEY_RAW_LEN];
	size_t exp_pub_key_len = 0;
	uint8_t pub_key[MBEDTLS_PK_MAX_EC_PUBKEY_RAW_LEN];
	size_t pub_key_len = 0;
	int ret;
	(void) f_rng;
	(void) p_rng;

	status = psa_export_public_key(prv->priv_id, exp_pub_key,
			sizeof(exp_pub_key), &exp_pub_key_len);
	if (status != PSA_SUCCESS) {
		ret = psa_pk_status_to_mbedtls(status);
		return ret;
	}
	ret = mbedtls_ecp_point_write_binary(&(mbedtls_pk_ec_ro(*pub)->grp),
			&(mbedtls_pk_ec_ro(*pub)->Q),
			MBEDTLS_ECP_PF_UNCOMPRESSED, &pub_key_len, pub_key,
			sizeof(pub_key));
	if (ret != 0) {
		return ret;
	}
	if ((exp_pub_key_len != pub_key_len)
			|| memcmp(exp_pub_key, pub_key, exp_pub_key_len)) {
		return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
	}
	return 0;
}
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if !defined(MBEDTLS_PK_USE_PSA_EC_DATA)
static void* eckey_alloc_wrap(void) {
	void *ctx = mbedtls_calloc(1, sizeof(mbedtls_ecp_keypair));

	if (ctx != NULL) {
		mbedtls_ecp_keypair_init(ctx);
	}

	return ctx;
}

static void eckey_free_wrap(void *ctx) {
	mbedtls_ecp_keypair_free((mbedtls_ecp_keypair*) ctx);
	mbedtls_free(ctx);
}
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */

static void eckey_debug(mbedtls_pk_context *pk, mbedtls_pk_debug_item *items) {
#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
    items->type = MBEDTLS_PK_DEBUG_PSA_EC;
    items->name = "eckey.Q";
    items->value = pk;
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
	mbedtls_ecp_keypair *ecp = (mbedtls_ecp_keypair*) pk->pk_ctx;
	items->type = MBEDTLS_PK_DEBUG_ECP;
	items->name = "eckey.Q";
	items->value = &(ecp->Q);
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */
}

const mbedtls_pk_info_t mbedtls_eckey_info = { .type = MBEDTLS_PK_ECKEY, .name =
		"EC", .get_bitlen = eckey_get_bitlen, .can_do = eckey_can_do,
#if defined(MBEDTLS_PK_CAN_ECDSA_VERIFY)
		.verify_func = ecdsa_verify_wrap, /* Compatible key structures */
#else /* MBEDTLS_PK_CAN_ECDSA_VERIFY */
    .verify_func = NULL,
#endif /* MBEDTLS_PK_CAN_ECDSA_VERIFY */
#if defined(MBEDTLS_PK_CAN_ECDSA_SIGN)
		.sign_func = ecdsa_sign_wrap, /* Compatible key structures */
#else /* MBEDTLS_PK_CAN_ECDSA_VERIFY */
    .sign_func = NULL,
#endif /* MBEDTLS_PK_CAN_ECDSA_VERIFY */
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    .verify_rs_func = eckey_verify_rs_wrap,
    .sign_rs_func = eckey_sign_rs_wrap,
    .rs_alloc_func = eckey_rs_alloc,
    .rs_free_func = eckey_rs_free,
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
		.decrypt_func = NULL, .encrypt_func = NULL, .check_pair_func =
				eckey_check_pair_wrap,
#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
    .ctx_alloc_func = NULL,
    .ctx_free_func = NULL,
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
		.ctx_alloc_func = eckey_alloc_wrap, .ctx_free_func = eckey_free_wrap,
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */
		.debug_func = eckey_debug, };

/*
 * EC key restricted to ECDH
 */
static int eckeydh_can_do(mbedtls_pk_type_t type) {
	return type == MBEDTLS_PK_ECKEY || type == MBEDTLS_PK_ECKEY_DH;
}

const mbedtls_pk_info_t mbedtls_eckeydh_info = { .type = MBEDTLS_PK_ECKEY_DH,
		.name = "EC_DH", .get_bitlen = eckey_get_bitlen, /* Same underlying key structure */
		.can_do = eckeydh_can_do, .verify_func = NULL, .sign_func = NULL,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    .verify_rs_func = NULL,
    .sign_rs_func = NULL,
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
		.decrypt_func = NULL, .encrypt_func = NULL, .check_pair_func =
				eckey_check_pair_wrap,
#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
    .ctx_alloc_func = NULL,
    .ctx_free_func = NULL,
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
		.ctx_alloc_func = eckey_alloc_wrap, /* Same underlying key structure */
		.ctx_free_func = eckey_free_wrap, /* Same underlying key structure */
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */
		.debug_func = eckey_debug, /* Same underlying key structure */
};

#if defined(MBEDTLS_PK_CAN_ECDSA_SOME)
static int ecdsa_can_do(mbedtls_pk_type_t type) {
	return type == MBEDTLS_PK_ECDSA;
}

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
static int ecdsa_verify_rs_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                                const unsigned char *hash, size_t hash_len,
                                const unsigned char *sig, size_t sig_len,
                                void *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ((void) md_alg);

    ret = mbedtls_ecdsa_read_signature_restartable(
        (mbedtls_ecdsa_context *) pk->pk_ctx,
        hash, hash_len, sig, sig_len,
        (mbedtls_ecdsa_restart_ctx *) rs_ctx);

    if (ret == MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH) {
        return MBEDTLS_ERR_PK_SIG_LEN_MISMATCH;
    }

    return ret;
}

static int ecdsa_sign_rs_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                              const unsigned char *hash, size_t hash_len,
                              unsigned char *sig, size_t sig_size, size_t *sig_len,
                              int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                              void *rs_ctx)
{
    return mbedtls_ecdsa_write_signature_restartable(
        (mbedtls_ecdsa_context *) pk->pk_ctx,
        md_alg, hash, hash_len, sig, sig_size, sig_len, f_rng, p_rng,
        (mbedtls_ecdsa_restart_ctx *) rs_ctx);

}


static void *ecdsa_rs_alloc(void)
{
    void *ctx = mbedtls_calloc(1, sizeof(mbedtls_ecdsa_restart_ctx));

    if (ctx != NULL) {
        mbedtls_ecdsa_restart_init(ctx);
    }

    return ctx;
}

static void ecdsa_rs_free(void *ctx)
{
    mbedtls_ecdsa_restart_free(ctx);
    mbedtls_free(ctx);
}
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */

const mbedtls_pk_info_t mbedtls_ecdsa_info = { .type = MBEDTLS_PK_ECDSA, .name =
		"ECDSA", .get_bitlen = eckey_get_bitlen, /* Compatible key structures */
.can_do = ecdsa_can_do,
#if defined(MBEDTLS_PK_CAN_ECDSA_VERIFY)
		.verify_func = ecdsa_verify_wrap, /* Compatible key structures */
#else /* MBEDTLS_PK_CAN_ECDSA_VERIFY */
    .verify_func = NULL,
#endif /* MBEDTLS_PK_CAN_ECDSA_VERIFY */
#if defined(MBEDTLS_PK_CAN_ECDSA_SIGN)
		.sign_func = ecdsa_sign_wrap, /* Compatible key structures */
#else /* MBEDTLS_PK_CAN_ECDSA_SIGN */
    .sign_func = NULL,
#endif /* MBEDTLS_PK_CAN_ECDSA_SIGN */
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    .verify_rs_func = ecdsa_verify_rs_wrap,
    .sign_rs_func = ecdsa_sign_rs_wrap,
    .rs_alloc_func = ecdsa_rs_alloc,
    .rs_free_func = ecdsa_rs_free,
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
		.decrypt_func = NULL, .encrypt_func = NULL, .check_pair_func =
				eckey_check_pair_wrap, /* Compatible key structures */
#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
    .ctx_alloc_func = NULL,
    .ctx_free_func = NULL,
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
		.ctx_alloc_func = eckey_alloc_wrap, /* Compatible key structures */
		.ctx_free_func = eckey_free_wrap, /* Compatible key structures */
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */
		.debug_func = eckey_debug, /* Compatible key structures */
};
#endif /* MBEDTLS_PK_CAN_ECDSA_SOME */
#endif /* MBEDTLS_PK_HAVE_ECC_KEYS */

//DAVIDE EDDSA
#define PRINTFNAME(NAME) \
	printf("[CUSTOM MBEDTLS] Inside " NAME " Function\n");
#define CREATE_STUB(NAME,RET) \
	PRINTFNAME(NAME) \
	return RET;

static int eddsa_sign_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
		const unsigned char *hash, size_t hash_len, unsigned char *sig,
		size_t sig_size, size_t *sig_len,
		int (*f_rng)(void*, unsigned char*, size_t), void *p_rng) {
	CREATE_STUB("eddsa_sign_wrap", 1)
}

static int eddsa_verify_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
		const unsigned char *hash, size_t hash_len, const unsigned char *sig,
		size_t sig_len) {
	/*
	 int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	 ((void) md_alg);

	 ret = mbedtls_ecdsa_read_signature_restartable(
	 (mbedtls_ecdsa_context *) pk->pk_ctx,
	 hash, hash_len, sig, sig_len,
	 (mbedtls_ecdsa_restart_ctx *) rs_ctx);

	 if (ret == MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH) {
	 return MBEDTLS_ERR_PK_SIG_LEN_MISMATCH;
	 }

	 return ret;
	 */

	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	((void) md_alg);
	//mbedtls_ecdsa_read_signature(ctx, hash, hlen, sig, slen);
	ret = mbedtls_eddsa_read_signature(pk->pk_ctx, hash, hash_len, sig, sig_len,
			MBEDTLS_EDDSA_PURE, NULL, 0);

	return ret;
	//CREATE_STUB("eddsa_verify_wrap",1)
}

static int eddsa_can_do(mbedtls_pk_type_t type) {
	return type == MBEDTLS_PK_EDDSA;
}

static int eddsa_verify_rs_wrap(mbedtls_pk_context *pk,
		mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len,
		const unsigned char *sig, size_t sig_len, void *rs_ctx) {
	CREATE_STUB("eddsa_verify_rs_wrap", 1)
}

static int eddsa_sign_rs_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
		const unsigned char *hash, size_t hash_len, unsigned char *sig,
		size_t sig_size, size_t *sig_len,
		int (*f_rng)(void*, unsigned char*, size_t), void *p_rng, void *rs_ctx) {
	CREATE_STUB("eddsa_sign_rs_wrap", 1)
}

static void* eddsa_rs_alloc(void) {
	CREATE_STUB("eddsa_rs_alloc", NULL)
}

static void eddsa_rs_free(void *ctx) {
	CREATE_STUB("eddsa_rs_free", NULL)
}

const mbedtls_pk_info_t mbedtls_eddsa_info = { //DAVIDE
		.type = MBEDTLS_PK_EDDSA, .name = "EDDSA", .get_bitlen =
				eckey_get_bitlen, /* Compatible key structures */
		.can_do = eddsa_can_do,
#if defined(MBEDTLS_PK_CAN_ECDSA_VERIFY)
				.verify_func = eddsa_verify_wrap, /* Compatible key structures */
#else /* MBEDTLS_PK_CAN_ECDSA_VERIFY */
    .verify_func = NULL,
#endif /* MBEDTLS_PK_CAN_ECDSA_VERIFY */
#if defined(MBEDTLS_PK_CAN_ECDSA_SIGN)
				.sign_func = eddsa_sign_wrap, /* Compatible key structures */
#else /* MBEDTLS_PK_CAN_ECDSA_SIGN */
    .sign_func = NULL,
#endif /* MBEDTLS_PK_CAN_ECDSA_SIGN */
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    .verify_rs_func = NULL,
    .sign_rs_func = NULL,
    .rs_alloc_func = NULL,
    .rs_free_func = NULL,
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
				.decrypt_func = NULL, .encrypt_func = NULL, .check_pair_func =
						eckey_check_pair_wrap, /* Compatible key structures */
#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
    .ctx_alloc_func = NULL,
    .ctx_free_func = NULL,
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
				.ctx_alloc_func = eckey_alloc_wrap, /* Compatible key structures */
				.ctx_free_func = eckey_free_wrap, /* Compatible key structures */
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */
				.debug_func = eckey_debug, /* Compatible key structures */
		};

//DAVIDE EDDSA END
/*#define CREATE_STUB(NAME,RET) \
	printf("[CUSTOM MBEDTLS] Inside " NAME " Function\n");\
	return RET;
 */

static int ed25519_mlds65_sign_wrap(mbedtls_pk_context *pk,
		mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len,
		unsigned char *sig, size_t sig_size, size_t *sig_len,
		int (*f_rng)(void*, unsigned char*, size_t), void *p_rng) {
//TODO: IMPLEMENTARE FUNC
	char oid_der[] = "\x06\x0B\x60\x86\x48\x01\x86\xFA\x6B\x50\x08\x01\x0a"; //"\x06\x0B\x60\x86\x48\x01\x86\xFA\x6B\x50\x08\x01\x0a";
	char prefix[] = "\x30\x82\x09\xBC\x03\x82\x09\x75";
	char sig_sep[] = "\x03\x41";
	mbedtls_ed25519_mlds65_ctx *ctx = (mbedtls_ed25519_mlds65_ctx*) pk->pk_ctx;
	unsigned char *new_msg = calloc(13 + 64, sizeof(char));
	mbedtls_sha512(hash, hash_len, new_msg + 13, 0);
	memcpy(new_msg, oid_der, 13);

	unsigned char *eddsa_sig;
	unsigned int mldsa_ssize = 0, ed_ssize = 0;

	memcpy(sig, prefix, 8);
	sig[8] = 0;

	MLDSA_65_SIGN(new_msg, 77, ctx->mldsa_pri_key, sig + 9, &mldsa_ssize, NULL,
			0);
	//EDDSA25519_SIGN(new_msg, 77, ctx->ed_pri_key , ctx->ed_prisize, sig + mldsa_ssize, &ed_ssize);
#if HW_IMPLEMENTATION==1

	eddsa25519_sign_hw(new_msg, 77, ctx->ed_pri_key, ctx->ed_prisize,
			ctx->ed_pub_key, ctx->ed_pubsize, &eddsa_sig, &ed_ssize, 0);

#else
	EDDSA25519_SIGN(new_msg, 77, ctx->ed_pri_key, ctx->ed_prisize, &eddsa_sig,
			&ed_ssize);
#endif

	memcpy(sig + mldsa_ssize + 9, sig_sep, 2);

	sig[mldsa_ssize + 9 + 2] = 0;

	memcpy(sig + mldsa_ssize + 9 + 3, eddsa_sig, 64);

	free(eddsa_sig);

	*sig_len = mldsa_ssize + 64 + 9 + 3;
	free(new_msg);
	return 0;
}

#define OID_SIZE 13
#define SIG_SIZE 64
#define MSG_LEN (OID_SIZE + SIG_SIZE)

#define SIG_PREFIX_SIZE 9

static int ed25519_mlds44_sign_wrap(mbedtls_pk_context *pk,
		mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len,
		unsigned char *sig, size_t sig_size, size_t *sig_len,
		int (*f_rng)(void*, unsigned char*, size_t), void *p_rng) {
//TODO: IMPLEMENTARE FUNC
	char oid_der[] = "\x06\x0B\x60\x86\x48\x01\x86\xFA\x6B\x50\x08\x01\x03";
	char prefix[] = "\x30\x82\x09\xBC\x03\x82\x09\x75";
	char sig_sep[] = "\x03\x41";

	printf("#############################################\n");
	printf("Starting MLDSA44 + EDDSA25519 signature...\n");

	mbedtls_ed25519_mlds44_ctx *ctx = (mbedtls_ed25519_mlds44_ctx*) pk->pk_ctx;

	unsigned char *msg_to_be_signed = calloc(MSG_LEN, sizeof(char));

	// 	MSG
	// | 13 OID | SHA512 |
	memcpy(msg_to_be_signed, oid_der, OID_SIZE);
	mbedtls_sha512(hash, hash_len, msg_to_be_signed + OID_SIZE, 0);

	unsigned char *eddsa_sig;
	unsigned int mldsa_ssize = 0, ed_ssize = 0;

	memcpy(sig, prefix, 8);
	sig[8] = 0;
	printf("SW MLDSA Signature...");

	mldsa44_sig(msg_to_be_signed, MSG_LEN, ctx->mldsa_pri_key,
			sig + SIG_PREFIX_SIZE, &mldsa_ssize, NULL, 0);
	printf("\t\t\033[1;32m\u2705\033[0m\n");

#if HW_IMPLEMENTATION==1
	printf("HW EDDSA Signature...");

	eddsa25519_sign_hw(msg_to_be_signed, 77, ctx->ed_pri_key, ctx->ed_prisize,
			ctx->ed_pub_key, ctx->ed_pubsize, &eddsa_sig, &ed_ssize, 0);
	printf("\t\t\033[1;32m\u2705\033[0m\n");

#else
	printf("SW EDDSA Sign...");

	eddsa25519_sign(msg_to_be_signed, MSG_LEN, ctx->ed_pri_key, ctx->ed_prisize,
			&eddsa_sig, &ed_ssize);
	printf("\t\t\033[1;32m\u2705\033[0m\n");

#endif

	// 	SIG
	// | prefix | MLDSA | SEP | EDDSA |
	//     9       2420	   3	 64
	memcpy(sig + SIG_PREFIX_SIZE + mldsa_ssize, sig_sep, 2);

	sig[mldsa_ssize + SIG_PREFIX_SIZE + 2] = 0;

	memcpy(sig + SIG_PREFIX_SIZE + mldsa_ssize + 3, eddsa_sig, SIG_SIZE);

	free(eddsa_sig);

	*sig_len = mldsa_ssize + SIG_SIZE + 9 + 3;
	free(msg_to_be_signed);

	printf("MLDSA44 + EDDSA25519 signature completed!\n");
	printf("#############################################\n\n");

	return 0;
}

static int ed25519_mlds65_verify_wrap(mbedtls_pk_context *pk,
		mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len,
		const unsigned char *sig, size_t sig_len) {
	//HARDCODING SHA256
	//TODO: MAKE IT AVAILABLE FROM md_alg;
	char oid_der[] = "\x06\x0B\x60\x86\x48\x01\x86\xFA\x6B\x50\x08\x01\x0a";
	((void) md_alg);
	unsigned int result = 0;

	mbedtls_ed25519_mlds65_ctx *ctx = (mbedtls_ed25519_mlds65_ctx*) pk->pk_ctx;
	unsigned char *new_msg = calloc(13 + 64, sizeof(char));
	mbedtls_sha512(hash, hash_len, new_msg + 13, 0);
	memcpy(new_msg, oid_der, 13);

#if HW_IMPLEMENTATION==1

	eddsa25519_verify_hw(new_msg, 77, ctx->ed_pub_key, ctx->ed_pubsize,
			sig + sig_len - 64, 64, &result, 0);

#else

	EDDSA25519_VERIFY(new_msg, 77, ctx->ed_pub_key, ctx->ed_pubsize,
			sig + sig_len - 64, 64, &result);

#endif

	if (result != 0) {
		free(new_msg);
		return result;
	}

	MLDSA_65_VERIFY(new_msg, 77, ctx->mldsa_pub_key, sig + 9, 3309, &result,
	NULL, 0);
	free(new_msg);

	return result;
}

static int ed25519_mlds44_verify_wrap(mbedtls_pk_context *pk,
		mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len,
		const unsigned char *sig, size_t sig_len) {

	char oid_der[] = "\x06\x0B\x60\x86\x48\x01\x86\xFA\x6B\x50\x08\x01\x03";//"\x06\x0B\x60\x86\x48\x01\x86\xFA\x6B\x50\x08\x01\x0a";
	((void) md_alg);
	unsigned int result = 0;

	mbedtls_ed25519_mlds65_ctx *ctx = (mbedtls_ed25519_mlds65_ctx*) pk->pk_ctx;
	unsigned char *new_msg = calloc(13 + 64, sizeof(char));
	mbedtls_sha512(hash, hash_len, new_msg + 13, 0);
	memcpy(new_msg, oid_der, 13);

	printf("#############################################\n");
	printf("Starting MLDSA44 + EDDSA25519 verify...\n");

#if HW_IMPLEMENTATION==1
	printf("HW EDDSA Verify...");

	eddsa25519_verify_hw(new_msg, 77, ctx->ed_pub_key, ctx->ed_pubsize,
			sig + sig_len - 64, 64, &result, 0);
	printf("\t\t\033[1;32m\u2705\033[0m\n");
	//printf("Result: %d\n", result);
	// I hate you Eros
	result = !result;

#else

	printf("SW EDDSA Verify...");

	eddsa25519_verify(new_msg, 77, ctx->ed_pub_key, ctx->ed_pubsize,
			sig + sig_len - 64, 64, &result);
	printf("\t\t\033[1;32m\u2705\033[0m\n");
	//printf("Result: %d\n", result);

#endif

	if (result != 0) {
		free(new_msg);
		return result;
	}
	printf("SW MLDSA44 Verify...");

	mldsa44_verify(new_msg, 77, ctx->mldsa_pub_key, sig + 9, 2420, &result,
	NULL, 0);
	printf("\t\t\033[1;32m\u2705\033[0m\n");
	//printf("Result: %d\n", result);
	printf("MLDSA44 + EDDSA25519 verify completed!\n");
	printf("#############################################\n\n");

	free(new_msg);
	return result;
}

static int ed25519_mlds65_can_do(mbedtls_pk_type_t type) {
	return type == MBEDTLS_PK_ED25519_MLDSA65;
}

static int ed25519_mlds44_can_do(mbedtls_pk_type_t type) {
	return type == MBEDTLS_PK_ED25519_MLDSA44;
}

static int ed25519_mlds65_verify_rs_wrap(mbedtls_pk_context *pk,
		mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len,
		const unsigned char *sig, size_t sig_len, void *rs_ctx) {
	CREATE_STUB("eddsa_verify_rs_wrap", 0)
}

static int ed25519_mlds44_verify_rs_wrap(mbedtls_pk_context *pk,
		mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len,
		const unsigned char *sig, size_t sig_len, void *rs_ctx) {
	CREATE_STUB("eddsa_verify_rs_wrap", 0)
}

static int ed25519_mlds65_sign_rs_wrap(mbedtls_pk_context *pk,
		mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len,
		unsigned char *sig, size_t sig_size, size_t *sig_len,
		int (*f_rng)(void*, unsigned char*, size_t), void *p_rng, void *rs_ctx) {
	CREATE_STUB("ed25519_mlds65_sign_rs_wrap", 1)
}

static int ed25519_mlds44_sign_rs_wrap(mbedtls_pk_context *pk,
		mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len,
		unsigned char *sig, size_t sig_size, size_t *sig_len,
		int (*f_rng)(void*, unsigned char*, size_t), void *p_rng, void *rs_ctx) {
	CREATE_STUB("ed25519_mlds44_sign_rs_wrap", 1)
}

static void* ed25519_mlds65_rs_alloc(void) {
	CREATE_STUB("ed25519_mlds65_rs_alloc", NULL)
}

static void* ed25519_mlds44_rs_alloc(void) {
	CREATE_STUB("ed25519_mlds44_rs_alloc", NULL)
}

static void ed25519_mlds65_rs_free(void *ctx) {
	CREATE_STUB("ed25519_mlds65_rs_free", NULL)
}

static void ed25519_mlds44_rs_free(void *ctx) {
	CREATE_STUB("ed25519_mlds44_rs_free", NULL)
}

static int ed25519_mlds65_check_pair_wrap(mbedtls_pk_context *pub,
		mbedtls_pk_context *prv, int (*f_rng)(void*, unsigned char*, size_t),
		void *p_rng) {
	CREATE_STUB("ed25519_mlds65_check_pair_wrap", 1)
}

static int ed25519_mlds44_check_pair_wrap(mbedtls_pk_context *pub,
		mbedtls_pk_context *prv, int (*f_rng)(void*, unsigned char*, size_t),
		void *p_rng) {
	CREATE_STUB("ed25519_mlds44_check_pair_wrap", 1)
}

#define ALLOC_SIZE(VAR,SIZE,FREE_FUNC,CONTAINER)\
	if((VAR=malloc(SIZE)) == NULL){\
		FREE_FUNC(CONTAINER);\
		return NULL;\
	}

#define FREE_OBJ(NAME) \
		if(NAME != NULL){\
			free(NAME);\
		}

static void ed25519_mlds65_free_wrap(void *ctx) {
	mbedtls_ed25519_mlds65_ctx *tmp = (mbedtls_ed25519_mlds65_ctx*) ctx;

	if (ctx == NULL) {
		return;
	}

	FREE_OBJ(tmp->ed_pri_key);
	FREE_OBJ(tmp->ed_pub_key);
	FREE_OBJ(tmp->mldsa_pri_key);
	FREE_OBJ(tmp->mldsa_pub_key);

	free(ctx);

	return;

}

static void ed25519_mlds44_free_wrap(void *ctx) {
	mbedtls_ed25519_mlds44_ctx *tmp = (mbedtls_ed25519_mlds44_ctx*) ctx;

	if (ctx == NULL) {
		return;
	}

	FREE_OBJ(tmp->ed_pri_key);
	FREE_OBJ(tmp->ed_pub_key);
	FREE_OBJ(tmp->mldsa_pri_key);
	FREE_OBJ(tmp->mldsa_pub_key);

	free(ctx);

	return;

}

static void* ed25519_mlds65_alloc_wrap(void) {
	mbedtls_ed25519_mlds65_ctx *ctx = malloc(
			sizeof(mbedtls_ed25519_mlds65_ctx));
	if (ctx == NULL)
		return NULL;

	ctx->ed_pri_key = NULL;
	ctx->ed_pub_key = NULL;
	ctx->mldsa_pri_key = NULL;
	ctx->mldsa_pub_key = NULL;

	ctx->ed_prisize = 32;
	ctx->ed_pubsize = 32;
	ctx->mldsa_prisize = 4032;
	ctx->mldsa_pubsize = 1952;

	ALLOC_SIZE(ctx->ed_pri_key, ctx->ed_prisize, ed25519_mlds65_free_wrap, ctx);
	ALLOC_SIZE(ctx->ed_pub_key, ctx->ed_pubsize, ed25519_mlds65_free_wrap, ctx);
	ALLOC_SIZE(ctx->mldsa_pri_key, ctx->mldsa_prisize, ed25519_mlds65_free_wrap,
			ctx);
	ALLOC_SIZE(ctx->mldsa_pub_key, ctx->mldsa_pubsize, ed25519_mlds65_free_wrap,
			ctx);

	return ctx;
}

static void* ed25519_mlds44_alloc_wrap(void) {

	mbedtls_ed25519_mlds44_ctx *ctx = malloc(
			sizeof(mbedtls_ed25519_mlds44_ctx));
	if (ctx == NULL)
		return NULL;

	ctx->ed_pri_key = NULL;
	ctx->ed_pub_key = NULL;
	ctx->mldsa_pri_key = NULL;
	ctx->mldsa_pub_key = NULL;

	ctx->ed_prisize = 32;
	ctx->ed_pubsize = 32;
	ctx->mldsa_prisize = 2560;
	//ctx->mldsa_prisize = 4032;
	ctx->mldsa_pubsize = 1312;
	//ctx->mldsa_prisize = 1952;

	ALLOC_SIZE(ctx->ed_pri_key, ctx->ed_prisize, ed25519_mlds44_free_wrap, ctx);
	ALLOC_SIZE(ctx->ed_pub_key, ctx->ed_pubsize, ed25519_mlds44_free_wrap, ctx);
	ALLOC_SIZE(ctx->mldsa_pri_key, ctx->mldsa_prisize, ed25519_mlds44_free_wrap,
			ctx);
	ALLOC_SIZE(ctx->mldsa_pub_key, ctx->mldsa_pubsize, ed25519_mlds44_free_wrap,
			ctx);

	return ctx;
}

static void ed25519_mlds65_debug(mbedtls_pk_context *pk,
		mbedtls_pk_debug_item *items) {
	CREATE_STUB("ed25519_mlds65_debug",)
}

static void ed25519_mlds44_debug(mbedtls_pk_context *pk,
		mbedtls_pk_debug_item *items) {
	//CREATE_STUB("ed25519_mlds44_debug",)
}

const mbedtls_pk_info_t mbedtls_ed25519_mlds65_info = { //DAVIDE
		.type = MBEDTLS_PK_ED25519_MLDSA65, .name = "ED25519+MLDS65",
				.get_bitlen = eckey_get_bitlen, /* Compatible key structures */
				.can_do = ed25519_mlds65_can_do,
#if defined(MBEDTLS_PK_CAN_ECDSA_VERIFY)
				.verify_func = ed25519_mlds65_verify_wrap, /* Compatible key structures */
#else /* MBEDTLS_PK_CAN_ECDSA_VERIFY */
    .verify_func = NULL,
#endif /* MBEDTLS_PK_CAN_ECDSA_VERIFY */
#if defined(MBEDTLS_PK_CAN_ECDSA_SIGN)
				.sign_func = ed25519_mlds65_sign_wrap, /* Compatible key structures */
#else /* MBEDTLS_PK_CAN_ECDSA_SIGN */
    .sign_func = NULL,
#endif /* MBEDTLS_PK_CAN_ECDSA_SIGN */
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    .verify_rs_func = NULL,
    .sign_rs_func = NULL,
    .rs_alloc_func = NULL,
    .rs_free_func = NULL,
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
				.decrypt_func = NULL, .encrypt_func = NULL, .check_pair_func =
						ed25519_mlds65_check_pair_wrap, /* Compatible key structures */
#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
    .ctx_alloc_func = NULL,
    .ctx_free_func = NULL,
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
				.ctx_alloc_func = ed25519_mlds65_alloc_wrap, /* Compatible key structures */
				.ctx_free_func = ed25519_mlds65_free_wrap, /* Compatible key structures */
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */
				.debug_func = ed25519_mlds65_debug, /* Compatible key structures */
		};

const mbedtls_pk_info_t mbedtls_ed25519_mlds44_info = { //DAVIDE
		.type = MBEDTLS_PK_ED25519_MLDSA44, .name = "ED25519+MLDS44",
				.get_bitlen = eckey_get_bitlen, /* Compatible key structures */
				.can_do = ed25519_mlds44_can_do,
#if defined(MBEDTLS_PK_CAN_ECDSA_VERIFY)
				.verify_func = ed25519_mlds44_verify_wrap, /* Compatible key structures */
#else /* MBEDTLS_PK_CAN_ECDSA_VERIFY */
    .verify_func = NULL,
#endif /* MBEDTLS_PK_CAN_ECDSA_VERIFY */
#if defined(MBEDTLS_PK_CAN_ECDSA_SIGN)
				.sign_func = ed25519_mlds44_sign_wrap, /* Compatible key structures */
#else /* MBEDTLS_PK_CAN_ECDSA_SIGN */
    .sign_func = NULL,
#endif /* MBEDTLS_PK_CAN_ECDSA_SIGN */
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    .verify_rs_func = NULL,
    .sign_rs_func = NULL,
    .rs_alloc_func = NULL,
    .rs_free_func = NULL,
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
				.decrypt_func = NULL, .encrypt_func = NULL, .check_pair_func =
						ed25519_mlds44_check_pair_wrap, /* Compatible key structures */
#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
    .ctx_alloc_func = NULL,
    .ctx_free_func = NULL,
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
				.ctx_alloc_func = ed25519_mlds44_alloc_wrap, /* Compatible key structures */
				.ctx_free_func = ed25519_mlds44_free_wrap, /* Compatible key structures */
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */
				.debug_func = ed25519_mlds44_debug, /* Compatible key structures */
		};
//DAVIDE PQ BEGIN

#if defined(MBEDTLS_PK_RSA_ALT_SUPPORT)
/*
 * Support for alternative RSA-private implementations
 */

static int rsa_alt_can_do(mbedtls_pk_type_t type) {
	return type == MBEDTLS_PK_RSA;
}

static size_t rsa_alt_get_bitlen(mbedtls_pk_context *pk) {
	const mbedtls_rsa_alt_context *rsa_alt = pk->pk_ctx;

	return 8 * rsa_alt->key_len_func(rsa_alt->key);
}

static int rsa_alt_sign_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
		const unsigned char *hash, size_t hash_len, unsigned char *sig,
		size_t sig_size, size_t *sig_len,
		int (*f_rng)(void*, unsigned char*, size_t), void *p_rng) {
	mbedtls_rsa_alt_context *rsa_alt = pk->pk_ctx;

#if SIZE_MAX > UINT_MAX
    if (UINT_MAX < hash_len) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
#endif

	*sig_len = rsa_alt->key_len_func(rsa_alt->key);
	if (*sig_len > MBEDTLS_PK_SIGNATURE_MAX_SIZE) {
		return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
	}
	if (*sig_len > sig_size) {
		return MBEDTLS_ERR_PK_BUFFER_TOO_SMALL;
	}

	return rsa_alt->sign_func(rsa_alt->key, f_rng, p_rng, md_alg,
			(unsigned int) hash_len, hash, sig);
}

static int rsa_alt_decrypt_wrap(mbedtls_pk_context *pk,
		const unsigned char *input, size_t ilen, unsigned char *output,
		size_t *olen, size_t osize, int (*f_rng)(void*, unsigned char*, size_t),
		void *p_rng) {
	mbedtls_rsa_alt_context *rsa_alt = pk->pk_ctx;

	((void) f_rng);
	((void) p_rng);

	if (ilen != rsa_alt->key_len_func(rsa_alt->key)) {
		return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
	}

	return rsa_alt->decrypt_func(rsa_alt->key, olen, input, output, osize);
}

#if defined(MBEDTLS_RSA_C)
static int rsa_alt_check_pair(mbedtls_pk_context *pub, mbedtls_pk_context *prv,
		int (*f_rng)(void*, unsigned char*, size_t), void *p_rng) {
	unsigned char sig[MBEDTLS_MPI_MAX_SIZE];
	unsigned char hash[32];
	size_t sig_len = 0;
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

	if (rsa_alt_get_bitlen(prv) != rsa_get_bitlen(pub)) {
		return MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
	}

	memset(hash, 0x2a, sizeof(hash));

	if ((ret = rsa_alt_sign_wrap(prv, MBEDTLS_MD_NONE, hash, sizeof(hash), sig,
			sizeof(sig), &sig_len, f_rng, p_rng)) != 0) {
		return ret;
	}

	if (rsa_verify_wrap(pub, MBEDTLS_MD_NONE, hash, sizeof(hash), sig, sig_len)
			!= 0) {
		return MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
	}

	return 0;
}
#endif /* MBEDTLS_RSA_C */

static void* rsa_alt_alloc_wrap(void) {
	void *ctx = mbedtls_calloc(1, sizeof(mbedtls_rsa_alt_context));

	if (ctx != NULL) {
		memset(ctx, 0, sizeof(mbedtls_rsa_alt_context));
	}

	return ctx;
}

static void rsa_alt_free_wrap(void *ctx) {
	mbedtls_zeroize_and_free(ctx, sizeof(mbedtls_rsa_alt_context));
}

const mbedtls_pk_info_t mbedtls_rsa_alt_info = { .type = MBEDTLS_PK_RSA_ALT,
		.name = "RSA-alt", .get_bitlen = rsa_alt_get_bitlen, .can_do =
				rsa_alt_can_do, .verify_func = NULL, .sign_func =
				rsa_alt_sign_wrap,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    .verify_rs_func = NULL,
    .sign_rs_func = NULL,
    .rs_alloc_func = NULL,
    .rs_free_func = NULL,
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
		.decrypt_func = rsa_alt_decrypt_wrap, .encrypt_func = NULL,
#if defined(MBEDTLS_RSA_C)
		.check_pair_func = rsa_alt_check_pair,
#else
    .check_pair_func = NULL,
#endif
		.ctx_alloc_func = rsa_alt_alloc_wrap,
		.ctx_free_func = rsa_alt_free_wrap, .debug_func = NULL, };
#endif /* MBEDTLS_PK_RSA_ALT_SUPPORT */

#if defined(MBEDTLS_USE_PSA_CRYPTO)
static size_t opaque_get_bitlen(mbedtls_pk_context *pk) {
	size_t bits;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

	if (PSA_SUCCESS != psa_get_key_attributes(pk->priv_id, &attributes)) {
		return 0;
	}

	bits = psa_get_key_bits(&attributes);
	psa_reset_key_attributes(&attributes);
	return bits;
}

#if defined(MBEDTLS_PK_HAVE_ECC_KEYS)
static int ecdsa_opaque_can_do(mbedtls_pk_type_t type) {
	return type == MBEDTLS_PK_ECKEY || type == MBEDTLS_PK_ECDSA;
}

const mbedtls_pk_info_t mbedtls_ecdsa_opaque_info = { .type = MBEDTLS_PK_OPAQUE,
		.name = "Opaque", .get_bitlen = opaque_get_bitlen, .can_do =
				ecdsa_opaque_can_do,
#if defined(MBEDTLS_PK_CAN_ECDSA_VERIFY)
		.verify_func = ecdsa_opaque_verify_wrap,
#else /* MBEDTLS_PK_CAN_ECDSA_VERIFY */
    .verify_func = NULL,
#endif /* MBEDTLS_PK_CAN_ECDSA_VERIFY */

#if defined(MBEDTLS_PK_CAN_ECDSA_SIGN)
		.sign_func = ecdsa_opaque_sign_wrap,
#else /* MBEDTLS_PK_CAN_ECDSA_SIGN */
    .sign_func = NULL,
#endif /* MBEDTLS_PK_CAN_ECDSA_SIGN */

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    .verify_rs_func = NULL,
    .sign_rs_func = NULL,
    .rs_alloc_func = NULL,
    .rs_free_func = NULL,
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
		.decrypt_func = NULL, .encrypt_func = NULL, .check_pair_func =
				ecdsa_opaque_check_pair_wrap, .ctx_alloc_func = NULL,
		.ctx_free_func = NULL, .debug_func = NULL, };
#endif /* MBEDTLS_PK_HAVE_ECC_KEYS */

static int rsa_opaque_can_do(mbedtls_pk_type_t type) {
	return type == MBEDTLS_PK_RSA || type == MBEDTLS_PK_RSASSA_PSS;
}

#if defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC)
static int rsa_opaque_decrypt(mbedtls_pk_context *pk,
		const unsigned char *input, size_t ilen, unsigned char *output,
		size_t *olen, size_t osize, int (*f_rng)(void*, unsigned char*, size_t),
		void *p_rng) {
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_algorithm_t alg;
	psa_key_type_t type;
	psa_status_t status;

	/* PSA has its own RNG */
	(void) f_rng;
	(void) p_rng;

	status = psa_get_key_attributes(pk->priv_id, &attributes);
	if (status != PSA_SUCCESS) {
		return PSA_PK_TO_MBEDTLS_ERR(status);
	}

	type = psa_get_key_type(&attributes);
	alg = psa_get_key_algorithm(&attributes);
	psa_reset_key_attributes(&attributes);

	if (!PSA_KEY_TYPE_IS_RSA(type)) {
		return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
	}

	status = psa_asymmetric_decrypt(pk->priv_id, alg, input, ilen, NULL, 0,
			output, osize, olen);
	if (status != PSA_SUCCESS) {
		return PSA_PK_RSA_TO_MBEDTLS_ERR(status);
	}

	return 0;
}
#endif /* PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC */

static int rsa_opaque_sign_wrap(mbedtls_pk_context *pk,
		mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len,
		unsigned char *sig, size_t sig_size, size_t *sig_len,
		int (*f_rng)(void*, unsigned char*, size_t), void *p_rng) {
#if defined(MBEDTLS_RSA_C)
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_algorithm_t alg;
	psa_key_type_t type;
	psa_status_t status;

	/* PSA has its own RNG */
	(void) f_rng;
	(void) p_rng;

	status = psa_get_key_attributes(pk->priv_id, &attributes);
	if (status != PSA_SUCCESS) {
		return PSA_PK_TO_MBEDTLS_ERR(status);
	}

	type = psa_get_key_type(&attributes);
	alg = psa_get_key_algorithm(&attributes);
	psa_reset_key_attributes(&attributes);

	if (PSA_KEY_TYPE_IS_RSA(type)) {
		alg = (alg & ~PSA_ALG_HASH_MASK) | mbedtls_md_psa_alg_from_type(md_alg);
	} else {
		return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
	}

	status = psa_sign_hash(pk->priv_id, alg, hash, hash_len, sig, sig_size,
			sig_len);
	if (status != PSA_SUCCESS) {
		if (PSA_KEY_TYPE_IS_RSA(type)) {
			return PSA_PK_RSA_TO_MBEDTLS_ERR(status);
		} else {
			return PSA_PK_TO_MBEDTLS_ERR(status);
		}
	}

	return 0;
#else /* !MBEDTLS_RSA_C */
    ((void) pk);
    ((void) md_alg);
    ((void) hash);
    ((void) hash_len);
    ((void) sig);
    ((void) sig_size);
    ((void) sig_len);
    ((void) f_rng);
    ((void) p_rng);
    return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
#endif /* !MBEDTLS_RSA_C */
}

const mbedtls_pk_info_t mbedtls_rsa_opaque_info = { .type = MBEDTLS_PK_OPAQUE,
		.name = "Opaque", .get_bitlen = opaque_get_bitlen, .can_do =
				rsa_opaque_can_do, .verify_func = NULL, .sign_func =
				rsa_opaque_sign_wrap,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    .verify_rs_func = NULL,
    .sign_rs_func = NULL,
    .rs_alloc_func = NULL,
    .rs_free_func = NULL,
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */

#if defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC)
		.decrypt_func = rsa_opaque_decrypt,
#else /* PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC */
    .decrypt_func = NULL,
#endif /* PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC */
		.encrypt_func = NULL, .check_pair_func = NULL, .ctx_alloc_func = NULL,
		.ctx_free_func = NULL, .debug_func = NULL, };

#endif /* MBEDTLS_USE_PSA_CRYPTO */

#endif /* MBEDTLS_PK_C */
