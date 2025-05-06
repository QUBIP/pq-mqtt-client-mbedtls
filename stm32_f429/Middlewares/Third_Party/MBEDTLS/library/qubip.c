/*
Copyright (c) 2016,  2024-2025, Security Pattern srl. All rights reserved.
SPDX-License-Identifier: MIT
*/

#include "mbedtls/qubip.h"
#include "mbedtls/ecp.h"
#include "se-qubip.h"
#include "crypto_api_sw.h"

#include <stdlib.h>

HybridKeyKEM* hybrid_key_gen() {

	HybridKeyKEM *out_keys = malloc(sizeof(HybridKeyKEM));
	printf("#############################################\n");
	printf("Starting X25519_MLKEM768 key generation...\n");

	out_keys->mlkem_768_pk = malloc(KYBER768_PK_SIZE);
	out_keys->mlkem_768_sk = malloc(KYBER768_SK_SIZE);
	out_keys->mlkem_768_pk_size = KYBER768_PK_SIZE;
	out_keys->mlkem_768_sk_size = KYBER768_SK_SIZE;
	unsigned int pri_len;
	unsigned int pub_len;

#if HW_IMPLEMENTATION==1
	printf("HW Hybrid Gen Key...");

	mlkem768_genkeys_hw(out_keys->mlkem_768_pk, out_keys->mlkem_768_sk, 0);
	x25519_genkeys_hw(&out_keys->x25519_sk, &out_keys->x25519_pk, &pri_len,
			&pub_len, 0);

	printf("\t\t\033[1;32m\u2705\033[0m\n");

#else
	printf("SW Hybrid Gen Key...");

	mlkem768_genkeys(out_keys->mlkem_768_pk, out_keys->mlkem_768_sk);
	x25519_genkeys(&out_keys->x25519_sk, &out_keys->x25519_pk, &pri_len,
			&pub_len);
	printf("\t\t\033[1;32m\u2705\033[0m\n");

#endif

	out_keys->x25519_pk_size = X25519_PK_SIZE;
	out_keys->x25519_sk_size = X25519_SK_SIZE;

	printf("Hybrid Gen Key completed!\n");
	printf("#############################################\n\n");
	return out_keys;
}

void hybrid_key_free(HybridKeyKEM *keys) {
	free(keys->mlkem_768_pk);
	free(keys->mlkem_768_sk);
	free(keys->x25519_pk);
	free(keys->x25519_sk);
	free(keys);
}

int qubip_pq_x25519_mlkem768_key_agreement(const uint8_t *peer_key,
		size_t peer_key_length, const uint8_t *key_buffer,
		size_t key_buffer_size, uint8_t *shared_secret,
		size_t shared_secret_size, size_t *shared_secret_length) {

	uint8_t *server_ecdh_key = malloc(32);
	uint8_t *server_kyber_ct = malloc(peer_key_length - 32);
	uint8_t *ssecret_kem = malloc(32);
	uint8_t *ssecret_x25519;
	unsigned int out_len;
	HybridKeyKEM *private_key = (HybridKeyKEM*) key_buffer;
	unsigned int result = 0;
	printf("#############################################\n");

	printf("Starting X25519_MLKEM768 key agreement...\n");

	mbedtls_ecp_point p;
	mbedtls_ecp_group grp;
	mbedtls_ecp_point_init(&p);
	mbedtls_ecp_group_init(&grp);

#ifdef SWAP_ORDER
	memcpy(server_ecdh_key, peer_key + peer_key_length - 32, 32);
	memcpy(server_kyber_ct, peer_key, peer_key_length - 32);
#else
	memcpy(server_ecdh_key,peer_key,32);
	memcpy(server_kyber_ct,peer_key + 32, peer_key_length - 32);
#endif //SWAP_ORDER

	result = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
	result = mbedtls_ecp_point_read_binary(&grp, &p, server_ecdh_key, 32);
	if (result != 0) {
		printf("Error loading mbedtls info...");
		return -1;
	}
	mbedtls_mpi_write_binary_le(&p.private_X, server_ecdh_key, 32);

#if HW_IMPLEMENTATION==1
	printf("HW MLKEM768 Dec...");
	mlkem768_dec_hw(private_key->mlkem_768_sk, server_kyber_ct, ssecret_kem,
			&result, 0);
	//HW returns 3 (?!?!) on success
	result = (result == 3 ? 0 : -1);
	printf("\t\t\033[1;32m\u2705\033[0m\n");
	//printf("Result: %d\n", result);

#else

	printf("SW MLKEM768 Dec...");

	mlkem768_dec(ssecret_kem, server_kyber_ct, private_key->mlkem_768_sk,
			&result);
	printf("\t\t\033[1;32m\u2705\033[0m\n");
	//printf("Result: %d\n", result);


#endif

#if HW_IMPLEMENTATION==1
	printf("HW x25519 SS GEN...");
	x25519_ss_gen_hw(&ssecret_x25519, &out_len, server_ecdh_key, 32,
			private_key->x25519_sk, private_key->x25519_sk_size, 0);
	printf("\t\t\033[1;32m\u2705\033[0m\n");

#else
	printf("SW x25519 SS GEN...");
	x25519_ss_gen(&ssecret_x25519, &out_len, server_ecdh_key, 32,
			private_key->x25519_sk, private_key->x25519_sk);
	printf("\t\t\033[1;32m\u2705\033[0m\n");

#endif

#ifdef SWAP_ORDER
	memcpy(shared_secret + 32, ssecret_x25519, 32);
	memcpy(shared_secret, ssecret_kem, 32);
#else
	memcpy(shared_secret,ssecret_x25519,32);
	memcpy(shared_secret + 32,ssecret_kem,32);
#endif // SWAP_ORDER
	free(server_ecdh_key);
	free(server_kyber_ct);
	free(ssecret_kem);
	free(ssecret_x25519);
	printf("X25519_MLKEM768 key agreement completed!\n");
	printf("#############################################\n\n");

	return result;
}

