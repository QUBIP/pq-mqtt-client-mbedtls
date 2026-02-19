/*
 Copyright (c) 2016,  2024-2025, Security Pattern srl. All rights reserved.
 SPDX-License-Identifier: MIT
 */

#include "qubip.h"
#include "tim_us.h"

#include "mbedtls/ecp.h"
#include "se-qubip.h"
#include "crypto_api_sw.h"
#include <stdlib.h>

unsigned long x25519_keygen_us = 0;
unsigned long x25519_kem_us = 0;

unsigned long mlkem768_keygen_us = 0;
unsigned long mlkem768_kem_us = 0;

unsigned long ed25519_verify_us = 0;
unsigned long ed25519_sign_us = 0;

unsigned long mldsa44_verify_us = 0;
unsigned long mldsa44_sign_us = 0;

unsigned long total_handshake_us = 0;

extern char mbedtls_root_certificate;
extern char client_cert;
extern char client_key;

HybridKeyKEM* hybrid_key_gen() {

	uint32_t end_time = 0;

	uint32_t start_time = micros();

	HybridKeyKEM *out_keys = (HybridKeyKEM*) pvPortMalloc(sizeof(HybridKeyKEM));
	printf("##########################################################\n");
	printf("Starting X25519_MLKEM768 key generation...\n");

	out_keys->mlkem_768_pk = (uint8_t*) pvPortMalloc(KYBER768_PK_SIZE);
	out_keys->mlkem_768_sk = (uint8_t*) pvPortMalloc(KYBER768_SK_SIZE);
	out_keys->mlkem_768_pk_size = KYBER768_PK_SIZE;
	out_keys->mlkem_768_sk_size = KYBER768_SK_SIZE;
	unsigned int pri_len;
	unsigned int pub_len;

	uint64_t mlkem_key_slot = 31;
	uint64_t x25519_key_slot = 31;

#if HW_IMPLEMENTATION==1

	//printf("HW Hybrid Gen Key...\n");

	secmem_store_key(ID_MLKEM, &mlkem_key_slot, false, NULL, 0, 0);
	secmem_store_key(ID_X25519, &x25519_key_slot, false, NULL, 0, 0);

	out_keys->x25519_key_slot = x25519_key_slot;
	out_keys->mlkem_768_key_slot = mlkem_key_slot;

	start_time = micros();

	mlkem_768_gen_keys_hw(out_keys->mlkem_768_pk, out_keys->mlkem_768_sk,
	false, &mlkem_key_slot, 0);
	end_time = micros();
	mlkem768_keygen_us = end_time - start_time;
	printf("MLKEM768 GenKeys HW - %lu us\t\t\t\033[1;32m\u2705\033[0m\n",
			mlkem768_keygen_us);

	start_time = micros();
	x25519_genkeys_hw(&out_keys->x25519_sk, &out_keys->x25519_pk, &pri_len,
			&pub_len, false, &x25519_key_slot, 0);
	end_time = micros();
	x25519_keygen_us = end_time - start_time;
	printf("X215519 GenKeys HW - %lu us\t\t\t\t\033[1;32m\u2705\033[0m\n",
			x25519_keygen_us);

	//printf("\t\t\033[1;32m\u2705\033[0m\n");

#else
	printf("SW Hybrid Gen Key...");

	mlkem768_genkeys(out_keys->mlkem_768_pk, out_keys->mlkem_768_sk);
	x25519_genkeys(&out_keys->x25519_sk, &out_keys->x25519_pk, &pri_len,
			&pub_len);
	printf("\t\t\033[1;32m\u2705\033[0m\n");

#endif

	out_keys->x25519_pk_size = X25519_PK_SIZE;
	out_keys->x25519_sk_size = X25519_SK_SIZE;
	secmem_delete_all_keys(0);
	printf("Hybrid Gen Key completed!\n");
	printf("##########################################################\n\n");
	return out_keys;
}

void hybrid_key_free(HybridKeyKEM *keys) {
	vPortFree(keys->mlkem_768_pk);
	vPortFree(keys->mlkem_768_sk);
	//vPortFree(keys->x25519_pk);
	//vPortFree(keys->x25519_sk);
	vPortFree(keys);
}

int qubip_pq_x25519_mlkem768_key_agreement(const uint8_t *peer_key,
		size_t peer_key_length, const uint8_t *key_buffer,
		size_t key_buffer_size, uint8_t *shared_secret,
		size_t shared_secret_size, size_t *shared_secret_length) {

	uint8_t *server_ecdh_key = (uint8_t*) pvPortMalloc(32);
	uint8_t *server_kyber_ct = (uint8_t*) pvPortMalloc(peer_key_length - 32);
	uint8_t *ssecret_mlkem768 = (uint8_t*) pvPortMalloc(32);
	uint8_t *ssecret_x25519;
	unsigned int out_len;
	HybridKeyKEM *private_key = (HybridKeyKEM*) key_buffer;
	unsigned int result = 0;
	uint32_t end_time = 0;
	uint32_t start_time = micros();

	printf("##########################################################\n");

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
	//printf("HW MLKEM768 Dec...\n");
	start_time = micros();
	mlkem768_dec_hw(private_key->mlkem_768_sk, server_kyber_ct,
			ssecret_mlkem768, &result, true, &private_key->mlkem_768_key_slot,
			0);
	end_time = micros();
	mlkem768_kem_us = end_time - start_time;
	printf("MLKEM768 Decapsulate HW - %lu us\t\t\t\033[1;32m\u2705\033[0m\n",
			mlkem768_kem_us);

	//HW returns 3 (?!?!) on success
	result = (result == 3 ? 0 : -1);
	//printf("\t\t\033[1;32m\u2705\033[0m\n");

#else

	printf("SW MLKEM768 Dec...");

	mlkem768_dec(ssecret_mlkem768, server_kyber_ct, private_key->mlkem_768_sk,
			&result);
	printf("\t\t\033[1;32m\u2705\033[0m\n");
	//printf("Result: %d\n", result);


#endif

#if HW_IMPLEMENTATION==1
	//printf("HW x25519 SS GEN...\n");

	start_time = micros();

	x25519_ss_gen_hw(&ssecret_x25519, &out_len, server_ecdh_key, 32,
			private_key->x25519_sk, private_key->x25519_sk_size, true,
			&private_key->x25519_key_slot, 0);
	end_time = micros();
	x25519_kem_us = end_time - start_time;
	printf("HW x25519 SS GEN HW - %lu us\t\t\t\t\033[1;32m\u2705\033[0m\n",
			x25519_kem_us);

	//printf("\t\t\033[1;32m\u2705\033[0m\n");

#else
	printf("SW x25519 SS GEN...");
	x25519_ss_gen(&ssecret_x25519, &out_len, server_ecdh_key, 32,
			private_key->x25519_sk, private_key->x25519_sk);
	printf("\t\t\033[1;32m\u2705\033[0m\n");

#endif

#ifdef SWAP_ORDER
	memcpy(shared_secret + 32, ssecret_x25519, 32);
	memcpy(shared_secret, ssecret_mlkem768, 32);
#else
	memcpy(shared_secret,ssecret_x25519,32);
	memcpy(shared_secret + 32,ssecret_mlkem768,32);
#endif // SWAP_ORDER
	vPortFree(server_ecdh_key);
	vPortFree(server_kyber_ct);
	vPortFree(ssecret_mlkem768);
	//vPortFree(ssecret_x25519);
	printf("X25519_MLKEM768 key agreement completed!\n");
	printf("##########################################################\n\n");

	return result;
}

int qubip_classic_x25519_key_agreement(const uint8_t *peer_key,
		size_t peer_key_length, const uint8_t *key_buffer,
		size_t key_buffer_size, uint8_t *shared_secret,
		size_t shared_secret_size, size_t *shared_secret_length) {

	uint8_t *ssecret_x25519;
	unsigned int out_len;
	unsigned int result = 0;
	uint32_t end_time = 0;
	uint32_t start_time = micros();
	unsigned int unused = 0;
	printf("##########################################################\n");

	printf("Starting X25519 key agreement...\n");

	mbedtls_ecp_point p;
	mbedtls_ecp_group grp;
	mbedtls_ecp_point_init(&p);
	mbedtls_ecp_group_init(&grp);
	/*
	 #ifdef SWAP_ORDER
	 memcpy(server_ecdh_key, peer_key + peer_key_length - 32, 32);
	 memcpy(server_kyber_ct, peer_key, peer_key_length - 32);
	 #else
	 memcpy(server_ecdh_key,peer_key,32);
	 memcpy(server_kyber_ct,peer_key + 32, peer_key_length - 32);
	 #endif //SWAP_ORDER
	 */
	result = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
	result = mbedtls_ecp_point_read_binary(&grp, &p, peer_key, 32);
	if (result != 0) {
		printf("Error loading mbedtls info...");
		return -1;
	}
	mbedtls_mpi_write_binary_le(&p.private_X, peer_key, 32);

#if HW_IMPLEMENTATION==1
	//printf("HW x25519 SS GEN...\n");

	start_time = micros();

	x25519_ss_gen_hw(&ssecret_x25519, &out_len, peer_key, 32, key_buffer,
			key_buffer_size, true, &unused, 0);
	end_time = micros();
	x25519_kem_us = end_time - start_time;
	printf("HW x25519 SS GEN HW - %lu us\t\t\t\t\033[1;32m\u2705\033[0m\n",
			x25519_kem_us);

	//printf("\t\t\033[1;32m\u2705\033[0m\n");

#else
	start_time = micros();
	x25519_ss_gen(&ssecret_x25519, &out_len, peer_key, 32,
			key_buffer, key_buffer_size);
	end_time = micros();
	printf("SW x25519 SS GEN HW - %lu us\t\t\t\t\033[1;32m\u2705\033[0m\n",
			end_time - start_time);

#endif
	/*
	 #ifdef SWAP_ORDER
	 memcpy(shared_secret + 32, ssecret_x25519, 32);
	 memcpy(shared_secret, ssecret_mlkem768, 32);
	 #else
	 memcpy(shared_secret,ssecret_x25519,32);
	 memcpy(shared_secret + 32,ssecret_mlkem768,32);
	 #endif // SWAP_ORDER
	 */
	memcpy(shared_secret, ssecret_x25519, 32);
	//vPortFree(ssecret_x25519);
	printf("X25519 key agreement completed!\n");
	printf("##########################################################\n\n");

	return result;
}
SPICert* make_certificate(CertType CERT_TYPE) {

	SPICert *out_cert = (SPICert*) pvPortMalloc(sizeof(SPICert));
	switch (CERT_TYPE) {

#ifdef CERTS_CLASSIC
	case ROOT_CA:
		out_cert->name = (unsigned char*) "Root CL";
		out_cert->cert_len = ROOT_CA_CLASSIC_CERT_SIZE_BYTES;
		out_cert->cert_spi_addr = ROOT_CA_CLASSIC_CERT_SPI_ADDR;
		out_cert->key_len = 0;
		out_cert->key_bytes = NULL;
		out_cert->cert_bytes = NULL;
		break;

	case CLIENT:
		out_cert->name = (unsigned char*) "ClientCL";
		out_cert->cert_len = CLIENT_CERT_CLASSIC_SIZE_BYTES;
		out_cert->cert_spi_addr = CLIENT_CERT_CLASSIC_SPI_ADDR;
		out_cert->key_len = CLIENT_KEY_CLASSIC_SIZE_BYTES;
		out_cert->key_spi_addr = CLIENT_KEY_CLASSIC_SPI_ADDR;
		out_cert->cert_bytes = NULL;
		break;

	case CRL:
		out_cert->name = (unsigned char*) "CRL CL";
		out_cert->cert_len = CRL_CERT_CLASSIC_SIZE_BYTES;
		out_cert->cert_spi_addr = CRL_CERT_CLASSIC_SPI_ADDR;
		out_cert->key_len = 0;
		out_cert->key_spi_addr = 0;
		out_cert->cert_bytes = NULL;
		break;
#else
	case ROOT_CA:
		out_cert->name = (unsigned char*) "Root CA44";
		out_cert->cert_len = ROOT_CA_CERT_44_SIZE_BYTES;
		out_cert->cert_spi_addr = ROOT_CA_CERT_44_SPI_ADDR;
		out_cert->key_len = 0;
		out_cert->key_bytes = NULL;
		out_cert->cert_bytes = NULL;
		break;

	case CLIENT:
		out_cert->name = (unsigned char*) "Client44";
		out_cert->cert_len = CLIENT_CERT_44_SIZE_BYTES;
		out_cert->cert_spi_addr = CLIENT_CERT_44_SPI_ADDR;
		out_cert->key_len = CLIENT_KEY_44_SIZE_BYTES;
		out_cert->key_spi_addr = CLIENT_KEY_44_SPI_ADDR;
		out_cert->cert_bytes = NULL;
		break;

	case CRL:
		out_cert->name = (unsigned char*) "CRL44";
		out_cert->cert_len = CRL_CERT_44_SIZE_BYTES;
		out_cert->cert_spi_addr = CRL_CERT_44_SPI_ADDR;
		out_cert->key_len = 0;
		out_cert->key_spi_addr = 0;
		out_cert->cert_bytes = NULL;
		break;
#endif

	default:
		break;
	}

	return out_cert;
}

void free_certificate(SPICert *certificate) {
	vPortFree(certificate->cert_bytes);
	if (certificate->key_len > 0) {
		vPortFree(certificate->key_bytes);
	}
	vPortFree(certificate);
}

void save_cert_to_spi(SPICert *certificate) {
	printf("Writing CERT \"%s\" of %d bytes to SPI at address 0x%x...",
			certificate->name, certificate->cert_len,
			certificate->cert_spi_addr);
	save_data_flash(certificate->cert_spi_addr, certificate->cert_len,
			certificate->cert_bytes, 0);
	printf("Certificate \"%s\" written!\n", certificate->name);
	if (certificate->key_len > 0) {
		printf("Writing KEY of %d bytes to SPI at address 0x%x...",
				certificate->key_len, certificate->key_spi_addr);
		save_data_flash(certificate->key_spi_addr, certificate->key_len,
				certificate->key_bytes, 0);
		printf("Key written!\n");

	}
}

void load_cert_from_spi(SPICert *certificate, bool load_key, bool alloc_buffers) {
	printf("##################################################\n");

	printf("Loading CERT \"%s\"\n%d bytes from SPI at address 0x%x\n",
			certificate->name, certificate->cert_len,
			certificate->cert_spi_addr);

	if (alloc_buffers == true) {
		printf("Allocating buf for cert...");
		certificate->cert_bytes = (unsigned char*) pvPortMalloc(
				sizeof(unsigned char) * certificate->cert_len);
		printf("\t\t\t\033[1;32m\u2705\033[0m\n");

	}
	printf("Loading data from SPI Flash...");

	recover_data_flash(certificate->cert_spi_addr, certificate->cert_len,
			certificate->cert_bytes, 0);
	printf("\t\t\t\033[1;32m\u2705\033[0m\n");

	printf("Certificate \"%s\" loaded!", certificate->name);
	printf("\t\t\t\033[1;32m\u2705\033[0m\n");

	if (load_key == true) {
		printf("Loading KEY\n%d bytes from SPI at address 0x%x\n",
				certificate->key_len, certificate->key_spi_addr);
		if (alloc_buffers == true) {
			printf("Allocating buf for key...");

			certificate->key_bytes = (unsigned char*) pvPortMalloc(
					sizeof(unsigned char) * certificate->key_len);
			printf("\t\t\t\033[1;32m\u2705\033[0m\n");

		}
		printf("Loading data from SPI Flash...");

		recover_data_flash(certificate->key_spi_addr, certificate->key_len,
				certificate->key_bytes, 0);
		printf("\t\t\t\033[1;32m\u2705\033[0m\n");

		printf("Key loaded!");
		printf("\t\t\t\t\t\033[1;32m\u2705\033[0m\n");

	}
	printf("##################################################\n\n\n");

}
