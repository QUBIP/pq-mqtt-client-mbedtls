/*
 Copyright (c) 2016,  2024-2025, Security Pattern srl. All rights reserved.
 SPDX-License-Identifier: MIT
 */

#ifndef QUBIP_H
#define QUBIP_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

extern unsigned long x25519_keygen_us;
extern unsigned long x25519_kem_us;

extern unsigned long mlkem768_keygen_us;
extern unsigned long mlkem768_kem_us;

extern unsigned long ed25519_verify_us;
extern unsigned long ed25519_sign_us;

extern unsigned long mldsa44_verify_us;
extern unsigned long mldsa44_sign_us;

extern unsigned long total_handshake_us;


// Public key size
#define KYBER768_PK_SIZE 1184
// Secret key Size
#define KYBER768_SK_SIZE 2400

#define X25519_PK_SIZE 32
#define X25519_SK_SIZE 32

// This branch only works with the HW for the PQ and CLASSIC
// and the SW implementation for the CLassic
// The SW Implementation for PQ is in the branch SW_ONLY
#define HW_IMPLEMENTATION 0 //1=ON, 0=OFF
#define SCP03			  1 //1=ON, 0=OFF

// OPTIONS: CERTS_PQ_44, CERTS_CLASSIC
#define CERTS_CLASSIC

#define SWAP_ORDER

//#define BROKER_IP		"192.168.1.12"
//#define BROKER_HOSTNAME "secpat"

#ifdef CERTS_CLASSIC
	#define BROKER_IP		"broker.smartfactory.it"
	#define BROKER_HOSTNAME "broker.smartfactory.it"
#else
	#define BROKER_IP		"broker.dm.qubip.eu"
	#define BROKER_HOSTNAME "broker.dm.qubip.eu"
#endif
// Force a CRL revocation check
#define FORCE_CRL_CHECK 0


#define MQTT_PORT		"8884"

#define DEVICE_NAME  "sfc10002"

#if HW_IMPLEMENTATION == 1
	#define HW_OR_SW "HW"
#else
	#define HW_OR_SW "SW"
#endif

#ifdef CERTS_CLASSIC
	#define CLASSIC_OR_PQ "Classic"
#else
	#define CLASSIC_OR_PQ "Hybrid PQ"
#endif
// Does not launch FreeRTOS but runs custom test functions
//#define TEST_SE

// Ultra verbose logs, deactivate in prod as they massively interfere with MQTT timeouts
//#define MQTT_INTERFACE_DEBUG

typedef enum {
	ROOT_CA, CLIENT, CRL
} CertType;

// CLASSIC CERTIFICATES
#define ROOT_CA_CLASSIC_CERT_SIZE_BYTES 681
#define ROOT_CA_CLASSIC_CERT_SPI_ADDR 0x9000

#define CLIENT_CERT_CLASSIC_SIZE_BYTES 557
#define CLIENT_CERT_CLASSIC_SPI_ADDR 0xB000

#define CLIENT_KEY_CLASSIC_SIZE_BYTES 123
#define CLIENT_KEY_CLASSIC_SPI_ADDR 0xD000

#define CRL_CERT_CLASSIC_SIZE_BYTES 0x0000
#define CRL_CERT_CLASSIC_SPI_ADDR 	0x0000

// MLDSA44
#define ROOT_CA_CERT_44_SIZE_BYTES 5871
#define ROOT_CA_CERT_44_SPI_ADDR 0x1000

#define CLIENT_CERT_44_SIZE_BYTES 6295
#define CLIENT_CERT_44_SPI_ADDR 0x3000

#define CLIENT_KEY_44_SIZE_BYTES 5523
#define CLIENT_KEY_44_SPI_ADDR 0x5000

#define CRL_CERT_44_SIZE_BYTES 3955
#define CRL_CERT_44_SPI_ADDR 	0x7000




typedef struct {
	unsigned char *name;

	// Cert data
	unsigned char *cert_bytes;
	size_t cert_len;
	size_t cert_spi_addr;
	// Optional key data if key_len > 0
	unsigned char *key_bytes;
	size_t key_len;
	size_t key_spi_addr;

} SPICert;

typedef struct {
	// Kyber768 Public Key
	uint8_t *mlkem_768_pk;
	uint32_t mlkem_768_pk_size;

	//Kyber 768 Secret Key
	uint8_t *mlkem_768_sk;
	uint32_t mlkem_768_sk_size;

	uint8_t mlkem_768_key_slot;

	// X25519 Public Key
	uint8_t *x25519_pk;
	uint32_t x25519_pk_size;

	//X25519 Secret Key
	uint8_t *x25519_sk;
	uint32_t x25519_sk_size;

	uint8_t x25519_key_slot;
} HybridKeyKEM;

HybridKeyKEM* hybrid_key_gen();
void hybrid_key_free(HybridKeyKEM*);
//void print_result_valid(unsigned char* str, unsigned int fail);
int qubip_pq_x25519_mlkem768_key_agreement(const uint8_t *peer_key,
		size_t peer_key_length, const uint8_t *key_buffer,
		size_t key_buffer_size, uint8_t *shared_secret,
		size_t shared_secret_size, size_t *shared_secret_length);

int qubip_classic_x25519_key_agreement(const uint8_t *peer_key,
		size_t peer_key_length, const uint8_t *key_buffer,
		size_t key_buffer_size, uint8_t *shared_secret,
		size_t shared_secret_size, size_t *shared_secret_length);

SPICert* make_certificate(CertType CERT_TYPE);
void save_cert_to_spi(SPICert *certificate);
void load_cert_from_spi(SPICert *certificate, bool load_key, bool alloc_buffers);
void free_certificate(SPICert *certificate);
#endif

