/*
Copyright (c) 2016,  2024-2025, Security Pattern srl. All rights reserved.
SPDX-License-Identifier: MIT
*/

#ifndef QUBIP_H
#define QUBIP_H


#include <stddef.h>
#include <stdint.h>

// Public key size
#define KYBER768_PK_SIZE 1184
// Secret key Size
#define KYBER768_SK_SIZE 2400

#define X25519_PK_SIZE 32
#define X25519_SK_SIZE 32

#define HW_IMPLEMENTATION 0 //1=ON, 0=OFF

// OPTIONS: CERTS_PQ_44, CERTS_PQ_65, CERTS_CLASSIC
#define CERTS_PQ_44

#define SWAP_ORDER


//#define BROKER_IP		"192.168.1.12"
#define BROKER_IP		"broker.dm.qubip.eu"
#define BROKER_HOSTNAME "broker.dm.qubip.eu"

// Does not launch FreeRTOS but runs custom test function
//#define TEST_SE

// Ultra verbose logs, deactivate in prod as they massively interfere with MQTT timeouts
//#define MQTT_INTERFACE_DEBUG



#ifdef CERTS_PQ_44

	#define MQTT_PORT		"8884"

#else

	#define MQTT_PORT		"8883"

#endif


typedef struct {
	// Kyber768 Public Key
	uint8_t *mlkem_768_pk;
	uint32_t mlkem_768_pk_size;

	//Kyber 768 Secret Key
	uint8_t *mlkem_768_sk;
	uint32_t mlkem_768_sk_size;

	// X25519 Public Key
	uint8_t *x25519_pk;
	uint32_t x25519_pk_size;

	//X25519 Secret Key
	uint8_t *x25519_sk;
	uint32_t x25519_sk_size;

} HybridKeyKEM;

HybridKeyKEM *hybrid_key_gen();
void hybrid_key_free(HybridKeyKEM *);
//void print_result_valid(unsigned char* str, unsigned int fail);
int qubip_pq_x25519_mlkem768_key_agreement(
    const uint8_t *peer_key,
    size_t peer_key_length,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    uint8_t *shared_secret,
    size_t shared_secret_size,
    size_t *shared_secret_length);
#endif

