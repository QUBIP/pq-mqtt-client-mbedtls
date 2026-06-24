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

extern unsigned long server_crt_parse_us;

extern unsigned long total_handshake_us;

extern unsigned long root_load_us;
extern unsigned long client_load_us;
extern unsigned long crl_verify_us;


// Public key size
#define KYBER768_PK_SIZE 1184
// Secret key Size
#define KYBER768_SK_SIZE 2400

#define X25519_PK_SIZE 32
#define X25519_SK_SIZE 32

// This branch only works with the HW for the PQ and CLASSIC
// and the SW implementation for the Classic
// The SW Implementation for PQ is in the branch SW_ONLY
#define HW_IMPLEMENTATION 1 //1=ON, 0=OFF
#define SCP03			  1 //1=ON, 0=OFF

// OPTIONS: CERTS_PQ_44, CERTS_CLASSIC
#define CERTS_PQ_44

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

#ifdef CERTS_CLASSIC

#define ROOT_CERTIFICATE_CLASSIC \
"-----BEGIN CERTIFICATE-----\r\n" \
"MIIBWTCCAQugAwIBAgIUduZv4RD2gXkOG6ee0OdqOTc6zPUwBQYDK2VwMCIxIDAe\r\n" \
"BgNVBAMMF1NNQVJURkFDVE9SWS1DTEFTU0lDLUNBMB4XDTI2MDIxNjA4MTQ0NFoX\r\n" \
"DTM2MDIxNDA4MTQ0NFowIjEgMB4GA1UEAwwXU01BUlRGQUNUT1JZLUNMQVNTSUMt\r\n" \
"Q0EwKjAFBgMrZXADIQCi7VLC/mNr3rwXxuYOO2ygoF8cfIqy0dirA5/97e+v/qNT\r\n" \
"MFEwHQYDVR0OBBYEFE6zifORurJ1t4LxDCvD8xiTKcymMB8GA1UdIwQYMBaAFE6z\r\n" \
"ifORurJ1t4LxDCvD8xiTKcymMA8GA1UdEwEB/wQFMAMBAf8wBQYDK2VwA0EAcL41\r\n" \
"RNfP8JfH6xpTBc3s93oWm3cW5KBJBZz+enLFCSQDSpDGfBww88osAKSvEkWYkfN/\r\n" \
"im/sV7YLzrSkpZMeBw==\r\n" \
"-----END CERTIFICATE-----\r\n"

#define ROOT_CERTIFICATE_CLASSIC_LEN sizeof(ROOT_CERTIFICATE_CLASSIC)

#define CLIENT_CERT_CLASSIC \
"-----BEGIN CERTIFICATE-----\r\n" \
"MIIBNTCB6KADAgECAhR4T486S/7pi02LcS0q0b7jPJY/EDAFBgMrZXAwIjEgMB4G\r\n" \
"A1UEAwwXU01BUlRGQUNUT1JZLUNMQVNTSUMtQ0EwHhcNMjYwMjE2MDkyNjM4WhcN\r\n" \
"MjcwMjE2MDkyNjM4WjAQMQ4wDAYDVQQDDAVtY3UwMTAqMAUGAytlcAMhABHHtgOl\r\n" \
"KZWXb3GA6z5u6znQ6feVIoPW/SzuYxLjrzX8o0IwQDAdBgNVHQ4EFgQUxJC34N/z\r\n" \
"A3oUWNSq6tSbpYOnveMwHwYDVR0jBBgwFoAUTrOJ85G6snW3gvEMK8PzGJMpzKYw\r\n" \
"BQYDK2VwA0EASpoad1w506PorRhpodsBAU5NA3w7lTaoDOvLLfLoB89PgcFfyLCk\r\n" \
"le68FRkqc0AYAYgjhudTWffqEVmIq5TOBA==\r\n" \
"-----END CERTIFICATE-----\r\n"

#define CLIENT_CERT_CLASSIC_LEN sizeof(CLIENT_CERT_CLASSIC)

#define CLIENT_KEY_CLASSIC \
"-----BEGIN PRIVATE KEY-----\r\n" \
"MC4CAQAwBQYDK2VwBCIEII6los10uQa6AkeczxIlxoQyWbWuCOHqxqBAvyOkcEFS\r\n" \
"-----END PRIVATE KEY-----\r\n"

#define CLIENT_KEY_CLASSIC_LEN sizeof(CLIENT_KEY_CLASSIC)

#define CRL_CLASSIC "-----BEGIN X509 CRL-----\r\n" \
"MIHTMIGGAgEBMAUGAytlcDAiMSAwHgYDVQQDDBdTTUFSVEZBQ1RPUlktQ0xBU1NJ\r\n" \
"Qy1DQRcNMjYwMzI2MTMxOTI1WhcNMjYwNDI1MTMxOTI1WjAnMCUCFHhPjzpL/umL\r\n" \
"TYtxLSrRvuM8lj8PFw0yNjAzMjYxMzE5MjVaoA8wDTALBgNVHRQEBAICEAAwBQYD\r\n" \
"K2VwA0EAetbOtCmrDJu0sw1jpgjXsmhxIuVTe6jTEUmIwpnyJjJvY0sA38M+qK5t\r\n" \
"ff/b57Af37BPzcmWhkDleKdBAOclAQ==\r\n" \
"-----END X509 CRL-----\r\n"

#define CRL_CLASSIC_LEN sizeof(CRL_CLASSIC);

#endif

typedef enum {
	ROOT_CA, CLIENT, CRL
} CertType;


// MLDSA44
#define ROOT_CA_CERT_44_SIZE_BYTES 5865
#define ROOT_CA_CERT_44_SPI_ADDR 0x1000

#define CLIENT_CERT_44_SIZE_BYTES 6221
#define CLIENT_CERT_44_SPI_ADDR 0xC000

#define CLIENT_KEY_44_SIZE_BYTES 177
#define CLIENT_KEY_44_SPI_ADDR 0xF000

#define CRL_CERT_44_SIZE_BYTES 3955
#define CRL_CERT_44_SPI_ADDR 	0x12000



// CLASSIC CERTIFICATES
#define ROOT_CA_CLASSIC_CERT_SIZE_BYTES 541
#define ROOT_CA_CLASSIC_CERT_SPI_ADDR 0x9000

#define CLIENT_CERT_CLASSIC_SIZE_BYTES 491
#define CLIENT_CERT_CLASSIC_SPI_ADDR 0xB000

#define CLIENT_KEY_CLASSIC_SIZE_BYTES 123
#define CLIENT_KEY_CLASSIC_SPI_ADDR 0xD000

#define CRL_CERT_CLASSIC_SIZE_BYTES 349
#define CRL_CERT_CLASSIC_SPI_ADDR 	0xE000





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

