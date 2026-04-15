#ifndef QUBIP_H
#define QUBIP_H

#include <stddef.h>
#include <stdint.h>

extern unsigned long x25519_keygen_us;
extern unsigned long x25519_kem_us;

extern unsigned long mlkem768_keygen_us;
extern unsigned long mlkem768_kem_us;

extern unsigned long ed25519_verify_us;
extern unsigned long ed25519_sign_us;

extern unsigned long mldsa44_verify_us;
extern unsigned long mldsa44_sign_us;

extern unsigned long server_crt_parse_us;
extern unsigned long crl_verify_us;

extern unsigned long total_handshake_us;


// Public key size
#define KYBER768_PK_SIZE 1184
// Secret key Size
#define KYBER768_SK_SIZE 2400

#define X25519_PK_SIZE 32
#define X25519_SK_SIZE 32

// This repo only works with the SW implementation (HW_IMPLEMENTATION=1) and the Hybrid Certificates (CERTS_PQ_44)
#define HW_IMPLEMENTATION 0 //1=ON, 0=OFF

// OPTIONS: CERTS_PQ_44, CERTS_PQ_65, CERTS_CLASSIC
#define CERTS_PQ_44

#define SWAP_ORDER

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

#ifdef CERTS_CLASSIC
	#define BROKER_IP		"broker.smartfactory.it"
	#define BROKER_HOSTNAME "broker.smartfactory.it"
#else
	#define BROKER_IP		"broker.dm.qubip.eu"
	#define BROKER_HOSTNAME "broker.dm.qubip.eu"
#endif

// Does not launch FreeRTOS but runs custom test function
//#define TEST_SE

// Ultra verbose logs, deactivate in prod as they massively interfere with MQTT timeouts
//#define MQTT_INTERFACE_DEBUG

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

HybridKeyKEM* hybrid_key_gen();
void hybrid_key_free(HybridKeyKEM*);
//void print_result_valid(unsigned char* str, unsigned int fail);
int qubip_pq_x25519_mlkem768_key_agreement(const uint8_t *peer_key,
		size_t peer_key_length, const uint8_t *key_buffer,
		size_t key_buffer_size, uint8_t *shared_secret,
		size_t shared_secret_size, size_t *shared_secret_length);
#endif

