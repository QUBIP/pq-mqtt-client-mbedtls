/**
 ******************************************************************************
 * File Name          : MQTTInterface.c
 * Description        : Code for freertos applications
 ******************************************************************************
 * @attention
 *
 * Copyright (c) 2024 SmartFactory s.r.l.
 * All rights reserved.
 *
 * This software is licensed under terms that can be found in the LICENSE file
 * in the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 * Contributors:
 *    Federico Parente - initial API and implementation and/or initial documentation
 ******************************************************************************
 */
#include "MQTTInterface.h"
#include "stm32f4xx_hal.h"
#include "intf.h"
#include <string.h>
#include "lwip.h"
#include "lwip/api.h"
#include "lwip/sockets.h"
#include "leds.h"

#ifdef MQTT_LWIP_SOCKET_TLS
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#endif

#include "qubip.h"

#include "mbedtls/eddsa.h" 
#include "mbedtls/psa_util.h"
#include "pk_wrap.h"

uint32_t MilliTimer;

#ifdef MQTT_LWIP_SOCKET_TLS
mbedtls_net_context server_fd;
const char *pers = "mbedtls";

mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_ssl_config conf;
mbedtls_x509_crt cacert;
mbedtls_x509_crt clicert;
mbedtls_pk_context pkey;
mbedtls_ssl_context ssl;
mbedtls_x509_crl crl;

/*
 const char mbedtls_crl[] =
 "-----BEGIN X509 CRL-----\r\n"
 "MIILETCCATkCAQEwDQYLYIZIAYb6a1AIAQMwRzELMAkGA1UEBhMCRVUxDjAMBgNV\r\n"
 "BAoMBVFVQklQMSgwJgYDVQQDDB9RVUJJUCBNQ1UgQ2VydGlmaWNhdGUgQXV0aG9y\r\n"
 "aXR5Fw0yNTExMTgxMzMzMjVaFw0yNTExMTkxMzMzMjVaMDUwMwIUEIln1I4CE3Bz\r\n"
 "0Nm3GET8UT9/0EUXDTI1MTExODEzMzAyNFowDDAKBgNVHRUEAwoBAaCBhjCBgzAf\r\n"
 "BgNVHSMEGDAWgBRgbQTTcyXwsMSOiELzMFXlyRHGRzBUBggrBgEFBQcBAQRIMEYw\r\n"
 "RAYIKwYBBQUHMAKGOGh0dHBzOi8vY2EuYWxsLnF1YmlwLmV1L3BraS00NC9xdWJp\r\n"
 "cC1yb290LWNhL2NlcnRpZmljYXRlMAoGA1UdFAQDAgEDMA0GC2CGSAGG+mtQCAED\r\n"
 "A4IJwQAwggm8A4IJdQAJlxrBWV4mUm7PIT1KuWOF792tsZVyVONpKNdTI7DEEK0M\r\n"
 "Aii+GFDjnUFh+H91grMC7dKnGRZVMM+IkR4g3U8IQuTNsCS40tfTVqjSbxRbwr5x\r\n"
 "MdA3NItTR3cViGBoVWMnNbh4fkYbLBK1FF/wvp6S8e73edEfj9gI7iHqmYXCgYNk\r\n"
 "bjSeCGyNfg0UbRdV6U4WR91lLgZYfc4su6hbRZzXmKvibG3WA1zVVESoHS5UQsFo\r\n"
 "Nbi9tdjEc4H6Q5KZ7bafvT+IHnvAnyMqJMgev1zIh52uFfUDt5qxa+6lEj1EIkQQ\r\n"
 "aNro5gTiMHfNVYTXF+w9im0ufp0KV1G2DVruvILfRI5JRrFvMAVz98DIlQDI4WT3\r\n"
 "8SXsrpzO7SP3GooLCLyW2Br3CsdbNHKJrNA7PGQCkJ7wZRTCRQQojxHJAHBo4ghS\r\n"
 "uWPHLT7CoUQ2g8wVy5QO837HdUVI5VJIh8xNQpRz2vG0bht17fzrps6kaQWEYToQ\r\n"
 "Q33hlOqrs1IDz3HJ4mzMCgdYuVtBzyWJRRGZZXkYIMq+qiEAcGYHypZ5mrsWnfR8\r\n"
 "q1SVZ6Iuj4eBmk5Bj7JJUMKNBzDwLdWB4/SNGl6qndpqPCd88zQuBPZvDU2hop2V\r\n"
 "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\r\n"
 "mOCwtA8=\r\n"
 "-----END X509 CRL-----\r\n";
 const size_t mbedtls_crl_len = sizeof(mbedtls_crl);
 */
#endif

#ifdef MQTT_LWIP_SOCKET
void mqtt_network_init(Network *n) {
	n->socket = 0; //clear
	n->mqttread = mqtt_network_read; //receive function
	n->mqttwrite = mqtt_network_write; //send function
	n->disconnect = mqtt_network_disconnect; //disconnection function
}

int mqtt_network_connect(Network *n, char *ip, int port) {
	struct sockaddr_in server_addr;

	if(n->socket)
	{
		close(n->socket);
	}

	n->socket = socket(PF_INET, SOCK_STREAM, 0); //create socket
	if(n->socket < 0)
	{
		n->socket = 0;
		return -1;
	}

	memset(&server_addr, 0, sizeof(struct sockaddr_in)); //broker address info
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(ip);
	server_addr.sin_port = htons(port);

	if(connect(n->socket, (struct sockaddr*)&server_addr, sizeof(struct sockaddr_in)) < 0) //connect to the broker
	{
		close(n->socket);
		return -1;
	}
	return 0;
}

int mqtt_network_read(Network *n, unsigned char *buffer, int len, int timeout_ms) {
	int available;

	/* !!! LWIP_SO_RCVBUF must be enabled !!! */
	if(ioctl(n->socket, FIONREAD, &available) < 0) return -1; //check receive buffer

	if(available > 0)
	{
		return recv(n->socket, buffer, len, 0);
	}

	return 0;
}

int mqtt_network_write(Network *n, unsigned char *buffer, int len, int timeout_ms) {
	return send(n->socket, buffer, len, 0);
}

void mqtt_network_disconnect(Network *n) {
	close(n->socket);
	n->socket = 0;
}
#endif
#ifdef MQTT_LWIP_SOCKET_TLS

static void my_debug(void *ctx, int level, const char *file, int line,
		const char *str) {
	((void) level);
	//mbedtls_fprintf((FILE*) ctx, "%s:%04d: %s", file, line, str);
	//fprintf((FILE*) ctx, "%s:%04d: %s", file, line, str);
	//MQTT_INTERFACE_DEBUG_LOG("[MQTT_INTERFACE]: %s:%04d: %s", file, line, str);
	MQTT_INTERFACE_DEBUG_LOG("[MQTT_INTERFACE]: %s", str);

	fflush((FILE*) ctx);
}

void mqtt_network_init(Network *n) {
	n->socket = 0; //clear
	n->mqttread = mqtt_network_read; //receive function
	n->mqttwrite = mqtt_network_write; //send function
	n->disconnect = mqtt_network_disconnect; //disconnection function
}

void test();

int mqtt_network_connect(Network *n, char *ip, char *port) {
	int ret = 0;

#if defined(MBEDTLS_DEBUG_C) && defined(DEBUG)
	mbedtls_debug_set_threshold(0);
#endif

	// Initialize the network interface
	mqtt_network_init(n);
	mqtt_network_clear();
	//mbedtls_net_init( &server_fd ); // MX_LWIP_Init() is called already
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_x509_crt_init(&cacert);
	mbedtls_x509_crt_init(&clicert);
	mbedtls_pk_init(&pkey);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
	mbedtls_x509_crl_init(&crl);

	ret = psa_crypto_init();
	if (ret != PSA_SUCCESS) {
		MQTT_INTERFACE_DEBUG_LOG(
				"[MQTT_INTERFACE] ERROR: psa_crypto_init failed.\n");
		return -1;
	}

	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
			(const unsigned char*) pers, strlen(pers))) != 0) {
		MQTT_INTERFACE_DEBUG_LOG(
				"[MQTT_INTERFACE] ERROR: mbedtls_ctr_drbg_seed returned %d\n",
				ret);
		return -1;
	}

#if SCP03 == 1
	printf("Setting UP SCP03 protected channel\n");
	open_INTF((INTF*) NULL, 0, 0);
	printf("SCP03 protected channel OK\n\n");
#endif

	// Reading certs from SPI Flash

	SPICert *root_ca = make_certificate(ROOT_CA);
#if defined(CERTS_CLASSIC) && HW_IMPLEMENTATION == 0
	root_ca->cert_bytes = ROOT_CERTIFICATE_CLASSIC;
#else
	uint32_t start = micros();
	load_cert_from_spi(root_ca, false, true);
	root_load_us = micros() - start;
#endif

	// Processi SSL/TLS
	ret = mbedtls_x509_crt_parse(&cacert,
			(const unsigned char*) root_ca->cert_bytes, root_ca->cert_len);
	if (ret < 0) {
		MQTT_INTERFACE_DEBUG_LOG(
				"[MQTT_INTERFACE] INFO: Root certificate is %d bytes long. Certificate is:\n %s\n",
				root_ca->cert_len, root_ca->cert_bytes);MQTT_INTERFACE_DEBUG_LOG(
				"[MQTT_INTERFACE] ERROR: mbedtls_x509_crt_parse failed for root certificate.\n");
		return -1;
	}

#if !defined(CERTS_CLASSIC) || HW_IMPLEMENTATION == 1
	free_certificate(root_ca);
#endif

	SPICert *client_certificate = make_certificate(CLIENT);
#if defined(CERTS_CLASSIC) && HW_IMPLEMENTATION == 0
	client_certificate->cert_bytes = CLIENT_CERT_CLASSIC;
	client_certificate->key_bytes = CLIENT_KEY_CLASSIC;
#else
	start = micros();
	load_cert_from_spi(client_certificate, true, true);
	client_load_us = micros() - start;
#endif

	// START
	// TLS V1.3
#if !defined(TLS_1V2) && defined(TLS_1V3)
	ret = mbedtls_x509_crt_parse(&clicert,
			(const unsigned char*) client_certificate->cert_bytes,
			client_certificate->cert_len);
	if (ret != 0) {
		MQTT_INTERFACE_DEBUG_LOG(
				"[MQTT_INTERFACE] ERROR: mbedtls_x509_crt_parse failed for client certificate\n");
		return -1;
	}

	// Aggiungi caricamento della chiave cliente
	ret = mbedtls_pk_parse_key(&pkey,
			(const unsigned char*) client_certificate->key_bytes,
			client_certificate->key_len, NULL, 0, mbedtls_ctr_drbg_random,
			&ctr_drbg);
	if (ret != 0) {
		MQTT_INTERFACE_DEBUG_LOG(
				"[MQTT_INTERFACE] ERROR: mbedtls_pk_parse_key failed.\n");
		return -1;
	}

#if !defined(CERTS_CLASSIC) || HW_IMPLEMENTATION == 1
	free_certificate(client_certificate);
#endif

#if FORCE_CRL_CHECK == 1
	SPICert *crl_cert = make_certificate(CRL);

#if defined(CERTS_CLASSIC) && HW_IMPLEMENTATION == 0
	crl_cert->cert_bytes = CRL_CLASSIC;
	crl_cert->cert_len = CRL_CLASSIC_LEN;
#else
	load_cert_from_spi(crl_cert, false, true);

#endif
	ret = mbedtls_x509_crl_parse(&crl,
			(const unsigned char*) crl_cert->cert_bytes, crl_cert->cert_len);

	if (ret != 0) {
		MQTT_INTERFACE_DEBUG_LOG(
				"[MQTT_INTERFACE] ERROR: mbedtls_x509_crl_parse failed.\n");
		return -1;
	}

#if !defined(CERTS_CLASSIC) || HW_IMPLEMENTATION == 1
	free_certificate(crl_cert);
#endif

#endif

	// Extract public from client cert: Not a perfect solution but as of now we don't have a way to derive the public from the private
	// Private and Public for MLDSA are inside the key, for the x25519 we can derive it. For now we import the one from cert (need to check the two keys match) and later we can derive it
	if (pkey.private_pk_info->type == MBEDTLS_PK_ED25519_MLDSA65) {
		mbedtls_ed25519_mlds65_ctx *pk_ctx =
				(mbedtls_ed25519_mlds65_ctx*) (pkey.private_pk_ctx);
		mbedtls_ed25519_mlds65_ctx *cl_pk_ctx =
				(mbedtls_ed25519_mlds65_ctx*) (clicert.pk.private_pk_ctx);

		memcpy(pk_ctx->ed_pub_key, cl_pk_ctx->ed_pub_key, pk_ctx->ed_pubsize);
	}
	if (pkey.private_pk_info->type == MBEDTLS_PK_ED25519_MLDSA44) {
		mbedtls_ed25519_mlds44_ctx *pk_ctx =
				(mbedtls_ed25519_mlds44_ctx*) (pkey.private_pk_ctx);
		mbedtls_ed25519_mlds65_ctx *cl_pk_ctx =
				(mbedtls_ed25519_mlds44_ctx*) (clicert.pk.private_pk_ctx);

		memcpy(pk_ctx->ed_pub_key, cl_pk_ctx->ed_pub_key, pk_ctx->ed_pubsize);
	}

	// Configura il certificato e la chiave privata nel contesto SSL
	ret = mbedtls_ssl_conf_own_cert(&conf, &clicert, &pkey);
	if (ret != 0) {
		MQTT_INTERFACE_DEBUG_LOG(
				"[MQTT_INTERFACE] ERROR: mbedtls_ssl_conf_own_cert failed.\n");
		return -1;
	}

#endif
	// END

	ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
	MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret < 0) {
		MQTT_INTERFACE_DEBUG_LOG(
				"[MQTT_INTERFACE] ERROR: mbedtls_ssl_config_defaults failed.\n");
		return -1;
	}

	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);

#if FORCE_CRL_CHECK == 1
	mbedtls_ssl_conf_ca_chain(&conf, &cacert, &crl);
#else
	mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
#endif

	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

	// TLS V1.2
#if defined(TLS_1V2) && !defined(TLS_1V3)
	mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
	mbedtls_ssl_conf_max_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
#endif
	// TLS V1.3
#if !defined(TLS_1V2) && defined(TLS_1V3)
	mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3,
	MBEDTLS_SSL_MINOR_VERSION_4);
	mbedtls_ssl_conf_max_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3,
	MBEDTLS_SSL_MINOR_VERSION_4);
#endif

	ret = mbedtls_ssl_setup(&ssl, &conf);
	if (ret < 0) {
		MQTT_INTERFACE_DEBUG_LOG(
				"[MQTT_INTERFACE] ERROR: mbedtls_ssl_setup failed.\n");
		return -1;
	}

	ret = mbedtls_ssl_set_hostname(&ssl, BROKER_HOSTNAME); // if the handshake fails check here
	if (ret < 0) {
		MQTT_INTERFACE_DEBUG_LOG(
				"[MQTT_INTERFACE] ERROR: mbedtls_ssl_set_hostname failed.\n");
		return -1;
	}

	mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv,
	NULL);

	// register functions
	n->mqttread = mqtt_network_read; //receive function
	n->mqttwrite = mqtt_network_write; //send function
	n->disconnect = mqtt_network_disconnect; //disconnection function

	// Connect

	ret = mbedtls_net_connect(&server_fd, (const char*) ip, port,
	MBEDTLS_NET_PROTO_TCP);
	if (ret < 0) {
		MQTT_INTERFACE_DEBUG_LOG(
				"[MQTT_INTERFACE] ERROR: mbedtls_net_connect failed.\n");
		return -1;
	}

	while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ
				&& ret != MBEDTLS_ERR_SSL_WANT_WRITE) {

			if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
				printf("CRL Verification failed - Certificate Revoked!\n");
				printf("CRL verified in %lu us\n", crl_verify_us);
			}

			MQTT_INTERFACE_DEBUG_LOG(
					"[MQTT_INTERFACE] ERROR: mbedtls_ssl_handshake failed.\n");
			return -2;
		}
	}

	ret = mbedtls_ssl_get_verify_result(&ssl);
	if (ret < 0) {
		MQTT_INTERFACE_DEBUG_LOG(
				"[MQTT_INTERFACE] ERROR: mbedtls_ssl_get_verify_result failed.\n");
		return -1;
	}

	return 0;
}

int mqtt_network_read(Network *n, unsigned char *buffer, int len,
		int timeout_ms) {
	int ret;
	int received = 0;
	int error = 0;
	int complete = 0;

	//set timeout
	if (timeout_ms != 0) {
		mbedtls_ssl_conf_read_timeout(&conf, timeout_ms);
	}

	//read until received length is bigger than variable len
	do {
		ret = mbedtls_ssl_read(&ssl, buffer, len);
		if (ret > 0) {
			received += ret;
		} else if (ret != MBEDTLS_ERR_SSL_WANT_READ) {
			error = 1;
		}
		if (received >= len) {
			complete = 1;
		}
	} while (!error && !complete);

	return received;
}

int mqtt_network_write(Network *n, unsigned char *buffer, int len,
		int timeout_ms) {
	int ret;
	int written;

	//check all bytes are written
	for (written = 0; written < len; written += ret) {
		while ((ret = mbedtls_ssl_write(&ssl, buffer + written, len - written))
				<= 0) {
			if (ret != MBEDTLS_ERR_SSL_WANT_READ
					&& ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
				return ret;
			}
		}
	}

	return written;
}

void mqtt_network_disconnect(Network *n) {
	int ret;

	do {
		ret = mbedtls_ssl_close_notify(&ssl);
	} while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);

	mbedtls_ssl_session_reset(&ssl);
	mbedtls_net_free(&server_fd);
}

void mqtt_network_clear() {
	mbedtls_net_free(&server_fd);
	mbedtls_x509_crt_free(&cacert);
	mbedtls_x509_crt_free(&clicert);
	mbedtls_pk_free(&pkey);
	mbedtls_psa_crypto_free();
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
}

#endif
#ifdef MQTT_LWIP_NETCONN
void mqtt_network_init(Network *n) {
	n->conn = NULL;
	n->buf = NULL;
	n->offset = 0;

	n->mqttread = mqtt_network_read;
	n->mqttwrite = mqtt_network_write;
	n->disconnect = mqtt_network_disconnect;
}

int mqtt_network_connect(Network *n, char *ip, int port) {
	err_t err;
	ip_addr_t server_ip;

	ipaddr_aton(ip, &server_ip);

	n->conn = netconn_new(NETCONN_TCP);
	if (n->conn != NULL) {
		err = netconn_connect(n->conn, &server_ip, port);

		if (err != ERR_OK) {
			netconn_delete(n->conn); //free memory
			return -1;
		}
	}

	return 0;
}

int mqtt_network_read(Network *n, unsigned char *buffer, int len, int timeout_ms) {
	int rc;
	struct netbuf *inbuf;
	int offset = 0;
	int bytes = 0;

	while(bytes < len) {
		if(n->buf != NULL) {
			inbuf = n->buf;
			offset = n->offset;
			rc = ERR_OK;
		} else {
			rc = netconn_recv(n->conn, &inbuf);
			offset = 0;
		}

		if(rc != ERR_OK) {
			if(rc != ERR_TIMEOUT) {
				bytes = -1;
			}
			break;
		} else {
			int nblen = netbuf_len(inbuf) - offset;
			if((bytes+nblen) > len) {
				netbuf_copy_partial(inbuf, buffer+bytes, len-bytes,offset);
				n->buf = inbuf;
				n->offset = offset + len - bytes;
				bytes = len;
			} else {
				netbuf_copy_partial(inbuf, buffer+bytes, nblen, offset);
				bytes += nblen;
				netbuf_delete(inbuf);
				n->buf = NULL;
				n->offset = 0;
			}
		}
	}
	return bytes;
}

int mqtt_network_write(Network *n, unsigned char *buffer, int len, int timeout_ms) {
	int rc = netconn_write(n->conn, buffer, len, NETCONN_NOCOPY);
	if(rc != ERR_OK) return -1;
	return len;
}

void mqtt_network_disconnect(Network *n) {
	netconn_close(n->conn); //close session
	netconn_delete(n->conn); //free memory
	n->conn = NULL;
}
#endif

#ifdef MQTT_TASK
int ThreadStart(Thread* thread, void (*fn)(void*), void* arg)
{
	int rc = 0;
	uint16_t usTaskStackSize = (configMINIMAL_STACK_SIZE * 5);
	UBaseType_t uxTaskPriority = uxTaskPriorityGet(NULL); /* set the priority as the same as the calling task*/

	rc = xTaskCreate(fn,	/* The function that implements the task. */
		"MQTTTask",			/* Just a text name for the task to aid debugging. */
		usTaskStackSize,	/* The stack size is defined in FreeRTOSIPConfig.h. */
		arg,				/* The task parameter, not used in this case. */
		uxTaskPriority,		/* The priority assigned to the task is defined in FreeRTOSConfig.h. */
		&thread->task);		/* The task handle is not used. */

	return rc;
}


void MutexInit(Mutex* mutex)
{
	mutex->sem = xSemaphoreCreateMutex();
}

int MutexLock(Mutex* mutex)
{
	return xSemaphoreTake(mutex->sem, portMAX_DELAY);
}

int MutexUnlock(Mutex* mutex)
{
	return xSemaphoreGive(mutex->sem);
}
#endif

//Timer functions
char TimerIsExpired(Timer *timer) {
	long left = timer->end_time - MilliTimer;
	return (left < 0);
}

void TimerCountdownMS(Timer *timer, unsigned int timeout) {
	timer->end_time = MilliTimer + timeout;
}

void TimerCountdown(Timer *timer, unsigned int timeout) {
	timer->end_time = MilliTimer + (timeout * 1000);
}

int TimerLeftMS(Timer *timer) {
	long left = timer->end_time - MilliTimer;
	return (left < 0) ? 0 : left;
}

void TimerInit(Timer *timer) {
	timer->end_time = 0;
}

