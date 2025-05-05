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

#include "mbedtls/qubip.h"

#include "mbedtls/eddsa.h" //DAVIDE: TEST SIGNATURE WITH KEY
#include "mbedtls/psa_util.h"
#include "pk_wrap.h"

uint32_t MilliTimer;

#ifdef MQTT_LWIP_SOCKET_TLS
mbedtls_net_context server_fd;
const char *pers = "mbedtls";

mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_ssl_context ssl;
mbedtls_ssl_config conf;
mbedtls_x509_crt cacert;
mbedtls_x509_crt clicert;
mbedtls_pk_context pkey;
#endif

#ifdef CERTS_CLASSIC
const char mbedtls_root_certificate[] =
	"-----BEGIN CERTIFICATE-----\r\n"
"MIIBwTCCAXOgAwIBAgIUbgQY6Rpt26pZ+MYlBMtF4lGaeMkwBQYDK2VwMFYxCzAJ\r\n"
"BgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5l\r\n"
"dCBXaWRnaXRzIFB0eSBMdGQxDzANBgNVBAMMBlRFU1RDQTAeFw0yNDA5MjcxMjM3\r\n"
"NTFaFw0zNDA5MjUxMjM3NTFaMFYxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21l\r\n"
"LVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxDzANBgNV\r\n"
"BAMMBlRFU1RDQTAqMAUGAytlcAMhAMDXLhb6KLllMI+Y8rFniDDKCETPwoDmxqUb\r\n"
"Z0qUWz4Uo1MwUTAdBgNVHQ4EFgQUzXcyEKGEnqslVrDt11E0g//t4s0wHwYDVR0j\r\n"
"BBgwFoAUzXcyEKGEnqslVrDt11E0g//t4s0wDwYDVR0TAQH/BAUwAwEB/zAFBgMr\r\n"
"ZXADQQDH+r4zWG9jloZnP22fIPzihvwyqVyzQqsL6X46KYkNR0VRJ1ITs3at3etc\r\n"
"eAvrbiDenKJb5YfQV6ul1KGuPTAC\r\n"
"-----END CERTIFICATE-----\r\n";

const size_t mbedtls_root_certificate_len = sizeof(mbedtls_root_certificate);


const char client_cert[] =
	"-----BEGIN CERTIFICATE-----\r\n"
"MIIBZjCCARgCFCqeMuJic+LcAiPxEW1F4CbgTXAzMAUGAytlcDBWMQswCQYDVQQG\r\n"
"EwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lk\r\n"
"Z2l0cyBQdHkgTHRkMQ8wDQYDVQQDDAZURVNUQ0EwHhcNMjUwMzE5MDgxNjQ5WhcN\r\n"
"MzUwMzE3MDgxNjQ5WjBVMQswCQYDVQQGEwJJVDETMBEGA1UECAwKU29tZS1TdGF0\r\n"
"ZTEZMBcGA1UECgwQU2VjdXJpdHkgUGF0dGVybjEWMBQGA1UEAwwNc2VjcGF0LWNs\r\n"
"aWVudDAqMAUGAytlcAMhAK6bJJLXcB8JpfdUgN23vAoMLvHxyeGkJNB3RmYz2FGT\r\n"
"MAUGAytlcANBAM/kLJdedAzUPmDTgFviis10CR7F2qjM8Ks+XUyig8VMvYNOqcWm\r\n"
"YmeFehNlQly/cYC3szQzXL+7xLQ2o0EuOA4=\r\n"
"-----END CERTIFICATE-----\r\n";

const size_t client_cert_len = sizeof(client_cert);


const char client_key[] =
-----BEGIN PRIVATE KEY-----\r\n"
MC4CAQAwBQYDK2VwBCIEIFw25wrDf6ammAOqv1+TOCPxnHxmg4R53dBJ260wcyvL\r\n"
-----END PRIVATE KEY-----\r\n";

const size_t client_key_len = sizeof(client_key);
#else
#ifdef CERTS_PQ_65
const char mbedtls_root_certificate[] =
		"-----BEGIN CERTIFICATE-----\r\n"
		"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\r\n"
		"eVHHTYc1jS1lUSUM\r\n"
		"-----END CERTIFICATE-----\r\n";


const size_t mbedtls_root_certificate_len = sizeof(mbedtls_root_certificate);


const char client_cert[] =
		"-----BEGIN CERTIFICATE-----\r\n"
		"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\r\n"
		"-----END CERTIFICATE-----\r\n";



const size_t client_cert_len = sizeof(client_cert);


const char client_key[] =
		"-----BEGIN PRIVATE KEY-----\r\n"
		"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\r\n"
		"-----END PRIVATE KEY-----\r\n";



const size_t client_key_len = sizeof(client_key);
#else
#ifdef CERTS_PQ_44
const char mbedtls_root_certificate[] =
		"-----BEGIN CERTIFICATE-----\r\n"
		"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\r\n"
		"z6wL\r\n"
		"-----END CERTIFICATE-----\r\n"
;

const size_t mbedtls_root_certificate_len = sizeof(mbedtls_root_certificate);

const char client_cert[] = "-----BEGIN CERTIFICATE-----\r\n"
		"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\r\n"
		"AQUFBwMCMB0GA1UdDgQWBBQN43p6ng2WKSfHVLMUoG++lfWvcTAfBgNVHSMEGDAW\r\n"
		"gBRgbQTTcyXwsMSOiELzMFXlyRHGRzCBxQYIKwYBBQUHAQEEgbgwgbUwWAYIKwYB\r\n"
		"BQUHMAKGTGh0dHA6Ly9jYS5hbGwucXViaXAuZXUvZG93bmxvYWRfY2FfY2VydGlm\r\n"
		"aWNhdGUvcXViaXAtbWN1LWNhL3F1YmlwLW1jdS1jYS5jZXIwWQYIKwYBBQUHMAGG\r\n"
		"TWh0dHA6Ly9jYS5hbGwucXViaXAuZXUvZG93bmxvYWRfY2FfY2VydGlmaWNhdGUv\r\n"
		"cXViaXAtbWN1LWNhL3F1YmlwLW1jdS1jYS5vY3NwMF0GA1UdHwRWMFQwUqBQoE6G\r\n"
		"TGh0dHA6Ly9jYS5hbGwucXViaXAuZXUvZG93bmxvYWRfY2FfY2VydGlmaWNhdGUv\r\n"
		"cXViaXAtbWN1LWNhL3F1YmlwLW1jdS1jYS5jcmwwEwYDVR0RAQH/BAkwB4IFU1RN\r\n"
		"MzIwDQYLYIZIAYb6a1AIAQMDggnBADCCCbwDggl1ADVPwzoFbg0r/1kR/kcScD/D\r\n"
		"47vpZ2fRIjt+HPTzTcogaD1feCsxpJ41/pEG4sllKt1CvP8cfeq5AFMGuw7un7v9\r\n"
		"s5ZMkkxMaA9SepW+XimSMghNu++LHjcIR9e1yXqbKFt8TnJI7QiUBSXVXVboj6aW\r\n"
		"Gg6VvvUY8Vem0OAJY9bQFn3U5UMQlZ9GQuWImbDYd4BgtiO5sGA72cNUWDSxIUAb\r\n"
		"GPJwGk4MfC+VdEla1M5ZoDd0ckX6VrBcldBqYJAtHHuesczV+1Fq2ERtOhyNB47e\r\n"
		"8kT2Tfb+evhxyAZGsxhtT12OZM4y5EDMXB86BOjRMAGLlUV82XRUd09C8+sDHkoB\r\n"
		"y6m8yUL7znO2tF6pl/9V6lrfuFmuKPPEVytcqWHCpzR241s3Mmbu5nJFEjxhU3h+\r\n"
		"OTJCiBDkK7iH6XdvIwefTGihDYJVfQXuih3urP1WMjbnB6CNkCwChfva5iDSrxKG\r\n"
		"L9LNkOHB50v+Ju7dtChYKsHNnuEYG6FFTm5qLWq57W84cVtV7aWiOhG0nL6RPsC1\r\n"
		"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\r\n"
		"8ZXHelMwJcbs+IBtOC4pYLT98PB8CA==\r\n"
		"-----END CERTIFICATE-----\r\n";

const size_t client_cert_len = sizeof(client_cert);

const char client_key[] = "-----BEGIN PRIVATE KEY-----\r\n"
		"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\r\n"
		"-----END PRIVATE KEY-----\r\n"
;

const size_t client_key_len = sizeof(client_key);
#else
const char mbedtls_root_certificate[] =
		"-----BEGIN CERTIFICATE-----\r\n"
		"MIIDjTCCAnWgAwIBAgIUVIJWJNIQHlL6XqX0l+zWk0cRqtEwDQYJKoZIhvcNAQEL\r\n"
		"BQAwVjELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\r\n"
		"GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEPMA0GA1UEAwwGQ0FURVNUMB4XDTI0\r\n"
		"MDkyNDEyNDY0NVoXDTM0MDkyMjEyNDY0NVowVjELMAkGA1UEBhMCQVUxEzARBgNV\r\n"
		"BAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0\r\n"
		"ZDEPMA0GA1UEAwwGQ0FURVNUMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\r\n"
		"AQEAvIHZY2+eTmRmIbAEM4XqAOKR2ih6Mqczp6t4tMpo6tp/GDMjwMLIlYmUPP+h\r\n"
		"94cEArLA37rGU2TS4QwcStcA9FGbUhZVem5rsqY+GiYDic0ORkqe6JDu0CmQdjlH\r\n"
		"H7ZpTpf9kuuD99sMuqVWe83WljNR7aVZyJMNVgVhk5ERdmcLRM7r+rNokZYWNf55\r\n"
		"eH4QVdtfy4/0ah6Xe36wDRT73sjRxImb6ntxYqB5KcVb7xwYzyrQNAaP9yAuQRgk\r\n"
		"BbTM9kFgihW+SMEkVM0hphbcsH+fxn0+jTAeDEcHe2GXYc6IZyg7RQLi9ISjAx8l\r\n"
		"v8djIjzFhyRQiCQ8yQubKjUX7QIDAQABo1MwUTAdBgNVHQ4EFgQU1NQAg5Mk/2hD\r\n"
		"aT3B+M3X/Z1F1rMwHwYDVR0jBBgwFoAU1NQAg5Mk/2hDaT3B+M3X/Z1F1rMwDwYD\r\n"
		"VR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAKpdqCgY7BxrgVAr/SR2F\r\n"
		"YBDZ+tLURNi/MZ0zENdLSW/Jwj+A/ZD9brpEVdNoUyZYXpnmjTBXC+PIj+J+l817\r\n"
		"yFPKb3fE7sB0X/OGZtgPu4ABWinup1VfqHCVHc4JKWE1qIw5CENeN1JMcVRGk8iD\r\n"
		"9ReWNltsUwZ26pKoPi7z97gtLMeM3t/9qJL7CwAOnxuuzSAtILcnksbH10Y9r56g\r\n"
		"wzBqWpvZ07LHmDUyxd/V9lvEDf2QSXHPTk3sBntXDw1TS41sfyAca5G/JVYVv4hA\r\n"
		"IA4RY7scIv5oAd3oooTe+82gWvoGLEdZ0Fb/qSvQtDSbJA2WP++RsGHSGHoLDjhj\r\n"
		"Iw==\r\n"
		"-----END CERTIFICATE-----\r\n";

const size_t mbedtls_root_certificate_len = sizeof(mbedtls_root_certificate);


const char client_cert[] =
		"-----BEGIN CERTIFICATE-----\r\n"
		"MIIDOTCCAiECFCTEBUjF19b1rMmdYDT8H2dxif3tMA0GCSqGSIb3DQEBCwUAMFYx\r\n"
		"CzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl\r\n"
		"cm5ldCBXaWRnaXRzIFB0eSBMdGQxDzANBgNVBAMMBkNBVEVTVDAeFw0yNDA5MjQx\r\n"
		"MjUwNDNaFw0zNDA5MjIxMjUwNDNaMFwxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApT\r\n"
		"b21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxFTAT\r\n"
		"BgNVBAMMDDE5Mi4xNjguMC41MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\r\n"
		"ggEBALuR+dmS0u7QH16O8uZkcvojbJpuuO3PsWx5hCUCPqS9FFjFv1Z2ZovC80XJ\r\n"
		"X/LI1b/te6qZ3Hfs7ZBdWWHhxrw77PJpcnlvU3k96juaB+QXc3ppl8d7ou6ZGGmf\r\n"
		"d3Dq+Rj94Bk5bL98n0gWjSXFLcKkRav7o5MzYw9xCkqEx5Q1eM8pPZB+LMAdK20f\r\n"
		"6rswiuT6o6VAM7BJnm2R6OwrRXf70Mpm/MGu2wmskWrEbAHB93hY7aIMzWVmvv92\r\n"
		"iujwgRJhSjqbyl7tasUNYKvY66qisg29WhpU7np9aUbQtor2jS50VNFD14V6MLzp\r\n"
		"Mw4RQRkD0Qwds1lr9xDZqscNMnECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAObPk\r\n"
		"vv1nlYXgg614s+wIVv/MTw0oNh/CmTtGavLtn6ML+sEiWp+hAkeqzFXOo4jYiM/V\r\n"
		"2bzfdc734ViH5HGACDf70J+Aq3rHcsqrXH0jSN0EfNDWKgjtTTfQjmTxJJ8lqiKH\r\n"
		"ePznASK537WRYJLOp7u0OtyJft4QyDAB+xUXvUD9O+c0hopeicr58Bz6zzK/WQtE\r\n"
		"lEUiZKQgz5bMeS/mGp/dJyPvpHUHlgq4WIs6OxXqoP5C+8kC1GEgfOHN7qFsw9yU\r\n"
		"nIu3cpTZstpBWMDTIgG+tE2bQ34prMAyAhN38pUMF8anTKIzIMAmA4ndu53nO3mm\r\n"
		"vkwvLeOvkqJDYfb5TQ==\r\n"
		"-----END CERTIFICATE-----\r\n";

const size_t client_cert_len = sizeof(client_cert);


const char client_key[] =
		"-----BEGIN PRIVATE KEY-----\r\n"
		"MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7kfnZktLu0B9e\r\n"
		"jvLmZHL6I2yabrjtz7FseYQlAj6kvRRYxb9WdmaLwvNFyV/yyNW/7Xuqmdx37O2Q\r\n"
		"XVlh4ca8O+zyaXJ5b1N5Peo7mgfkF3N6aZfHe6LumRhpn3dw6vkY/eAZOWy/fJ9I\r\n"
		"Fo0lxS3CpEWr+6OTM2MPcQpKhMeUNXjPKT2QfizAHSttH+q7MIrk+qOlQDOwSZ5t\r\n"
		"kejsK0V3+9DKZvzBrtsJrJFqxGwBwfd4WO2iDM1lZr7/doro8IESYUo6m8pe7WrF\r\n"
		"DWCr2OuqorINvVoaVO56fWlG0LaK9o0udFTRQ9eFejC86TMOEUEZA9EMHbNZa/cQ\r\n"
		"2arHDTJxAgMBAAECggEAT6BlNjmvxQTiRESgFjFvZAQUzyyQ4hfpBJlDgWiGCm5g\r\n"
		"TF1KYFysJMnSd35I9qrOnwckmCRwJRMWONKAJt7vfKpd6PzdxXJ+t7oSjVHS5sAT\r\n"
		"3FQmRF+Wp/6jD/fL/0opDDR+ZYbsxQ+VGMfGDNI7nmUZVKzjYJKQi5Yb3c2nYiFl\r\n"
		"Bebm1BURtNZChXHw3mTc/46Jzfm+rN2BYp+TPEkYjTU/TuWFYMQNLSalNZNLqAYz\r\n"
		"CF9SRVsiglGq1dYJFqqMGwvszqc+f7kHjHhKXoqLp79tInS03wHaHlGlVtze/iMS\r\n"
		"q7czzbqTxK3XDmbDG0i6Byt0LieleQY5t5LXRCApXwKBgQDb/KflWpiiI6gD7TYA\r\n"
		"kCjWNcYzpPth12duPDBNW12azqtISy9V/Se4It3114jsfe43MyzQOV9cct9TeDNo\r\n"
		"RR9ErsdQSoy4iBWy4sSApc7PkMqvc+K2/y3Vv1kAy84atdQCjGzr9HYnWY4uEXKf\r\n"
		"129qfapR0jGhoMW1ubiS7oPZQwKBgQDaRsfp2i+iTlGT85KSL0ieb5Si01QCkXbd\r\n"
		"Mtlq1e+ZRuR05Xm0464ljerd6oEQZP1WN6uh/e57vb4sF9QWZmjlu6Cjul4XReU/\r\n"
		"IxQg/hExcPCjnDc4Q+nTwBJhgqG30/5LPuERFKc2STIPNY+sD8oddZ+gsh5ZiG+u\r\n"
		"9IxcfntgOwKBgQDMQezWzWbZbYgMlU1F+pSgSO/OdgqfTzUPKr2ipgnkuq5ZAs5h\r\n"
		"5hviIiW7pbPR+h+ci1y5vfuoSFTKGNqKn1uoFyyjhYThtiGHpnzUAqBjI8q+XDiO\r\n"
		"t6MkS3XlglbNgDTpZN+huquWX9XfOn4Woh8mXqYtMKC6tR++W0Jg0ywDJwKBgQCp\r\n"
		"OUDaG27cnW1/j9Hthbz+IDGS/tXd29rUaQzIWC4WnjCWNCZkSDQGJ32UKK+A/1qt\r\n"
		"EiH9R/oxcwxR8PNbnm/q08kZxm4WCvlNNqvvXCoGM7JMldr1wykwInPdp0IrW66F\r\n"
		"ta0V6fYtDxhBVFwboG4o4r0r/4uqDC3R7QQ43VJXawKBgQDB9AqAReySz182S9DT\r\n"
		"0Pq3DH4i8MwYt+NOoEBDRDG6L7as3ZEj+Jdr3FvwLw8Lf2/+/tzJSC/tRQNhBVs2\r\n"
		"fQmqbwGx0c7wJxIIJMj/cLGaWUVkkTuVTC9OPvbxvqnfgZs7YDDrizlBkZ150Jjw\r\n"
		"QCq+0v5gC0Sqz8qtDdID2sIfGg==\r\n"
		"-----END PRIVATE KEY-----\r\n";

const size_t client_key_len = sizeof(client_key);
#endif
#endif
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
	mbedtls_debug_set_threshold(99);
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

	// Processi SSL/TLS
	ret = mbedtls_x509_crt_parse(&cacert,
			(const unsigned char*) mbedtls_root_certificate,
			mbedtls_root_certificate_len);
	if (ret < 0) {
		MQTT_INTERFACE_DEBUG_LOG(
				"[MQTT_INTERFACE] INFO: Root certificate is %d bytes long. Certificate is:\n %s\n",
				mbedtls_root_certificate_len, mbedtls_root_certificate);
		MQTT_INTERFACE_DEBUG_LOG(
				"[MQTT_INTERFACE] ERROR: mbedtls_x509_crt_parse failed for root certificate.\n");
		return -1;
	}

	// START
	// TLS V1.3
#if !defined(TLS_1V2) && defined(TLS_1V3)
	ret = mbedtls_x509_crt_parse(&clicert, (const unsigned char*) client_cert,
			client_cert_len);
	if (ret != 0) {
		MQTT_INTERFACE_DEBUG_LOG(
				"[MQTT_INTERFACE] ERROR: mbedtls_x509_crt_parse failed for client certificate\n");
		return -1;
	}

	// Aggiungi caricamento della chiave cliente
	ret = mbedtls_pk_parse_key(&pkey, (const unsigned char*) client_key,
			client_key_len, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
	if (ret != 0) {
		MQTT_INTERFACE_DEBUG_LOG(
				"[MQTT_INTERFACE] ERROR: mbedtls_pk_parse_key failed.\n");
		return -1;
	}
	//DAVIDE Extract public from client cert: Not a perfect solution but as of now we don't have a way to derive the public from the private
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
	mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
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

	ret = mbedtls_ssl_set_hostname(&ssl, BROKER_HOSTNAME); // if the handshake fail check here
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

