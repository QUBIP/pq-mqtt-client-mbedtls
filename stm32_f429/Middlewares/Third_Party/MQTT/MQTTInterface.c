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
		"MIIBWTCCAQugAwIBAgIUduZv4RD2gXkOG6ee0OdqOTc6zPUwBQYDK2VwMCIxIDAe\r\n"
		"BgNVBAMMF1NNQVJURkFDVE9SWS1DTEFTU0lDLUNBMB4XDTI2MDIxNjA4MTQ0NFoX\r\n"
		"DTM2MDIxNDA4MTQ0NFowIjEgMB4GA1UEAwwXU01BUlRGQUNUT1JZLUNMQVNTSUMt\r\n"
		"Q0EwKjAFBgMrZXADIQCi7VLC/mNr3rwXxuYOO2ygoF8cfIqy0dirA5/97e+v/qNT\r\n"
		"MFEwHQYDVR0OBBYEFE6zifORurJ1t4LxDCvD8xiTKcymMB8GA1UdIwQYMBaAFE6z\r\n"
		"ifORurJ1t4LxDCvD8xiTKcymMA8GA1UdEwEB/wQFMAMBAf8wBQYDK2VwA0EAcL41\r\n"
		"RNfP8JfH6xpTBc3s93oWm3cW5KBJBZz+enLFCSQDSpDGfBww88osAKSvEkWYkfN/\r\n"
		"im/sV7YLzrSkpZMeBw==\r\n"
		"-----END CERTIFICATE-----\r\n";

const size_t mbedtls_root_certificate_len = sizeof(mbedtls_root_certificate);


const char client_cert[] =
		"-----BEGIN CERTIFICATE-----\r\n"
		"MIIBNTCB6KADAgECAhR4T486S/7pi02LcS0q0b7jPJY/EDAFBgMrZXAwIjEgMB4G\r\n"
		"A1UEAwwXU01BUlRGQUNUT1JZLUNMQVNTSUMtQ0EwHhcNMjYwMjE2MDkyNjM4WhcN\r\n"
		"MjcwMjE2MDkyNjM4WjAQMQ4wDAYDVQQDDAVtY3UwMTAqMAUGAytlcAMhABHHtgOl\r\n"
		"KZWXb3GA6z5u6znQ6feVIoPW/SzuYxLjrzX8o0IwQDAdBgNVHQ4EFgQUxJC34N/z\r\n"
		"A3oUWNSq6tSbpYOnveMwHwYDVR0jBBgwFoAUTrOJ85G6snW3gvEMK8PzGJMpzKYw\r\n"
		"BQYDK2VwA0EASpoad1w506PorRhpodsBAU5NA3w7lTaoDOvLLfLoB89PgcFfyLCk\r\n"
		"le68FRkqc0AYAYgjhudTWffqEVmIq5TOBA==\r\n"
		"-----END CERTIFICATE-----\r\n";

const size_t client_cert_len = sizeof(client_cert);


const char client_key[] = "-----BEGIN PRIVATE KEY-----\r\n"
		"MC4CAQAwBQYDK2VwBCIEII6los10uQa6AkeczxIlxoQyWbWuCOHqxqBAvyOkcEFS\r\n"
		"-----END PRIVATE KEY-----\r\n";

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
				"AQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUl473OE2GhyoJbtPyMC1cAsqs\r\n"
				"f4kwHwYDVR0jBBgwFoAUl473OE2GhyoJbtPyMC1cAsqsf4kwgZMGCCsGAQUFBwEB\r\n"
				"BIGGMIGDMEMGCCsGAQUFBzAChjdodHRwOi8vY2EuYWxsLnF1YmlwLmV1L3BraS00\r\n"
				"NC9xdWJpcC1yb290LWNhL2NlcnRpZmljYXRlMDwGCCsGAQUFBzABhjBodHRwOi8v\r\n"
				"Y2EuYWxsLnF1YmlwLmV1L3BraS00NC9xdWJpcC1yb290LWNhL29jc3AwQAYDVR0f\r\n"
				"BDkwNzA1oDOgMYYvaHR0cDovL2NhLmFsbC5xdWJpcC5ldS9wa2ktNDQvcXViaXAt\r\n"
				"cm9vdC1jYS9jcmwwEQYDVR0gBAowCDAGBgRVHSAAMA0GC2CGSAGG+mtQCAEDA4IJ\r\n"
				"wQAwggm8A4IJdQAKfz9hHrzfGqtjdKx6FK3mmLaM335tinMAYgQnGAaf1Hi0HNAi\r\n"
				"1sYlH/JfsvzJB1he763Eqk/kkrMmi8zOnZ5gfPuyjHszwc6yEX/bnEIfAMexNIT1\r\n"
				"QD2xO1UMBrKSRUuXGU4IfaOFvqMx673+Stx3d/ZdB7lKxorcWEleW0MGNHWLRCiP\r\n"
				"rPkaAB2bjIplPNRhcEJ7fKpvT8OwpUjf1cA60zObeTI+fQSJj5VCuEB0Q0uBbOHN\r\n"
				"e7jfW+sM0yHfw0YJYSfwu7tBugUQwbjzIrLVVGKLK8QZ6jvpx+8KgATj4MyGqf10\r\n"
				"24vnx2Lbj4d3ce4aQBHfdacUm5jJDOhNQk/+9VQUx+DjKosOz4KlkzQx1cJSBDpZ\r\n"
				"3sP1IUcYCi9WCxO9NNuxDyN6NL3CKGaO/NT9zQSpggoOlSMTNOkozu7ddC88Gl4+\r\n"
				"nj8eS51oXg5ECPQpzoZ61V1Uh48wWMgC2cGmOmXi4WZ9RyM8FKs95ZWPNuBD3yBR\r\n"
				"7MPtL7RoqGJPRcppfrlPJ/DwQ5ay0p8hG1weS4n0ivk/vy68tZafXWQC4fvQMRIQ\r\n"
				"4JbVL5CVYHhlnEFsNDG64sHMm0AbVw6irJdXOvlMMGnAEagDUzFci0uzP3U5U4e3\r\n"
				"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\r\n"
				"cwU=\r\n"
				"-----END CERTIFICATE-----\r\n"
;

const size_t mbedtls_root_certificate_len = sizeof(mbedtls_root_certificate);

const char client_cert[] = "-----BEGIN CERTIFICATE-----\r\n"
		"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\r\n"
		"BgNVHSUEDDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUrffgfj2/tdeWJpvgVVhLkbJi\r\n"
		"X8YwHwYDVR0jBBgwFoAUURl29GFVimaXTFJt/gC1TnTgDFswgZEGCCsGAQUFBwEB\r\n"
		"BIGEMIGBMEIGCCsGAQUFBzAChjZodHRwOi8vY2EuYWxsLnF1YmlwLmV1L3BraS00\r\n"
		"NC9xdWJpcC1tY3UtY2EvY2VydGlmaWNhdGUwOwYIKwYBBQUHMAGGL2h0dHA6Ly9j\r\n"
		"YS5hbGwucXViaXAuZXUvcGtpLTQ0L3F1YmlwLW1jdS1jYS9vY3NwMD8GA1UdHwQ4\r\n"
		"MDYwNKAyoDCGLmh0dHA6Ly9jYS5hbGwucXViaXAuZXUvcGtpLTQ0L3F1YmlwLW1j\r\n"
		"dS1jYS9jcmwwIAYDVR0RAQH/BBYwFIISYnJva2VyLmRtLnF1YmlwLmV1MA0GC2CG\r\n"
		"SAGG+mtQCAEDA4IJwQAwggm8A4IJdQA4jCsv9QsbqD8j0CBTR+mrpBcv9RVkn4qx\r\n"
		"R4UKjhuHNUOfW/QYdTq/NL/tvhvIDxeYoISYk2SeoSfJa/k7Sz5b6Bek+6hI1E6E\r\n"
		"8D7qwEqSJvId0J27K0QQfhc/2QDk4qxP8sOn1AsgruvMVP63GGpF/15ffDXRewRj\r\n"
		"zlOUnoxUrGRlnq/CAM4sn/PxivzhtzITY01WaDZ3vKo+NYDDUqhe+RG+i+LdUa5i\r\n"
		"p2R3JVXClgS7bXuaM3ByQ4/QetPKWdkntFiRFcckGwxQEWXyGLp/tR5UUo4TxE0u\r\n"
		"7+bv1r3IBZ/hdbhzK7XH6tgiW8qFB7oVUDGIPHJZl+U7lwVMs1/g14B4HqbZxcsA\r\n"
		"nJSA4tLoXzbRlxw47lAcm+kYRLIOkicDg0FzK0YtRKHD+tlRoUcr2bXjplhsslYB\r\n"
		"EcclyhnTLmbTXtSvYqNGyhGe8YwOfWmWihmvQEGCTZSKKQ3SnyG4Xp+RdzC2csdg\r\n"
		"cQjjKemNfW2LXLDrAQXkqj9/38CRgn/taDvnP7XKFF6Y+FV52dJxEXH7sl0GvsHl\r\n"
		"c+G2OIVsE764uGHRrzHB8Gu9wsiZE+nt8XZczzbasvhqV66ewKeGHwJ4GkBxIwVs\r\n"
		"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\r\n"
		"xw98yQk8/OyuVZ1ZVws=\r\n"
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

