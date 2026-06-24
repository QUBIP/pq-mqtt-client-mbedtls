#include "qubip.h"
#include <stdio.h>
#include "intf.h"
#include "scp03/scp03.h"

/* MLDSA44 CERTIFICATES */
const char root_certificate_44[] = "-----BEGIN CERTIFICATE-----\r\n"
		"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\r\n"
		"-----END CERTIFICATE-----\r\n"
;

const size_t root_certificate_44_len = sizeof(root_certificate_44);

const char client_cert_44[] = "-----BEGIN CERTIFICATE-----\r\n"
		"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\r\n"
		"BQcDAjAdBgNVHQ4EFgQUA+LTCPqMkYd2Q3Zx0rO5yyJl1H0wHwYDVR0jBBgwFoAU\r\n"
		"tVCQCc6g0E86m9cntc/R6P29HYYwgbUGCCsGAQUFBwEBBIGoMIGlMFQGCCsGAQUF\r\n"
		"BzAChkhodHRwOi8vY2EuYWxsLnF1YmlwLmV1L3YyL2NlcnRzL3F1YmlwLWNhLWNs\r\n"
		"aWVudC1tY3UtZmI4MTg5NWIvY2VydGlmaWNhdGUwTQYIKwYBBQUHMAGGQWh0dHA6\r\n"
		"Ly9jYS5hbGwucXViaXAuZXUvdjIvY2VydHMvcXViaXAtY2EtY2xpZW50LW1jdS1m\r\n"
		"YjgxODk1Yi9vY3NwMFEGA1UdHwRKMEgwRqBEoEKGQGh0dHA6Ly9jYS5hbGwucXVi\r\n"
		"aXAuZXUvdjIvY2VydHMvcXViaXAtY2EtY2xpZW50LW1jdS1mYjgxODk1Yi9jcmww\r\n"
		"DAYDVR0RAQH/BAIwADAKBggrBgEFBQcGJwOCCbUAONpEDtjVm0pMTxm9x64czQd2\r\n"
		"ZnyROgKC9UyxuOOQGXvrfYIt9rpQlow+moO56jBl1FiOId2zcIk4DRjjdwdEye6W\r\n"
		"/MuLn8UCFniPNGjloS0+bEdS4CRwK3Zu3xWRj3C1esozVIA77yLP8abWGCdjsrI2\r\n"
		"g3UM2M7eiTtp2lh5bzOgT+TkoHVT5WaT6MIIaGiKlbQzj/4vzmMDkNX68l5wGyM7\r\n"
		"TK6A78Hmk3m8oKunqr0K0+uGOkz4r08MgRX9WJn8d5zSjEurEfvnTU8k4RKd+D4O\r\n"
		"IhsxYYfyLCjdhbZXF2I+u/ZDR9EaRBFDSeA4FEYmpG6VvaYylg1OdOn7ZvZehGk9\r\n"
		"XDwtBL8i45PWamfKyE+AosmGAFTqCOsHiO+HX4zmX5pIE3vPMx3jxN4zTJF/A97r\r\n"
		"y6YTTULw+L16PT13Z4H/jQ1IsLuB/KnSyhvY+82tw+OrCBGg3NvjnG7byeROTLV1\r\n"
		"fzMrHQ/nqymJBk0dNGF36mZ6VQutapPJeC12Ari0eDJiMkEaimRuG1ZZApLZBTHP\r\n"
		"KuPV0xCbZVSi+1DVig3tixOrakfL22Cui0SjAPOpvhMqWs5qa0XMPAXU+ZquCG8v\r\n"
		"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\r\n"
		"hqnVqeiFm5tbrktbUjJHNVEP\r\n"
		"-----END CERTIFICATE-----\r\n";

const size_t client_cert_44_len = sizeof(client_cert_44);

const char client_44_key[] = "-----BEGIN PRIVATE KEY-----\r\n"
		"MFMCAQAwCgYIKwYBBQUHBicEQoBAmwCMjExxiMbh3Xed0jiP32r3hfrK8yD1FkiY\r\n"
		"xS1oy0fEoi7OTh+L/Q6UFpEf+BoPtycNBiwcsbuBDddUz+Di1g==\r\n"
		"-----END PRIVATE KEY-----\r\n";

const size_t client_key_44_len = sizeof(client_44_key);

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

/* CLASSIC CERTIFICATES */

const char root_certificate_classic[] = "-----BEGIN CERTIFICATE-----\r\n"
"MIIBWTCCAQugAwIBAgIUduZv4RD2gXkOG6ee0OdqOTc6zPUwBQYDK2VwMCIxIDAe\r\n"
"BgNVBAMMF1NNQVJURkFDVE9SWS1DTEFTU0lDLUNBMB4XDTI2MDIxNjA4MTQ0NFoX\r\n"
"DTM2MDIxNDA4MTQ0NFowIjEgMB4GA1UEAwwXU01BUlRGQUNUT1JZLUNMQVNTSUMt\r\n"
"Q0EwKjAFBgMrZXADIQCi7VLC/mNr3rwXxuYOO2ygoF8cfIqy0dirA5/97e+v/qNT\r\n"
"MFEwHQYDVR0OBBYEFE6zifORurJ1t4LxDCvD8xiTKcymMB8GA1UdIwQYMBaAFE6z\r\n"
"ifORurJ1t4LxDCvD8xiTKcymMA8GA1UdEwEB/wQFMAMBAf8wBQYDK2VwA0EAcL41\r\n"
"RNfP8JfH6xpTBc3s93oWm3cW5KBJBZz+enLFCSQDSpDGfBww88osAKSvEkWYkfN/\r\n"
"im/sV7YLzrSkpZMeBw==\r\n"
"-----END CERTIFICATE-----\r\n";

const size_t root_certificate_classic_len = sizeof(root_certificate_classic);

const char client_cert_classic[] = "-----BEGIN CERTIFICATE-----\r\n"
"MIIBNTCB6KADAgECAhR4T486S/7pi02LcS0q0b7jPJY/EDAFBgMrZXAwIjEgMB4G\r\n"
"A1UEAwwXU01BUlRGQUNUT1JZLUNMQVNTSUMtQ0EwHhcNMjYwMjE2MDkyNjM4WhcN\r\n"
"MjcwMjE2MDkyNjM4WjAQMQ4wDAYDVQQDDAVtY3UwMTAqMAUGAytlcAMhABHHtgOl\r\n"
"KZWXb3GA6z5u6znQ6feVIoPW/SzuYxLjrzX8o0IwQDAdBgNVHQ4EFgQUxJC34N/z\r\n"
"A3oUWNSq6tSbpYOnveMwHwYDVR0jBBgwFoAUTrOJ85G6snW3gvEMK8PzGJMpzKYw\r\n"
"BQYDK2VwA0EASpoad1w506PorRhpodsBAU5NA3w7lTaoDOvLLfLoB89PgcFfyLCk\r\n"
"le68FRkqc0AYAYgjhudTWffqEVmIq5TOBA==\r\n"
"-----END CERTIFICATE-----\r\n";

const size_t client_cert_classic_len = sizeof(client_cert_classic);

const char client_key_classic[] = "-----BEGIN PRIVATE KEY-----\r\n"
"MC4CAQAwBQYDK2VwBCIEII6los10uQa6AkeczxIlxoQyWbWuCOHqxqBAvyOkcEFS\r\n"
"-----END PRIVATE KEY-----\r\n";

const size_t client_key_classic_len = sizeof(client_key_classic);

const char crl_classic[] = "-----BEGIN X509 CRL-----\r\n" \
"MIHTMIGGAgEBMAUGAytlcDAiMSAwHgYDVQQDDBdTTUFSVEZBQ1RPUlktQ0xBU1NJ\r\n" \
"Qy1DQRcNMjYwMzI2MTMxOTI1WhcNMjYwNDI1MTMxOTI1WjAnMCUCFHhPjzpL/umL\r\n" \
"TYtxLSrRvuM8lj8PFw0yNjAzMjYxMzE5MjVaoA8wDTALBgNVHRQEBAICEAAwBQYD\r\n" \
"K2VwA0EAetbOtCmrDJu0sw1jpgjXsmhxIuVTe6jTEUmIwpnyJjJvY0sA38M+qK5t\r\n" \
"ff/b57Af37BPzcmWhkDleKdBAOclAQ==\r\n" \
"-----END X509 CRL-----\r\n";
const size_t crl_classic_len = sizeof(crl_classic);

void write_certificates_to_spi() {
	printf("Writing CLASSIC and MLDSA44 Certificates to SPI FLASH\n");

	printf("Setting UP SCP03 protected channel\n");
	open_INTF((INTF*) NULL, 0, 0);
	printf("SCP03 protected channel OK\n\n");

	printf(
			"CLIENT CERT 44: %d bytes SPI ADDR: 0x%x, KEY: %d bytes ROOT CA: %d\n",
			client_cert_44_len, CLIENT_CERT_44_SPI_ADDR, client_key_44_len,
			root_certificate_44_len);

	SPICert client44 = { .cert_bytes = client_cert_44, .cert_len =
			client_cert_44_len, .cert_spi_addr = CLIENT_CERT_44_SPI_ADDR,
			.key_len = client_key_44_len, .key_bytes = client_44_key,
			.key_spi_addr = CLIENT_KEY_44_SPI_ADDR, .name = "MLDSA44" };
	save_cert_to_spi(&client44);

	SPICert root44 = { .cert_bytes = root_certificate_44, .cert_len =
			root_certificate_44_len, .cert_spi_addr = ROOT_CA_CERT_44_SPI_ADDR,
			.key_len = 0, .name = "CA_MLDSA44" };
	save_cert_to_spi(&root44);


	SPICert crl = { .cert_bytes = mbedtls_crl, .cert_len = mbedtls_crl_len,
			.cert_spi_addr = CRL_CERT_44_SPI_ADDR, .key_len = 0, .name = "CRL_MLDSA44" };
	save_cert_to_spi(&crl);
/*
	printf(
			"CLIENT CERT CLASSIC: %d bytes SPI ADDR: 0x%x, KEY: %d bytes ROOT CA: %d\n",
			client_cert_classic_len, CLIENT_CERT_CLASSIC_SPI_ADDR,
			client_key_classic_len, root_certificate_classic_len);

	SPICert clientClassic = { .cert_bytes = client_cert_classic, .cert_len =
			client_cert_classic_len, .cert_spi_addr =
	CLIENT_CERT_CLASSIC_SPI_ADDR, .key_len = client_key_classic_len,
			.key_bytes = client_key_classic, .key_spi_addr =
			CLIENT_KEY_CLASSIC_SPI_ADDR, .name = "CLASSIC" };
	save_cert_to_spi(&clientClassic);

	SPICert rootClassic = { .cert_bytes = root_certificate_classic, .cert_len =
			root_certificate_classic_len, .cert_spi_addr =
	ROOT_CA_CLASSIC_CERT_SPI_ADDR, .key_len = 0, .name = "CA_CLASSIC" };
	save_cert_to_spi(&rootClassic);

	SPICert crlClassic = { .cert_bytes = crl_classic, .cert_len = crl_classic_len,
				.cert_spi_addr = CRL_CERT_CLASSIC_SPI_ADDR, .key_len = 0, .name = "CRL_CLASSIC" };
		save_cert_to_spi(&crlClassic);
*/
	printf("Done!\n");

	while (1)
		;

}
