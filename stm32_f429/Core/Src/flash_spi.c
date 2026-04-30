#include "qubip.h"
#include <stdio.h>
#include "intf.h"
#include "scp03/scp03.h"

/* MLDSA44 CERTIFICATES */
const char root_certificate_44[] = "-----BEGIN CERTIFICATE-----\r\n"
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
		"-----END CERTIFICATE-----\r\n";

const size_t root_certificate_44_len = sizeof(root_certificate_44);

const char client_cert_44[] = "-----BEGIN CERTIFICATE-----\r\n"
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
		"-----END CERTIFICATE-----\r\n"
;

const size_t client_cert_44_len = sizeof(client_cert_44);

const char client_44_key[] = "-----BEGIN PRIVATE KEY-----\r\n"
		"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\r\n"
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

	printf("Done!\n");

	while (1)
		;

}
