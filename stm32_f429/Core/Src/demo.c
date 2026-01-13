#include "../Inc/demo.h"
#include "qubip.h"
#define ARRAY_SIZE_BYTES ( (unsigned int) 5 * 1024)
/*
 * NOT WORKING ADDRESSES
 * #define SPI_START_ADDR 0x200000
 * #define SPI_START_ADDR 0x100000
 *
 */

extern const char mbedtls_root_certificate[];
extern const size_t mbedtls_root_certificate_len;

extern const char client_cert[];
extern const size_t client_cert_len;

extern const char client_key[];
extern const size_t client_key_len;

extern const char mbedtls_crl[];
extern const size_t mbedtls_crl_len;

void write_certificates_to_spi() {

	print_title_demo();

	printf("CRL Size %d\n", mbedtls_crl_len);
	SPICert crl = { .cert_bytes = mbedtls_crl, .cert_len = mbedtls_crl_len,
			.cert_spi_addr = 0x7000, .key_len = 0 };
	save_cert_to_spi(&crl);
	printf("Done\n");
	/*
	 SPICert *crl_read_back = make_certificate(CRL);
	 load_cert_from_spi(crl_read_back, false, true);
	 */
	/*
	 SPICert *root_ca = make_certificate(ROOT_CA);
	 root_ca->cert_bytes = mbed;
	 root_ca->cert_len = 5871;

	 SPICert *client = make_certificate(CLIENT);
	 client->cert_bytes = client_cert;
	 client->cert_len = 6295;
	 client->key_bytes = client_key;
	 client->key_len = 5523;

	 save_cert_to_spi(root_ca);
	 save_cert_to_spi(client);

	 SPICert *root_ca_read_back = make_certificate(ROOT_CA);
	 SPICert *client_read_back = make_certificate(CLIENT);
	 load_cert_from_spi(root_ca_read_back, false, true);
	 load_cert_from_spi(client_read_back, true, true);
	 */
	printf("\n\n");

}
