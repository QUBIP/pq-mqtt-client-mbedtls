#include "../Inc/demo.h"

void start_demo_csic_se() {

	print_title_demo();

	int verb = 3;

	// --- Open Interface --- //
	INTF interface = 0;

	/*
	printf("\n\t ---- Test Evaluation --- ");
	printf("\n Configuration: ");
	printf("\n %-10s: ", "AES");
	printf("yes");

	printf("\n %-10s: ", "SHA3");
	printf("yes");

	printf("\n %-10s: ", "SHA2");
	printf("yes");

	printf("\n %-10s: ", "EdDSA");
	printf("yes");

	printf("\n %-10s: ", "ECDH");
	printf("yes");

	printf("\n %-10s: ", "MLKEM");
	printf("yes");

	printf("\n %-10s: ", "DRBG");
	printf("yes");

	printf("\n\n %-30s | Result ", "Algorithm");
	printf("\n %-30s | ------ ", "---------");

	demo_aes_hw(128, verb, interface);	// Security level: 128
	demo_aes_hw(192, verb, interface);	// Security level: 192
	demo_aes_hw(256, verb, interface);	// Security level: 256

	demo_sha3_hw(verb, interface);

	demo_sha2_hw(verb, interface);

	demo_eddsa_hw(25519, verb, interface);

	demo_x25519_hw(25519, verb, interface);

	demo_mlkem_hw(512, verb, interface);
	demo_mlkem_hw(768, verb, interface);
	//demo_mlkem_hw(1024, verb, interface);
	 */
	/*
	demo_trng_hw(128, verb, interface);
	demo_trng_hw(256, verb, interface);
	demo_trng_hw(512, verb, interface);
	demo_trng_hw(1024, verb, interface);
	demo_trng_hw(2048, verb, interface);
	 */
	demo_eddsa_hw(25519, verb, interface);
	printf("\n\n");

}
