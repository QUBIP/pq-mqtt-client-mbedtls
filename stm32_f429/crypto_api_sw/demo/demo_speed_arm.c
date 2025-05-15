/**
  * @file demo_speed.c
  * @brief Performance Test code
  *
  * @section License
  *
  * MIT License
  *
  * Copyright (c) 2024 Eros Camacho
  *
  * Permission is hereby granted, free of charge, to any person obtaining a copy
  * of this software and associated documentation files (the "Software"), to deal
  * in the Software without restriction, including without limitation the rights
  * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  * copies of the Software, and to permit persons to whom the Software is
  * furnished to do so, subject to the following conditions:
  *
  * The above copyright notice and this permission notice shall be included in all
  * copies or substantial portions of the Software.
  *
  * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  * SOFTWARE.
  *
  *
  *
  * @author Eros Camacho-Ruiz (camacho@imse-cnm.csic.es)
  * @version 6.0
  **/ 

#include "src/demo.h"
#include "src/test_func.h"

#define AES		0
#define SHA3	0
#define SHA2	0
#define HKDF	0
#define RSA		0
#define EDDSA	0
#define ECDH	0
#define MLKEM	0
#define MLDSA	0
#define SLHDSA	1
#define DRBG	0

void demo_speed_arm(int verb, int n_test) {

	time_result tr;
	time_result tr_kg;
	time_result tr_en;
	time_result tr_de;
	time_result tr_si;
	time_result tr_ve;
	time_result tr_ss;

	print_title_demo();

	printf("\n\t ---- Performance Evaluation --- "); /*
	printf("\n Configuration: ");
	printf("\n %-10s: ", "AES");		if (data_conf.aes)		printf("yes"); else printf("no");
	printf("\n %-10s: ", "SHA3");		if (data_conf.sha3)		printf("yes"); else printf("no");
	printf("\n %-10s: ", "SHA2");		if (data_conf.sha2)		printf("yes"); else printf("no");
	printf("\n %-10s: ", "HKDF");		if (data_conf.hkdf)		printf("yes"); else printf("no");
	printf("\n %-10s: ", "RSAPKE");		if (data_conf.rsa)		printf("yes"); else printf("no");
	printf("\n %-10s: ", "EdDSA");		if (data_conf.eddsa)	printf("yes"); else printf("no");
	printf("\n %-10s: ", "ECDH");		if (data_conf.ecdh)		printf("yes"); else printf("no");
	printf("\n %-10s: ", "MLKEM");		if (data_conf.mlkem)	printf("yes"); else printf("no");
	printf("\n %-10s: ", "MLDSA");		if (data_conf.mldsa)	printf("yes"); else printf("no");
	printf("\n %-10s: ", "DRBG");		if (data_conf.drbg)		printf("yes"); else printf("no");
	printf("\n Number of Tests: \t%d\n", n_test);
	*/
	printf("\n\n %-30s | %-30s | %-30s | Validation Test ", "Algorithm", "Execution Time (ms)", "Execution Time (us)");
	printf("\n %-30s | %-30s | %-30s | --------------- ", "---------", "-------------------", "-------------------");

#if AES == 1
		
		// 128
		test_aes("ecb", 128, n_test, verb, &tr_en, &tr_de);
		print_results_str_1_tab_2(n_test, "AES-128-ECB", tr_en, tr_de);

		test_aes("cbc", 128, n_test, verb, &tr_en, &tr_de);
		print_results_str_1_tab_2(n_test, "AES-128-CBC", tr_en, tr_de);

		test_aes("cmac", 128, n_test, verb, &tr_en, &tr_de);
		print_results_str_1_tab_1(n_test, "AES-128-CMAC", tr_en);

		test_aes("gcm", 128, n_test, verb, &tr_en, &tr_de);
		print_results_str_1_tab_2(n_test, "AES-128-GCM", tr_en, tr_de);

		test_aes("ccm", 128, n_test, verb, &tr_en, &tr_de);
		print_results_str_1_tab_2(n_test, "AES-128-CCM-8", tr_en, tr_de);

		// 192
		test_aes("ecb", 192, n_test, verb, &tr_en, &tr_de);
		print_results_str_1_tab_2(n_test, "AES-192-ECB", tr_en, tr_de);

		test_aes("cbc", 192, n_test, verb, &tr_en, &tr_de);
		print_results_str_1_tab_2(n_test, "AES-192-CBC", tr_en, tr_de);

		test_aes("cmac", 192, n_test, verb, &tr_en, &tr_de);
		print_results_str_1_tab_1(n_test, "AES-192-CMAC", tr_en);

		test_aes("gcm", 192, n_test, verb, &tr_en, &tr_de);
		print_results_str_1_tab_2(n_test, "AES-192-GCM", tr_en, tr_de);

		test_aes("ccm", 192, n_test, verb, &tr_en, &tr_de);
		print_results_str_1_tab_2(n_test, "AES-192-CCM-8", tr_en, tr_de);

		// 256
		test_aes("ecb", 256, n_test, verb, &tr_en, &tr_de);
		print_results_str_1_tab_2(n_test, "AES-256-ECB", tr_en, tr_de);

		test_aes("cbc", 256, n_test, verb, &tr_en, &tr_de);
		print_results_str_1_tab_2(n_test, "AES-256-CBC", tr_en, tr_de);

		test_aes("cmac", 256, n_test, verb, &tr_en, &tr_de);
		print_results_str_1_tab_1(n_test, "AES-256-CMAC", tr_en);

		test_aes("gcm", 256, n_test, verb, &tr_en, &tr_de);
		print_results_str_1_tab_2(n_test, "AES-256-GCM", tr_en, tr_de);

		test_aes("ccm", 256, n_test, verb, &tr_en, &tr_de);
		print_results_str_1_tab_2(n_test, "AES-256-CCM-8", tr_en, tr_de);
#endif

#if SHA3 == 1

		test_sha3(4, n_test, &tr, verb); // SHA3-224
		print_results_str_1_tab_1(n_test, "SHA3-224", tr);

		test_sha3(0, n_test, &tr, verb); // SHA3-256
		print_results_str_1_tab_1(n_test, "SHA3-256", tr);

		test_sha3(5, n_test, &tr, verb); // SHA3-384
		print_results_str_1_tab_1(n_test, "SHA3-384", tr);

		test_sha3(1, n_test, &tr, verb); // SHA3-512
		print_results_str_1_tab_1(n_test, "SHA3-512", tr);

		test_sha3(2, n_test, &tr, verb); // SHAKE-128
		print_results_str_1_tab_1(n_test, "SHAKE-128", tr);

		test_sha3(3, n_test, &tr, verb); // SHAKE-256
		print_results_str_1_tab_1(n_test, "SHAKE-256", tr);

#endif

#if SHA2 == 1

		test_sha2(4, n_test, &tr, verb); // SHA-224
		print_results_str_1_tab_1(n_test, "SHA-224", tr);

		test_sha2(0, n_test, &tr, verb); // SHA-256
		print_results_str_1_tab_1(n_test, "SHA-256", tr);

		test_sha2(1, n_test, &tr, verb); // SHA-384
		print_results_str_1_tab_1(n_test, "SHA-384", tr);

		test_sha2(2, n_test, &tr, verb); // SHA-512
		print_results_str_1_tab_1(n_test, "SHA-512", tr);

		test_sha2(5, n_test, &tr, verb); // SHA-512/224
		print_results_str_1_tab_1(n_test, "SHA-512/224", tr);

		test_sha2(3, n_test, &tr, verb); // SHA-512/256
		print_results_str_1_tab_1(n_test, "SHA-512/256", tr);
#endif

#if HKDF == 1

		test_hkdf(16, n_test, verb, &tr); print_results_str_2_tab_1(n_test, "HKDF-SHA256", "16 bytes", tr);
		test_hkdf(32, n_test, verb, &tr); print_results_str_2_tab_1(n_test, "HKDF-SHA256", "32 bytes", tr);
		test_hkdf(64, n_test, verb, &tr); print_results_str_2_tab_1(n_test, "HKDF-SHA256", "64 bytes", tr);
		test_hkdf(128, n_test, verb, &tr); print_results_str_2_tab_1(n_test, "HKDF-SHA256", "128 bytes", tr);
#endif

#if RSA == 1

		test_rsa(2048, n_test, verb, &tr_kg, &tr_en, &tr_de);
		print_results_str_1_tab_3(n_test, "RSAPKE-2048", tr_kg, tr_en, tr_de);

		test_rsa(3072, n_test, verb, &tr_kg, &tr_en, &tr_de);
		print_results_str_1_tab_3(n_test, "RSAPKE-3072", tr_kg, tr_en, tr_de);

		test_rsa(4096, n_test, verb, &tr_kg, &tr_en, &tr_de);
		print_results_str_1_tab_3(n_test, "RSAPKE-4096", tr_kg, tr_en, tr_de);

		test_rsa(6144, n_test, verb, &tr_kg, &tr_en, &tr_de);
		print_results_str_1_tab_3(n_test, "RSAPKE-6144", tr_kg, tr_en, tr_de);

		test_rsa(8192, n_test, verb, &tr_kg, &tr_en, &tr_de);
		print_results_str_1_tab_3(n_test, "RSAPKE-8192", tr_kg, tr_en, tr_de);
	
#endif

#if EDDSA == 1

		test_eddsa(25519, n_test, verb, &tr_kg, &tr_si, &tr_ve);
		print_results_str_1_tab_3(n_test, "EdDSA-25519", tr_kg, tr_si, tr_ve);

		test_eddsa(448, n_test, verb, &tr_kg, &tr_si, &tr_ve);
		print_results_str_1_tab_3(n_test, "EdDSA-448", tr_kg, tr_si, tr_ve);

#endif

#if ECDH == 1

		test_x25519(25519, n_test, verb, &tr_kg, &tr_ss);
		print_results_str_1_tab_2(n_test, "X25519", tr_kg, tr_ss);

		test_x25519(448, n_test, verb, &tr_kg, &tr_ss);
		print_results_str_1_tab_2(n_test, "X448", tr_kg, tr_ss);

#endif

#if MLKEM == 1

		test_mlkem(512, n_test, verb, &tr_kg, &tr_en, &tr_de);
		print_results_str_1_tab_3(n_test, "MLKEM-512", tr_kg, tr_en, tr_de);

		test_mlkem(768, n_test, verb, &tr_kg, &tr_en, &tr_de);
		print_results_str_1_tab_3(n_test, "MLKEM-768", tr_kg, tr_en, tr_de);

		test_mlkem(1024, n_test, verb, &tr_kg, &tr_en, &tr_de);
		print_results_str_1_tab_3(n_test, "MLKEM-1024", tr_kg, tr_en, tr_de);

#endif

#if MLDSA == 1

		test_mldsa(44, n_test, verb, &tr_kg, &tr_si, &tr_ve);
		print_results_str_1_tab_3(n_test, "MLDSA-44", tr_kg, tr_si, tr_ve);

		test_mldsa(65, n_test, verb, &tr_kg, &tr_si, &tr_ve);
		print_results_str_1_tab_3(n_test, "MLDSA-65", tr_kg, tr_si, tr_ve);

		test_mldsa(87, n_test, verb, &tr_kg, &tr_si, &tr_ve);
		print_results_str_1_tab_3(n_test, "MLDSA-87", tr_kg, tr_si, tr_ve);
#endif

#if SLHDSA == 1

		test_slhdsa("shake-128-f", n_test, verb, &tr_kg, &tr_si, &tr_ve);
		print_results_str_1_tab_3(n_test, "SLHDSA-SHAKE128F", tr_kg, tr_si, tr_ve);

		test_slhdsa("shake-128-s", n_test, verb, &tr_kg, &tr_si, &tr_ve);
		print_results_str_1_tab_3(n_test, "SLHDSA-SHAKE128S", tr_kg, tr_si, tr_ve);

		test_slhdsa("shake-192-f", n_test, verb, &tr_kg, &tr_si, &tr_ve);
		print_results_str_1_tab_3(n_test, "SLHDSA-SHAKE192F", tr_kg, tr_si, tr_ve);

		test_slhdsa("shake-192-s", n_test, verb, &tr_kg, &tr_si, &tr_ve);
		print_results_str_1_tab_3(n_test, "SLHDSA-SHAKE192S", tr_kg, tr_si, tr_ve);

		test_slhdsa("shake-256-f", n_test, verb, &tr_kg, &tr_si, &tr_ve);
		print_results_str_1_tab_3(n_test, "SLHDSA-SHAKE256F", tr_kg, tr_si, tr_ve);

		test_slhdsa("shake-256-s", n_test, verb, &tr_kg, &tr_si, &tr_ve);
		print_results_str_1_tab_3(n_test, "SLHDSA-SHAKE256S", tr_kg, tr_si, tr_ve);

#endif

#if DRBG == 1

		test_trng(0, 128, n_test, &tr, verb); print_results_str_2_tab_1(n_test, "TRNG", "128 bits", tr);
		test_trng(1, 128, n_test, &tr, verb); print_results_str_2_tab_1(n_test, "CTR-DRBG", "128 bits", tr);
		test_trng(2, 128, n_test, &tr, verb); print_results_str_2_tab_1(n_test, "HMAC-DRBG", "128 bits", tr);

		test_trng(0, 256, n_test, &tr, verb); print_results_str_2_tab_1(n_test, "TRNG", "256 bits", tr);
		test_trng(1, 256, n_test, &tr, verb); print_results_str_2_tab_1(n_test, "CTR-DRBG", "256 bits", tr);
		test_trng(2, 256, n_test, &tr, verb); print_results_str_2_tab_1(n_test, "HMAC-DRBG", "256 bits", tr);

		test_trng(0, 512, n_test, &tr, verb); print_results_str_2_tab_1(n_test, "TRNG", "512 bits", tr);
		test_trng(1, 512, n_test, &tr, verb); print_results_str_2_tab_1(n_test, "CTR-DRBG", "512 bits", tr);
		test_trng(2, 512, n_test, &tr, verb); print_results_str_2_tab_1(n_test, "HMAC-DRBG", "512 bits", tr);

		test_trng(0, 1024, n_test, &tr, verb); print_results_str_2_tab_1(n_test, "TRNG", "1024 bits", tr);
		test_trng(1, 1024, n_test, &tr, verb); print_results_str_2_tab_1(n_test, "CTR-DRBG", "1024 bits", tr);
		test_trng(2, 1024, n_test, &tr, verb); print_results_str_2_tab_1(n_test, "HMAC-DRBG", "1024 bits", tr);

		test_trng(0, 2048, n_test, &tr, verb); print_results_str_2_tab_1(n_test, "TRNG", "2048 bits", tr);
		test_trng(1, 2048, n_test, &tr, verb); print_results_str_2_tab_1(n_test, "CTR-DRBG", "2048 bits", tr);
		test_trng(2, 2048, n_test, &tr, verb); print_results_str_2_tab_1(n_test, "HMAC-DRBG", "2048 bits", tr);
#endif

	printf("\n\n");
}