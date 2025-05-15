/**
  * @file demo.c
  * @brief Validation Test code
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

void main(int argc, char** argv) {
	
	print_title_demo();

	int verb = 0;

	for (int arg = 1; arg < argc; arg++) {

		if (argv[arg][0] == '-') {
			if (argv[arg][1] == 'h') {
				printf("\n Usage: ./demo-XXX-YYY [-h] [-v] [-vv] \n");
				printf("\n -h  : Show the help.");
				printf("\n -v  : Verbose level 1");
				printf("\n -vv : Verbose level 2");
				printf("\n \n");

				return;
			}
			else if (argv[arg][1] == 'v') {
				if (argv[arg][2] == 'v') verb = 3;
				else verb = 1;
			}
			else {
				printf("\n Unknow option: %s\n", argv[arg]);

				return;
			}
		}
	}



	data_conf data_conf;

	read_conf(&data_conf);

	printf("\n\t ---- Test Evaluation --- "); /*
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
	printf("\n %-10s: ", "SLHDSA");		if (data_conf.slhdsa)	printf("yes"); else printf("no");
	printf("\n %-10s: ", "DRBG");		if (data_conf.drbg)		printf("yes"); else printf("no");
	*/

	printf("\n\n %-30s | Result ", "Algorithm");
	printf("\n %-30s | ------ ", "---------");

	if (data_conf.aes) {
		demo_aes(128, verb);	// Security level: 128
		demo_aes(192, verb);	// Security level: 192
		demo_aes(256, verb);	// Security level: 256
	}

	if (data_conf.sha3) {
		demo_sha3(verb);
	}

	if (data_conf.sha2) {
		demo_sha2(verb);
	}

	if (data_conf.hkdf) {
		demo_hkdf(verb);
	}

	if (data_conf.rsa) {
		demo_rsa(2048, verb);  // Security level: 112
		demo_rsa(3072, verb);  // Security level: 128
		demo_rsa(4096, verb);  // Security level: 152
		demo_rsa(6144, verb);  // Security level: 176
		demo_rsa(8192, verb);  // Security level: 200
	}

	if (data_conf.eddsa) {
		demo_eddsa(25519, verb);
		demo_eddsa(448, verb);
	}

	if (data_conf.ecdh) {
		demo_x25519(25519, verb);
		demo_x25519(448, verb);
	}

	if (data_conf.mlkem) {
		demo_mlkem(512, verb);
		demo_mlkem(768, verb);
		demo_mlkem(1024, verb);
	}
	if (data_conf.mldsa) {
		demo_mldsa(44, verb);
		demo_mldsa(65, verb);
		demo_mldsa(87, verb);
	}
	if (data_conf.slhdsa) {
		demo_slhdsa("shake-128-f", verb);
		demo_slhdsa("shake-128-s", verb);
		demo_slhdsa("shake-192-f", verb);
		demo_slhdsa("shake-192-s", verb);
		demo_slhdsa("shake-256-f", verb);
		demo_slhdsa("shake-256-s", verb);
	}

	if (data_conf.drbg) {
		demo_trng(128, verb);
		demo_trng(256, verb);
		demo_trng(512, verb);
		demo_trng(1024, verb);
		demo_trng(2048, verb);
	}
	

	printf("\n\n");
}