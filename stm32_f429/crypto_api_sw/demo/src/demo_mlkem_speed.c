/**
  * @file demo_mlkem_speed.c
  * @brief Performance test for MLKEM code
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
  * @version 5.0
  **/ 

#include "demo.h"
#include "test_func.h"

void test_mlkem(unsigned int mode, unsigned int n_test, unsigned int verb, time_result* tr_kg, time_result* tr_en, time_result* tr_de) {

	uint64_t start_t, stop_t;

	//-- Initialize to avoid 1st measure error
	start_t = timeInMicroseconds();
	stop_t = timeInMicroseconds();

	tr_kg->time_mean_value_sw = 0;
	tr_kg->time_max_value_sw = 0;
	tr_kg->time_min_value_sw = 0;
	tr_kg->val_result = 0;

	tr_en->time_mean_value_sw = 0;
	tr_en->time_max_value_sw = 0;
	tr_en->time_min_value_sw = 0;
	tr_en->val_result = 0;

	tr_de->time_mean_value_sw = 0;
	tr_de->time_max_value_sw = 0;
	tr_de->time_min_value_sw = 0;
	tr_de->val_result = 0;

	uint64_t time_sw = 0;
	uint64_t time_total_kg_sw = 0;
	uint64_t time_total_en_sw = 0;
	uint64_t time_total_de_sw = 0;
	
	unsigned char* pk_512;
	unsigned char* sk_512;
	unsigned char* ct_512;
	unsigned char* pk_768;
	unsigned char* sk_768;
	unsigned char* ct_768;
	unsigned char* pk_1024;
	unsigned char* sk_1024;
	unsigned char* ct_1024;

	unsigned char ss[32];
	unsigned char ss1[32];
	unsigned int result = 0;

	pk_512 = malloc(800);
	sk_512 = malloc(1632);
	ct_512 = malloc(768);
	pk_768 = malloc(1184);
	sk_768 = malloc(2400);
	ct_768 = malloc(1088);
	pk_1024 = malloc(1568);
	sk_1024 = malloc(3168);
	ct_1024 = malloc(1568);

	/*
	if (mode == 512)        printf("\n\n -- Test MLKEM-512 --");
	else if (mode == 768)   printf("\n\n -- Test MLKEM-768 --");
	else if (mode == 1024)  printf("\n\n -- Test MLKEM-1024 --");
	*/

	for (int test = 1; test <= n_test; test++) {

		if (verb >= 1) printf("\n test: %d", test);

		if (mode == 512) {

			// keygen_sw
			start_t = timeInMicroseconds();
			mlkem512_genkeys(pk_512, sk_512); // from crypto_api_sw.h
			stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW GEN KEYS: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));

			time_sw = stop_t - start_t;
			time_total_kg_sw += time_sw;

			if (test == 1)										tr_kg->time_min_value_sw = time_sw;
			else if (tr_kg->time_min_value_sw > time_sw)		tr_kg->time_min_value_sw = time_sw;
			if (tr_kg->time_max_value_sw < time_sw)				tr_kg->time_max_value_sw = time_sw;

			if (verb >= 3) {
				printf("\n pk_512: \t");  show_array(pk_512, 800, 32);
				printf("\n sk_512: \t");  show_array(sk_512, 1632, 32);
			}

			// enc_sw
			start_t = timeInMicroseconds();
			mlkem512_enc(ct_512, ss, pk_512); // from crypto_api_sw.h
			stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW ENCAP: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));

			time_sw = stop_t - start_t;
			time_total_en_sw += time_sw;

			if (test == 1)										tr_en->time_min_value_sw = time_sw;
			else if (tr_en->time_min_value_sw > time_sw)		tr_en->time_min_value_sw = time_sw;
			if (tr_en->time_max_value_sw < time_sw)				tr_en->time_max_value_sw = time_sw;

			if (verb >= 3) {
				printf("\n ct_512: \t");  show_array(ct_512, 768, 32);
			}

			// dec_sw
			start_t = timeInMicroseconds();
			mlkem512_dec(ss1, ct_512, sk_512, &result); // from crypto_api_sw.h
			stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW DECAP: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));

			time_sw = stop_t - start_t;
			time_total_de_sw += time_sw;

			if (test == 1)										tr_de->time_min_value_sw = time_sw;
			else if (tr_de->time_min_value_sw > time_sw)		tr_de->time_min_value_sw = time_sw;
			if (tr_de->time_max_value_sw < time_sw)				tr_de->time_max_value_sw = time_sw;

			if (verb >= 2) {
				printf("\n ss original: \t");  show_array(ss, 32, 32);
				printf("\n ss recover: \t");   show_array(ss1, 32, 32);
			}

			if (!result) tr_de->val_result++;

		}

		else if (mode == 768) {

			// keygen_sw
			start_t = timeInMicroseconds();
			mlkem768_genkeys(pk_768, sk_768); // from crypto_api_sw.h
			stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW GEN KEYS: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));

			time_sw = stop_t - start_t;
			time_total_kg_sw += time_sw;

			if (test == 1)										tr_kg->time_min_value_sw = time_sw;
			else if (tr_kg->time_min_value_sw > time_sw)		tr_kg->time_min_value_sw = time_sw;
			if (tr_kg->time_max_value_sw < time_sw)				tr_kg->time_max_value_sw = time_sw;

			if (verb >= 2) {
				printf("\n pk_768: \t");  show_array(pk_768, 1184, 32);
				printf("\n sk_768: \t");  show_array(sk_768, 2400, 32);
			}

			// enc_sw
			start_t = timeInMicroseconds();
			mlkem768_enc(ct_768, ss, pk_768); // from crypto_api_sw.h
			stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW ENCAP: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));

			time_sw = stop_t - start_t;
			time_total_en_sw += time_sw;

			if (test == 1)										tr_en->time_min_value_sw = time_sw;
			else if (tr_en->time_min_value_sw > time_sw)		tr_en->time_min_value_sw = time_sw;
			if (tr_en->time_max_value_sw < time_sw)				tr_en->time_max_value_sw = time_sw;

			if (verb >= 2) {
				printf("\n ct_768: \t");  show_array(ct_768, 1088, 32);
			}

			// dec_sw
			start_t = timeInMicroseconds();
			mlkem768_dec(ss1, ct_768, sk_768, &result); // from crypto_api_sw.h
			stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW DECAP: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));

			time_sw = stop_t - start_t;
			time_total_de_sw += time_sw;

			if (test == 1)										tr_de->time_min_value_sw = time_sw;
			else if (tr_de->time_min_value_sw > time_sw)		tr_de->time_min_value_sw = time_sw;
			if (tr_de->time_max_value_sw < time_sw)				tr_de->time_max_value_sw = time_sw;

			if (verb >= 2) {
				printf("\n ss original: \t");  show_array(ss, 32, 32);
				printf("\n ss recover: \t");   show_array(ss1, 32, 32);
			}

			if (!result) tr_de->val_result++;

		}
		else if (mode == 1024) {

			// keygen_sw
			start_t = timeInMicroseconds();
			mlkem1024_genkeys(pk_1024, sk_1024); // from crypto_api_sw.h
			stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW GEN KEYS: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));

			time_sw = stop_t - start_t;
			time_total_kg_sw += time_sw;

			if (test == 1)										tr_kg->time_min_value_sw = time_sw;
			else if (tr_kg->time_min_value_sw > time_sw)		tr_kg->time_min_value_sw = time_sw;
			if (tr_kg->time_max_value_sw < time_sw)				tr_kg->time_max_value_sw = time_sw;

			if (verb >= 2) {
				printf("\n pk_1024: \t");  show_array(pk_1024, 1568, 32);
				printf("\n sk_1024: \t");  show_array(sk_1024, 3168, 32);
			}

			// enc_sw
			start_t = timeInMicroseconds();
			mlkem1024_enc(ct_1024, ss, pk_1024); // from crypto_api_sw.h
			stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW ENCAP: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));

			time_sw = stop_t - start_t;
			time_total_en_sw += time_sw;

			if (test == 1)										tr_en->time_min_value_sw = time_sw;
			else if (tr_en->time_min_value_sw > time_sw)		tr_en->time_min_value_sw = time_sw;
			if (tr_en->time_max_value_sw < time_sw)				tr_en->time_max_value_sw = time_sw;

			if (verb >= 2) {
				printf("\n ct_1024: \t");  show_array(ct_1024, 1568, 32);
			}

			// dec_sw
			start_t = timeInMicroseconds();
			mlkem1024_dec(ss1, ct_1024, sk_1024, &result); // from crypto_api_sw.h
			stop_t = timeInMicroseconds(); if (verb >= 1) printf("\n SW DECAP: ET: %.3f s \t %.3f ms \t %d us", (stop_t - start_t) / 1000000.0, (stop_t - start_t) / 1000.0, (unsigned int)(stop_t - start_t));

			time_sw = stop_t - start_t;
			time_total_de_sw += time_sw;

			if (test == 1)										tr_de->time_min_value_sw = time_sw;
			else if (tr_de->time_min_value_sw > time_sw)		tr_de->time_min_value_sw = time_sw;
			if (tr_de->time_max_value_sw < time_sw)				tr_de->time_max_value_sw = time_sw;

			if (verb >= 2) {
				printf("\n ss original: \t");  show_array(ss, 32, 32);
				printf("\n ss recover: \t");   show_array(ss1, 32, 32);
			}

			if (!result) tr_de->val_result++;

		}
	}

	tr_kg->time_mean_value_sw = (uint64_t)(time_total_kg_sw / n_test);
	tr_en->time_mean_value_sw = (uint64_t)(time_total_en_sw / n_test);
	tr_de->time_mean_value_sw = (uint64_t)(time_total_de_sw / n_test);

	free(sk_512);
	free(pk_512);
	free(ct_512);

	free(sk_768);
	free(pk_768);
	free(ct_768);

	free(sk_1024);
	free(pk_1024);
	free(ct_1024);
	

}