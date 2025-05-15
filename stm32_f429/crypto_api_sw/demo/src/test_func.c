/**
  * @file test_func.c
  * @brief Extra functions for Demo code
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

#include "test_func.h"

// Counting number of 1's (HW) - Fast test - No reliable

#define thres 10 // threshold in percentage around 50%

int test_random(unsigned char* random, unsigned int size) {
	
	unsigned int num_ones = 0;


	unsigned char data;
	for (int i = 0; i < size; i++) {
		data = random[i];
		for (int j = 0; j < 8; j++) {
			num_ones += (data & 0x01); 
			data = data >> 1; 
		}
	
	}

	int result = 1; 
	int val_max = (8.0*size * ((50 + thres) / (1.0*100)));
	int val_min = (8.0*size * ((50 - thres) / (1.0*100)));

	// printf("\n %d %d %d", num_ones, val_max, val_min);

	if ((num_ones < val_max) & (num_ones > val_min)) result = 0;
	else result = 1;

	return result; 

}

void print_result_valid(unsigned char* str, unsigned int fail) {
	if(!fail)	printf("\n %-30s | \u2705 ", str);
	else		printf("\n %-30s | \u274c ", str);
}

void print_result_double_valid(unsigned char* str, unsigned char* str2, unsigned int fail) {
	if (!fail)	printf("\n %-14s %-15s | \u2705 ", str, str2);
	else		printf("\n %-14s %-15s | \u274c ", str, str2);
}


void read_conf(data_conf* data) {

	unsigned char name[20] = "config.conf";

	FILE* fp;
	fp = fopen(name, "r");

	unsigned char str[20];

	unsigned int ind = 0;
	unsigned int ind_vread = 0;
	unsigned int vread[12];

	while (fgets(str, 20, fp)) {
		// printf("%s", str);
		char* token;
		char* delimiter = "\t";
		token = strtok(str, delimiter);
		while (token != NULL) {
			if ((ind % 2 != 0)) {
				vread[ind_vread] = atoi(token);
				ind_vread++;
			}
			// printf("%s\n", token);
			token = strtok(NULL, delimiter);
			ind += 1;
		}


	}

	data->aes		= vread[0];
	data->sha3		= vread[1];
	data->sha2		= vread[2];
	data->hkdf		= vread[3];
	data->rsa		= vread[4];
	data->eddsa		= vread[5];
	data->ecdh		= vread[6];
	data->mlkem		= vread[7];
	data->mldsa		= vread[8];
	data->slhdsa	= vread[9];
	data->drbg		= vread[10];
	data->n_test	= vread[11];

	fclose(fp);

}

void print_results(unsigned int verb, unsigned int n_test, time_result tr) {

	printf("\n mean sw: %.3f s \t %.3f ms \t %d us", tr.time_mean_value_sw / 1000000.0, tr.time_mean_value_sw / 1000.0, (unsigned int)tr.time_mean_value_sw);
	if (verb >= 1) printf("\n max sw: %.3f s \t %.3f ms \t %d us", tr.time_max_value_sw / 1000000.0, tr.time_max_value_sw / 1000.0, (unsigned int)tr.time_max_value_sw);
	if (verb >= 1) printf("\n min sw: %.3f s \t %.3f ms \t %d us", tr.time_min_value_sw / 1000000.0, tr.time_min_value_sw / 1000.0, (unsigned int)tr.time_min_value_sw);
	printf("\n val result: %d /", (unsigned int)tr.val_result); printf(" %d", n_test);

}

void print_results_str_1_tab_3(unsigned int n_test, unsigned char* str, time_result tr1, time_result tr2, time_result tr3) {

	double time1_s = tr1.time_mean_value_sw / 1000000.0;
	double time1_ms = tr1.time_mean_value_sw / 1000.0;
	unsigned int time1_us = tr1.time_mean_value_sw;

	double time2_s = tr2.time_mean_value_sw / 1000000.0;
	double time2_ms = tr2.time_mean_value_sw / 1000.0;
	unsigned int time2_us = tr2.time_mean_value_sw;

	double time3_s = tr3.time_mean_value_sw / 1000000.0;
	double time3_ms = tr3.time_mean_value_sw / 1000.0;
	unsigned int time3_us = tr3.time_mean_value_sw;

	// unsigned char time_s[20];	sprintf(time_s,		"%.3f / %.3f", time1_s,  time2_s);
	unsigned char time_ms[30];	sprintf(time_ms, "%.3f / %.3f / %.3f", time1_ms, time2_ms, time3_ms);
	unsigned char time_us[30];	sprintf(time_us, "%d / %d / %d", time1_us, time2_us, time3_us);
	unsigned char s_test[20];	if (tr3.val_result != 0xFFFFFFFF)	sprintf(s_test, "%d / %d", (unsigned int)tr3.val_result, n_test);
								else								strcpy(s_test, "-");

	// printf("\n %-30s | %-25s | %-25s | %-25s | %-15s ", str, time_s, time_ms, time_us, s_test);
	printf("\n %-30s | %-30s | %-30s | %-15s ", str, time_ms, time_us, s_test);

}

void print_results_str_1_tab_2(unsigned int n_test, unsigned char* str, time_result tr1, time_result tr2) {

	double time1_s	= tr1.time_mean_value_sw / 1000000.0; 
	double time1_ms = tr1.time_mean_value_sw / 1000.0;
	unsigned int time1_us = tr1.time_mean_value_sw;

	double time2_s	= tr2.time_mean_value_sw / 1000000.0;
	double time2_ms = tr2.time_mean_value_sw / 1000.0;
	unsigned int time2_us = tr2.time_mean_value_sw;

	// unsigned char time_s[20];	sprintf(time_s,		"%.3f / %.3f", time1_s,  time2_s);
	unsigned char time_ms[20];	sprintf(time_ms,	"%.3f / %.3f", time1_ms, time2_ms);
	unsigned char time_us[20];	sprintf(time_us,	"%d / %d", time1_us, time2_us);
	unsigned char s_test[20];	if(tr2.val_result != 0xFFFFFFFF)	sprintf(s_test,	"%d / %d", (unsigned int)tr2.val_result, n_test);
								else								strcpy(s_test, "-");

	// printf("\n %-30s | %-25s | %-25s | %-25s | %-15s ", str, time_s, time_ms, time_us, s_test);
	printf("\n %-30s | %-30s | %-30s | %-15s ", str, time_ms, time_us, s_test);

}

void print_results_str_1_tab_1(unsigned int n_test, unsigned char* str, time_result tr) {

	double time1_s			= tr.time_mean_value_sw / 1000000.0;
	double time1_ms			= tr.time_mean_value_sw / 1000.0;
	unsigned int time1_us	= tr.time_mean_value_sw;

	// unsigned char time_s[20];	sprintf(time_s,		"%.3f / %.3f", time1_s,  time2_s);
	unsigned char time_ms[20];	sprintf(time_ms, "%.3f", time1_ms);
	unsigned char time_us[20];	sprintf(time_us, "%d", time1_us);
	unsigned char s_test[20];	if (tr.val_result != 0xFFFFFFFF)	sprintf(s_test, "%d / %d", (unsigned int)tr.val_result, n_test);
								else								strcpy(s_test, "-");

	// printf("\n %-30s | %-25s | %-25s | %-25s | %-15s ", str, time_s, time_ms, time_us, s_test);
	printf("\n %-30s | %-30s | %-30s | %-15s ", str, time_ms, time_us, s_test);

}

void print_results_str_2_tab_1(unsigned int n_test, unsigned char* str1, unsigned char* str2, time_result tr) {

	double time1_s = tr.time_mean_value_sw / 1000000.0;
	double time1_ms = tr.time_mean_value_sw / 1000.0;
	unsigned int time1_us = tr.time_mean_value_sw;

	// unsigned char time_s[20];	sprintf(time_s,		"%.3f / %.3f", time1_s,  time2_s);
	unsigned char time_ms[20];	sprintf(time_ms, "%.3f", time1_ms);
	unsigned char time_us[20];	sprintf(time_us, "%d", time1_us);
	unsigned char s_test[20];	if (tr.val_result != 0xFFFFFFFF)	sprintf(s_test, "%d / %d", (unsigned int)tr.val_result, n_test);
	else								strcpy(s_test, "-");

	// printf("\n %-30s | %-25s | %-25s | %-25s | %-15s ", str, time_s, time_ms, time_us, s_test);
	printf("\n %-14s %-15s | %-30s | %-30s | %-15s ", str1, str2, time_ms, time_us, s_test);

}


void show_array(const unsigned char* r, const unsigned int size, const unsigned int mod) {

	unsigned int ind = 0;

	printf("\n");
	for (int i = 0; i < (int)ceil((double)size / (double)mod); i++) {
		for (int j = 0; j < mod; j++) {
			ind = i * mod + j;
			if (ind < size) printf("%02x", r[ind]);
			else printf("  ");
		}
		printf("\n");
	}
}

int cmpchar(unsigned char* in1, unsigned char* in2, unsigned int len) {
	
	int cmp = 1;

	for (int i = 0; i < len; i++) {
		if (in1[i] != in2[i]) {
			cmp = 1;
			return cmp;
		}
		else cmp = 0;
	}
	return cmp;

}

void char2hex(unsigned char* in, unsigned char* out) {
	
	unsigned int index = 0;
	unsigned char char_out; 

	for (int i = 0; i < (int)(strlen(in) / 2); i++) {
		index = 2 * i;
		// printf("\n %c %c %x", in[index], in[index + 1], char_out);
		char_to_hex(in[index], in[index + 1], &char_out);
		// printf("\n %c %c %x", in[index], in[index + 1], char_out);
		out[i] = char_out;
	}

}

void char_to_hex(unsigned char in0, unsigned char in1, unsigned char* out) {

	switch (in0) {
	case '0':
		switch (in1) {
		case '0': *out = 0x00; break;
		case '1': *out = 0x01; break;
		case '2': *out = 0x02; break;
		case '3': *out = 0x03; break;
		case '4': *out = 0x04; break;
		case '5': *out = 0x05; break;
		case '6': *out = 0x06; break;
		case '7': *out = 0x07; break;
		case '8': *out = 0x08; break;
		case '9': *out = 0x09; break;
		case 'a': *out = 0x0a; break;
		case 'b': *out = 0x0b; break;
		case 'c': *out = 0x0c; break;
		case 'd': *out = 0x0d; break;
		case 'e': *out = 0x0e; break;
		case 'f': *out = 0x0f; break;
		case 'A': *out = 0x0a; break;
		case 'B': *out = 0x0b; break;
		case 'C': *out = 0x0c; break;
		case 'D': *out = 0x0d; break;
		case 'E': *out = 0x0e; break;
		case 'F': *out = 0x0f; break;
		} break;
	case '1':
		switch (in1) {
		case '0': *out = 0x10; break;
		case '1': *out = 0x11; break;
		case '2': *out = 0x12; break;
		case '3': *out = 0x13; break;
		case '4': *out = 0x14; break;
		case '5': *out = 0x15; break;
		case '6': *out = 0x16; break;
		case '7': *out = 0x17; break;
		case '8': *out = 0x18; break;
		case '9': *out = 0x19; break;
		case 'a': *out = 0x1a; break;
		case 'b': *out = 0x1b; break;
		case 'c': *out = 0x1c; break;
		case 'd': *out = 0x1d; break;
		case 'e': *out = 0x1e; break;
		case 'f': *out = 0x1f; break;
		case 'A': *out = 0x1a; break;
		case 'B': *out = 0x1b; break;
		case 'C': *out = 0x1c; break;
		case 'D': *out = 0x1d; break;
		case 'E': *out = 0x1e; break;
		case 'F': *out = 0x1f; break;
		} break;
	case '2':
		switch (in1) {
		case '0': *out = 0x20; break;
		case '1': *out = 0x21; break;
		case '2': *out = 0x22; break;
		case '3': *out = 0x23; break;
		case '4': *out = 0x24; break;
		case '5': *out = 0x25; break;
		case '6': *out = 0x26; break;
		case '7': *out = 0x27; break;
		case '8': *out = 0x28; break;
		case '9': *out = 0x29; break;
		case 'a': *out = 0x2a; break;
		case 'b': *out = 0x2b; break;
		case 'c': *out = 0x2c; break;
		case 'd': *out = 0x2d; break;
		case 'e': *out = 0x2e; break;
		case 'f': *out = 0x2f; break;
		case 'A': *out = 0x2a; break;
		case 'B': *out = 0x2b; break;
		case 'C': *out = 0x2c; break;
		case 'D': *out = 0x2d; break;
		case 'E': *out = 0x2e; break;
		case 'F': *out = 0x2f; break;
		} break;
	case '3':
		switch (in1) {
		case '0': *out = 0x30; break;
		case '1': *out = 0x31; break;
		case '2': *out = 0x32; break;
		case '3': *out = 0x33; break;
		case '4': *out = 0x34; break;
		case '5': *out = 0x35; break;
		case '6': *out = 0x36; break;
		case '7': *out = 0x37; break;
		case '8': *out = 0x38; break;
		case '9': *out = 0x39; break;
		case 'a': *out = 0x3a; break;
		case 'b': *out = 0x3b; break;
		case 'c': *out = 0x3c; break;
		case 'd': *out = 0x3d; break;
		case 'e': *out = 0x3e; break;
		case 'f': *out = 0x3f; break;
		case 'A': *out = 0x3a; break;
		case 'B': *out = 0x3b; break;
		case 'C': *out = 0x3c; break;
		case 'D': *out = 0x3d; break;
		case 'E': *out = 0x3e; break;
		case 'F': *out = 0x3f; break;
		} break;
	case '4':
		switch (in1) {
		case '0': *out = 0x40; break;
		case '1': *out = 0x41; break;
		case '2': *out = 0x42; break;
		case '3': *out = 0x43; break;
		case '4': *out = 0x44; break;
		case '5': *out = 0x45; break;
		case '6': *out = 0x46; break;
		case '7': *out = 0x47; break;
		case '8': *out = 0x48; break;
		case '9': *out = 0x49; break;
		case 'a': *out = 0x4a; break;
		case 'b': *out = 0x4b; break;
		case 'c': *out = 0x4c; break;
		case 'd': *out = 0x4d; break;
		case 'e': *out = 0x4e; break;
		case 'f': *out = 0x4f; break;
		case 'A': *out = 0x4a; break;
		case 'B': *out = 0x4b; break;
		case 'C': *out = 0x4c; break;
		case 'D': *out = 0x4d; break;
		case 'E': *out = 0x4e; break;
		case 'F': *out = 0x4f; break;
		} break;
	case '5':
		switch (in1) {
		case '0': *out = 0x50; break;
		case '1': *out = 0x51; break;
		case '2': *out = 0x52; break;
		case '3': *out = 0x53; break;
		case '4': *out = 0x54; break;
		case '5': *out = 0x55; break;
		case '6': *out = 0x56; break;
		case '7': *out = 0x57; break;
		case '8': *out = 0x58; break;
		case '9': *out = 0x59; break;
		case 'a': *out = 0x5a; break;
		case 'b': *out = 0x5b; break;
		case 'c': *out = 0x5c; break;
		case 'd': *out = 0x5d; break;
		case 'e': *out = 0x5e; break;
		case 'f': *out = 0x5f; break;
		case 'A': *out = 0x5a; break;
		case 'B': *out = 0x5b; break;
		case 'C': *out = 0x5c; break;
		case 'D': *out = 0x5d; break;
		case 'E': *out = 0x5e; break;
		case 'F': *out = 0x5f; break;
		} break;
	case '6':
		switch (in1) {
		case '0': *out = 0x60; break;
		case '1': *out = 0x61; break;
		case '2': *out = 0x62; break;
		case '3': *out = 0x63; break;
		case '4': *out = 0x64; break;
		case '5': *out = 0x65; break;
		case '6': *out = 0x66; break;
		case '7': *out = 0x67; break;
		case '8': *out = 0x68; break;
		case '9': *out = 0x69; break;
		case 'a': *out = 0x6a; break;
		case 'b': *out = 0x6b; break;
		case 'c': *out = 0x6c; break;
		case 'd': *out = 0x6d; break;
		case 'e': *out = 0x6e; break;
		case 'f': *out = 0x6f; break;
		case 'A': *out = 0x6a; break;
		case 'B': *out = 0x6b; break;
		case 'C': *out = 0x6c; break;
		case 'D': *out = 0x6d; break;
		case 'E': *out = 0x6e; break;
		case 'F': *out = 0x6f; break;
		} break;
	case '7':
		switch (in1) {
		case '0': *out = 0x70; break;
		case '1': *out = 0x71; break;
		case '2': *out = 0x72; break;
		case '3': *out = 0x73; break;
		case '4': *out = 0x74; break;
		case '5': *out = 0x75; break;
		case '6': *out = 0x76; break;
		case '7': *out = 0x77; break;
		case '8': *out = 0x78; break;
		case '9': *out = 0x79; break;
		case 'a': *out = 0x7a; break;
		case 'b': *out = 0x7b; break;
		case 'c': *out = 0x7c; break;
		case 'd': *out = 0x7d; break;
		case 'e': *out = 0x7e; break;
		case 'f': *out = 0x7f; break;
		case 'A': *out = 0x7a; break;
		case 'B': *out = 0x7b; break;
		case 'C': *out = 0x7c; break;
		case 'D': *out = 0x7d; break;
		case 'E': *out = 0x7e; break;
		case 'F': *out = 0x7f; break;
		} break;
	case '8':
		switch (in1) {
		case '0': *out = 0x80; break;
		case '1': *out = 0x81; break;
		case '2': *out = 0x82; break;
		case '3': *out = 0x83; break;
		case '4': *out = 0x84; break;
		case '5': *out = 0x85; break;
		case '6': *out = 0x86; break;
		case '7': *out = 0x87; break;
		case '8': *out = 0x88; break;
		case '9': *out = 0x89; break;
		case 'a': *out = 0x8a; break;
		case 'b': *out = 0x8b; break;
		case 'c': *out = 0x8c; break;
		case 'd': *out = 0x8d; break;
		case 'e': *out = 0x8e; break;
		case 'f': *out = 0x8f; break;
		case 'A': *out = 0x8a; break;
		case 'B': *out = 0x8b; break;
		case 'C': *out = 0x8c; break;
		case 'D': *out = 0x8d; break;
		case 'E': *out = 0x8e; break;
		case 'F': *out = 0x8f; break;
		} break;
	case '9':
		switch (in1) {
		case '0': *out = 0x90; break;
		case '1': *out = 0x91; break;
		case '2': *out = 0x92; break;
		case '3': *out = 0x93; break;
		case '4': *out = 0x94; break;
		case '5': *out = 0x95; break;
		case '6': *out = 0x96; break;
		case '7': *out = 0x97; break;
		case '8': *out = 0x98; break;
		case '9': *out = 0x99; break;
		case 'a': *out = 0x9a; break;
		case 'b': *out = 0x9b; break;
		case 'c': *out = 0x9c; break;
		case 'd': *out = 0x9d; break;
		case 'e': *out = 0x9e; break;
		case 'f': *out = 0x9f; break;
		case 'A': *out = 0x9a; break;
		case 'B': *out = 0x9b; break;
		case 'C': *out = 0x9c; break;
		case 'D': *out = 0x9d; break;
		case 'E': *out = 0x9e; break;
		case 'F': *out = 0x9f; break;
		} break;
	case 'a':
		switch (in1) {
		case '0': *out = 0xa0; break;
		case '1': *out = 0xa1; break;
		case '2': *out = 0xa2; break;
		case '3': *out = 0xa3; break;
		case '4': *out = 0xa4; break;
		case '5': *out = 0xa5; break;
		case '6': *out = 0xa6; break;
		case '7': *out = 0xa7; break;
		case '8': *out = 0xa8; break;
		case '9': *out = 0xa9; break;
		case 'a': *out = 0xaa; break;
		case 'b': *out = 0xab; break;
		case 'c': *out = 0xac; break;
		case 'd': *out = 0xad; break;
		case 'e': *out = 0xae; break;
		case 'f': *out = 0xaf; break;
		case 'A': *out = 0xaa; break;
		case 'B': *out = 0xab; break;
		case 'C': *out = 0xac; break;
		case 'D': *out = 0xad; break;
		case 'E': *out = 0xae; break;
		case 'F': *out = 0xaf; break;
		} break;
	case 'b':
		switch (in1) {
		case '0': *out = 0xb0; break;
		case '1': *out = 0xb1; break;
		case '2': *out = 0xb2; break;
		case '3': *out = 0xb3; break;
		case '4': *out = 0xb4; break;
		case '5': *out = 0xb5; break;
		case '6': *out = 0xb6; break;
		case '7': *out = 0xb7; break;
		case '8': *out = 0xb8; break;
		case '9': *out = 0xb9; break;
		case 'a': *out = 0xba; break;
		case 'b': *out = 0xbb; break;
		case 'c': *out = 0xbc; break;
		case 'd': *out = 0xbd; break;
		case 'e': *out = 0xbe; break;
		case 'f': *out = 0xbf; break;
		case 'A': *out = 0xba; break;
		case 'B': *out = 0xbb; break;
		case 'C': *out = 0xbc; break;
		case 'D': *out = 0xbd; break;
		case 'E': *out = 0xbe; break;
		case 'F': *out = 0xbf; break;
		} break;
	case 'c':
		switch (in1) {
		case '0': *out = 0xc0; break;
		case '1': *out = 0xc1; break;
		case '2': *out = 0xc2; break;
		case '3': *out = 0xc3; break;
		case '4': *out = 0xc4; break;
		case '5': *out = 0xc5; break;
		case '6': *out = 0xc6; break;
		case '7': *out = 0xc7; break;
		case '8': *out = 0xc8; break;
		case '9': *out = 0xc9; break;
		case 'a': *out = 0xca; break;
		case 'b': *out = 0xcb; break;
		case 'c': *out = 0xcc; break;
		case 'd': *out = 0xcd; break;
		case 'e': *out = 0xce; break;
		case 'f': *out = 0xcf; break;
		case 'A': *out = 0xca; break;
		case 'B': *out = 0xcb; break;
		case 'C': *out = 0xcc; break;
		case 'D': *out = 0xcd; break;
		case 'E': *out = 0xce; break;
		case 'F': *out = 0xcf; break;
		} break;
	case 'd':
		switch (in1) {
		case '0': *out = 0xd0; break;
		case '1': *out = 0xd1; break;
		case '2': *out = 0xd2; break;
		case '3': *out = 0xd3; break;
		case '4': *out = 0xd4; break;
		case '5': *out = 0xd5; break;
		case '6': *out = 0xd6; break;
		case '7': *out = 0xd7; break;
		case '8': *out = 0xd8; break;
		case '9': *out = 0xd9; break;
		case 'a': *out = 0xda; break;
		case 'b': *out = 0xdb; break;
		case 'c': *out = 0xdc; break;
		case 'd': *out = 0xdd; break;
		case 'e': *out = 0xde; break;
		case 'f': *out = 0xdf; break;
		case 'A': *out = 0xda; break;
		case 'B': *out = 0xdb; break;
		case 'C': *out = 0xdc; break;
		case 'D': *out = 0xdd; break;
		case 'E': *out = 0xde; break;
		case 'F': *out = 0xdf; break;
		} break;
	case 'e':
		switch (in1) {
		case '0': *out = 0xe0; break;
		case '1': *out = 0xe1; break;
		case '2': *out = 0xe2; break;
		case '3': *out = 0xe3; break;
		case '4': *out = 0xe4; break;
		case '5': *out = 0xe5; break;
		case '6': *out = 0xe6; break;
		case '7': *out = 0xe7; break;
		case '8': *out = 0xe8; break;
		case '9': *out = 0xe9; break;
		case 'a': *out = 0xea; break;
		case 'b': *out = 0xeb; break;
		case 'c': *out = 0xec; break;
		case 'd': *out = 0xed; break;
		case 'e': *out = 0xee; break;
		case 'f': *out = 0xef; break;
		case 'A': *out = 0xea; break;
		case 'B': *out = 0xeb; break;
		case 'C': *out = 0xec; break;
		case 'D': *out = 0xed; break;
		case 'E': *out = 0xee; break;
		case 'F': *out = 0xef; break;
		} break;
	case 'f':
		switch (in1) {
		case '0': *out = 0xf0; break;
		case '1': *out = 0xf1; break;
		case '2': *out = 0xf2; break;
		case '3': *out = 0xf3; break;
		case '4': *out = 0xf4; break;
		case '5': *out = 0xf5; break;
		case '6': *out = 0xf6; break;
		case '7': *out = 0xf7; break;
		case '8': *out = 0xf8; break;
		case '9': *out = 0xf9; break;
		case 'a': *out = 0xfa; break;
		case 'b': *out = 0xfb; break;
		case 'c': *out = 0xfc; break;
		case 'd': *out = 0xfd; break;
		case 'e': *out = 0xfe; break;
		case 'f': *out = 0xff; break;
		case 'A': *out = 0xfa; break;
		case 'B': *out = 0xfb; break;
		case 'C': *out = 0xfc; break;
		case 'D': *out = 0xfd; break;
		case 'E': *out = 0xfe; break;
		case 'F': *out = 0xff; break;
		} break;
	case 'A':
		switch (in1) {
		case '0': *out = 0xa0; break;
		case '1': *out = 0xa1; break;
		case '2': *out = 0xa2; break;
		case '3': *out = 0xa3; break;
		case '4': *out = 0xa4; break;
		case '5': *out = 0xa5; break;
		case '6': *out = 0xa6; break;
		case '7': *out = 0xa7; break;
		case '8': *out = 0xa8; break;
		case '9': *out = 0xa9; break;
		case 'a': *out = 0xaa; break;
		case 'b': *out = 0xab; break;
		case 'c': *out = 0xac; break;
		case 'd': *out = 0xad; break;
		case 'e': *out = 0xae; break;
		case 'f': *out = 0xaf; break;
		case 'A': *out = 0xaa; break;
		case 'B': *out = 0xab; break;
		case 'C': *out = 0xac; break;
		case 'D': *out = 0xad; break;
		case 'E': *out = 0xae; break;
		case 'F': *out = 0xaf; break;
		} break;
	case 'B':
		switch (in1) {
		case '0': *out = 0xb0; break;
		case '1': *out = 0xb1; break;
		case '2': *out = 0xb2; break;
		case '3': *out = 0xb3; break;
		case '4': *out = 0xb4; break;
		case '5': *out = 0xb5; break;
		case '6': *out = 0xb6; break;
		case '7': *out = 0xb7; break;
		case '8': *out = 0xb8; break;
		case '9': *out = 0xb9; break;
		case 'a': *out = 0xba; break;
		case 'b': *out = 0xbb; break;
		case 'c': *out = 0xbc; break;
		case 'd': *out = 0xbd; break;
		case 'e': *out = 0xbe; break;
		case 'f': *out = 0xbf; break;
		case 'A': *out = 0xba; break;
		case 'B': *out = 0xbb; break;
		case 'C': *out = 0xbc; break;
		case 'D': *out = 0xbd; break;
		case 'E': *out = 0xbe; break;
		case 'F': *out = 0xbf; break;
		} break;
	case 'C':
		switch (in1) {
		case '0': *out = 0xc0; break;
		case '1': *out = 0xc1; break;
		case '2': *out = 0xc2; break;
		case '3': *out = 0xc3; break;
		case '4': *out = 0xc4; break;
		case '5': *out = 0xc5; break;
		case '6': *out = 0xc6; break;
		case '7': *out = 0xc7; break;
		case '8': *out = 0xc8; break;
		case '9': *out = 0xc9; break;
		case 'a': *out = 0xca; break;
		case 'b': *out = 0xcb; break;
		case 'c': *out = 0xcc; break;
		case 'd': *out = 0xcd; break;
		case 'e': *out = 0xce; break;
		case 'f': *out = 0xcf; break;
		case 'A': *out = 0xca; break;
		case 'B': *out = 0xcb; break;
		case 'C': *out = 0xcc; break;
		case 'D': *out = 0xcd; break;
		case 'E': *out = 0xce; break;
		case 'F': *out = 0xcf; break;
		} break;
	case 'D':
		switch (in1) {
		case '0': *out = 0xd0; break;
		case '1': *out = 0xd1; break;
		case '2': *out = 0xd2; break;
		case '3': *out = 0xd3; break;
		case '4': *out = 0xd4; break;
		case '5': *out = 0xd5; break;
		case '6': *out = 0xd6; break;
		case '7': *out = 0xd7; break;
		case '8': *out = 0xd8; break;
		case '9': *out = 0xd9; break;
		case 'a': *out = 0xda; break;
		case 'b': *out = 0xdb; break;
		case 'c': *out = 0xdc; break;
		case 'd': *out = 0xdd; break;
		case 'e': *out = 0xde; break;
		case 'f': *out = 0xdf; break;
		case 'A': *out = 0xda; break;
		case 'B': *out = 0xdb; break;
		case 'C': *out = 0xdc; break;
		case 'D': *out = 0xdd; break;
		case 'E': *out = 0xde; break;
		case 'F': *out = 0xdf; break;
		} break;
	case 'E':
		switch (in1) {
		case '0': *out = 0xe0; break;
		case '1': *out = 0xe1; break;
		case '2': *out = 0xe2; break;
		case '3': *out = 0xe3; break;
		case '4': *out = 0xe4; break;
		case '5': *out = 0xe5; break;
		case '6': *out = 0xe6; break;
		case '7': *out = 0xe7; break;
		case '8': *out = 0xe8; break;
		case '9': *out = 0xe9; break;
		case 'a': *out = 0xea; break;
		case 'b': *out = 0xeb; break;
		case 'c': *out = 0xec; break;
		case 'd': *out = 0xed; break;
		case 'e': *out = 0xee; break;
		case 'f': *out = 0xef; break;
		case 'A': *out = 0xea; break;
		case 'B': *out = 0xeb; break;
		case 'C': *out = 0xec; break;
		case 'D': *out = 0xed; break;
		case 'E': *out = 0xee; break;
		case 'F': *out = 0xef; break;
		} break;
	case 'F':
		switch (in1) {
		case '0': *out = 0xf0; break;
		case '1': *out = 0xf1; break;
		case '2': *out = 0xf2; break;
		case '3': *out = 0xf3; break;
		case '4': *out = 0xf4; break;
		case '5': *out = 0xf5; break;
		case '6': *out = 0xf6; break;
		case '7': *out = 0xf7; break;
		case '8': *out = 0xf8; break;
		case '9': *out = 0xf9; break;
		case 'a': *out = 0xfa; break;
		case 'b': *out = 0xfb; break;
		case 'c': *out = 0xfc; break;
		case 'd': *out = 0xfd; break;
		case 'e': *out = 0xfe; break;
		case 'f': *out = 0xff; break;
		case 'A': *out = 0xfa; break;
		case 'B': *out = 0xfb; break;
		case 'C': *out = 0xfc; break;
		case 'D': *out = 0xfd; break;
		case 'E': *out = 0xfe; break;
		case 'F': *out = 0xff; break;
		} break;
	}

}


void print_title_demo() {

	/*
	printf("\n%s", "  ___ _____   _____ _____ ___      _   ___ ___");
	printf("\n%s", " / __ | _ \\ \\ / / _ \\_   _ / _ \\ / _\\ | _ \\_ _|");
	printf("\n%s", "| (__|   /\\ V /|  _/ | || (_) |  / _ \\ | _/| |");
	printf("\n%s", " \\___| _ | _\\ | _| |_|   |_ | \\___/  /_ / \\_\\_| |___ |");
	*/
	 // https://patorjk.com/software/taag/#p=testall&v=0&f=Small&t=CRYPTO%20API

	printf("\n\t ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗      █████╗ ██████╗ ██╗");
	printf("\n\t██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗    ██╔══██╗██╔══██╗██║");
	printf("\n\t██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║    ███████║██████╔╝██║");
	printf("\n\t██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║    ██╔══██║██╔═══╝ ██║");
	printf("\n\t╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝    ██║  ██║██║     ██║");
	printf("\n\t ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝     ╚═╝  ╚═╝╚═╝     ╚═╝");
	printf("\n\t Developer: Eros Camacho Ruiz                                         v6.3");
	printf("\n\n");






}


#ifdef CRYPTO_ARM
uint32_t timeInMicroseconds() {
	return HAL_GetTick(); // (now - epochMilli) ;
}
#else
uint64_t timeInMicroseconds() {
	struct timeval tv;
	uint64_t now;
	gettimeofday(&tv, NULL);
	now = (uint64_t)tv.tv_sec * (uint64_t)1000000 + (uint64_t)tv.tv_usec; // in us
	return (uint64_t)now; // (now - epochMilli) ;
}
#endif