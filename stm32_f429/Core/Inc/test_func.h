#ifndef TEST_FUNC_H
#define	TEST_FUNC_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <sys/time.h>
#include "se-qubip.h"

typedef struct {
	unsigned int aes;
	unsigned int sha3;
	unsigned int sha2;
	unsigned int eddsa;
	unsigned int ecdh;
	unsigned int mlkem;
	unsigned int drbg;
	unsigned int n_test;
} data_conf;


typedef struct {
	uint64_t time_mean_value;
	uint64_t time_max_value;
	uint64_t time_min_value;
	uint64_t val_result;
} time_result;

#ifdef AXI
    void load_bitstream(char* BITSTREAM_FILE);
#endif

int test_random(unsigned char* random, unsigned int size);
void print_result_valid(unsigned char* str, unsigned int fail);
void print_result_double_valid(unsigned char* str, unsigned char* str2, unsigned int fail);
void print_results(unsigned int verb, unsigned int n_test, time_result tr);
void print_results_str_1_tab_3(unsigned int n_test, unsigned char* str, time_result tr1, time_result tr2, time_result tr3);
void print_results_str_1_tab_2(unsigned int n_test, unsigned char* str, time_result tr1, time_result tr2);
void print_results_str_1_tab_1(unsigned int n_test, unsigned char* str, time_result tr);
void print_results_str_2_tab_1(unsigned int n_test, unsigned char* str1, unsigned char* str2, time_result tr);
void print_results_str_1_tab_2_acc(unsigned int n_test, unsigned char* str, time_result tr1_hw, time_result tr2_hw, time_result tr1_sw, time_result tr2_sw);
void print_results_str_1_tab_1_acc(unsigned int n_test, unsigned char* str, time_result tr_hw, time_result tr_sw);
void print_results_str_1_tab_3_acc(unsigned int n_test, unsigned char* str, time_result tr1_hw, time_result tr2_hw, time_result tr3_hw, time_result tr1_sw, time_result tr2_sw, time_result tr3_sw);
void print_results_str_2_tab_1_acc(unsigned int n_test, unsigned char* str1, unsigned char* str2, time_result tr_hw, time_result tr_sw);
void read_conf(data_conf* data);
void start_demo_csic_se();

void show_array(const unsigned char* r, const unsigned int size, const unsigned int mod);
int cmpchar(unsigned char* in1, unsigned char* in2, unsigned int len);
void char2hex(unsigned char* in, unsigned char* out);
void char_to_hex(unsigned char in0, unsigned char in1, unsigned char* out);
uint64_t timeInMicroseconds();

void print_title_demo();

#endif
