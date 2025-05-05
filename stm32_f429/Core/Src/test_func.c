
#include "../Inc/test_func.h"
#include "qubip.h"
#define thres 10 // threshold in percentage around 50%

int test_random(unsigned char *random, unsigned int size) {

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
	int val_max = (8.0 * size * ((50 + thres) / (1.0 * 100)));
	int val_min = (8.0 * size * ((50 - thres) / (1.0 * 100)));

	// printf("\n %d %d %d", num_ones, val_max, val_min);

	if ((num_ones < val_max) & (num_ones > val_min))
		result = 0;
	else
		result = 1;

	return result;

}

void print_result_valid(unsigned char *str, unsigned int fail) {
	if (!fail)
		printf("\n %-30s | \033[1;32m\u2705\033[0m", str);
	else
		printf("\n %-30s | \033[1;31m\u274c\033[0m ", str);
}

void print_result_double_valid(unsigned char *str, unsigned char *str2,
		unsigned int fail) {
	if (!fail)
		printf("\n %-14s %-15s | \033[1;32m\u2705\033[0m ", str, str2);
	else
		printf("\n %-14s %-15s | \033[1;31m\u274c\033[0m ", str, str2);
}

void read_conf(data_conf *data) {

	unsigned char name[20] = "config.conf";

	FILE *fp;
	fp = fopen(name, "r");

	unsigned char str[20];

	unsigned int ind = 0;
	unsigned int ind_vread = 0;
	unsigned int vread[10];

	while (fgets(str, 20, fp)) {
		// printf("%s", str);
		char *token;
		char *delimiter = "\t";
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

	data->aes = vread[0];
	data->sha3 = vread[1];
	data->sha2 = vread[2];
	data->eddsa = vread[3];
	data->ecdh = vread[4];
	data->mlkem = vread[5];
	data->drbg = vread[6];
	data->n_test = vread[7];

	fclose(fp);

}

void print_results(unsigned int verb, unsigned int n_test, time_result tr) {

	printf("\n mean sw: %.3f s \t %.3f ms \t %d us",
			tr.time_mean_value / 1000000.0, tr.time_mean_value / 1000.0,
			(unsigned int) tr.time_mean_value);
	if (verb >= 1)
		printf("\n max sw: %.3f s \t %.3f ms \t %d us",
				tr.time_max_value / 1000000.0, tr.time_max_value / 1000.0,
				(unsigned int) tr.time_max_value);
	if (verb >= 1)
		printf("\n min sw: %.3f s \t %.3f ms \t %d us",
				tr.time_min_value / 1000000.0, tr.time_min_value / 1000.0,
				(unsigned int) tr.time_min_value);
	printf("\n val result: %d /", (unsigned int) tr.val_result);
	printf(" %d", n_test);

}

void print_results_str_1_tab_3(unsigned int n_test, unsigned char *str,
		time_result tr1, time_result tr2, time_result tr3) {

	double time1_s = tr1.time_mean_value / 1000000.0;
	double time1_ms = tr1.time_mean_value / 1000.0;
	unsigned int time1_us = tr1.time_mean_value;

	double time2_s = tr2.time_mean_value / 1000000.0;
	double time2_ms = tr2.time_mean_value / 1000.0;
	unsigned int time2_us = tr2.time_mean_value;

	double time3_s = tr3.time_mean_value / 1000000.0;
	double time3_ms = tr3.time_mean_value / 1000.0;
	unsigned int time3_us = tr3.time_mean_value;

	// unsigned char time_s[20];	sprintf(time_s,		"%.3f / %.3f", time1_s,  time2_s);
	unsigned char time_ms[30];
	sprintf(time_ms, "%.3f / %.3f / %.3f", time1_ms, time2_ms, time3_ms);
	unsigned char time_us[30];
	sprintf(time_us, "%d / %d / %d", time1_us, time2_us, time3_us);
	unsigned char s_test[20];
	if (tr3.val_result != 0xFFFFFFFF)
		sprintf(s_test, "%d / %d", (unsigned int) tr3.val_result, n_test);
	else
		strcpy(s_test, "-");

	// printf("\n %-30s | %-25s | %-25s | %-25s | %-15s ", str, time_s, time_ms, time_us, s_test);
	printf("\n %-30s | %-30s | %-30s | %-15s ", str, time_ms, time_us, s_test);

}

void print_results_str_1_tab_3_acc(unsigned int n_test, unsigned char *str,
		time_result tr1_hw, time_result tr2_hw, time_result tr3_hw,
		time_result tr1_sw, time_result tr2_sw, time_result tr3_sw) {

	unsigned int time1_hw_us = tr1_hw.time_mean_value;
	unsigned int time2_hw_us = tr2_hw.time_mean_value;
	unsigned int time3_hw_us = tr3_hw.time_mean_value;
	unsigned int time1_sw_us = tr1_sw.time_mean_value;
	unsigned int time2_sw_us = tr2_sw.time_mean_value;
	unsigned int time3_sw_us = tr3_sw.time_mean_value;

	// unsigned char time_s[20];	sprintf(time_s,		"%.3f / %.3f", time1_s,  time2_s);
	unsigned char time_us_hw[20];
	sprintf(time_us_hw, "%d / %d / %d", time1_hw_us, time2_hw_us, time3_hw_us);
	unsigned char time_us_sw[20];
	sprintf(time_us_sw, "%d / %d / %d", time1_sw_us, time2_sw_us, time3_sw_us);

	// Print acc with colours
	double acc_1 = (double) time1_sw_us / (double) time1_hw_us;
	double acc_2 = (double) time2_sw_us / (double) time2_hw_us;
	double acc_3 = (double) time3_sw_us / (double) time3_hw_us;
	unsigned char acc_1_text[30];
	unsigned char acc_2_text[30];
	unsigned char acc_3_text[30];
	if (acc_1 > 1)
		sprintf(acc_1_text, "\x1b[32m\x1b[1m%.2f\x1b[0m", acc_1); // green https://talyian.github.io/ansicolors/
	else
		sprintf(acc_1_text, "\x1b[31m\x1b[1m%.2f\x1b[0m", acc_1); // red
	if (acc_2 > 1)
		sprintf(acc_2_text, "\x1b[32m\x1b[1m%.2f\x1b[0m", acc_2); // green
	else
		sprintf(acc_2_text, "\x1b[31m\x1b[1m%.2f\x1b[0m", acc_2); // red
	if (acc_3 > 1)
		sprintf(acc_3_text, "\x1b[32m\x1b[1m%.2f\x1b[0m", acc_3); // green
	else
		sprintf(acc_3_text, "\x1b[31m\x1b[1m%.2f\x1b[0m", acc_3); // red

	unsigned char acc[120];
	sprintf(acc, "%s / %s / %s", acc_1_text, acc_2_text, acc_3_text);

	unsigned char s_test[20];
	if (tr3_hw.val_result != 0xFFFFFFFF)
		sprintf(s_test, "%d / %d", (unsigned int) tr3_hw.val_result, n_test);
	else
		strcpy(s_test, "-");

	// printf("\n %-30s | %-25s | %-25s | %-25s | %-15s ", str, time_s, time_ms, time_us, s_test);
	printf("\n %-30s | %-30s | %-30s | %-69s | %-15s ", str, time_us_hw,
			time_us_sw, acc, s_test); // 56 purely empirical value

}

void print_results_str_1_tab_2(unsigned int n_test, unsigned char *str,
		time_result tr1, time_result tr2) {

	double time1_s = tr1.time_mean_value / 1000000.0;
	double time1_ms = tr1.time_mean_value / 1000.0;
	unsigned int time1_us = tr1.time_mean_value;

	double time2_s = tr2.time_mean_value / 1000000.0;
	double time2_ms = tr2.time_mean_value / 1000.0;
	unsigned int time2_us = tr2.time_mean_value;

	// unsigned char time_s[20];	sprintf(time_s,		"%.3f / %.3f", time1_s,  time2_s);
	unsigned char time_ms[20];
	sprintf(time_ms, "%.3f / %.3f", time1_ms, time2_ms);
	unsigned char time_us[20];
	sprintf(time_us, "%d / %d", time1_us, time2_us);
	unsigned char s_test[20];
	if (tr2.val_result != 0xFFFFFFFF)
		sprintf(s_test, "%d / %d", (unsigned int) tr2.val_result, n_test);
	else
		strcpy(s_test, "-");

	// printf("\n %-30s | %-25s | %-25s | %-25s | %-15s ", str, time_s, time_ms, time_us, s_test);
	printf("\n %-30s | %-30s | %-30s | %-15s ", str, time_ms, time_us, s_test);

}

void print_results_str_1_tab_2_acc(unsigned int n_test, unsigned char *str,
		time_result tr1_hw, time_result tr2_hw, time_result tr1_sw,
		time_result tr2_sw) {

	unsigned int time1_hw_us = tr1_hw.time_mean_value;
	unsigned int time2_hw_us = tr2_hw.time_mean_value;
	unsigned int time1_sw_us = tr1_sw.time_mean_value;
	unsigned int time2_sw_us = tr2_sw.time_mean_value;

	// unsigned char time_s[20];	sprintf(time_s,		"%.3f / %.3f", time1_s,  time2_s);
	unsigned char time_us_hw[20];
	sprintf(time_us_hw, "%d / %d", time1_hw_us, time2_hw_us);
	unsigned char time_us_sw[20];
	sprintf(time_us_sw, "%d / %d", time1_sw_us, time2_sw_us);

	// Print acc with colours
	double acc_1 = (double) time1_sw_us / (double) time1_hw_us;
	double acc_2 = (double) time2_sw_us / (double) time2_hw_us;
	unsigned char acc_1_text[30];
	unsigned char acc_2_text[30];
	if (acc_1 > 1)
		sprintf(acc_1_text, "\x1b[32m\x1b[1m%.2f\x1b[0m", acc_1); // green https://talyian.github.io/ansicolors/
	else
		sprintf(acc_1_text, "\x1b[31m\x1b[1m%.2f\x1b[0m", acc_1); // red
	if (acc_2 > 1)
		sprintf(acc_2_text, "\x1b[32m\x1b[1m%.2f\x1b[0m", acc_2); // green
	else
		sprintf(acc_2_text, "\x1b[31m\x1b[1m%.2f\x1b[0m", acc_2); // red

	unsigned char acc[80];
	sprintf(acc, "%s / %s", acc_1_text, acc_2_text);

	unsigned char s_test[20];
	if (tr2_hw.val_result != 0xFFFFFFFF)
		sprintf(s_test, "%d / %d", (unsigned int) tr2_hw.val_result, n_test);
	else
		strcpy(s_test, "-");

	// printf("\n %-30s | %-25s | %-25s | %-25s | %-15s ", str, time_s, time_ms, time_us, s_test);
	printf("\n %-30s | %-30s | %-30s | %-56s | %-15s ", str, time_us_hw,
			time_us_sw, acc, s_test); // 56 purely empirical value

}

void print_results_str_1_tab_1(unsigned int n_test, unsigned char *str,
		time_result tr) {

	double time1_s = tr.time_mean_value / 1000000.0;
	double time1_ms = tr.time_mean_value / 1000.0;
	unsigned int time1_us = tr.time_mean_value;

	// unsigned char time_s[20];	sprintf(time_s,		"%.3f / %.3f", time1_s,  time2_s);
	unsigned char time_ms[20];
	sprintf(time_ms, "%.3f", time1_ms);
	unsigned char time_us[20];
	sprintf(time_us, "%d", time1_us);
	unsigned char s_test[20];
	if (tr.val_result != 0xFFFFFFFF)
		sprintf(s_test, "%d / %d", (unsigned int) tr.val_result, n_test);
	else
		strcpy(s_test, "-");

	// printf("\n %-30s | %-25s | %-25s | %-25s | %-15s ", str, time_s, time_ms, time_us, s_test);
	printf("\n %-30s | %-30s | %-30s | %-15s ", str, time_ms, time_us, s_test);

}

void print_results_str_1_tab_1_acc(unsigned int n_test, unsigned char *str,
		time_result tr_hw, time_result tr_sw) {

	unsigned int time_hw_us = tr_hw.time_mean_value;
	unsigned int time_sw_us = tr_sw.time_mean_value;

	// unsigned char time_s[20];	sprintf(time_s,		"%.3f / %.3f", time1_s,  time2_s);
	unsigned char time_us_hw[20];
	sprintf(time_us_hw, "%d / %d", time_hw_us, time_hw_us);
	unsigned char time_us_sw[20];
	sprintf(time_us_sw, "%d / %d", time_sw_us, time_sw_us);

	// Print acc with colours
	double acc_1 = (double) time_sw_us / (double) time_hw_us;
	unsigned char acc_1_text[30];
	if (acc_1 > 1)
		sprintf(acc_1_text, "\x1b[32m\x1b[1m%.2f\x1b[0m", acc_1); // green https://talyian.github.io/ansicolors/
	else
		sprintf(acc_1_text, "\x1b[31m\x1b[1m%.2f\x1b[0m", acc_1); // red

	unsigned char acc[80];
	sprintf(acc, "%s", acc_1_text);

	unsigned char s_test[20];
	if (tr_hw.val_result != 0xFFFFFFFF)
		sprintf(s_test, "%d / %d", (unsigned int) tr_hw.val_result, n_test);
	else
		strcpy(s_test, "-");

	// printf("\n %-30s | %-25s | %-25s | %-25s | %-15s ", str, time_s, time_ms, time_us, s_test);
	printf("\n %-30s | %-30s | %-30s | %-43s | %-15s ", str, time_us_hw,
			time_us_sw, acc, s_test); // 30 purely empirical value

}

void print_results_str_2_tab_1(unsigned int n_test, unsigned char *str1,
		unsigned char *str2, time_result tr) {

	double time1_s = tr.time_mean_value / 1000000.0;
	double time1_ms = tr.time_mean_value / 1000.0;
	unsigned int time1_us = tr.time_mean_value;

	// unsigned char time_s[20];	sprintf(time_s,		"%.3f / %.3f", time1_s,  time2_s);
	unsigned char time_ms[20];
	sprintf(time_ms, "%.3f", time1_ms);
	unsigned char time_us[20];
	sprintf(time_us, "%d", time1_us);
	unsigned char s_test[20];
	if (tr.val_result != 0xFFFFFFFF)
		sprintf(s_test, "%d / %d", (unsigned int) tr.val_result, n_test);
	else
		strcpy(s_test, "-");

	// printf("\n %-30s | %-25s | %-25s | %-25s | %-15s ", str, time_s, time_ms, time_us, s_test);
	printf("\n %-14s %-15s | %-30s | %-30s | %-15s ", str1, str2, time_ms,
			time_us, s_test);

}

void print_results_str_2_tab_1_acc(unsigned int n_test, unsigned char *str1,
		unsigned char *str2, time_result tr_hw, time_result tr_sw) {

	unsigned int time_hw_us = tr_hw.time_mean_value;
	unsigned int time_sw_us = tr_sw.time_mean_value;

	// unsigned char time_s[20];	sprintf(time_s,		"%.3f / %.3f", time1_s,  time2_s);
	unsigned char time_us_hw[20];
	sprintf(time_us_hw, "%d / %d", time_hw_us, time_hw_us);
	unsigned char time_us_sw[20];
	sprintf(time_us_sw, "%d / %d", time_sw_us, time_sw_us);

	// Print acc with colours
	double acc_1 = (double) time_sw_us / (double) time_hw_us;
	unsigned char acc_1_text[30];
	if (acc_1 > 1)
		sprintf(acc_1_text, "\x1b[32m\x1b[1m%.2f\x1b[0m", acc_1); // green https://talyian.github.io/ansicolors/
	else
		sprintf(acc_1_text, "\x1b[31m\x1b[1m%.2f\x1b[0m", acc_1); // red

	unsigned char acc[80];
	sprintf(acc, "%s", acc_1_text);

	unsigned char s_test[20];
	if (tr_hw.val_result != 0xFFFFFFFF)
		sprintf(s_test, "%d / %d", (unsigned int) tr_hw.val_result, n_test);
	else
		strcpy(s_test, "-");

	// printf("\n %-30s | %-25s | %-25s | %-25s | %-15s ", str, time_s, time_ms, time_us, s_test);
	printf("\n %-14s %-15s | %-30s | %-30s | %-43s | %-15s ", str1, str2,
			time_us_hw, time_us_sw, acc, s_test); // 43 purely empirical value

}

#ifdef AXI
void load_bitstream(char* BITSTREAM_FILE)
{
	unsigned long long tic = 0, toc;
	int Status;
	char bitstream_file[80];

	sprintf(bitstream_file, "%s", BITSTREAM_FILE);

	FILE* file;

	if (!(file = fopen(bitstream_file, "r"))) {
		printf("\n   Bitstream not available. Bye ...\n\n");
	}
	fclose(file);

	Status = PYNQ_loadBitstream(bitstream_file);
	if (Status != PYNQ_SUCCESS) {
		printf(" Failed Loading !!!\n");
	}
}
#endif

void show_array(const unsigned char *r, const unsigned int size,
		const unsigned int mod) {

	unsigned int ind = 0;

	printf("\n");
	for (int i = 0; i < (int) ceil((double) size / (double) mod); i++) {
		for (int j = 0; j < mod; j++) {
			ind = i * mod + j;
			if (ind < size)
				printf("%02x", r[ind]);
			else
				printf("  ");
		}
		printf("\n");
	}
}

int cmpchar(unsigned char *in1, unsigned char *in2, unsigned int len) {

	int cmp = 0;

	for (int i = 0; i < len; i++) {
		if (in1[i] != in2[i]) {
			cmp = 1;
			return cmp;
		} else
			cmp = 0;
	}
	return cmp;

}

void char2hex(unsigned char *in, unsigned char *out) {

	unsigned int index = 0;
	unsigned char char_out;

	for (int i = 0; i < (int) (strlen(in) / 2); i++) {
		index = 2 * i;
		char_to_hex(in[index], in[index + 1], &char_out);
		out[i] = char_out;
	}

}

void char_to_hex(unsigned char in0, unsigned char in1, unsigned char *out) {

	switch (in0) {
	case '0':
		switch (in1) {
		case '0':
			*out = 0x00;
			break;
		case '1':
			*out = 0x01;
			break;
		case '2':
			*out = 0x02;
			break;
		case '3':
			*out = 0x03;
			break;
		case '4':
			*out = 0x04;
			break;
		case '5':
			*out = 0x05;
			break;
		case '6':
			*out = 0x06;
			break;
		case '7':
			*out = 0x07;
			break;
		case '8':
			*out = 0x08;
			break;
		case '9':
			*out = 0x09;
			break;
		case 'a':
			*out = 0x0a;
			break;
		case 'b':
			*out = 0x0b;
			break;
		case 'c':
			*out = 0x0c;
			break;
		case 'd':
			*out = 0x0d;
			break;
		case 'e':
			*out = 0x0e;
			break;
		case 'f':
			*out = 0x0f;
			break;
		}
		break;
	case '1':
		switch (in1) {
		case '0':
			*out = 0x10;
			break;
		case '1':
			*out = 0x11;
			break;
		case '2':
			*out = 0x12;
			break;
		case '3':
			*out = 0x13;
			break;
		case '4':
			*out = 0x14;
			break;
		case '5':
			*out = 0x15;
			break;
		case '6':
			*out = 0x16;
			break;
		case '7':
			*out = 0x17;
			break;
		case '8':
			*out = 0x18;
			break;
		case '9':
			*out = 0x19;
			break;
		case 'a':
			*out = 0x1a;
			break;
		case 'b':
			*out = 0x1b;
			break;
		case 'c':
			*out = 0x1c;
			break;
		case 'd':
			*out = 0x1d;
			break;
		case 'e':
			*out = 0x1e;
			break;
		case 'f':
			*out = 0x1f;
			break;
		}
		break;
	case '2':
		switch (in1) {
		case '0':
			*out = 0x20;
			break;
		case '1':
			*out = 0x21;
			break;
		case '2':
			*out = 0x22;
			break;
		case '3':
			*out = 0x23;
			break;
		case '4':
			*out = 0x24;
			break;
		case '5':
			*out = 0x25;
			break;
		case '6':
			*out = 0x26;
			break;
		case '7':
			*out = 0x27;
			break;
		case '8':
			*out = 0x28;
			break;
		case '9':
			*out = 0x29;
			break;
		case 'a':
			*out = 0x2a;
			break;
		case 'b':
			*out = 0x2b;
			break;
		case 'c':
			*out = 0x2c;
			break;
		case 'd':
			*out = 0x2d;
			break;
		case 'e':
			*out = 0x2e;
			break;
		case 'f':
			*out = 0x2f;
			break;
		}
		break;
	case '3':
		switch (in1) {
		case '0':
			*out = 0x30;
			break;
		case '1':
			*out = 0x31;
			break;
		case '2':
			*out = 0x32;
			break;
		case '3':
			*out = 0x33;
			break;
		case '4':
			*out = 0x34;
			break;
		case '5':
			*out = 0x35;
			break;
		case '6':
			*out = 0x36;
			break;
		case '7':
			*out = 0x37;
			break;
		case '8':
			*out = 0x38;
			break;
		case '9':
			*out = 0x39;
			break;
		case 'a':
			*out = 0x3a;
			break;
		case 'b':
			*out = 0x3b;
			break;
		case 'c':
			*out = 0x3c;
			break;
		case 'd':
			*out = 0x3d;
			break;
		case 'e':
			*out = 0x3e;
			break;
		case 'f':
			*out = 0x3f;
			break;
		}
		break;
	case '4':
		switch (in1) {
		case '0':
			*out = 0x40;
			break;
		case '1':
			*out = 0x41;
			break;
		case '2':
			*out = 0x42;
			break;
		case '3':
			*out = 0x43;
			break;
		case '4':
			*out = 0x44;
			break;
		case '5':
			*out = 0x45;
			break;
		case '6':
			*out = 0x46;
			break;
		case '7':
			*out = 0x47;
			break;
		case '8':
			*out = 0x48;
			break;
		case '9':
			*out = 0x49;
			break;
		case 'a':
			*out = 0x4a;
			break;
		case 'b':
			*out = 0x4b;
			break;
		case 'c':
			*out = 0x4c;
			break;
		case 'd':
			*out = 0x4d;
			break;
		case 'e':
			*out = 0x4e;
			break;
		case 'f':
			*out = 0x4f;
			break;
		}
		break;
	case '5':
		switch (in1) {
		case '0':
			*out = 0x50;
			break;
		case '1':
			*out = 0x51;
			break;
		case '2':
			*out = 0x52;
			break;
		case '3':
			*out = 0x53;
			break;
		case '4':
			*out = 0x54;
			break;
		case '5':
			*out = 0x55;
			break;
		case '6':
			*out = 0x56;
			break;
		case '7':
			*out = 0x57;
			break;
		case '8':
			*out = 0x58;
			break;
		case '9':
			*out = 0x59;
			break;
		case 'a':
			*out = 0x5a;
			break;
		case 'b':
			*out = 0x5b;
			break;
		case 'c':
			*out = 0x5c;
			break;
		case 'd':
			*out = 0x5d;
			break;
		case 'e':
			*out = 0x5e;
			break;
		case 'f':
			*out = 0x5f;
			break;
		}
		break;
	case '6':
		switch (in1) {
		case '0':
			*out = 0x60;
			break;
		case '1':
			*out = 0x61;
			break;
		case '2':
			*out = 0x62;
			break;
		case '3':
			*out = 0x63;
			break;
		case '4':
			*out = 0x64;
			break;
		case '5':
			*out = 0x65;
			break;
		case '6':
			*out = 0x66;
			break;
		case '7':
			*out = 0x67;
			break;
		case '8':
			*out = 0x68;
			break;
		case '9':
			*out = 0x69;
			break;
		case 'a':
			*out = 0x6a;
			break;
		case 'b':
			*out = 0x6b;
			break;
		case 'c':
			*out = 0x6c;
			break;
		case 'd':
			*out = 0x6d;
			break;
		case 'e':
			*out = 0x6e;
			break;
		case 'f':
			*out = 0x6f;
			break;
		}
		break;
	case '7':
		switch (in1) {
		case '0':
			*out = 0x70;
			break;
		case '1':
			*out = 0x71;
			break;
		case '2':
			*out = 0x72;
			break;
		case '3':
			*out = 0x73;
			break;
		case '4':
			*out = 0x74;
			break;
		case '5':
			*out = 0x75;
			break;
		case '6':
			*out = 0x76;
			break;
		case '7':
			*out = 0x77;
			break;
		case '8':
			*out = 0x78;
			break;
		case '9':
			*out = 0x79;
			break;
		case 'a':
			*out = 0x7a;
			break;
		case 'b':
			*out = 0x7b;
			break;
		case 'c':
			*out = 0x7c;
			break;
		case 'd':
			*out = 0x7d;
			break;
		case 'e':
			*out = 0x7e;
			break;
		case 'f':
			*out = 0x7f;
			break;
		}
		break;
	case '8':
		switch (in1) {
		case '0':
			*out = 0x80;
			break;
		case '1':
			*out = 0x81;
			break;
		case '2':
			*out = 0x82;
			break;
		case '3':
			*out = 0x83;
			break;
		case '4':
			*out = 0x84;
			break;
		case '5':
			*out = 0x85;
			break;
		case '6':
			*out = 0x86;
			break;
		case '7':
			*out = 0x87;
			break;
		case '8':
			*out = 0x88;
			break;
		case '9':
			*out = 0x89;
			break;
		case 'a':
			*out = 0x8a;
			break;
		case 'b':
			*out = 0x8b;
			break;
		case 'c':
			*out = 0x8c;
			break;
		case 'd':
			*out = 0x8d;
			break;
		case 'e':
			*out = 0x8e;
			break;
		case 'f':
			*out = 0x8f;
			break;
		}
		break;
	case '9':
		switch (in1) {
		case '0':
			*out = 0x90;
			break;
		case '1':
			*out = 0x91;
			break;
		case '2':
			*out = 0x92;
			break;
		case '3':
			*out = 0x93;
			break;
		case '4':
			*out = 0x94;
			break;
		case '5':
			*out = 0x95;
			break;
		case '6':
			*out = 0x96;
			break;
		case '7':
			*out = 0x97;
			break;
		case '8':
			*out = 0x98;
			break;
		case '9':
			*out = 0x99;
			break;
		case 'a':
			*out = 0x9a;
			break;
		case 'b':
			*out = 0x9b;
			break;
		case 'c':
			*out = 0x9c;
			break;
		case 'd':
			*out = 0x9d;
			break;
		case 'e':
			*out = 0x9e;
			break;
		case 'f':
			*out = 0x9f;
			break;
		}
		break;
	case 'a':
		switch (in1) {
		case '0':
			*out = 0xa0;
			break;
		case '1':
			*out = 0xa1;
			break;
		case '2':
			*out = 0xa2;
			break;
		case '3':
			*out = 0xa3;
			break;
		case '4':
			*out = 0xa4;
			break;
		case '5':
			*out = 0xa5;
			break;
		case '6':
			*out = 0xa6;
			break;
		case '7':
			*out = 0xa7;
			break;
		case '8':
			*out = 0xa8;
			break;
		case '9':
			*out = 0xa9;
			break;
		case 'a':
			*out = 0xaa;
			break;
		case 'b':
			*out = 0xab;
			break;
		case 'c':
			*out = 0xac;
			break;
		case 'd':
			*out = 0xad;
			break;
		case 'e':
			*out = 0xae;
			break;
		case 'f':
			*out = 0xaf;
			break;
		}
		break;
	case 'b':
		switch (in1) {
		case '0':
			*out = 0xb0;
			break;
		case '1':
			*out = 0xb1;
			break;
		case '2':
			*out = 0xb2;
			break;
		case '3':
			*out = 0xb3;
			break;
		case '4':
			*out = 0xb4;
			break;
		case '5':
			*out = 0xb5;
			break;
		case '6':
			*out = 0xb6;
			break;
		case '7':
			*out = 0xb7;
			break;
		case '8':
			*out = 0xb8;
			break;
		case '9':
			*out = 0xb9;
			break;
		case 'a':
			*out = 0xba;
			break;
		case 'b':
			*out = 0xbb;
			break;
		case 'c':
			*out = 0xbc;
			break;
		case 'd':
			*out = 0xbd;
			break;
		case 'e':
			*out = 0xbe;
			break;
		case 'f':
			*out = 0xbf;
			break;
		}
		break;
	case 'c':
		switch (in1) {
		case '0':
			*out = 0xc0;
			break;
		case '1':
			*out = 0xc1;
			break;
		case '2':
			*out = 0xc2;
			break;
		case '3':
			*out = 0xc3;
			break;
		case '4':
			*out = 0xc4;
			break;
		case '5':
			*out = 0xc5;
			break;
		case '6':
			*out = 0xc6;
			break;
		case '7':
			*out = 0xc7;
			break;
		case '8':
			*out = 0xc8;
			break;
		case '9':
			*out = 0xc9;
			break;
		case 'a':
			*out = 0xca;
			break;
		case 'b':
			*out = 0xcb;
			break;
		case 'c':
			*out = 0xcc;
			break;
		case 'd':
			*out = 0xcd;
			break;
		case 'e':
			*out = 0xce;
			break;
		case 'f':
			*out = 0xcf;
			break;
		}
		break;
	case 'd':
		switch (in1) {
		case '0':
			*out = 0xd0;
			break;
		case '1':
			*out = 0xd1;
			break;
		case '2':
			*out = 0xd2;
			break;
		case '3':
			*out = 0xd3;
			break;
		case '4':
			*out = 0xd4;
			break;
		case '5':
			*out = 0xd5;
			break;
		case '6':
			*out = 0xd6;
			break;
		case '7':
			*out = 0xd7;
			break;
		case '8':
			*out = 0xd8;
			break;
		case '9':
			*out = 0xd9;
			break;
		case 'a':
			*out = 0xda;
			break;
		case 'b':
			*out = 0xdb;
			break;
		case 'c':
			*out = 0xdc;
			break;
		case 'd':
			*out = 0xdd;
			break;
		case 'e':
			*out = 0xde;
			break;
		case 'f':
			*out = 0xdf;
			break;
		}
		break;
	case 'e':
		switch (in1) {
		case '0':
			*out = 0xe0;
			break;
		case '1':
			*out = 0xe1;
			break;
		case '2':
			*out = 0xe2;
			break;
		case '3':
			*out = 0xe3;
			break;
		case '4':
			*out = 0xe4;
			break;
		case '5':
			*out = 0xe5;
			break;
		case '6':
			*out = 0xe6;
			break;
		case '7':
			*out = 0xe7;
			break;
		case '8':
			*out = 0xe8;
			break;
		case '9':
			*out = 0xe9;
			break;
		case 'a':
			*out = 0xea;
			break;
		case 'b':
			*out = 0xeb;
			break;
		case 'c':
			*out = 0xec;
			break;
		case 'd':
			*out = 0xed;
			break;
		case 'e':
			*out = 0xee;
			break;
		case 'f':
			*out = 0xef;
			break;
		}
		break;
	case 'f':
		switch (in1) {
		case '0':
			*out = 0xf0;
			break;
		case '1':
			*out = 0xf1;
			break;
		case '2':
			*out = 0xf2;
			break;
		case '3':
			*out = 0xf3;
			break;
		case '4':
			*out = 0xf4;
			break;
		case '5':
			*out = 0xf5;
			break;
		case '6':
			*out = 0xf6;
			break;
		case '7':
			*out = 0xf7;
			break;
		case '8':
			*out = 0xf8;
			break;
		case '9':
			*out = 0xf9;
			break;
		case 'a':
			*out = 0xfa;
			break;
		case 'b':
			*out = 0xfb;
			break;
		case 'c':
			*out = 0xfc;
			break;
		case 'd':
			*out = 0xfd;
			break;
		case 'e':
			*out = 0xfe;
			break;
		case 'f':
			*out = 0xff;
			break;
		}
		break;
	}

}

uint64_t timeInMicroseconds() {
	struct timeval tv;
	uint64_t now;
	gettimeofday(&tv, NULL);
	now = (uint64_t) tv.tv_sec * (uint64_t) 1000000 + (uint64_t) tv.tv_usec; // in us
	return (uint64_t) now; // (now - epochMilli) ;
}

void print_title_demo() {

	printf("   _____                      _ _           _____      _   _                  \n"\
			"  / ____|                    (_) |         |  __ \\    | | | |                 \n"\
			" | (___   ___  ___ _   _ _ __ _| |_ _   _  | |__) |_ _| |_| |_ ___ _ __ _ __  \n"\
			"  \\___ \\ / _ \\/ __| | | | '__| | __| | | | |  ___/ _` | __| __/ _ \\ '__| '_ \\ \n"\
			"  ____) |  __/ (__| |_| | |  | | |_| |_| | | |  | (_| | |_| ||  __/ |  | | | |\n"\
			" |_____/ \\___|\\___|\\__,_|_|  |_|\\__|\\__, | |_|   \\__,_|\\__|\\__\\___|_|  |_| |_|\n"\
			"                                     __/ |                                    \n"\
			"                                    |___/                                     \n");

	printf("\n\n");
#if HW_IMPLEMENTATION==1
	printf( "  _    ___          __   _____ ______ \n" \
			" | |  | \\ \\        / /  / ____|  ____|\n" \
			" | |__| |\\ \\  /\\  / /  | (___ | |__   \n" \
			" |  __  | \\ \\/  \\/ /    \\___ \\|  __|  \n" \
			" | |  | |  \\  /\\  /     ____) | |____ \n" \
			" |_|  |_|   \\/  \\/     |_____/|______|\n" );
#else
	printf( "   _______          __           _____ _____ \n" \
			"  / ____\\ \\        / /     /\\   |  __ \\_   _|\n" \
			" | (___  \\ \\  /\\  / /     /  \\  | |__) || |  \n" \
			"  \\___ \\  \\ \\/  \\/ /     / /\\ \\ |  ___/ | |  \n" \
			"  ____) |  \\  /\\  /     / ____ \\| |    _| |_ \n" \
			" |_____/    \\/  \\/     /_/    \\_\\_|   |_____|\n" );
#endif
	printf("\n\n\n");
}
