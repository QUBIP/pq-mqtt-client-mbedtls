#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

void swapEndianness(unsigned char *data, size_t size);
void seed_rng();
void gen_priv_key(unsigned char* priv_key, unsigned int priv_len);
void print_progress_bar(int percentage, float ETA_time);
unsigned long long Wtime();

#define BAR_WIDTH 50 // Width of the progress bar
#define EXTRA_LINES 3
