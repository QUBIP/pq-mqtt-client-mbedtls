/*
 * demo_task.c
 *
 *  Created on: Nov 26, 2024
 *      Author: vagrant
 */
#include "demo_task.h"

extern RNG_HandleTypeDef hrng;

void randombytes_mldsa(uint8_t *out, size_t outlen) {
	uint32_t rnd;

	while(outlen > 0){
		HAL_RNG_GenerateRandomNumber(&hrng, &rnd);
		*out = ((uint8_t *) &rnd)[0];

		outlen -= 1;
		out += 1;
	}


}

void test();

osThreadId demoTaskHandle;

void DemoTask(void const *argument){
	test();
}

