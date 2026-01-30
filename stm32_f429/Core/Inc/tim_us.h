#ifndef __TIM_US_H
#define __TIM_US_H

#include "main.h"

extern TIM_HandleTypeDef htim_us;

void MX_TIM_US_Init(void);
uint32_t micros(void);
void delay_us(uint32_t us);

#endif
