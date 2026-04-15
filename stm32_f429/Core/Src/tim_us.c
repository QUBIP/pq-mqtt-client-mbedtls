#include "tim_us.h"

TIM_HandleTypeDef htim_us;

/* TIM2 init function - 1 MHz microsecond timer */
void MX_TIM_US_Init(void) {
	TIM_ClockConfigTypeDef sClockSourceConfig = { 0 };

	htim_us.Instance = TIM2;					// Based on APB1 on STM32F4
	htim_us.Init.CounterMode = TIM_COUNTERMODE_UP;
	htim_us.Init.Prescaler = 83;              // 84 MHz / (83 + 1) = 1 MHz
	htim_us.Init.Period = 0xFFFFFFFF;         // 32-bit free running
	htim_us.Init.AutoReloadPreload = TIM_AUTORELOAD_PRELOAD_DISABLE;
	htim_us.Init.ClockDivision = TIM_CLOCKDIVISION_DIV1;

	if (HAL_TIM_Base_Init(&htim_us) != HAL_OK) {
		Error_Handler();
	}

	sClockSourceConfig.ClockSource = TIM_CLOCKSOURCE_INTERNAL;
	HAL_TIM_ConfigClockSource(&htim_us, &sClockSourceConfig);

	HAL_TIM_Base_Start(&htim_us);
}

uint32_t micros(void) {
	return (uint32_t) TIM2->CNT;
}

void delay_us(uint32_t us) {
	uint32_t start = micros();
	while ((uint32_t) (micros() - start) < us)
		;
}
