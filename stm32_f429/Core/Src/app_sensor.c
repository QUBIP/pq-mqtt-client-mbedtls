#include "app_sensor.h"
#include "platform.h"
#include "stm32f4xx_hal.h"
#include "stm32f4xx_hal_adc.h"   // <-- QUESTO MANCAVA

/* ADC handle */
static ADC_HandleTypeDef hadc1;

/* === PROTOTIPO PRIVATO === */
static void ADC1_Init(void);

/* ========================================================= */
void Sensor_Init(void) {
	ADC1_Init();
}

/* ========================================================= */
float Sensor_Read_Temperature(void) {
	HAL_ADC_Start(&hadc1);
	HAL_ADC_PollForConversion(&hadc1, HAL_MAX_DELAY);

	int raw = HAL_ADC_GetValue(&hadc1);
	float voltage = (raw * 3.3f) / 4095.0f;
	float temperature = (voltage - 0.4) / 0.0195;
	/* conversione base (identica a sensor_test, adattabile)
	 float voltage = (raw * 3.3f) / 4095.0f;
	 float temperature = voltage * 100.0f;*/

	return temperature;
}

/* ========================================================= */
/* =============== ADC MANUAL INIT (NO IOC) ================= */
/* ========================================================= */
static void ADC1_Init(void) {
	__HAL_RCC_ADC1_CLK_ENABLE();
	__HAL_RCC_GPIOA_CLK_ENABLE();

	/* GPIO PA0 -> ADC1_IN0 (ESEMPIO, usa il pin reale) */
	GPIO_InitTypeDef GPIO_InitStruct = { 0 };
	GPIO_InitStruct.Pin = GPIO_PIN_3;
	GPIO_InitStruct.Mode = GPIO_MODE_ANALOG;
	GPIO_InitStruct.Pull = GPIO_NOPULL;
	HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);

	hadc1.Instance = ADC1;
	hadc1.Init.ClockPrescaler = ADC_CLOCKPRESCALER_PCLK_DIV4;
	hadc1.Init.Resolution = ADC_RESOLUTION_12B;
	hadc1.Init.ScanConvMode = DISABLE;
	hadc1.Init.ContinuousConvMode = DISABLE;
	hadc1.Init.DiscontinuousConvMode = DISABLE;
	hadc1.Init.ExternalTrigConvEdge = ADC_EXTERNALTRIG_EDGE_NONE;
	hadc1.Init.DataAlign = ADC_DATAALIGN_RIGHT;
	hadc1.Init.NbrOfConversion = 1;

	HAL_ADC_Init(&hadc1);

	ADC_ChannelConfTypeDef sConfig = { 0 };
	sConfig.Channel = ADC_CHANNEL_3;   // PA1
	sConfig.Rank = 1;
	sConfig.SamplingTime = ADC_SAMPLETIME_144CYCLES;

	HAL_ADC_ConfigChannel(&hadc1, &sConfig);
}
