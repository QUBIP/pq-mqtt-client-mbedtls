/*
 * leds.h
 *
 *  Created on: Aug 12, 2024
 *      Author: federico parente
 */

#ifndef INC_LEDS_H_
#define INC_LEDS_H_

#include "stm32f4xx_hal.h"
#include <stdint.h>


#define DOT_DURATION 200
#define DASH_DURATION 400
#define END_WORD 500
#define SAME_LETTER_DURATION 100
#define DIFFERENT_LETTER_DURATION 200

void dot(GPIO_TypeDef* GPIOx, uint16_t GPIO_Pin);
void dash(GPIO_TypeDef* GPIOx, uint16_t GPIO_Pin);

void leds_blink_on_stackoverflow(void);
void leds_flash_error_on_malloc_failure(void);
void leds_signal_hard_fault(void);
void leds_indicate_tls_handshake_failure(void);
void leds_blink_while_mqtt_client_disconnected(void);
void leds_blink_on_mqtt_message_sent(void);
void leds_blink_freertos_task_creation_failed(void);

#endif /* INC_LEDS_H_ */
