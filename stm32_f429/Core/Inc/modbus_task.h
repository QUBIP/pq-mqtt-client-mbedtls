/*
 * modbus_task.h
 *
 *  Created on: Aug 21, 2024
 *      Author: federico
 */

#ifndef INC_MODBUS_TASK_H_
#define INC_MODBUS_TASK_H_
/* Private includes ----------------------------------------------------------*/
#include "FreeRTOS.h"


/* Private define ------------------------------------------------------------*/
#if defined MODBUS_TASK_DEBUG
#define MODBUS_TASK_DEBUG_LOG(message, ...) DEBUG_LOG(message, ##__VA_ARGS__)
#else
#define MODBUS_TASK_DEBUG_LOG(message, ...)
#endif
/* Extern variables ----------------------------------------------------------*/

/* Private function prototypes -----------------------------------------------*/
void ModbusClientTask(void *argument);    		// modbus client task function

#endif /* INC_MODBUS_TASK_H_ */
