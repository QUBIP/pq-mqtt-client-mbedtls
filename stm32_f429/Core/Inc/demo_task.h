/*
 * demo_task.h
 *
 *  Created on: Jan 10, 2025
 *      Author: vagrant
 */
#include "FreeRTOS.h"
#include "task.h"
#include "main.h"
#include "rng.h"
#include "cmsis_os.h"

extern osThreadId demoTaskHandle;
void DemoTask(void const *argument);
