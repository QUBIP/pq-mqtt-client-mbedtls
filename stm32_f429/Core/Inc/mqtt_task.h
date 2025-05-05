/*
 * mqtt_task.h
 *
 *  Created on: Aug 21, 2024
 *      Author: federico
 */

#ifndef INC_MQTT_TASK_H_
#define INC_MQTT_TASK_H_
/* Private includes ----------------------------------------------------------*/
#include "MQTTClient.h"
#include "cmsis_os.h"

/* Private define ------------------------------------------------------------*/
#if defined MQTT_SUB_TASK_DEBUG
#define MQTT_SUB_TASK_DEBUG_LOG(message, ...) DEBUG_LOG(message, ##__VA_ARGS__)
#else
#define MQTT_SUB_TASK_DEBUG_LOG(message, ...)
#endif

#if defined MQTT_PUB_TASK_DEBUG
#define MQTT_PUB_TASK_DEBUG_LOG(message, ...) DEBUG_LOG(message, ##__VA_ARGS__)
#else
#define MQTT_PUB_TASK_DEBUG_LOG(message, ...)
#endif

/* Extern variables ----------------------------------------------------------*/
extern MQTTClient mqttClient;
extern osThreadId mqttClientSubTaskHandle;
extern osThreadId mqttClientPubTaskHandle;

/* Private function prototypes -----------------------------------------------*/
void MqttClientSubTask(void const *argument); 	// mqtt client subscribe task function
void MqttClientPubTask(void const *argument); 	// mqtt client publish task function
void DemoTask(void const *argument); //Demo task

#endif /* INC_MQTT_TASK_H_ */
