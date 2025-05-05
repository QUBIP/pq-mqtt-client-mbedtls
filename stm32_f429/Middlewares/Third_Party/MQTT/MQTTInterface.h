/*
 * MQTTInterface.h
 *
 *  Created on: 2020. 4. 29.
 *      Author: https://github.com/eziya
 */
/**
 ******************************************************************************
 * File Name          : freertos.c
 * Description        : Code for freertos applications
 ******************************************************************************
 * @attention
 *
 * Copyright (c) 2024 SmartFactory s.r.l.
 * All rights reserved.
 *
 * This software is licensed under terms that can be found in the LICENSE file
 * in the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 * Contributors:
 *    Federico Parente - initial API and implementation and/or initial documentation
 ******************************************************************************
 */

#ifndef __MQTT_INTERFACE_H_
#define __MQTT_INTERFACE_H_
/* Private includes ----------------------------------------------------------*/
#include "cmsis_os.h"

/* Private define ------------------------------------------------------------*/
/* CONFIG */
#define MQTT_LWIP_SOCKET_TLS  //Use SOCKET API WITH TLS
//#define MQTT_LWIP_SOCKET	//Use SOCKET API
//#define MQTT_LWIP_NETCONN //Use NETCONN API


#if defined MQTT_INTERFACE_DEBUG
#define MQTT_INTERFACE_DEBUG_LOG(message, ...) DEBUG_LOG(message, ##__VA_ARGS__)
#else
#define MQTT_INTERFACE_DEBUG_LOG(message, ...)
#endif


/* Typedef -----------------------------------------------------------*/
typedef struct Timer Timer;

struct Timer {
	unsigned long systick_period;
	unsigned long end_time;
};

typedef struct Network Network;

struct Network
{
#if defined(MQTT_LWIP_SOCKET) || defined(MQTT_LWIP_SOCKET_TLS)
	int socket;
#endif
#if defined(MQTT_LWIP_NETCONN)
	struct netconn *conn;
	struct netbuf *buf;
	int offset;
#endif
	int (*mqttread) (Network*, unsigned char*, int, int);
	int (*mqttwrite) (Network*, unsigned char*, int, int);
	void (*disconnect) (Network*);
};

/* Extern variables ----------------------------------------------------------*/

/* Private function prototypes -----------------------------------------------*/

void InitTimer(Timer*);
char TimerIsExpired(Timer*);
void TimerCountdownMS(Timer*, unsigned int);
void TimerCountdown(Timer*, unsigned int);
int  TimerLeftMS(Timer*);

int  mqtt_network_read(Network*, unsigned char*, int, int);
int  mqtt_network_write(Network*, unsigned char*, int, int);
void mqtt_network_disconnect(Network*);
void mqtt_network_init(Network*);
void mqtt_network_clear(void);
#ifdef MQTT_LWIP_SOCKET_TLS
int  mqtt_network_connect(Network*, char*, char*);
#endif
#ifdef MQTT_LWIP_SOCKET
int  mqtt_network_connect(Network*, char*, int);
#endif

#ifdef MQTT_TASK
typedef struct Mutex
{
	SemaphoreHandle_t sem;
} Mutex;

void MutexInit(Mutex*);
int MutexLock(Mutex*);
int MutexUnlock(Mutex*);

typedef struct Thread
{
	TaskHandle_t task;
} Thread;
int ThreadStart(Thread* thread, void (*fn)(void*), void* arg);
#endif

#endif
