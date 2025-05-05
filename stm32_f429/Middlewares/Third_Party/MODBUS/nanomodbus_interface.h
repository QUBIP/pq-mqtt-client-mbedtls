/*
 * nanomodbus_interface.h
 *
 *  Created on: Aug 13, 2024
 *      Author: federico
 */

#ifndef __NANOMODBUS_INTERFACE_H__
#define __NANOMODBUS_INTERFACE_H__
/* Private includes ----------------------------------------------------------*/
#include <stdint.h>
#include "nanomodbus.h"


/* Private define ------------------------------------------------------------*/
#if defined NANOMODBUS_INTERFACE_DEBUG
#define NANOMODBUS_INTERFACE_DEBUG_LOG(message, ...) DEBUG_LOG(message, ##__VA_ARGS__)
#else
#define NANOMODBUS_INTERFACE_DEBUG_LOG(message, ...)
#endif


/* Private function prototypes -----------------------------------------------*/

// ----------------------------------------------------------------------------
// Platform-Specific Communication Functions
// ----------------------------------------------------------------------------

/**
 * Initializes the Modbus platform, establishing a connection to the server
 * and creating the Modbus client.
 *
 * @param[out] fd Pointer to a file descriptor to store the connection handle.
 *
 * @return 0 on success, -1 on failure.
 */
int8_t nmbs_platform_setup(int* fd, nmbs_t *nmbs);

/**
 * Establishes a TCP connection to a specified IP address and port.
 *
 * @param[in] host The IP address of the remote host to connect to (e.g., "192.168.1.100").
 * @param[in] port The port number on the remote host to connect to (e.g., "502").
 *
 * @return A file descriptor representing the established connection if successful.
 *         Returns -1 if the connection fails.
 */
int32_t nmbs_platform_connect_tcp(const char *host, const char *port);

/**
 * Disconnects from the Modbus server, closing the connection.
 *
 * @param[in] fd Pointerto File descriptor representing the connection to close.
 */
void nmbs_platform_disconnect(int *fd);

/**
 * Sends data over the established Modbus connection.
 *
 * @param[in] buf Pointer to the buffer containing data to send.
 * @param[in] len Length of the data in the buffer.
 * @param[in] timeout_ms Timeout in milliseconds for the send operation.
 * @param[in] arg Optional argument for platform-specific use.
 *
 * @return The number of bytes sent on success, -1 on failure.
 */
int32_t nmbs_platform_send(const uint8_t* buf, uint16_t len, int32_t timeout_ms, void* arg );

/**
 * Reads data from the established Modbus connection.
 *
 * @param[out] buf Pointer to the buffer to store the received data.
 * @param[in] count Maximum number of bytes to read.
 * @param[in] timeout_ms Timeout in milliseconds for the read operation. Not used
 * @param[in] arg Optional argument for platform-specific use.
 *
 * @return The number of bytes read on success, -1 on failure.
 */
int32_t nmbs_platform_read(uint8_t* buf, uint16_t count, int32_t timeout_ms, void* arg);

/**
 * Reads data from the established Modbus connection with a timeout.
 *
 * @param[out] buf Pointer to the buffer to store the received data.
 * @param[in] count Maximum number of bytes to read.
 * @param[in] timeout_ms Timeout in milliseconds for the read operation.
 * @param[in] arg Optional argument for platform-specific use.
 *
 * @return The number of bytes read on success, -1 on failure.
 */
int32_t nmbs_platform_read_timeout(uint8_t* buf, uint16_t count, int32_t timeout_ms, void* arg);

#endif
