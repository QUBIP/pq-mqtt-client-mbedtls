/**
 * @file scp03_driver.h
 * @brief High-level driver for communicating with the SE-QUBIP SCP-03 Hardware Accelerator.
 * 
 * This driver abstracts the low-level I2C transactions and SCP-03 cryptographic
 * operations into three main functions: init, write, and read.
 */

#ifndef SCP03_H
#define SCP03_H


#include <stdbool.h>

#include "i2c.h"

#include "scp03/kdf/scp03_kdf.h"
#include "scp03/aes/aes.h"

#ifdef __cplusplus
extern "C" {
#endif

// SCP-03 Configuration
#define SCP03_KEY_BITS          128
#define SCP03_STATIC_KEY_ENC    { \
                                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, \
                                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, \
                                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, \
                                0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F  \
                                }
#define SCP03_STATIC_KEY_MAC    { \
                                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, \
                                0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,  \
                                0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, \
                                0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F  \
                                }

// SCP-03 Session Context
typedef struct 
{
    // Configuration
    int key_bits;                   // 128/192/256
    unsigned char static_enc[32];
    unsigned char static_mac[32];
    
    // Session State
    unsigned char s_enc[32];
    unsigned char s_mac[32];
    unsigned char s_rmac[32];
    unsigned char host_chal[8];
    unsigned char card_chal[8];
    
    // Security State (Chaining & Counters)
    unsigned char mac_chain[16];    
    unsigned char counter[16];      
} scp03_session_t;

// ---------------------------------------------------------------------------
// FPGA Register Map
// ---------------------------------------------------------------------------
// Input Buffer (Host -> FPGA)
#define REG_DATA_IN         0x00

// Output Buffer (FPGA -> Host)
#define REG_DATA_OUT        0x08

// Control & Status
#define REG_CMD             0x10
#define REG_STATUS          0x11

// ---------------------------------------------------------------------------
// Secure Element Register Map
// ---------------------------------------------------------------------------
#define REG_SE_DATA_IN      0x00
#define REG_SE_DATA_OUT     0x01
#define REG_SE_CONTROL      0x02
#define REG_SE_RAM_WR       0x03
#define REG_SE_RAM_RD       0x04

// ---------------------------------------------------------------------------
// SCP-03 Commands (Written to REG_CMD)
// ---------------------------------------------------------------------------
#define CMD_INIT_UPDATE     0x01
#define CMD_EXT_AUTH        0x02
#define CMD_LOAD_BUF        0x10
#define CMD_UNWRAP          0x11
#define CMD_WRAP            0x12

// ---------------------------------------------------------------------------
// SCP-03 Status Bits (Read from REG_STATUS)
// ---------------------------------------------------------------------------
#define STATUS_BUSY         0x01 // Bit 0
#define STATUS_DATA_AVAIL   0x02 // Bit 1
#define STATUS_AUTH         0x04 // Bit 2
#define STATUS_ERROR        0x80 // Bit 7

bool scp03_init(I2C_FD interface, scp03_session_t* session);
bool scp03_write(I2C_FD interface, scp03_session_t* session, uint8_t addr, uint64_t* data);
bool scp03_read(I2C_FD interface, scp03_session_t* session, uint8_t addr, uint64_t* data);

#ifdef __cplusplus
}
#endif

#endif // SCP03_H
