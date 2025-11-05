////////////////////////////////////////////////////////////////////////////////////
// Company: IMSE-CNM CSIC
// Engineer: Pablo Navarro Torrero
//
// Create Date: 14/05/2024
// File Name: picorv32.h
// Project Name: SE-QUBIP
// Target Devices: PYNQ-Z2
// Description:
//
//		picorv32 Driver Header File
//
// Additional Comment:
//
////////////////////////////////////////////////////////////////////////////////////

#include "intf.h"
#include "extra_func.h"

// --- PICORV32 PROGRAM --- //
#define PICORV32_PROGRAM_SIZE       0x40000

// --- PICORV32 CMD CONTROL DEFINITION --- //
#define CMD_IDLE                    0
#define CMD_PUTCHAR                 1
#define CMD_GETCHAR                 2
#define CMD_SE_CODE                 3
#define CMD_SE_WRITE                4
#define CMD_SE_WAIT                 5
#define CMD_SE_READ                 6
#define CMD_END                     7
#define CMD_ERROR                  -1

// --- SE Operation Codes --- //
#define OP_SHA2                     (1 << 0)        //-- SHA-2
#define OP_SHA3                     (1 << 1)        //-- SHA-3
#define OP_ECDSA                    (1 << 2)        //-- EdDSA25519
#define OP_ECDH                     (1 << 3)        //-- X25519
#define OP_TRNG	                    (1 << 4)        //-- TRNG
#define OP_AES 	                    (1 << 5)        //-- AES
#define OP_MLKEM                    (1 << 6)        //-- MLKEM
#define OP_MLDSA                    (1 << 7)        //-- MLDSA
#define OP_SLHDSA                   (1 << 8)        //-- SLHDSA

// --- Error Codes --- // 
#define ERROR_SE_CODE               0
#define ERROR_ILLEGAL_INSTR         1 << 1
#define ERROR_MISALIGNED            1 << 2
#define ERROR_TIMEOUT               1 << 3
#define ERROR_DMA                   1 << 4
#define ERROR_ILLEGAL_ADDR          1 << 5
#define ERROR_SECMEM_STORE          0x5C
#define ERROR_SECMEM_DELETE         0x5D
#define ERROR_SECMEM_GET            0x5E

// --- ANSI Color and Style Macros ---
// Resets all text attributes to default
#define RESET   "\033[0m"

// Text Styles
#define BOLD    "\033[1m"
#define DIM     "\033[2m"
#define UNDERLINE "\033[4m"

// Foreground Colors
#define BLACK   "\033[30m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define WHITE   "\033[37m"

// --- PICORV32 FIFO CHARACTERISTICS --- //
#define FIFO_IN_DEPTH               128
#define FIFO_OUT_DEPTH              128

//------------------------------------------------------------------
//-- Picorv32 Communication
//------------------------------------------------------------------

void picorv32_control(INTF interface, uint64_t* control);

//----------------------------------------------------------------------------------------------------
// READ & WRITE PICORV PROGRAM MEMORY
//----------------------------------------------------------------------------------------------------

void READ_PICORV_PROGRAM(INTF interface);
void WRITE_PICORV_PROGRAM(INTF interface);