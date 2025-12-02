////////////////////////////////////////////////////////////////////////////////////
// Company: IMSE-CNM CSIC
// Engineer: Pablo Navarro Torrero
//
// Create Date: 08/09/2025
// File Name: secmem_hw.h 
// Project Name: SE-QUBIP
// Target Devices: PYNQ-Z2
// Description:
//
//		Secure Memory HW Handler Functions Header File
//
////////////////////////////////////////////////////////////////////////////////////

#ifndef SECMEM_H
#define SECMEM_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "intf.h"
#include "conf.h"
#include "picorv32.h"
#include "extra_func.h"

#define OP_STORE_KEY                (1 << 0)
#define OP_DELETE_KEY               (1 << 1)
#define OP_GET_KEY                  (1 << 2)
#define OP_INFO                     (1 << 3)

#define KEY_ID_OFFSET               4
#define KEY_ORIGIN_OFFSET           10
#define ALG_ID_OFFSET               11

#define ID_AES                      0
#define ID_X25519                   1
#define ID_EDDSA                    2
#define ID_SLHDSA                   3
#define ID_MLKEM                    4
#define ID_MLDSA                    5

#define KEY_NUM_AES                 48
#define KEY_NUM_X25519              8
#define KEY_NUM_EDDSA               8
#define KEY_NUM_SLHDSA              8
#define KEY_NUM_MLKEM               8
#define KEY_NUM_MLDSA               8

#define KEY_LEN_AES                 32
#define KEY_LEN_X25519              64
#define KEY_LEN_EDDSA               64
#define KEY_LEN_SLHDSA              128
#define KEY_LEN_MLKEM               32
#define KEY_LEN_MLDSA               32

#define KEY_OFFSET_AES              0x000
#define KEY_OFFSET_X25519           0x600
#define KEY_OFFSET_EDDSA            0x800
#define KEY_OFFSET_SLHDSA           0xA00
#define KEY_OFFSET_MLKEM            0xE00
#define KEY_OFFSET_MLDSA            0xF00

#define SECMEM_MAX_KEYS             48

typedef struct {
	const char alg_id[8];                          //  Algorithm name
	const uint8_t max_keys;        //  Maximum number of keys (e.g., 48 for AES)
	const uint8_t key_len;            //  Key length in bytes (e.g., 32 for AES)
	const uint16_t addr_offset;            //  Starting address in Secure Memory
	uint8_t num_keys_stored;                 //  Number of keys currently stored
	bool key_slot_in_use[SECMEM_MAX_KEYS];   //  Keys in use
} secmem_alg_t;

extern secmem_alg_t secmem_aes;
extern secmem_alg_t secmem_x25519;
extern secmem_alg_t secmem_eddsa;
extern secmem_alg_t secmem_slhdsa;
extern secmem_alg_t secmem_mlkem;
extern secmem_alg_t secmem_mldsa;

//==============================================================================
// SECURE MEMORY OPERATIONS
//==============================================================================

void secmem_store_key(uint8_t alg_id, uint8_t *key_id, bool is_external,
		uint8_t *key_external, uint8_t key_len, INTF interface);
void secmem_delete_key(uint8_t alg_id, uint8_t key_id, INTF interface);
void secmem_get_key(uint8_t alg_id, uint8_t key_id, uint8_t *key_data,
		INTF interface);
void secmem_info(int DBG, INTF interface);
void secmem_delete_all_keys(INTF interface);

#endif
