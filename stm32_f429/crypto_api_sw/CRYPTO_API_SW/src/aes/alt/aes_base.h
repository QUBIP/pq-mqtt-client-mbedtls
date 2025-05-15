/**
  * @file aes.h
  * @brief AES (Advanced Encryption Standard)
  *
  * @section License
  *
  * SPDX-License-Identifier: GPL-2.0-or-later
  *
  * Copyright (C) 2010-2024 Oryx Embedded SARL. All rights reserved.
  *
  * This file is part of CycloneCRYPTO Open.
  *
  * This program is free software; you can redistribute it and/or
  * modify it under the terms of the GNU General Public License
  * as published by the Free Software Foundation; either version 2
  * of the License, or (at your option) any later version.
  *
  * This program is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  * GNU General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program; if not, write to the Free Software Foundation,
  * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
  *
  * @author Oryx Embedded SARL (www.oryx-embedded.com)
  * @version 2.4.4
  **/

#ifndef _AES_BASE_H
#define _AES_BASE_H

#include <stdint.h>
#include <stddef.h>

typedef char char_t;
typedef signed int int_t;
typedef unsigned int uint_t;
typedef unsigned char uchar;    // add some convienent shorter types
typedef unsigned int uint;

//AES block size
#define AES_BLOCK_SIZE 16
//Common interface for encryption algorithms
#define AES_CIPHER_ALGO (&aesCipherAlgo)

/**
    * @brief AES algorithm context
    **/

typedef struct
{
    uint_t nr;
    uint32_t ek[60];
    uint32_t dk[60];
} AesContext;

//Common API for encryption algorithms
typedef void(*CipherAlgoInit)(void* context, const uint8_t* key, size_t keyLen);

typedef void (*CipherAlgoEncryptStream)(void* context, const uint8_t* input, uint8_t* output, size_t length);

typedef void (*CipherAlgoDecryptStream)(void* context, const uint8_t* input, uint8_t* output, size_t length);

typedef void (*CipherAlgoEncryptBlock)(void* context, const uint8_t* input, uint8_t* output);

typedef void (*CipherAlgoDecryptBlock)(void* context, const uint8_t* input, uint8_t* output);

typedef void (*CipherAlgoDeinit)(void* context);

typedef enum
{
    CIPHER_ALGO_TYPE_STREAM = 0,
    CIPHER_ALGO_TYPE_BLOCK = 1
} CipherAlgoType;


/**
 * @brief Cipher operation modes
 **/

typedef enum
{
    CIPHER_MODE_NULL = 0,
    CIPHER_MODE_STREAM = 1,
    CIPHER_MODE_ECB = 2,
    CIPHER_MODE_CBC = 3,
    CIPHER_MODE_CFB = 4,
    CIPHER_MODE_OFB = 5,
    CIPHER_MODE_CTR = 6,
    CIPHER_MODE_CCM = 7,
    CIPHER_MODE_GCM = 8,
    CIPHER_MODE_CHACHA20_POLY1305 = 9,
} CipherMode;

/**
 * @brief Common interface for encryption algorithms
 **/

typedef struct
{
    const char_t* name;
    size_t contextSize;
    CipherAlgoType type;
    size_t blockSize;
    CipherAlgoInit init;
    CipherAlgoEncryptStream encryptStream;
    CipherAlgoDecryptStream decryptStream;
    CipherAlgoEncryptBlock encryptBlock;
    CipherAlgoDecryptBlock decryptBlock;
    CipherAlgoDeinit deinit;
} CipherAlgo;


//AES related constants
extern const CipherAlgo aesCipherAlgo;

//AES related functions
void aesInit(AesContext* context, const uint8_t* key, size_t keyLen);

void aesEncryptBlock(AesContext* context, const uint8_t* input,
    uint8_t* output);

void aesDecryptBlock(AesContext* context, const uint8_t* input,
    uint8_t* output);

void aesDeinit(AesContext* context);

#define MIN(a, b) ((a) < (b) ? (a) : (b))

//Rotate left operation
#define ROL8(a, n) (((a) << (n)) | ((a) >> (8 - (n))))
#define ROL16(a, n) (((a) << (n)) | ((a) >> (16 - (n))))
#define ROL32(a, n) (((a) << (n)) | ((a) >> (32 - (n))))
#define ROL64(a, n) (((a) << (n)) | ((a) >> (64 - (n))))

//Rotate right operation
#define ROR8(a, n) (((a) >> (n)) | ((a) << (8 - (n))))
#define ROR16(a, n) (((a) >> (n)) | ((a) << (16 - (n))))
#define ROR32(a, n) (((a) >> (n)) | ((a) << (32 - (n))))
#define ROR64(a, n) (((a) >> (n)) | ((a) << (64 - (n))))

//Shift left operation
#define SHL8(a, n) ((a) << (n))
#define SHL16(a, n) ((a) << (n))
#define SHL32(a, n) ((a) << (n))
#define SHL64(a, n) ((a) << (n))

//Shift right operation
#define SHR8(a, n) ((a) >> (n))
#define SHR16(a, n) ((a) >> (n))
#define SHR32(a, n) ((a) >> (n))
#define SHR64(a, n) ((a) >> (n))

//Micellaneous macros
#define _U8(x) ((uint8_t) (x))
#define _U16(x) ((uint16_t) (x))
#define _U32(x) ((uint32_t) (x))
#define _U64(x) ((uint64_t) (x))

//Load unaligned 16-bit integer (little-endian encoding)
#define LOAD16LE(p) ( \
    ((uint16_t)(((uint8_t *)(p))[0]) << 0) | \
    ((uint16_t)(((uint8_t *)(p))[1]) << 8))

 //Load unaligned 16-bit integer (big-endian encoding)
#define LOAD16BE(p) ( \
    ((uint16_t)(((uint8_t *)(p))[0]) << 8) | \
    ((uint16_t)(((uint8_t *)(p))[1]) << 0))

 //Load unaligned 24-bit integer (little-endian encoding)
#define LOAD24LE(p) ( \
    ((uint32_t)(((uint8_t *)(p))[0]) << 0)| \
    ((uint32_t)(((uint8_t *)(p))[1]) << 8) | \
    ((uint32_t)(((uint8_t *)(p))[2]) << 16))

 //Load unaligned 24-bit integer (big-endian encoding)
#define LOAD24BE(p) ( \
    ((uint32_t)(((uint8_t *)(p))[0]) << 16) | \
    ((uint32_t)(((uint8_t *)(p))[1]) << 8) | \
    ((uint32_t)(((uint8_t *)(p))[2]) << 0))

 //Load unaligned 32-bit integer (little-endian encoding)
#define LOAD32LE(p) ( \
    ((uint32_t)(((uint8_t *)(p))[0]) << 0) | \
    ((uint32_t)(((uint8_t *)(p))[1]) << 8) | \
    ((uint32_t)(((uint8_t *)(p))[2]) << 16) | \
    ((uint32_t)(((uint8_t *)(p))[3]) << 24))

 //Load unaligned 32-bit integer (big-endian encoding)
#define LOAD32BE(p) ( \
    ((uint32_t)(((uint8_t *)(p))[0]) << 24) | \
    ((uint32_t)(((uint8_t *)(p))[1]) << 16) | \
    ((uint32_t)(((uint8_t *)(p))[2]) << 8) | \
    ((uint32_t)(((uint8_t *)(p))[3]) << 0))

 //Load unaligned 48-bit integer (little-endian encoding)
#define LOAD48LE(p) ( \
    ((uint64_t)(((uint8_t *)(p))[0]) << 0) | \
    ((uint64_t)(((uint8_t *)(p))[1]) << 8) | \
    ((uint64_t)(((uint8_t *)(p))[2]) << 16) | \
    ((uint64_t)(((uint8_t *)(p))[3]) << 24) | \
    ((uint64_t)(((uint8_t *)(p))[4]) << 32) | \
    ((uint64_t)(((uint8_t *)(p))[5]) << 40)

 //Load unaligned 48-bit integer (big-endian encoding)
#define LOAD48BE(p) ( \
    ((uint64_t)(((uint8_t *)(p))[0]) << 40) | \
    ((uint64_t)(((uint8_t *)(p))[1]) << 32) | \
    ((uint64_t)(((uint8_t *)(p))[2]) << 24) | \
    ((uint64_t)(((uint8_t *)(p))[3]) << 16) | \
    ((uint64_t)(((uint8_t *)(p))[4]) << 8) | \
    ((uint64_t)(((uint8_t *)(p))[5]) << 0))

 //Load unaligned 64-bit integer (little-endian encoding)
#define LOAD64LE(p) ( \
    ((uint64_t)(((uint8_t *)(p))[0]) << 0) | \
    ((uint64_t)(((uint8_t *)(p))[1]) << 8) | \
    ((uint64_t)(((uint8_t *)(p))[2]) << 16) | \
    ((uint64_t)(((uint8_t *)(p))[3]) << 24) | \
    ((uint64_t)(((uint8_t *)(p))[4]) << 32) | \
    ((uint64_t)(((uint8_t *)(p))[5]) << 40) | \
    ((uint64_t)(((uint8_t *)(p))[6]) << 48) | \
    ((uint64_t)(((uint8_t *)(p))[7]) << 56))

 //Load unaligned 64-bit integer (big-endian encoding)
#define LOAD64BE(p) ( \
    ((uint64_t)(((uint8_t *)(p))[0]) << 56) | \
    ((uint64_t)(((uint8_t *)(p))[1]) << 48) | \
    ((uint64_t)(((uint8_t *)(p))[2]) << 40) | \
    ((uint64_t)(((uint8_t *)(p))[3]) << 32) | \
    ((uint64_t)(((uint8_t *)(p))[4]) << 24) | \
    ((uint64_t)(((uint8_t *)(p))[5]) << 16) | \
    ((uint64_t)(((uint8_t *)(p))[6]) << 8) | \
    ((uint64_t)(((uint8_t *)(p))[7]) << 0))

 //Store unaligned 16-bit integer (little-endian encoding)
#define STORE16LE(a, p) \
    ((uint8_t *)(p))[0] = ((uint16_t)(a) >> 0) & 0xFFU, \
    ((uint8_t *)(p))[1] = ((uint16_t)(a) >> 8) & 0xFFU

 //Store unaligned 16-bit integer (big-endian encoding)
#define STORE16BE(a, p) \
    ((uint8_t *)(p))[0] = ((uint16_t)(a) >> 8) & 0xFFU, \
    ((uint8_t *)(p))[1] = ((uint16_t)(a) >> 0) & 0xFFU

 //Store unaligned 24-bit integer (little-endian encoding)
#define STORE24LE(a, p) \
    ((uint8_t *)(p))[0] = ((uint32_t)(a) >> 0) & 0xFFU, \
    ((uint8_t *)(p))[1] = ((uint32_t)(a) >> 8) & 0xFFU, \
    ((uint8_t *)(p))[2] = ((uint32_t)(a) >> 16) & 0xFFU

 //Store unaligned 24-bit integer (big-endian encoding)
#define STORE24BE(a, p) \
    ((uint8_t *)(p))[0] = ((uint32_t)(a) >> 16) & 0xFFU, \
    ((uint8_t *)(p))[1] = ((uint32_t)(a) >> 8) & 0xFFU, \
    ((uint8_t *)(p))[2] = ((uint32_t)(a) >> 0) & 0xFFU

 //Store unaligned 32-bit integer (little-endian encoding)
#define STORE32LE(a, p) \
    ((uint8_t *)(p))[0] = ((uint32_t)(a) >> 0) & 0xFFU, \
    ((uint8_t *)(p))[1] = ((uint32_t)(a) >> 8) & 0xFFU, \
    ((uint8_t *)(p))[2] = ((uint32_t)(a) >> 16) & 0xFFU, \
    ((uint8_t *)(p))[3] = ((uint32_t)(a) >> 24) & 0xFFU

 //Store unaligned 32-bit integer (big-endian encoding)
#define STORE32BE(a, p) \
    ((uint8_t *)(p))[0] = ((uint32_t)(a) >> 24) & 0xFFU, \
    ((uint8_t *)(p))[1] = ((uint32_t)(a) >> 16) & 0xFFU, \
    ((uint8_t *)(p))[2] = ((uint32_t)(a) >> 8) & 0xFFU, \
    ((uint8_t *)(p))[3] = ((uint32_t)(a) >> 0) & 0xFFU

 //Store unaligned 48-bit integer (little-endian encoding)
#define STORE48LE(a, p) \
    ((uint8_t *)(p))[0] = ((uint64_t)(a) >> 0) & 0xFFU, \
    ((uint8_t *)(p))[1] = ((uint64_t)(a) >> 8) & 0xFFU, \
    ((uint8_t *)(p))[2] = ((uint64_t)(a) >> 16) & 0xFFU, \
    ((uint8_t *)(p))[3] = ((uint64_t)(a) >> 24) & 0xFFU, \
    ((uint8_t *)(p))[4] = ((uint64_t)(a) >> 32) & 0xFFU, \
    ((uint8_t *)(p))[5] = ((uint64_t)(a) >> 40) & 0xFFU,

 //Store unaligned 48-bit integer (big-endian encoding)
#define STORE48BE(a, p) \
    ((uint8_t *)(p))[0] = ((uint64_t)(a) >> 40) & 0xFFU, \
    ((uint8_t *)(p))[1] = ((uint64_t)(a) >> 32) & 0xFFU, \
    ((uint8_t *)(p))[2] = ((uint64_t)(a) >> 24) & 0xFFU, \
    ((uint8_t *)(p))[3] = ((uint64_t)(a) >> 16) & 0xFFU, \
    ((uint8_t *)(p))[4] = ((uint64_t)(a) >> 8) & 0xFFU, \
    ((uint8_t *)(p))[5] = ((uint64_t)(a) >> 0) & 0xFFU

 //Store unaligned 64-bit integer (little-endian encoding)
#define STORE64LE(a, p) \
    ((uint8_t *)(p))[0] = ((uint64_t)(a) >> 0) & 0xFFU, \
    ((uint8_t *)(p))[1] = ((uint64_t)(a) >> 8) & 0xFFU, \
    ((uint8_t *)(p))[2] = ((uint64_t)(a) >> 16) & 0xFFU, \
    ((uint8_t *)(p))[3] = ((uint64_t)(a) >> 24) & 0xFFU, \
    ((uint8_t *)(p))[4] = ((uint64_t)(a) >> 32) & 0xFFU, \
    ((uint8_t *)(p))[5] = ((uint64_t)(a) >> 40) & 0xFFU, \
    ((uint8_t *)(p))[6] = ((uint64_t)(a) >> 48) & 0xFFU, \
    ((uint8_t *)(p))[7] = ((uint64_t)(a) >> 56) & 0xFFU

 //Store unaligned 64-bit integer (big-endian encoding)
#define STORE64BE(a, p) \
    ((uint8_t *)(p))[0] = ((uint64_t)(a) >> 56) & 0xFFU, \
    ((uint8_t *)(p))[1] = ((uint64_t)(a) >> 48) & 0xFFU, \
    ((uint8_t *)(p))[2] = ((uint64_t)(a) >> 40) & 0xFFU, \
    ((uint8_t *)(p))[3] = ((uint64_t)(a) >> 32) & 0xFFU, \
    ((uint8_t *)(p))[4] = ((uint64_t)(a) >> 24) & 0xFFU, \
    ((uint8_t *)(p))[5] = ((uint64_t)(a) >> 16) & 0xFFU, \
    ((uint8_t *)(p))[6] = ((uint64_t)(a) >> 8) & 0xFFU, \
    ((uint8_t *)(p))[7] = ((uint64_t)(a) >> 0) & 0xFFU

 //Swap a 16-bit integer
#define SWAPINT16(x) ( \
    (((uint16_t)(x) & 0x00FFU) << 8) | \
    (((uint16_t)(x) & 0xFF00U) >> 8))

 //Swap a 32-bit integer
#define SWAPINT32(x) ( \
    (((uint32_t)(x) & 0x000000FFUL) << 24) | \
    (((uint32_t)(x) & 0x0000FF00UL) << 8) | \
    (((uint32_t)(x) & 0x00FF0000UL) >> 8) | \
    (((uint32_t)(x) & 0xFF000000UL) >> 24))

 //Swap a 64-bit integer
#define SWAPINT64(x) ( \
    (((uint64_t)(x) & 0x00000000000000FFULL) << 56) | \
    (((uint64_t)(x) & 0x000000000000FF00ULL) << 40) | \
    (((uint64_t)(x) & 0x0000000000FF0000ULL) << 24) | \
    (((uint64_t)(x) & 0x00000000FF000000ULL) << 8) | \
    (((uint64_t)(x) & 0x000000FF00000000ULL) >> 8) | \
    (((uint64_t)(x) & 0x0000FF0000000000ULL) >> 24) | \
    (((uint64_t)(x) & 0x00FF000000000000ULL) >> 40) | \
    (((uint64_t)(x) & 0xFF00000000000000ULL) >> 56))

/* Macros for handling unaligned memory accesses */

#define WPA_GET_BE16(a) ((uint16_t) (((a)[0] << 8) | (a)[1]))
#define WPA_PUT_BE16(a, val)			\
	do {					\
		(a)[0] = ((uint16_t) (val)) >> 8;	\
		(a)[1] = ((uint16_t) (val)) & 0xff;	\
	} while (0)

#define WPA_GET_LE16(a) ((uint16_t) (((a)[1] << 8) | (a)[0]))
#define WPA_PUT_LE16(a, val)			\
	do {					\
		(a)[1] = ((uint16_t) (val)) >> 8;	\
		(a)[0] = ((uint16_t) (val)) & 0xff;	\
	} while (0)

#define WPA_GET_BE24(a) ((((uint32_t) (a)[0]) << 16) | (((uint32_t) (a)[1]) << 8) | \
			 ((uint32_t) (a)[2]))
#define WPA_PUT_BE24(a, val)					\
	do {							\
		(a)[0] = (uint8_t) ((((uint32_t) (val)) >> 16) & 0xff);	\
		(a)[1] = (uint8_t) ((((uint32_t) (val)) >> 8) & 0xff);	\
		(a)[2] = (uint8_t) (((uint32_t) (val)) & 0xff);		\
	} while (0)

#define WPA_GET_BE32(a) ((((uint32_t) (a)[0]) << 24) | (((uint32_t) (a)[1]) << 16) | \
			 (((uint32_t) (a)[2]) << 8) | ((uint32_t) (a)[3]))
#define WPA_PUT_BE32(a, val)					\
	do {							\
		(a)[0] = (uint8_t) ((((uint32_t) (val)) >> 24) & 0xff);	\
		(a)[1] = (uint8_t) ((((uint32_t) (val)) >> 16) & 0xff);	\
		(a)[2] = (uint8_t) ((((uint32_t) (val)) >> 8) & 0xff);	\
		(a)[3] = (uint8_t) (((uint32_t) (val)) & 0xff);		\
	} while (0)

#define WPA_GET_LE32(a) ((((uint32_t) (a)[3]) << 24) | (((uint32_t) (a)[2]) << 16) | \
			 (((uint32_t) (a)[1]) << 8) | ((uint32_t) (a)[0]))
#define WPA_PUT_LE32(a, val)					\
	do {							\
		(a)[3] = (uint8_t) ((((uint32_t) (val)) >> 24) & 0xff);	\
		(a)[2] = (uint8_t) ((((uint32_t) (val)) >> 16) & 0xff);	\
		(a)[1] = (uint8_t) ((((uint32_t) (val)) >> 8) & 0xff);	\
		(a)[0] = (uint8_t) (((uint32_t) (val)) & 0xff);		\
	} while (0)

#define WPA_GET_BE64(a) ((((uint64_t) (a)[0]) << 56) | (((uint64_t) (a)[1]) << 48) | \
			 (((uint64_t) (a)[2]) << 40) | (((uint64_t) (a)[3]) << 32) | \
			 (((uint64_t) (a)[4]) << 24) | (((uint64_t) (a)[5]) << 16) | \
			 (((uint64_t) (a)[6]) << 8) | ((uint64_t) (a)[7]))
#define WPA_PUT_BE64(a, val)				\
	do {						\
		(a)[0] = (uint8_t) (((uint64_t) (val)) >> 56);	\
		(a)[1] = (uint8_t) (((uint64_t) (val)) >> 48);	\
		(a)[2] = (uint8_t) (((uint64_t) (val)) >> 40);	\
		(a)[3] = (uint8_t) (((uint64_t) (val)) >> 32);	\
		(a)[4] = (uint8_t) (((uint64_t) (val)) >> 24);	\
		(a)[5] = (uint8_t) (((uint64_t) (val)) >> 16);	\
		(a)[6] = (uint8_t) (((uint64_t) (val)) >> 8);	\
		(a)[7] = (uint8_t) (((uint64_t) (val)) & 0xff);	\
	} while (0)

#define WPA_GET_LE64(a) ((((uint64_t) (a)[7]) << 56) | (((uint64_t) (a)[6]) << 48) | \
			 (((uint64_t) (a)[5]) << 40) | (((uint64_t) (a)[4]) << 32) | \
			 (((uint64_t) (a)[3]) << 24) | (((uint64_t) (a)[2]) << 16) | \
			 (((uint64_t) (a)[1]) << 8) | ((uint64_t) (a)[0]))


//Fill block of memory
#ifndef osMemset
#include <string.h>
#define osMemset(p, value, length) (void) memset(p, value, length)
#endif


#endif