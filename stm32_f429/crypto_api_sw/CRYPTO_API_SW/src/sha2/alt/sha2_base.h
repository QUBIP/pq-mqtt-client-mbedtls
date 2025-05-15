

#ifndef SHA_BASE_H
#define	SHA_BASE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "../../common/cpu_endian.h"

//Common API for hash algorithms
typedef void(*HashAlgoCompute)(const void* data, size_t length,
	uint8_t* digest);

typedef void (*HashAlgoInit)(void* context);

typedef void (*HashAlgoUpdate)(void* context, const void* data, size_t length);

typedef void (*HashAlgoFinal)(void* context, uint8_t* digest);

typedef void (*HashAlgoFinalRaw)(void* context, uint8_t* digest);

typedef char char_t;
typedef signed int int_t;
typedef unsigned int uint_t;
typedef int bool_t;

/**
 * @brief Common interface for hash algorithms
 **/

typedef struct
{
	const char_t* name;
	const uint8_t* oid;
	size_t oidSize;
	size_t contextSize;
	size_t blockSize;
	size_t digestSize;
	size_t minPadSize;
	bool_t bigEndian;
	HashAlgoCompute compute;
	HashAlgoInit init;
	HashAlgoUpdate update;
	HashAlgoFinal final;
	HashAlgoFinalRaw finalRaw;
} HashAlgo;

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

#ifndef LSB
#define LSB(x) ((x) & 0xFF)
#endif

#ifndef MSB
#define MSB(x) (((x) >> 8) & 0xFF)
#endif

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifndef arraysize
#define arraysize(a) (sizeof(a) / sizeof(a[0]))
#endif

#endif