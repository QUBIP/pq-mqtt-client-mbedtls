/**
 * @file curve448.h
 * @brief Curve448 elliptic curve (constant-time implementation)
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

#ifndef _CURVE448_H
#define _CURVE448_H

 //Dependencies
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "mpi.h"
#include "curve25519.h"

//Length of the elliptic curve
#define CURVE448_BIT_LEN 448
#define CURVE448_BYTE_LEN 56
#define CURVE448_WORD_LEN 14

//A24 constant
#define CURVE448_A24 39082


extern const uint8_t ED448_OID[3];

//Curve448 related functions
void curve448SetInt(uint32_t *a, uint32_t b);
void curve448Add(uint32_t *r, const uint32_t *a, const uint32_t *b);
void curve448AddInt(uint32_t *r, const uint32_t *a, uint32_t b);
void curve448Sub(uint32_t *r, const uint32_t *a, const uint32_t *b);
void curve448SubInt(uint32_t *r, const uint32_t *a, uint32_t b);
void curve448Mul(uint32_t *r, const uint32_t *a, const uint32_t *b);
void curve448MulInt(uint32_t *r, const uint32_t *a, uint32_t b);
void curve448Red(uint32_t *r, const uint32_t *a, uint32_t h);
void curve448Sqr(uint32_t *r, const uint32_t *a);
void curve448Pwr2(uint32_t *r, const uint32_t *a, uint_t n);
void curve448Inv(uint32_t *r, const uint32_t *a);

uint32_t curve448Sqrt(uint32_t *r, const uint32_t *a, const uint32_t *b);

void curve448Copy(uint32_t *a, const uint32_t *b);
void curve448Swap(uint32_t *a, uint32_t *b, uint32_t c);

void curve448Select(uint32_t *r, const uint32_t *a, const uint32_t *b,
   uint32_t c);

uint32_t curve448Comp(const uint32_t *a, const uint32_t *b);

void curve448Import(uint32_t *a, const uint8_t *data);
void curve448Export(uint32_t *a, uint8_t *data);



extern const EcCurveInfo ed448Curve;


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



#endif
