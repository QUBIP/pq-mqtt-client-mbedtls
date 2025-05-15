/**
 * @file curve25519.h
 * @brief Curve25519 elliptic curve (constant-time implementation)
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

#ifndef _CURVE25519_H
#define _CURVE25519_H

//Dependencies
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "mpi.h"
#include "../../common/cpu_endian.h"

//Length of the elliptic curve
#define CURVE25519_BIT_LEN 255
#define CURVE25519_BYTE_LEN 32
#define CURVE25519_WORD_LEN 8

//A24 constant
#define CURVE25519_A24 121666

typedef char char_t;
typedef signed int int_t;
typedef unsigned int uint_t;
typedef int bool_t;

extern const uint8_t ED448_OID[3];

//Curve25519 related functions
void curve25519SetInt(uint32_t *a, uint32_t b);
void curve25519Add(uint32_t *r, const uint32_t *a, const uint32_t *b);
void curve25519AddInt(uint32_t *r, const uint32_t *a, uint32_t b);
void curve25519Sub(uint32_t *r, const uint32_t *a, const uint32_t *b);
void curve25519SubInt(uint32_t *r, const uint32_t *a, uint32_t b);
void curve25519Mul(uint32_t *r, const uint32_t *a, const uint32_t *b);
void curve25519MulInt(uint32_t *r, const uint32_t *a, uint32_t b);
void curve25519Red(uint32_t *r, const uint32_t *a);
void curve25519Sqr(uint32_t *r, const uint32_t *a);
void curve25519Pwr2(uint32_t *r, const uint32_t *a, uint_t n);
void curve25519Inv(uint32_t *r, const uint32_t *a);

uint32_t curve25519Sqrt(uint32_t *r, const uint32_t *a, const uint32_t *b);

void curve25519Copy(uint32_t *a, const uint32_t *b);
void curve25519Swap(uint32_t *a, uint32_t *b, uint32_t c);

void curve25519Select(uint32_t *r, const uint32_t *a, const uint32_t *b,
   uint32_t c);

uint32_t curve25519Comp(const uint32_t *a, const uint32_t *b);

void curve25519Import(uint32_t *a, const uint8_t *data);
void curve25519Export(uint32_t *a, uint8_t *data);

typedef enum
{
    EC_CURVE_TYPE_NONE = 0,
    EC_CURVE_TYPE_SECT_K1 = 1,
    EC_CURVE_TYPE_SECT_R1 = 2,
    EC_CURVE_TYPE_SECT_R2 = 3,
    EC_CURVE_TYPE_SECP_K1 = 4,
    EC_CURVE_TYPE_SECP_R1 = 5,
    EC_CURVE_TYPE_SECP_R2 = 6,
    EC_CURVE_TYPE_BRAINPOOLP_R1 = 7,
    EC_CURVE_TYPE_X25519 = 8,
    EC_CURVE_TYPE_X448 = 9,
    EC_CURVE_TYPE_ED25519 = 10,
    EC_CURVE_TYPE_ED448 = 11
} EcCurveType;

/**
 * @brief Elliptic curve parameters
 **/

typedef error_mpi_t(*EcFastModAlgo)(Mpi* a, const Mpi* p);

typedef struct
{
    const char_t* name;   ///<Curve name
    const uint8_t* oid;   ///<Object identifier
    size_t oidSize;       ///<OID size
    EcCurveType type;     ///<Curve type
    const uint8_t p[66];  ///<Prime modulus p
    size_t pLen;          ///<Length of p
    const uint8_t a[66];  ///<Curve parameter a
    size_t aLen;          ///<Length of a
    const uint8_t b[66];  ///<Curve parameter b
    size_t bLen;          ///<Length of b
    const uint8_t gx[66]; ///<x-coordinate of the base point G
    size_t gxLen;         ///<Length of Gx
    const uint8_t gy[66]; ///<y-coordinate of the base point G
    size_t gyLen;         ///<Length of Gy
    const uint8_t q[66];  ///<Order of the base point G
    size_t qLen;          ///<Length of q
    uint32_t h;           ///<Cofactor h
    EcFastModAlgo mod;    ///<Fast modular reduction
} EcCurveInfo;

extern const EcCurveInfo ed25519Curve;



/**
 * @brief Data chunk descriptor
 **/

typedef struct
{
    const void* buffer;
    size_t length;
} DataChunk;

#endif
