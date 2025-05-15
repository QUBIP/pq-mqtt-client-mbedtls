/**
 * @file ecdh.c
 * @brief ECDH (Elliptic Curve Diffie-Hellman) key exchange
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


//Dependencies
#include "ecdh.h"

const uint8_t gx_25519[32] = {0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t gx_448[56] = {0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/**
 * @brief Initialize ECDH context
 * @param[in] context Pointer to the ECDH context
 **/

/*
void ecdhInit(EcdhContext *context)
{
   //Initialize EC domain parameters
   ecInitDomainParameters(&context->params);

   //Initialize private and public keys
   ecInitPrivateKey(&context->da);
   ecInitPublicKey(&context->qa);
   ecInitPublicKey(&context->qb);
}
*/

/**
 * @brief Release ECDH context
 * @param[in] context Pointer to the ECDH context
 **/
/*
void ecdhFree(EcdhContext *context)
{
   //Release EC domain parameters
   ecFreeDomainParameters(&context->params);

   //Release private and public keys
   ecFreePrivateKey(&context->da);
   ecFreePublicKey(&context->qa);
   ecFreePublicKey(&context->qb);
}
*/

/**
 * @brief ECDH key pair generation
 * @param[in] context Pointer to the ECDH context
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @return Error code
 **/

void ecdhGenerateKeyPair(unsigned int curve, unsigned char* pri_key, unsigned char* pub_key)
{

    unsigned char rng[64];
    CTR_DRBG(rng, 64);
   //Curve25519 elliptic curve?
   if(curve == 25519)
   {
      uint8_t da[CURVE25519_BYTE_LEN];
      uint8_t qa[CURVE25519_BYTE_LEN];
      uint8_t g[CURVE25519_BYTE_LEN];

        //Generate 32 random bytes
        // prngAlgo->read(prngContext, da, CURVE25519_BYTE_LEN);
        memcpy(da, rng, CURVE25519_BYTE_LEN);

        //Get the u-coordinate of the base point
        // mpiExport(&context->params.g.x, g, CURVE25519_BYTE_LEN, MPI_FORMAT_LITTLE_ENDIAN);
        
        //Generate the public value using X25519 function
        x25519(qa, da, gx_25519);

        //Save private key
        // mpiImport(&context->da.d, da, CURVE25519_BYTE_LEN, MPI_FORMAT_LITTLE_ENDIAN);
        memcpy(pri_key, da, 32);
        
        //Save public key
        // mpiImport(&context->qa.q.x, qa, CURVE25519_BYTE_LEN, MPI_FORMAT_LITTLE_ENDIAN);
        memcpy(pub_key, qa, 32);

   }
   //Curve448 elliptic curve?
   else if(curve == 448)
   {
      uint8_t da[CURVE448_BYTE_LEN];
      uint8_t qa[CURVE448_BYTE_LEN];
      uint8_t g[CURVE448_BYTE_LEN];

        //Generate 56 random bytes
        // prngAlgo->read(prngContext, da, CURVE448_BYTE_LEN);
        memcpy(da, rng, CURVE448_BYTE_LEN);
        
        //Get the u-coordinate of the base point
        //mpiExport(&context->params.g.x, g, CURVE448_BYTE_LEN, MPI_FORMAT_LITTLE_ENDIAN);
       
        //Generate the public value using X448 function
        x448(qa, da, gx_448);

        //Save private key
        // mpiImport(&context->da.d, da, CURVE448_BYTE_LEN, MPI_FORMAT_LITTLE_ENDIAN);
        memcpy(pri_key, da, 56);

        //Save public key
        // mpiImport(&context->qa.q.x, qa, CURVE448_BYTE_LEN, MPI_FORMAT_LITTLE_ENDIAN);
        memcpy(pub_key, qa, 56);
    }

}


/**
 * @brief Check ECDH public key
 * @param[in] params EC domain parameters
 * @param[in] publicKey Public key to be checked
 * @return Error code
 **/

/*
error_t ecdhCheckPublicKey(const EcDomainParameters *params, EcPoint *publicKey)
{
   bool_t valid;

   //Initialize flag
   valid = FALSE;

   //Weierstrass elliptic curve?
   if(params->type == EC_CURVE_TYPE_SECT_K1 ||
      params->type == EC_CURVE_TYPE_SECT_R1 ||
      params->type == EC_CURVE_TYPE_SECT_R2 ||
      params->type == EC_CURVE_TYPE_SECP_K1 ||
      params->type == EC_CURVE_TYPE_SECP_R1 ||
      params->type == EC_CURVE_TYPE_SECP_R2 ||
      params->type == EC_CURVE_TYPE_BRAINPOOLP_R1)
   {
      //Verify that 0 <= Qx < p
      if(mpiCompInt(&publicKey->x, 0) >= 0 &&
         mpiComp(&publicKey->x, &params->p) < 0)
      {
         //Verify that 0 <= Qy < p
         if(mpiCompInt(&publicKey->y, 0) >= 0 &&
            mpiComp(&publicKey->y, &params->p) < 0)
         {
            //Check whether the point is on the curve
            valid = ecIsPointAffine(params, publicKey);
         }
      }

      //Valid point?
      if(valid)
      {
         //If the cofactor is not 1, the implementation must verify that n.Q
         //is the point at the infinity
         if(params->h != 1)
         {
            error_t error;
            EcPoint r;

            //Initialize flag
            valid = FALSE;
            //Initialize EC points
            ecInit(&r);

            //Convert the peer's public key to projective representation
            error = ecProjectify(params, publicKey, publicKey);

            //Check status code
            if(!error)
            {
               //Compute R = n.Q
               error = ecMult(params, &r, &params->q, publicKey);
            }

            //Check status code
            if(!error)
            {
               //Verify that the result is the point at the infinity
               if(mpiCompInt(&r.z, 0) == 0)
               {
                  valid = TRUE;
               }
            }

            //Release EC point
            ecFree(&r);
         }
      }
   }
#if (X25519_SUPPORT == ENABLED)
   //Curve25519 elliptic curve?
   else if(params->type == EC_CURVE_TYPE_X25519)
   {
      //The public key does not need to be validated
      valid = TRUE;
   }
#endif
#if (X448_SUPPORT == ENABLED)
   //Curve448 elliptic curve?
   else if(params->type == EC_CURVE_TYPE_X448)
   {
      //The public key does not need to be validated
      valid = TRUE;
   }
#endif
   //Invalid elliptic curve?
   else
   {
      //Just for sanity
      valid = FALSE;
   }

   //Return status code
   if(valid)
   {
      return NO_ERROR;
   }
   else
   {
      return ERROR_ILLEGAL_PARAMETER;
   }
}
*/

/**
 * @brief Compute ECDH shared secret
 * @param[in] context Pointer to the ECDH context
 * @param[out] output Buffer where to store the shared secret
 * @param[in] outputSize Size of the buffer in bytes
 * @param[out] outputLen Length of the resulting shared secret
 * @return Error code
 **/

void ecdhComputeSharedSecret(unsigned int curve, const unsigned char *pri_key, const unsigned char *pub_key,
   uint8_t *output)
{
   
   //Curve25519 elliptic curve?
   if(curve == 25519)
   {
      uint8_t da[CURVE25519_BYTE_LEN];
      uint8_t qb[CURVE25519_BYTE_LEN];

    //Length of the resulting shared secret
    // *outputLen = CURVE25519_BYTE_LEN;

    //Retrieve private key
    // mpiExport(&context->da.d, da, CURVE25519_BYTE_LEN, MPI_FORMAT_LITTLE_ENDIAN);
    memcpy(da, pri_key, CURVE25519_BYTE_LEN);

    //Get peer's public key
    // mpiExport(&context->qb.q.x, qb, CURVE25519_BYTE_LEN, MPI_FORMAT_LITTLE_ENDIAN);
    memcpy(qb, pub_key, CURVE25519_BYTE_LEN);

    //Generate shared secret K using X25519 function
    x25519(output, da, qb);
      
   }

   //Curve448 elliptic curve?
   else if(curve == 448)
   {
      uint8_t da[CURVE448_BYTE_LEN];
      uint8_t qb[CURVE448_BYTE_LEN];

    //Length of the resulting shared secret
    // *outputLen = CURVE448_BYTE_LEN;

    //Retrieve private key
    // mpiExport(&context->da.d, da, CURVE25519_BYTE_LEN, MPI_FORMAT_LITTLE_ENDIAN);
    memcpy(da, pri_key, CURVE448_BYTE_LEN);

    //Get peer's public key
    // mpiExport(&context->qb.q.x, qb, CURVE25519_BYTE_LEN, MPI_FORMAT_LITTLE_ENDIAN);
    memcpy(qb, pub_key, CURVE448_BYTE_LEN);

    //Generate shared secret K using X25519 function
    x448(output, da, qb);
      
   }

}

