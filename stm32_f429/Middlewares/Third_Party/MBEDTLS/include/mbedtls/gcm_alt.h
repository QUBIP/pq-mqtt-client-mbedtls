/*
 * gcm_alt.h
 *
 *  Created on: Sep 12, 2024
 *      Author: vagrant
 */

#ifndef THIRD_PARTY_MBEDTLS_INCLUDE_MBEDTLS_GCM_ALT_H_
#define THIRD_PARTY_MBEDTLS_INCLUDE_MBEDTLS_GCM_ALT_H_

#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include "mbedtls/cipher.h"

#if defined(MBEDTLS_BLOCK_CIPHER_C)
#include "mbedtls/block_cipher.h"
#endif

#include <stdint.h>

#define MBEDTLS_GCM_ENCRYPT     1
#define MBEDTLS_GCM_DECRYPT     0

/** Authenticated decryption failed. */
#define MBEDTLS_ERR_GCM_AUTH_FAILED                       -0x0012
/** Bad input parameters to function. */
#define MBEDTLS_ERR_GCM_BAD_INPUT                         -0x0014
/** An output buffer is too small. */
#define MBEDTLS_ERR_GCM_BUFFER_TOO_SMALL                  -0x0016

#if defined(MBEDTLS_GCM_LARGE_TABLE)
#define MBEDTLS_GCM_HTABLE_SIZE 256
#else
#define MBEDTLS_GCM_HTABLE_SIZE 16
#endif
/**
 * \brief          The GCM context structure.
 */
typedef struct mbedtls_gcm_context {
#if defined(MBEDTLS_BLOCK_CIPHER_C)
    mbedtls_block_cipher_context_t MBEDTLS_PRIVATE(block_cipher_ctx);  /*!< The cipher context used. */
#else
    mbedtls_cipher_context_t MBEDTLS_PRIVATE(cipher_ctx);    /*!< The cipher context used. */
#endif
    uint64_t MBEDTLS_PRIVATE(H)[MBEDTLS_GCM_HTABLE_SIZE][2]; /*!< Precalculated HTable. */
    uint64_t MBEDTLS_PRIVATE(len);                           /*!< The total length of the encrypted data. */
    uint64_t MBEDTLS_PRIVATE(add_len);                       /*!< The total length of the additional data. */
    unsigned char MBEDTLS_PRIVATE(base_ectr)[16];            /*!< The first ECTR for tag. */
    unsigned char MBEDTLS_PRIVATE(y)[16];                    /*!< The Y working value. */
    unsigned char MBEDTLS_PRIVATE(buf)[16];                  /*!< The buf working value. */
    unsigned char MBEDTLS_PRIVATE(mode);                     /*!< The operation to perform:
                                                              #MBEDTLS_GCM_ENCRYPT or
                                                              #MBEDTLS_GCM_DECRYPT. */
    unsigned char MBEDTLS_PRIVATE(acceleration);             /*!< The acceleration to use. */
    unsigned int MBEDTLS_PRIVATE(keysize);
    unsigned char MBEDTLS_PRIVATE(keyval)[32];
    mbedtls_cipher_id_t MBEDTLS_PRIVATE(cipher);
}
mbedtls_gcm_context;


#endif /* THIRD_PARTY_MBEDTLS_INCLUDE_MBEDTLS_GCM_ALT_H_ */
