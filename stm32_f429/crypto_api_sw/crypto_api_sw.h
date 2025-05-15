/**
  * @file crypto_api_sw.h
  * @brief Crypto API SW header
  *
  * @section License
  *
  * MIT License
  *
  * Copyright (c) 2024 Eros Camacho
  *
  * Permission is hereby granted, free of charge, to any person obtaining a copy
  * of this software and associated documentation files (the "Software"), to deal
  * in the Software without restriction, including without limitation the rights
  * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  * copies of the Software, and to permit persons to whom the Software is
  * furnished to do so, subject to the following conditions:
  *
  * The above copyright notice and this permission notice shall be included in all
  * copies or substantial portions of the Software.
  *
  * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  * SOFTWARE.
  *
  *
  *
  * @author Eros Camacho-Ruiz (camacho@imse-cnm.csic.es)
  * @version 4.0
  **/ 

#ifndef CRYPTO_API_SW_H
#define CRYPTO_API_SW_H

#include "CRYPTO_API_SW/src/rsa/rsa.h"

#define rsa_genkeys RSA_GEN_KEYS
#define rsa_encrypt RSA_ENCRYPT
#define rsa_decrypt RSA_DECRYPT

#include "CRYPTO_API_SW/src/sha2/sha2.h"

#define sha_256		SHA_256
#define sha_224		SHA_224
#define sha_384		SHA_384
#define sha_512		SHA_512
#define sha_512_224 SHA_512_224
#define sha_512_256 SHA_512_256

#include "CRYPTO_API_SW/src/sha3/sha3.h"

#define sha3_256	SHA3_256
#define sha3_224	SHA3_224
#define sha3_384	SHA3_384
#define sha3_512	SHA3_512
#define shake_128	SHAKE_128
#define shake_256	SHAKE_256

#include "CRYPTO_API_SW/src/aes/aes.h"

#define aes_128_ecb_encrypt	AES_128_ECB_ENCRYPT
#define aes_128_ecb_decrypt	AES_128_ECB_DECRYPT
#define aes_192_ecb_encrypt	AES_192_ECB_ENCRYPT
#define aes_192_ecb_decrypt	AES_192_ECB_DECRYPT
#define aes_256_ecb_encrypt	AES_256_ECB_ENCRYPT
#define aes_256_ecb_decrypt	AES_256_ECB_DECRYPT

#define aes_128_cbc_encrypt	AES_128_CBC_ENCRYPT
#define aes_128_cbc_decrypt	AES_128_CBC_DECRYPT
#define aes_192_cbc_encrypt	AES_192_CBC_ENCRYPT
#define aes_192_cbc_decrypt	AES_192_CBC_DECRYPT
#define aes_256_cbc_encrypt	AES_256_CBC_ENCRYPT
#define aes_256_cbc_decrypt	AES_256_CBC_DECRYPT

#define aes_128_cmac	AES_128_CMAC
#define aes_192_cmac	AES_192_CMAC
#define aes_256_cmac	AES_256_CMAC

#define aes_128_gcm_encrypt	AES_128_GCM_ENCRYPT
#define aes_128_gcm_decrypt	AES_128_GCM_DECRYPT
#define aes_192_gcm_encrypt	AES_192_GCM_ENCRYPT
#define aes_192_gcm_decrypt	AES_192_GCM_DECRYPT
#define aes_256_gcm_encrypt	AES_256_GCM_ENCRYPT
#define aes_256_gcm_decrypt	AES_256_GCM_DECRYPT

#define aes_128_ccm_8_encrypt	AES_128_CCM_8_ENCRYPT
#define aes_128_ccm_8_decrypt	AES_128_CCM_8_DECRYPT
#define aes_192_ccm_8_encrypt	AES_192_CCM_8_ENCRYPT
#define aes_192_ccm_8_decrypt	AES_192_CCM_8_DECRYPT
#define aes_256_ccm_8_encrypt	AES_256_CCM_8_ENCRYPT
#define aes_256_ccm_8_decrypt	AES_256_CCM_8_DECRYPT

#include "CRYPTO_API_SW/src/trng/trng.h"

#define trng		TRNG
#define ctr_drbg	CTR_DRBG
#define hash_drbg	HASH_DRBG

#include "CRYPTO_API_SW/src/hkdf/hkdf.h"

#define hkdf_sha256		HKDF_SHA256

#include "CRYPTO_API_SW/src/eddsa/eddsa.h"	

#define eddsa25519_genkeys  EDDSA25519_GEN_KEYS
#define eddsa25519_sign		EDDSA25519_SIGN
#define eddsa25519_verify	EDDSA25519_VERIFY

#define eddsa448_genkeys	EDDSA448_GEN_KEYS
#define eddsa448_sign		EDDSA448_SIGN
#define eddsa448_verify		EDDSA448_VERIFY

#include "CRYPTO_API_SW/src/x25519/x25519.h"	

#define x25519_genkeys  X25519_GEN_KEYS
#define x25519_ss_gen	X25519_SS_GEN

#define x448_genkeys	X448_GEN_KEYS
#define x448_ss_gen		X448_SS_GEN

#include "CRYPTO_API_SW/src/mlkem/mlkem.h"

#define mlkem512_genkeys	MLKEM_512_GEN_KEYS
#define mlkem768_genkeys	MLKEM_768_GEN_KEYS
#define mlkem1024_genkeys	MLKEM_1024_GEN_KEYS

#define mlkem512_enc		MLKEM_512_ENC
#define mlkem768_enc		MLKEM_768_ENC
#define mlkem1024_enc		MLKEM_1024_ENC

#define mlkem512_dec		MLKEM_512_DEC
#define mlkem768_dec		MLKEM_768_DEC
#define mlkem1024_dec		MLKEM_1024_DEC

#include "CRYPTO_API_SW/src/mldsa/mldsa.h"

#define mldsa44_genkeys		MLDSA_44_GEN_KEYS
#define mldsa65_genkeys		MLDSA_65_GEN_KEYS
#define mldsa87_genkeys		MLDSA_87_GEN_KEYS

#define mldsa44_sig			MLDSA_44_SIGN
#define mldsa65_sig			MLDSA_65_SIGN
#define mldsa87_sig			MLDSA_87_SIGN

#define mldsa44_verify		MLDSA_44_VERIFY
#define mldsa65_verify		MLDSA_65_VERIFY
#define mldsa87_verify		MLDSA_87_VERIFY

#include "CRYPTO_API_SW/src/slhdsa/slhdsa.h"

#define slhdsa_shake128f_genkeys		SLHDSA_SHAKE_128_F_GEN_KEYS
#define slhdsa_shake128s_genkeys		SLHDSA_SHAKE_128_S_GEN_KEYS
#define slhdsa_shake192f_genkeys		SLHDSA_SHAKE_192_F_GEN_KEYS
#define slhdsa_shake192s_genkeys		SLHDSA_SHAKE_192_S_GEN_KEYS
#define slhdsa_shake256f_genkeys		SLHDSA_SHAKE_256_F_GEN_KEYS
#define slhdsa_shake256s_genkeys		SLHDSA_SHAKE_256_S_GEN_KEYS

#define slhdsa_shake128f_sig		SLHDSA_SHAKE_128_F_SIGN
#define slhdsa_shake128s_sig		SLHDSA_SHAKE_128_S_SIGN
#define slhdsa_shake192f_sig		SLHDSA_SHAKE_192_F_SIGN
#define slhdsa_shake192s_sig		SLHDSA_SHAKE_192_S_SIGN
#define slhdsa_shake256f_sig		SLHDSA_SHAKE_256_F_SIGN
#define slhdsa_shake256s_sig		SLHDSA_SHAKE_256_S_SIGN

#define slhdsa_shake128f_verify		SLHDSA_SHAKE_128_F_VERIFY
#define slhdsa_shake128s_verify		SLHDSA_SHAKE_128_S_VERIFY
#define slhdsa_shake192f_verify		SLHDSA_SHAKE_192_F_VERIFY
#define slhdsa_shake192s_verify		SLHDSA_SHAKE_192_S_VERIFY
#define slhdsa_shake256f_verify		SLHDSA_SHAKE_256_F_VERIFY
#define slhdsa_shake256s_verify		SLHDSA_SHAKE_256_S_VERIFY

#endif