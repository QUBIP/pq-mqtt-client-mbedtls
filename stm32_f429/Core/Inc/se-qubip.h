/**
 * @file  se-qubip.h
 * @brief SEQUBIP header
 *
 * @section License
 *
 * Secure Element for QUBIP Project
 *
 * This Secure Element repository for QUBIP Project is subject to the
 * BSD 3-Clause License below.
 *
 * Copyright (c) 2024,
 *         Eros Camacho-Ruiz
 *         Pablo Navarro-Torrero
 *         Pau Ortega-Castro
 *         Apurba Karmakar
 *         Macarena C. Martínez-Rodríguez
 *         Piedad Brox
 *
 * All rights reserved.
 *
 * This Secure Element was developed by Instituto de Microelectrónica de
 * Sevilla - IMSE (CSIC/US) as part of the QUBIP Project, co-funded by the
 * European Union under the Horizon Europe framework programme
 * [grant agreement no. 101119746].
 *
 * -----------------------------------------------------------------------
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 *
 *
 * @author Eros Camacho-Ruiz (camacho@imse-cnm.csic.es)
 * @version 1.0
 **/

#ifndef SE_QUBIP_H_INCLUDED
#define SE_QUBIP_H_INCLUDED

#include <stdlib.h>

#include "intf.h"
#include "picorv32.h"
#include "sha3_shake_hw.h"
#include "sha2_hw.h"
#include "eddsa_hw.h"
#include "x25519_hw.h"
#include "trng_hw.h"
#include "aes_hw.h"
#include "mlkem_hw.h"
#include "mldsa_hw.h"
#include "slhdsa_hw.h"
#include "secmem_hw.h"
#include "spi_hw.h"

//-- SHA-3 / SHAKE
#define sha3_512_hw			                sha3_512_hw_func
#define sha3_256_hw			                sha3_256_hw_func
#define shake_128_hw		                shake128_hw_func
#define shake_256_hw		                shake256_hw_func

#define sha_256_hw			                sha_256_hw_func
#define sha_384_hw			                sha_384_hw_func
#define sha_512_hw			                sha_512_hw_func
#define sha_512_256_hw		                sha_512_256_hw_func

//-- EdDSA25519
#define eddsa25519_genkeys_hw               eddsa25519_genkeys_hw
#define eddsa25519_sign_hw                  eddsa25519_sign_hw
#define eddsa25519_verify_hw                eddsa25519_verify_hw

//-- X25519
#define x25519_genkeys_hw                   x25519_genkeys_hw
#define x25519_ss_gen_hw                    x25519_ss_gen_hw

//-- TRNG
#define trng_hw        			            trng_hw

//-- AES-128/192/256-ECB
#define aes_128_ecb_encrypt_hw              aes_128_ecb_encrypt_hw
#define aes_128_ecb_decrypt_hw              aes_128_ecb_decrypt_hw
#define aes_192_ecb_encrypt_hw              aes_192_ecb_encrypt_hw
#define aes_192_ecb_decrypt_hw              aes_192_ecb_decrypt_hw
#define aes_256_ecb_encrypt_hw              aes_256_ecb_encrypt_hw
#define aes_256_ecb_decrypt_hw              aes_256_ecb_decrypt_hw

//-- AES-128/192/256-CBC
#define aes_128_cbc_encrypt_hw              aes_128_cbc_encrypt_hw
#define aes_128_cbc_decrypt_hw              aes_128_cbc_decrypt_hw
#define aes_192_cbc_encrypt_hw              aes_192_cbc_encrypt_hw
#define aes_192_cbc_decrypt_hw              aes_192_cbc_decrypt_hw
#define aes_256_cbc_encrypt_hw              aes_256_cbc_encrypt_hw
#define aes_256_cbc_decrypt_hw              aes_256_cbc_decrypt_hw

//-- AES-128/192/256-CMAC
#define aes_128_cmac_hw                     aes_128_cmac_hw
#define aes_192_cmac_hw                     aes_192_cmac_hw
#define aes_256_cmac_hw                     aes_256_cmac_hw

//-- AES-128/192/256-CCM-8
#define aes_128_ccm_8_encrypt_hw            aes_128_ccm_8_encrypt_hw
#define aes_128_ccm_8_decrypt_hw            aes_128_ccm_8_decrypt_hw
#define aes_192_ccm_8_encrypt_hw            aes_192_ccm_8_encrypt_hw
#define aes_192_ccm_8_decrypt_hw            aes_192_ccm_8_decrypt_hw
#define aes_256_ccm_8_encrypt_hw            aes_256_ccm_8_encrypt_hw
#define aes_256_ccm_8_decrypt_hw            aes_256_ccm_8_decrypt_hw

//-- AES-128/192/256-GCM
#define aes_128_gcm_encrypt_hw              aes_128_gcm_encrypt_hw
#define aes_128_gcm_decrypt_hw              aes_128_gcm_decrypt_hw
#define aes_192_gcm_encrypt_hw              aes_192_gcm_encrypt_hw
#define aes_192_gcm_decrypt_hw              aes_192_gcm_decrypt_hw
#define aes_256_gcm_encrypt_hw              aes_256_gcm_encrypt_hw
#define aes_256_gcm_decrypt_hw              aes_256_gcm_decrypt_hw

//-- MLKEM
#define mlkem512_genkeys_hw                 mlkem_512_gen_keys_hw
#define mlkem768_genkeys_hw                 mlkem_768_gen_keys_hw
#define mlkem1024_genkeys_hw                mlkem_1024_gen_keys_hw
#define mlkem_gen_keys_hw                   mlkem_gen_keys_hw

#define mlkem512_enc_hw                     mlkem_512_enc_hw
#define mlkem768_enc_hw                     mlkem_768_enc_hw
#define mlkem1024_enc_hw                    mlkem_1024_enc_hw
#define mlkem_enc_hw                        mlkem_enc_hw

#define mlkem512_dec_hw                     mlkem_512_dec_hw
#define mlkem768_dec_hw                     mlkem_768_dec_hw
#define mlkem1024_dec_hw                    mlkem_1024_dec_hw
#define mlkem_dec_hw                        mlkem_dec_hw

//-- MLDSA
#define mldsa44_genkeys_hw                  mldsa44_genkeys_hw
#define mldsa65_genkeys_hw                  mldsa65_genkeys_hw
#define mldsa87_genkeys_hw                  mldsa87_genkeys_hw

#define mldsa44_sign_hw                     mldsa44_sign_hw
#define mldsa65_sign_hw                     mldsa65_sign_hw
#define mldsa87_sign_hw                     mldsa87_sign_hw

#define mldsa44_verify_hw                   mldsa44_verify_hw
#define mldsa65_verify_hw                   mldsa65_verify_hw
#define mldsa87_verify_hw                   mldsa87_verify_hw

//-- SLHDSA
#define slhdsa_shake_128_f_gen_keys_hw      slhdsa_shake_128_f_gen_keys_hw
#define slhdsa_shake_128_s_gen_keys_hw      slhdsa_shake_128_s_gen_keys_hw
#define slhdsa_shake_192_f_gen_keys_hw      slhdsa_shake_192_f_gen_keys_hw
#define slhdsa_shake_192_s_gen_keys_hw      slhdsa_shake_192_s_gen_keys_hw
#define slhdsa_shake_256_f_gen_keys_hw      slhdsa_shake_256_f_gen_keys_hw
#define slhdsa_shake_256_s_gen_keys_hw      slhdsa_shake_256_s_gen_keys_hw

#define slhdsa_sha2_128_f_gen_keys_hw       slhdsa_sha2_128_f_gen_keys_hw
#define slhdsa_sha2_128_s_gen_keys_hw       slhdsa_sha2_128_s_gen_keys_hw
#define slhdsa_sha2_192_f_gen_keys_hw       slhdsa_sha2_192_f_gen_keys_hw
#define slhdsa_sha2_192_s_gen_keys_hw       slhdsa_sha2_192_s_gen_keys_hw
#define slhdsa_sha2_256_f_gen_keys_hw       slhdsa_sha2_256_f_gen_keys_hw
#define slhdsa_sha2_256_s_gen_keys_hw       slhdsa_sha2_256_s_gen_keys_hw

#define slhdsa_shake_128_f_ph_sign_hw       slhdsa_shake_128_f_ph_sign_hw
#define slhdsa_shake_128_s_ph_sign_hw       slhdsa_shake_128_s_ph_sign_hw
#define slhdsa_shake_192_f_ph_sign_hw       slhdsa_shake_192_f_ph_sign_hw
#define slhdsa_shake_192_s_ph_sign_hw       slhdsa_shake_192_s_ph_sign_hw
#define slhdsa_shake_256_f_ph_sign_hw       slhdsa_shake_256_f_ph_sign_hw
#define slhdsa_shake_256_s_ph_sign_hw       slhdsa_shake_256_s_ph_sign_hw

#define slhdsa_sha2_128_f_ph_sign_hw        slhdsa_sha2_128_f_ph_sign_hw
#define slhdsa_sha2_128_s_ph_sign_hw        slhdsa_sha2_128_s_ph_sign_hw
#define slhdsa_sha2_192_f_ph_sign_hw        slhdsa_sha2_192_f_ph_sign_hw
#define slhdsa_sha2_192_s_ph_sign_hw        slhdsa_sha2_192_s_ph_sign_hw
#define slhdsa_sha2_256_f_ph_sign_hw        slhdsa_sha2_256_f_ph_sign_hw
#define slhdsa_sha2_256_s_ph_sign_hw        slhdsa_sha2_256_s_ph_sign_hw

#define slhdsa_shake_128_f_ph_verify_hw     slhdsa_shake_128_f_ph_verify_hw
#define slhdsa_shake_128_s_ph_verify_hw     slhdsa_shake_128_s_ph_verify_hw
#define slhdsa_shake_192_f_ph_verify_hw     slhdsa_shake_192_f_ph_verify_hw
#define slhdsa_shake_192_s_ph_verify_hw     slhdsa_shake_192_s_ph_verify_hw
#define slhdsa_shake_256_f_ph_verify_hw     slhdsa_shake_256_f_ph_verify_hw
#define slhdsa_shake_256_s_ph_verify_hw     slhdsa_shake_256_s_ph_verify_hw

#define slhdsa_sha2_128_f_ph_verify_hw      slhdsa_sha2_128_f_ph_verify_hw
#define slhdsa_sha2_128_s_ph_verify_hw      slhdsa_sha2_128_s_ph_verify_hw
#define slhdsa_sha2_192_f_ph_verify_hw      slhdsa_sha2_192_f_ph_verify_hw
#define slhdsa_sha2_192_s_ph_verify_hw      slhdsa_sha2_192_s_ph_verify_hw
#define slhdsa_sha2_256_f_ph_verify_hw      slhdsa_sha2_256_f_ph_verify_hw
#define slhdsa_sha2_256_s_ph_verify_hw      slhdsa_sha2_256_s_ph_verify_hw

//-- SECMEM
#define secmem_store_key                    secmem_store_key
#define secmem_delete_key                   secmem_delete_key
#define secmem_get_key                      secmem_get_key
#define secmem_info                         secmem_info

//-- SPI FLASH
#define save_secmem_flash                   save_secmem_flash
#define recover_secmem_flash                recover_secmem_flash
#define save_data_flash                     save_data_flash
#define recover_data_flash                  recover_data_flash

//-- INTERFACE
#ifdef I2C
    #define INTF_ADDRESS            0x1A            //-- I2C_DEVICE_ADDRESS
    #define INTF_LENGTH		        0x40
#elif AXI
    // ------- MS2XL_BASEADDR ------- //
    #define INTF_LENGTH		        0x40

    #ifdef PYNQZ2
        #define INTF_ADDRESS		0x43C00000      //-- MS2XL_BASEADDR
    #elif ZCU104
        #define INTF_ADDRESS        0x00A0000000    //-- MS2XL_BASEADDR
    #else
        #define INTF_ADDRESS        0x0000000000
    #endif

    // ------- BITSTREAM_FILE ------- //
    #ifdef PYNQZ2
        #define BITSTREAM_AXI       "../se-qubip/bit/PYNQZ2_SE_QUBIP_3.3.bit"
    #elif ZCU104
        #define BITSTREAM_AXI       "../se-qubip/bit/ZCU104_SE_QUBIP_3.3.bit"
    #endif

    /* ------- FREQUENCIES DEFINITION ------- */
    #ifdef PYNQZ2
        #define FREQ_TYPICAL       100.0
        #define FREQ_SHA2          100.0
        #define FREQ_SHA3          100.0
        #define FREQ_EDDSA          60.0
        #define FREQ_X25519        100.0
        #define FREQ_MLKEM         100.0
        #define FREQ_AES           100.0
    #elif ZCU104
        #define FREQ_TYPICAL       320.0
        #define FREQ_SHA2          320.0
        #define FREQ_SHA3          320.0
        #define FREQ_EDDSA         320.0
        #define FREQ_X25519        320.0
        #define FREQ_MLKEM         320.0
        #define FREQ_AES           320.0
    #endif
#endif

#endif // SE_QUBIP_H_INCLUDED
