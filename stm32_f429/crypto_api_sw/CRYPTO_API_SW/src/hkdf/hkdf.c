/**
  * @file hkdf.c
  * @brief HKDF-SHA256 code
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

#include "hkdf.h"

#ifdef OPENSSL
void HKDF_SHA256(unsigned char* key, unsigned int len_key, unsigned char* salt, unsigned int len_salt, unsigned char* info, unsigned int len_info, unsigned char* out, unsigned int len_out) {
	
    EVP_KDF* kdf;
    EVP_KDF_CTX* kctx;
    OSSL_PARAM params[5], * p = params;

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,SN_sha256, strlen(SN_sha256));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, key, len_key);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, len_salt);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, len_info);
    *p = OSSL_PARAM_construct_end();

    EVP_KDF_derive(kctx, out, len_out, params);

    EVP_KDF_CTX_free(kctx);

}

#elif MBEDTLS

void HKDF_SHA256(unsigned char* key, unsigned int len_key, unsigned char* salt, unsigned int len_salt, unsigned char* info, unsigned int len_info, unsigned char* out, unsigned int len_out) {

    mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), salt, (size_t)(len_salt), key, (size_t)(len_key), info, (size_t)(len_info), out, (size_t)(len_out));
}

#else

void HKDF_SHA256(unsigned char* key, unsigned int len_key, unsigned char* salt, unsigned int len_salt, unsigned char* info, unsigned int len_info, unsigned char* out, unsigned int len_out) {

    unsigned char PRK[32];

    hmac_sha256(salt, len_salt, key, len_key, PRK); // [RFC-5869] https://datatracker.ietf.org/doc/html/rfc5869

    size_t len = 0; 

    unsigned char h[32];
    // t update
    unsigned char* t;
    size_t st = 32 + len_info + 1;
    t = malloc(st);
    memset(t, 0, st);
    // t first
    unsigned char* tf;
    size_t stf = len_info + 1;
    tf = malloc(stf);
    memset(tf, 0, stf);

    unsigned char pad = 0;

    while (len < len_out) {
        // t | info | 0x01
        if (len != 0) {
            memcpy(t, h, 32);
            memcpy(t + 32, info, len_info);
            pad++; memcpy(t + len_info + 32, &pad, 1);

            // t = hmac(t)
            hmac_sha256(PRK, 32, t, st, h);
        }
        else {
            memcpy(tf, info, len_info);
            pad++; memcpy(tf + len_info, &pad, 1);

            // t = hmac(t)
            hmac_sha256(PRK, 32, tf, stf, h);
        
        }

        // out
        memcpy(out + len, h, 32);
        len = len + 32;
        memset(t, 0, st);
    }

    free(tf);
    free(t);
}



#endif