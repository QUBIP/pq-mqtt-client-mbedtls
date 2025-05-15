/**
  * @file sha3.c
  * @brief SHA3 code
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

#include "sha3.h"

// https://www.openssl.org/docs/manmaster/man7/OSSL_PROVIDER-default.html
// https://www.openssl.org/docs/manmaster/man7/EVP_MD-SHA3.html
// https://www.openssl.org/docs/manmaster/man7/EVP_MD-SHAKE.html

#ifdef OPENSSL

void SHA3_224(unsigned char* input, unsigned int len_input, unsigned char* md_value)
{

    EVP_MD_CTX* mdctx;
    const EVP_MD* md = EVP_MD_fetch(NULL, "SHA3-224", NULL);

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex2(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input, len_input);
    EVP_DigestFinal_ex(mdctx, md_value, NULL);
    EVP_MD_CTX_free(mdctx);


}

void SHA3_256(unsigned char* input, unsigned int len_input, unsigned char* md_value)
{

    EVP_MD_CTX* mdctx;
    const EVP_MD* md = EVP_MD_fetch(NULL, "SHA3-256", NULL);

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex2(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input, len_input);
    EVP_DigestFinal_ex(mdctx, md_value, NULL);
    EVP_MD_CTX_free(mdctx);


}

void SHA3_384(unsigned char* input, unsigned int len_input, unsigned char* md_value)
{

    EVP_MD_CTX* mdctx;
    const EVP_MD* md = EVP_MD_fetch(NULL, "SHA3-384", NULL);

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex2(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input, len_input);
    EVP_DigestFinal_ex(mdctx, md_value, NULL);
    EVP_MD_CTX_free(mdctx);


}

void SHA3_512(unsigned char* input, unsigned int len_input, unsigned char* md_value)
{

    EVP_MD_CTX* mdctx;
    const EVP_MD* md = EVP_MD_fetch(NULL, "SHA3-512", NULL);

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex2(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input, len_input);
    EVP_DigestFinal_ex(mdctx, md_value, NULL);
    EVP_MD_CTX_free(mdctx);


}

void SHAKE_128(unsigned char* input, unsigned int len_input, unsigned char* md_value, unsigned int len_md)
{

    EVP_MD_CTX* mdctx;
    const EVP_MD* md = EVP_MD_fetch(NULL, "SHAKE-128", NULL);

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex2(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input, len_input);
    EVP_DigestFinalXOF(mdctx, md_value, len_md);
    EVP_MD_CTX_free(mdctx);


}

void SHAKE_256(unsigned char* input, unsigned int len_input, unsigned char* md_value, unsigned int len_md)
{

    EVP_MD_CTX* mdctx;
    const EVP_MD* md = EVP_MD_fetch(NULL, "SHAKE-256", NULL);

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex2(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input, len_input);
    EVP_DigestFinalXOF(mdctx, md_value, len_md);
    EVP_MD_CTX_free(mdctx);


}

#elif MBEDTLS


void SHA3_224(unsigned char* input, unsigned int len_input, unsigned char* md_value)
{
    mbedtls_sha3(MBEDTLS_SHA3_224, input, len_input, md_value, 28);
}

void SHA3_256(unsigned char* input, unsigned int len_input, unsigned char* md_value)
{
    mbedtls_sha3(MBEDTLS_SHA3_256, input, len_input, md_value, 32);
}

void SHA3_384(unsigned char* input, unsigned int len_input, unsigned char* md_value)
{
    mbedtls_sha3(MBEDTLS_SHA3_384, input, len_input, md_value, 48);
}

void SHA3_512(unsigned char* input, unsigned int len_input, unsigned char* md_value)
{
    mbedtls_sha3(MBEDTLS_SHA3_512, input, len_input, md_value, 64);
}

void SHAKE_128(unsigned char* input, unsigned int len_input, unsigned char* md_value, unsigned int len_md)
{
    printf("\n Not supported in MbedTLS");

}

void SHAKE_256(unsigned char* input, unsigned int len_input, unsigned char* md_value, unsigned int len_md)
{
    printf("\n Not supported in MbedTLS");
}

#else

void SHA3_224(unsigned char* input, unsigned int len_input, unsigned char* md_value)
{
    sha3_224Compute(input, len_input, md_value);
}

void SHA3_256(unsigned char* input, unsigned int len_input, unsigned char* md_value)
{
    sha3_256Compute(input, len_input, md_value);
}

void SHA3_384(unsigned char* input, unsigned int len_input, unsigned char* md_value)
{
    sha3_384Compute(input, len_input, md_value);
}

void SHA3_512(unsigned char* input, unsigned int len_input, unsigned char* md_value)
{
    sha3_512Compute(input, len_input, md_value);
}

void SHAKE_128(unsigned char* input, unsigned int len_input, unsigned char* md_value, unsigned int len_md)
{
    shakeCompute(128, input, len_input, md_value, len_md);
}

void SHAKE_256(unsigned char* input, unsigned int len_input, unsigned char* md_value, unsigned int len_md)
{
    shakeCompute(256, input, len_input, md_value, len_md);
}

#endif // OPENSSL
