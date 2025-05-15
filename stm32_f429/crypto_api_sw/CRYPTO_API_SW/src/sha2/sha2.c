/**
  * @file sha2.c
  * @brief SHA2 code
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

#include "sha2.h"

// https://www.openssl.org/docs/manmaster/man7/OSSL_PROVIDER-default.html
// https://www.openssl.org/docs/manmaster/man7/EVP_MD-SHA2.html

#ifdef OPENSSL
void SHA_224(unsigned char* input, unsigned int len_input, unsigned char* md_value)
{

    EVP_MD_CTX* mdctx;
    const EVP_MD* md = EVP_MD_fetch(NULL, "SHA224", NULL);

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex2(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input, len_input);
    EVP_DigestFinal_ex(mdctx, md_value, NULL);
    EVP_MD_CTX_free(mdctx);


}

void SHA_256(unsigned char* input, unsigned int len_input, unsigned char* md_value)
{

    EVP_MD_CTX* mdctx;
    const EVP_MD* md = EVP_MD_fetch(NULL, "SHA256", NULL);

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex2(mdctx, md, NULL); 
    EVP_DigestUpdate(mdctx, input, len_input);
    EVP_DigestFinal_ex(mdctx, md_value, NULL);
    EVP_MD_CTX_free(mdctx);


}

void SHA_384(unsigned char* input, unsigned int len_input, unsigned char* md_value)
{

    EVP_MD_CTX* mdctx;
    const EVP_MD* md = EVP_MD_fetch(NULL, "SHA384", NULL);

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex2(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input, len_input);
    EVP_DigestFinal_ex(mdctx, md_value, NULL);
    EVP_MD_CTX_free(mdctx);


}

void SHA_512(unsigned char* input, unsigned int len_input, unsigned char* md_value)
{

    EVP_MD_CTX* mdctx;
    const EVP_MD* md = EVP_MD_fetch(NULL, "SHA512", NULL);

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex2(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input, len_input);
    EVP_DigestFinal_ex(mdctx, md_value, NULL);
    EVP_MD_CTX_free(mdctx);


}

void SHA_512_224(unsigned char* input, unsigned int len_input, unsigned char* md_value)
{

    EVP_MD_CTX* mdctx;
    const EVP_MD* md = EVP_MD_fetch(NULL, "SHA512-224", NULL);

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex2(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input, len_input);
    EVP_DigestFinal_ex(mdctx, md_value, NULL);
    EVP_MD_CTX_free(mdctx);


}

void SHA_512_256(unsigned char* input, unsigned int len_input, unsigned char* md_value)
{

    EVP_MD_CTX* mdctx;
    const EVP_MD* md = EVP_MD_fetch(NULL, "SHA512-256", NULL);

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex2(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input, len_input);
    EVP_DigestFinal_ex(mdctx, md_value, NULL);
    EVP_MD_CTX_free(mdctx);


}

#elif MBEDTLS 

void SHA_224(unsigned char* input, unsigned int len_input, unsigned char* md_value)
{
    mbedtls_sha256(input, len_input, md_value, 1);
}

void SHA_256(unsigned char* input, unsigned int len_input, unsigned char* md_value)
{
    mbedtls_sha256(input, len_input, md_value, 0);
}

void SHA_384(unsigned char* input, unsigned int len_input, unsigned char* md_value)
{
    mbedtls_sha512(input, len_input, md_value, 1);
}

void SHA_512(unsigned char* input, unsigned int len_input, unsigned char* md_value)
{

    mbedtls_sha512(input, len_input, md_value, 0);
}

void SHA_512_224(unsigned char* input, unsigned int len_input, unsigned char* md_value)
{
    printf("\n Not supported in MbedTLS");
}

void SHA_512_256(unsigned char* input, unsigned int len_input, unsigned char* md_value)
{
    printf("\n Not supported in MbedTLS");
}

#else 

// https://github.com/Oryx-Embedded/CycloneCRYPTO/tree/master/hash

void SHA_224(unsigned char* input, unsigned int len_input, unsigned char* md_value)
{
    sha224Compute(input, len_input, md_value);
}

void SHA_256(unsigned char* input, unsigned int len_input, unsigned char* md_value)
{
    sha256Compute(input, len_input, md_value);
}

void SHA_384(unsigned char* input, unsigned int len_input, unsigned char* md_value)
{
    sha384Compute(input, len_input, md_value);
}

void SHA_512(unsigned char* input, unsigned int len_input, unsigned char* md_value)
{
    sha512Compute(input, len_input, md_value);
}

void SHA_512_224(unsigned char* input, unsigned int len_input, unsigned char* md_value)
{
    sha512_224Compute(input, len_input, md_value);
}

void SHA_512_256(unsigned char* input, unsigned int len_input, unsigned char* md_value)
{
    sha512_256Compute(input, len_input, md_value);
}

#endif
