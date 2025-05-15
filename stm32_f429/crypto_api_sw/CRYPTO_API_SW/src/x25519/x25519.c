/**
  * @file x25519.c
  * @brief ECDH code
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

#include "x25519.h"
// #include "../../../demo/src/test_func.h"

// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br2.pdf
// https://stackoverflow.com/questions/76683427/extracting-the-encoded-public-key-from-rsa-key-pair-in-openssl-3
// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
// https://github.com/danbev/learning-openssl/blob/master/rsa.c
// https://stackoverflow.com/questions/68102808/how-to-use-openssl-3-0-rsa-in-c

#ifdef OPENSSL
void X25519_GEN_KEYS(unsigned char** pri_key, unsigned char** pub_key, unsigned int* pri_len, unsigned int* pub_len) {

    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);

    size_t priv_len;
    size_t publ_len;

    EVP_PKEY_get_raw_private_key(pkey, NULL, &priv_len);
    EVP_PKEY_get_raw_public_key(pkey, NULL, &publ_len);
    
    *pri_key = malloc(priv_len);
    *pub_key = malloc(publ_len);

    EVP_PKEY_get_raw_private_key(pkey, *pri_key, &priv_len);
    EVP_PKEY_get_raw_public_key(pkey, *pub_key, &publ_len);

    *pri_len = (unsigned int)priv_len;
    *pub_len = (unsigned int)publ_len;

}

void X448_GEN_KEYS(unsigned char** pri_key, unsigned char** pub_key, unsigned int* pri_len, unsigned int* pub_len) {

    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X448, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);

    size_t priv_len;
    size_t publ_len;

    EVP_PKEY_get_raw_private_key(pkey, NULL, &priv_len);
    EVP_PKEY_get_raw_public_key(pkey, NULL, &publ_len);

    *pri_key = malloc(priv_len);
    *pub_key = malloc(publ_len);

    EVP_PKEY_get_raw_private_key(pkey, *pri_key, &priv_len);
    EVP_PKEY_get_raw_public_key(pkey, *pub_key, &publ_len);

    *pri_len = (unsigned int)priv_len;
    *pub_len = (unsigned int)publ_len;

}

void X25519_SS_GEN(unsigned char** shared_secret, unsigned int* shared_secret_len, const unsigned char* pub_key, unsigned int pub_len, const unsigned char* pri_key, unsigned int pri_len)
{
    EVP_PKEY_CTX* ctx;
    EVP_PKEY* pkey;
    EVP_PKEY* peerkey;
    unsigned char* skey;

    size_t len;
    size_t l1;
    size_t l2;

    // Decode the public & private key
    pkey    = EVP_PKEY_new_raw_private_key  (EVP_PKEY_X25519, NULL, pri_key, pri_len);
    peerkey = EVP_PKEY_new_raw_public_key   (EVP_PKEY_X25519, NULL, pub_key, pub_len);
    ctx = EVP_PKEY_CTX_new(pkey, NULL);

    if (!ctx)
        printf("\n Error");
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peerkey);

    EVP_PKEY_derive(ctx, NULL, &len);
    *shared_secret = malloc(len);
    EVP_PKEY_derive(ctx, *shared_secret, &len);

    *shared_secret_len = (unsigned int)len;

    EVP_PKEY_free(pkey);
    EVP_PKEY_free(peerkey);
    EVP_PKEY_CTX_free(ctx);
}

void X448_SS_GEN(unsigned char** shared_secret, unsigned int* shared_secret_len, const unsigned char* pub_key, unsigned int pub_len, const unsigned char* pri_key, unsigned int pri_len)
{
    EVP_PKEY_CTX* ctx;
    EVP_PKEY* pkey;
    EVP_PKEY* peerkey;
    unsigned char* skey;

    size_t len;
    size_t l1;
    size_t l2;

    // Decode the public & private key
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X448, NULL, pri_key, pri_len);
    peerkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X448, NULL, pub_key, pub_len);
    ctx = EVP_PKEY_CTX_new(pkey, NULL);

    if (!ctx)
        printf("\n Error");
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peerkey);

    EVP_PKEY_derive(ctx, NULL, &len);
    *shared_secret = malloc(len);
    EVP_PKEY_derive(ctx, *shared_secret, &len);

    *shared_secret_len = (unsigned int)len;

    EVP_PKEY_free(pkey);
    EVP_PKEY_free(peerkey);
    EVP_PKEY_CTX_free(ctx);
}

#elif MBEDTLS

void X25519_GEN_KEYS(unsigned char** pri_key, unsigned char** pub_key, unsigned int* pri_len, unsigned int* pub_len) {


    // Entropy function //
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    unsigned char seed[16];
    sprintf(seed, "%ld", time(NULL));
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, seed, 16);
    

    // Key generation //
    
    mbedtls_ecdh_context ctx;
    mbedtls_ecp_group_id curve = MBEDTLS_ECP_DP_CURVE25519;

    *pri_key = malloc(32);
    *pub_key = malloc(32);

    mbedtls_ecp_group ctx_grp;
    mbedtls_ecp_group_init(&ctx_grp);

    mbedtls_ecp_group_load(&ctx_grp, curve);

    mbedtls_mpi in_pri_key;
    mbedtls_mpi_init(&in_pri_key);

    mbedtls_ecp_point in_pub_key;
    mbedtls_ecp_point_init(&in_pub_key);


    mbedtls_ecp_gen_keypair(&ctx_grp, &in_pri_key, &in_pub_key, mbedtls_ctr_drbg_random, &ctr_drbg);

    size_t len;

    unsigned char* pkey1;
    pkey1 = malloc(32);
    unsigned char* pkey2;
    pkey2 = malloc(32);

    mbedtls_ecp_point_write_binary(&ctx_grp, &in_pub_key, MBEDTLS_ECP_PF_UNCOMPRESSED, &len, pkey1, 32);
    memcpy(*pub_key, pkey1, 32);
    mbedtls_mpi_write_binary(&in_pri_key, pkey2, 32);
    memcpy(*pri_key, pkey2, 32);

    *pub_len = 32;
    *pri_len = 32;
}

void X448_GEN_KEYS(unsigned char** pri_key, unsigned char** pub_key, unsigned int* pri_len, unsigned int* pub_len) {


    // Entropy function //
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    unsigned char seed[16];
    sprintf(seed, "%ld", time(NULL));
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, seed, 16);


    // Key generation //

    mbedtls_ecp_group_id curve = MBEDTLS_ECP_DP_CURVE448;

    *pri_key = malloc(56);
    *pub_key = malloc(56);

    mbedtls_ecp_group ctx_grp;
    mbedtls_ecp_group_init(&ctx_grp);

    mbedtls_ecp_group_load(&ctx_grp, curve);

    mbedtls_mpi in_pri_key;
    mbedtls_mpi_init(&in_pri_key);

    mbedtls_ecp_point in_pub_key;
    mbedtls_ecp_point_init(&in_pub_key);


    mbedtls_ecp_gen_keypair(&ctx_grp, &in_pri_key, &in_pub_key, mbedtls_ctr_drbg_random, &ctr_drbg);

    size_t len;

    unsigned char* pkey1;
    pkey1 = malloc(56);
    unsigned char* pkey2;
    pkey2 = malloc(56);

    mbedtls_ecp_point_write_binary(&ctx_grp, &in_pub_key, MBEDTLS_ECP_PF_UNCOMPRESSED, &len, pkey1, 56);
    memcpy(*pub_key, pkey1, 56);
    mbedtls_mpi_write_binary(&in_pri_key, pkey2, 56);
    memcpy(*pri_key, pkey2, 56);

    *pub_len = 56;
    *pri_len = 56;

}

void X25519_SS_GEN(unsigned char** shared_secret, unsigned int* shared_secret_len, const unsigned char* pub_key, unsigned int pub_len, const unsigned char* pri_key, unsigned int pri_len)
{   
    // Entropy function //
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    unsigned char seed[16];
    sprintf(seed, "%ld", time(NULL));
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, seed, 16);

    // Ini curve //
    mbedtls_ecp_group_id curve = MBEDTLS_ECP_DP_CURVE25519;

    mbedtls_ecp_group ctx_grp;
    mbedtls_ecp_group_init(&ctx_grp);
    mbedtls_ecp_group_load(&ctx_grp, curve);

    // Ini pri_key //
    mbedtls_mpi in_pri_key;
    mbedtls_mpi_init(&in_pri_key);
    mbedtls_mpi_read_binary(&in_pri_key, pri_key, pri_len);

    mbedtls_ecp_point in_pub_key;
    mbedtls_ecp_point_init(&in_pub_key);
    mbedtls_ecp_point_read_binary(&ctx_grp, &in_pub_key, pub_key, pub_len);

    mbedtls_mpi out_ss;
    mbedtls_mpi_init(&out_ss);

    mbedtls_ecdh_compute_shared(&ctx_grp, &out_ss, &in_pub_key, &in_pri_key, mbedtls_ctr_drbg_random, &ctr_drbg);

    unsigned char out_ss_char[32];
    mbedtls_mpi_write_binary(&out_ss, out_ss_char, 32);
    *shared_secret = malloc(32);
    *shared_secret_len = 32;
    memcpy(*shared_secret, out_ss_char, 32);
}

void X448_SS_GEN(unsigned char** shared_secret, unsigned int* shared_secret_len, const unsigned char* pub_key, unsigned int pub_len, const unsigned char* pri_key, unsigned int pri_len)
{
    // Entropy function //
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    unsigned char seed[16];
    sprintf(seed, "%ld", time(NULL));
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, seed, 16);

    // Ini curve //
    mbedtls_ecp_group_id curve = MBEDTLS_ECP_DP_CURVE448;

    mbedtls_ecp_group ctx_grp;
    mbedtls_ecp_group_init(&ctx_grp);
    mbedtls_ecp_group_load(&ctx_grp, curve);

    // Ini pri_key //
    mbedtls_mpi in_pri_key;
    mbedtls_mpi_init(&in_pri_key);
    mbedtls_mpi_read_binary(&in_pri_key, pri_key, pri_len);

    mbedtls_ecp_point in_pub_key;
    mbedtls_ecp_point_init(&in_pub_key);
    mbedtls_ecp_point_read_binary(&ctx_grp, &in_pub_key, pub_key, pub_len);

    mbedtls_mpi out_ss;
    mbedtls_mpi_init(&out_ss);

    mbedtls_ecdh_compute_shared(&ctx_grp, &out_ss, &in_pub_key, &in_pri_key, mbedtls_ctr_drbg_random, &ctr_drbg);

    unsigned char out_ss_char[56];
    mbedtls_mpi_write_binary(&out_ss, out_ss_char, 56);
    *shared_secret = malloc(56);
    *shared_secret_len = 56;
    memcpy(*shared_secret, out_ss_char, 56);
}

#else 


void X25519_GEN_KEYS(unsigned char** pri_key, unsigned char** pub_key, unsigned int* pri_len, unsigned int* pub_len) {


    *pri_key = malloc(32);
    *pub_key = malloc(32);
    *pub_len = 32;
    *pri_len = 32;

    ecdhGenerateKeyPair(25519, *pri_key, *pub_key);

}

void X448_GEN_KEYS(unsigned char** pri_key, unsigned char** pub_key, unsigned int* pri_len, unsigned int* pub_len) {

    *pri_key = malloc(56);
    *pub_key = malloc(56);
    *pub_len = 56;
    *pri_len = 56;

    ecdhGenerateKeyPair(448, *pri_key, *pub_key);

}

void X25519_SS_GEN(unsigned char** shared_secret, unsigned int* shared_secret_len, const unsigned char* pub_key, unsigned int pub_len, const unsigned char* pri_key, unsigned int pri_len)
{
    *shared_secret = malloc(32);
    *shared_secret_len = 32;

    ecdhComputeSharedSecret(25519, pri_key, pub_key, *shared_secret);
}

void X448_SS_GEN(unsigned char** shared_secret, unsigned int* shared_secret_len, const unsigned char* pub_key, unsigned int pub_len, const unsigned char* pri_key, unsigned int pri_len)
{
    *shared_secret = malloc(56);
    *shared_secret_len = 56;

    ecdhComputeSharedSecret(448, pri_key, pub_key, *shared_secret);

}

#endif