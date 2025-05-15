/**
  * @file eddsa.c
  * @brief EdDSA code
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

#include "eddsa.h"

#include "../../../demo/src/test_func.h"

// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br2.pdf
// https://stackoverflow.com/questions/76683427/extracting-the-encoded-public-key-from-rsa-key-pair-in-openssl-3
// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
// https://github.com/danbev/learning-openssl/blob/master/rsa.c
// https://stackoverflow.com/questions/68102808/how-to-use-openssl-3-0-rsa-in-c

#ifdef OPENSSL

void EDDSA25519_GEN_KEYS(unsigned char** pri_key, unsigned char** pub_key, unsigned int* pri_len, unsigned int* pub_len) {

    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
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

void EDDSA448_GEN_KEYS(unsigned char** pri_key, unsigned char** pub_key, unsigned int* pri_len, unsigned int* pub_len) {

    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED448, NULL);
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

void EDDSA25519_SIGN(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pri_key, const unsigned int pri_len, unsigned char** sig, unsigned int* sig_len) {
        
    EVP_PKEY* prikey = NULL;
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();

    prikey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, pri_key, pri_len);

    size_t len;

    EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, prikey);
    EVP_DigestSign(md_ctx, NULL, &len, msg, msg_len);
    *sig = malloc(len);
    EVP_DigestSign(md_ctx, *sig, &len, msg, msg_len);

    *sig_len = (unsigned int)len;

    EVP_MD_CTX_free(md_ctx);
}

void EDDSA448_SIGN(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pri_key, const unsigned int pri_len, unsigned char** sig, unsigned int* sig_len) {

    EVP_PKEY* prikey = NULL;
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();

    prikey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED448, NULL, pri_key, pri_len);

    size_t len;

    EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, prikey);
    EVP_DigestSign(md_ctx, NULL, &len, msg, msg_len);
    *sig = malloc(len);
    EVP_DigestSign(md_ctx, *sig, &len, msg, msg_len);

    *sig_len = (unsigned int)len;

    EVP_MD_CTX_free(md_ctx);
}


void EDDSA25519_VERIFY(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pub_key, const unsigned int pub_len, const unsigned char* sig, const unsigned int sig_len, unsigned int* result) {

    EVP_PKEY* pubkey = NULL;
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();

    pubkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub_key, pub_len);

    size_t len;
    *result = 0;

    EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pubkey);
    *result = !EVP_DigestVerify(md_ctx, sig, sig_len, msg, msg_len);

    EVP_MD_CTX_free(md_ctx);
}

void EDDSA448_VERIFY(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pub_key, const unsigned int pub_len, const unsigned char* sig, const unsigned int sig_len, unsigned int* result) {

    EVP_PKEY* pubkey = NULL;
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();

    pubkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED448, NULL, pub_key, pub_len);

    size_t len;
    *result = 0;

    EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pubkey);
    *result = !EVP_DigestVerify(md_ctx, sig, sig_len, msg, msg_len);

    EVP_MD_CTX_free(md_ctx);
}

#elif MBEDTLS 

static const unsigned char ed25519_b[] = {
    0x52, 0x03, 0x6C, 0xEE, 0x2B, 0x6F, 0xFE, 0x73,
    0x8C, 0xC7, 0x40, 0x79, 0x77, 0x79, 0xE8, 0x98,
    0x00, 0x70, 0x0A, 0x4D, 0x41, 0x41, 0xD8, 0xAB,
    0x75, 0xEB, 0x4D, 0xCA, 0x13, 0x59, 0x78, 0xA3,
};
static const unsigned char ed25519_g_x[] = {
    0x21, 0x69, 0x36, 0xD3, 0xCD, 0x6E, 0x53, 0xFE,
    0xC0, 0xA4, 0xE2, 0x31, 0xFD, 0xD6, 0xDC, 0x5C,
    0x69, 0x2C, 0xC7, 0x60, 0x95, 0x25, 0xA7, 0xB2,
    0xC9, 0x56, 0x2D, 0x60, 0x8F, 0x25, 0xD5, 0x1A,
};
static const unsigned char ed25519_g_y[] = {
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x58,
};

typedef struct {
    mbedtls_mpi* X;
    mbedtls_mpi* Y;
    mbedtls_mpi* Z;
} point_eddsa;

static void dump_buf(const char* title, unsigned char* buf, size_t len)
{
    size_t i;

    mbedtls_printf("%s", title);
    for (i = 0; i < len; i++) {
        mbedtls_printf("%c%c", "0123456789ABCDEF"[buf[i] / 16],
            "0123456789ABCDEF"[buf[i] % 16]);
    }
    mbedtls_printf("\n");
}

static void dump_pubkey(const char* title, mbedtls_ecdsa_context* key)
{
    unsigned char buf[300];
    size_t len;

    if (mbedtls_ecp_write_public_key(key, MBEDTLS_ECP_PF_UNCOMPRESSED,
        &len, buf, sizeof(buf)) != 0) {
        mbedtls_printf("internal error\n");
        return;
    }

    dump_buf(title, buf, len);
}

static int ecdsa_signature_to_asn1(const mbedtls_mpi* r, const mbedtls_mpi* s,
    unsigned char* sig, size_t sig_size,
    size_t* slen)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char buf[MBEDTLS_ECDSA_MAX_LEN] = { 0 };
    unsigned char* p = buf + sizeof(buf);
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, buf, s));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, buf, r));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf,
        MBEDTLS_ASN1_CONSTRUCTED |
        MBEDTLS_ASN1_SEQUENCE));

    if (len > sig_size) {
        return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
    }

    show_array(buf, MBEDTLS_ECDSA_MAX_LEN, 32);

    memcpy(sig, p, len);
    *slen = len;

    return 0;
}

void EDDSA25519_GEN_KEYS(unsigned char** pri_key, unsigned char** pub_key, unsigned int* pri_len, unsigned int* pub_len) 
{
    /*
    *pri_key = malloc(32);
    *pub_key = malloc(32);
    *pub_len = 32;
    *pri_len = 32;

    // Entropy function //
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    unsigned char seed[16];
    sprintf(seed, "%ld", time(NULL));
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, seed, 16);

    // Priv key gen //
    mbedtls_entropy_func(&entropy, *pri_key, 32);

    // Hash priv //
    unsigned char buf[64];
    mbedtls_sha512(*pri_key, 32, buf, 0);
    buf[0] &= 0xF8;
    buf[31] &= 0x7F;
    buf[31] |= 0x40;

    // base point
    point_eddsa pe;
    mbedtls_mpi_read_binary(pe.X, ed25519_g_x, sizeof(ed25519_g_x));
    mbedtls_mpi_read_binary(pe.Y, ed25519_g_y, sizeof(ed25519_g_y));
    mbedtls_mpi_lset(pe.Z, 1);

    /*
    // scalar base mult
    mbedtls_mpi point; mbedtls_mpi_init(&point);
    mbedtls_mpi sb; mbedtls_mpi_init(&sb);

    mbedtls_mpi_read_binary(&point, buf, 32);
    mbedtls_mpi_read_binary(&sb, ed25519_b, 32);

    mbedtls_mpi pub; mbedtls_mpi_init(&pub);
    mbedtls_mpi_mul_mpi(&pub, &point, &sb); // mult scalar base

    */


    /*
    // Entropy function //
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    unsigned char seed[16];
    sprintf(seed, "%ld", time(NULL));
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, seed, 16);


    // Key generation //
    mbedtls_ecp_group_id curve = MBEDTLS_ECP_DP_CURVE25519;

    // Export 
    *pri_key = malloc(32);
    *pub_key = malloc(32);
    *pub_len = 32;
    *pri_len = 32;
    size_t len = 0;
         
    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, curve);

    mbedtls_ecp_keypair key_pair;
    mbedtls_ecp_keypair_init(&key_pair);

    mbedtls_ecp_gen_key(curve, &key_pair, mbedtls_entropy_func, &entropy);
    mbedtls_ecp_write_key_ext(&key_pair, &len, *pri_key, 32);
    mbedtls_ecp_write_public_key(&key_pair, MBEDTLS_ECP_PF_UNCOMPRESSED, &len, *pub_key, 32);
    
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_keypair_free(&key_pair);
    */

    printf("\n Not supported yet in MbedTLS");
}

void EDDSA448_GEN_KEYS(unsigned char** pri_key, unsigned char** pub_key, unsigned int* pri_len, unsigned int* pub_len) 
{
    printf("\n Not supported yet in MbedTLS");
}

void EDDSA25519_SIGN(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pri_key, const unsigned int pri_len, unsigned char** sig, unsigned int* sig_len) 
{
    /*
    unsigned char* hash;
    hash = malloc(64);

    mbedtls_sha512(msg, msg_len, hash, 0);
    */

    /*
    // Entropy function //
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    unsigned char seed[16];
    sprintf(seed, "%ld", time(NULL));
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, seed, 16);

    // hash message
    unsigned char* hash;
    hash = malloc(64);

    mbedtls_sha512(msg, msg_len, hash, 0);
    show_array(hash, 64, 32);

    *sig = malloc(MBEDTLS_ECDSA_MAX_LEN);
    *sig_len = MBEDTLS_ECDSA_MAX_LEN;

    // Recover key
    mbedtls_ecp_group_id curve = MBEDTLS_ECP_DP_CURVE25519;

    mbedtls_ecp_keypair key_pair;
    mbedtls_ecp_keypair_init(&key_pair);

    mbedtls_ecp_read_key(curve, &key_pair, pri_key, 32);
    mbedtls_ecp_keypair_calc_public(&key_pair, mbedtls_entropy_func, &entropy);

    // Gen context
    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);
    mbedtls_ecdsa_from_keypair(&ctx, &key_pair);

    // Gen signature
    size_t len;
    mbedtls_ecdsa_write_signature(&ctx, MBEDTLS_MD_SHA512, hash, 64, *sig, 64, &len, mbedtls_entropy_func, &entropy);
    printf("\n %ld \n", len);
    */

    printf("\n Not supported yet in MbedTLS");

}

void EDDSA448_SIGN(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pri_key, const unsigned int pri_len, unsigned char** sig, unsigned int* sig_len) 
{
    printf("\n Not supported yet in MbedTLS");
}


void EDDSA25519_VERIFY(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pub_key, const unsigned int pub_len, const unsigned char* sig, const unsigned int sig_len, unsigned int* result) 
{
    printf("\n Not supported yet in MbedTLS");
}

void EDDSA448_VERIFY(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pub_key, const unsigned int pub_len, const unsigned char* sig, const unsigned int sig_len, unsigned int* result) 
{
    printf("\n Not supported yet in MbedTLS");
}

#else

void EDDSA25519_GEN_KEYS(unsigned char** pri_key, unsigned char** pub_key, unsigned int* pri_len, unsigned int* pub_len)
{
    *pri_key = malloc(32);
    *pub_key = malloc(32);
    *pri_len = 32;
    *pub_len = 32;

    CTR_DRBG(*pri_key, 32);

    ed25519GeneratePublicKey(*pri_key, *pub_key);

}

void EDDSA448_GEN_KEYS(unsigned char** pri_key, unsigned char** pub_key, unsigned int* pri_len, unsigned int* pub_len)
{
    *pri_key = malloc(57);
    *pub_key = malloc(57);
    *pri_len = 57;
    *pub_len = 57;

    unsigned char ctr[64];
    CTR_DRBG(ctr, 64);
    memcpy(*pri_key, ctr, 57);

    ed448GeneratePublicKey(*pri_key, *pub_key);
}

void EDDSA25519_SIGN(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pri_key, const unsigned int pri_len, unsigned char** sig, unsigned int* sig_len)
{

    unsigned char pub_key[32];

    *sig = malloc(76);
    *sig_len = 76;

    ed25519GeneratePublicKey(pri_key, pub_key);

    ed25519GenerateSignature(pri_key, pub_key, msg, msg_len, NULL, 0, 0, *sig);

}

void EDDSA448_SIGN(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pri_key, const unsigned int pri_len, unsigned char** sig, unsigned int* sig_len)
{
    unsigned char pub_key[57];

    *sig = malloc(114);
    *sig_len = 114;

    ed448GeneratePublicKey(pri_key, pub_key);

    ed448GenerateSignature(pri_key, pub_key, msg, msg_len, NULL, 0, 0, *sig);
}


void EDDSA25519_VERIFY(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pub_key, const unsigned int pub_len, const unsigned char* sig, const unsigned int sig_len, unsigned int* result)
{
    uint8_t result_sig = 0; 
    ed25519VerifySignature(pub_key, msg, msg_len, NULL, 0, 0, sig, &result_sig);
    *result = 0x0000000 | result_sig;
}

void EDDSA448_VERIFY(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pub_key, const unsigned int pub_len, const unsigned char* sig, const unsigned int sig_len, unsigned int* result)
{
    uint8_t result_sig = 0;
    ed448VerifySignature(pub_key, msg, msg_len, NULL, 0, 0, sig, &result_sig);
    *result = 0x0000000 | result_sig;

}


#endif

