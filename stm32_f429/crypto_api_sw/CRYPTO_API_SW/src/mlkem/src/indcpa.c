#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "params.h"
#include "indcpa.h"
#include "polyvec.h"
#include "poly.h"
#include "ntt.h"
#include "symmetric.h"
#include "randombytes.h"

/*************************************************
* Name:        pack_pk
*
* Description: Serialize the public key as concatenation of the
*              serialized vector of polynomials pk
*              and the public seed used to generate the matrix A.
*
* Arguments:   uint8_t *r: pointer to the output serialized public key
*              polyvec *pk: pointer to the input public-key polyvec
*              const uint8_t *seed: pointer to the input public seed
**************************************************/
/*
static void pack_pk(uint8_t r[KYBER_INDCPA_PUBLICKEYBYTES],
                    polyvec *pk,
                    const uint8_t seed[KYBER_SYMBYTES])
{
  size_t i;
  polyvec_tobytes(r, pk);
  for(i=0;i<KYBER_SYMBYTES;i++)
    r[i+KYBER_POLYVECBYTES] = seed[i];
}
*/

static void pack_pk_512(uint8_t r[KYBER_INDCPA_PUBLICKEYBYTES_512],
    polyvec* pk,
    const uint8_t seed[KYBER_SYMBYTES])
{
    polyvec_tobytes_512(r, pk);
    memcpy(r + KYBER_POLYVECBYTES_512, seed, KYBER_SYMBYTES);
}

static void pack_pk_768(uint8_t r[KYBER_INDCPA_PUBLICKEYBYTES_768],
    polyvec* pk,
    const uint8_t seed[KYBER_SYMBYTES])
{
    polyvec_tobytes_768(r, pk);
    memcpy(r + KYBER_POLYVECBYTES_768, seed, KYBER_SYMBYTES);
}

static void pack_pk_1024(uint8_t r[KYBER_INDCPA_PUBLICKEYBYTES_1024],
    polyvec* pk,
    const uint8_t seed[KYBER_SYMBYTES])
{
    polyvec_tobytes_1024(r, pk);
    memcpy(r + KYBER_POLYVECBYTES_1024, seed, KYBER_SYMBYTES);
}


/*************************************************
* Name:        unpack_pk
*
* Description: De-serialize public key from a byte array;
*              approximate inverse of pack_pk
*
* Arguments:   - polyvec *pk: pointer to output public-key polynomial vector
*              - uint8_t *seed: pointer to output seed to generate matrix A
*              - const uint8_t *packedpk: pointer to input serialized public key
**************************************************/
/*
static void unpack_pk(polyvec *pk,
                      uint8_t seed[KYBER_SYMBYTES],
                      const uint8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES])
{
  size_t i;
  polyvec_frombytes(pk, packedpk);
  for(i=0;i<KYBER_SYMBYTES;i++)
    seed[i] = packedpk[i+KYBER_POLYVECBYTES];
}
*/
static void unpack_pk_512(polyvec* pk,
    uint8_t seed[KYBER_SYMBYTES],
    const uint8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES_512])
{
    polyvec_frombytes_512(pk, packedpk);
    memcpy(seed, packedpk + KYBER_POLYVECBYTES_512, KYBER_SYMBYTES);
}

static void unpack_pk_768(polyvec* pk,
    uint8_t seed[KYBER_SYMBYTES],
    const uint8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES_768])
{
    size_t i;
    polyvec_frombytes_768(pk, packedpk);
    memcpy(seed, packedpk + KYBER_POLYVECBYTES_768, KYBER_SYMBYTES);
}

static void unpack_pk_1024(polyvec* pk,
    uint8_t seed[KYBER_SYMBYTES],
    const uint8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES_1024])
{
    size_t i;
    polyvec_frombytes_1024(pk, packedpk);
    memcpy(seed, packedpk + KYBER_POLYVECBYTES_1024, KYBER_SYMBYTES);
}


/*************************************************
* Name:        pack_sk
*
* Description: Serialize the secret key
*
* Arguments:   - uint8_t *r: pointer to output serialized secret key
*              - polyvec *sk: pointer to input vector of polynomials (secret key)
**************************************************/
/*
static void pack_sk(uint8_t r[KYBER_INDCPA_SECRETKEYBYTES], polyvec *sk)
{
  polyvec_tobytes(r, sk);
}
*/

static void pack_sk_512(uint8_t r[KYBER_INDCPA_SECRETKEYBYTES_512], polyvec* sk)
{
    polyvec_tobytes_512(r, sk);
}

static void pack_sk_768(uint8_t r[KYBER_INDCPA_SECRETKEYBYTES_768], polyvec* sk)
{
    polyvec_tobytes_768(r, sk);
}

static void pack_sk_1024(uint8_t r[KYBER_INDCPA_SECRETKEYBYTES_1024], polyvec* sk)
{
    polyvec_tobytes_1024(r, sk);
}

/*************************************************
* Name:        unpack_sk
*
* Description: De-serialize the secret key; inverse of pack_sk
*
* Arguments:   - polyvec *sk: pointer to output vector of polynomials (secret key)
*              - const uint8_t *packedsk: pointer to input serialized secret key
**************************************************/
/*
static void unpack_sk(polyvec *sk, const uint8_t packedsk[KYBER_INDCPA_SECRETKEYBYTES])
{
  polyvec_frombytes(sk, packedsk);
}
*/

static void unpack_sk_512(polyvec* sk, const uint8_t packedsk[KYBER_INDCPA_SECRETKEYBYTES_512])
{
    polyvec_frombytes_512(sk, packedsk);
}

static void unpack_sk_768(polyvec* sk, const uint8_t packedsk[KYBER_INDCPA_SECRETKEYBYTES_768])
{
    polyvec_frombytes_768(sk, packedsk);
}

static void unpack_sk_1024(polyvec* sk, const uint8_t packedsk[KYBER_INDCPA_SECRETKEYBYTES_1024])
{
    polyvec_frombytes_1024(sk, packedsk);
}

/*************************************************
* Name:        pack_ciphertext
*
* Description: Serialize the ciphertext as concatenation of the
*              compressed and serialized vector of polynomials b
*              and the compressed and serialized polynomial v
*
* Arguments:   uint8_t *r: pointer to the output serialized ciphertext
*              poly *pk: pointer to the input vector of polynomials b
*              poly *v: pointer to the input polynomial v
**************************************************/
/*
static void pack_ciphertext(uint8_t r[KYBER_INDCPA_BYTES], polyvec *b, poly *v)
{
  polyvec_compress(r, b);
  poly_compress(r+KYBER_POLYVECCOMPRESSEDBYTES, v);
}
*/

static void pack_ciphertext_512(uint8_t r[KYBER_INDCPA_BYTES_512], polyvec* b, poly* v)
{
    polyvec_compress_512(r, b);
    poly_compress_512(r + KYBER_POLYVECCOMPRESSEDBYTES_512, v);
}

static void pack_ciphertext_768(uint8_t r[KYBER_INDCPA_BYTES_768], polyvec* b, poly* v)
{
    polyvec_compress_768(r, b);
    poly_compress_768(r + KYBER_POLYVECCOMPRESSEDBYTES_768, v);
}

static void pack_ciphertext_1024(uint8_t r[KYBER_INDCPA_BYTES_1024], polyvec* b, poly* v)
{
    polyvec_compress_1024(r, b);
    poly_compress_1024(r + KYBER_POLYVECCOMPRESSEDBYTES_1024, v);
}

/*************************************************
* Name:        unpack_ciphertext
*
* Description: De-serialize and decompress ciphertext from a byte array;
*              approximate inverse of pack_ciphertext
*
* Arguments:   - polyvec *b: pointer to the output vector of polynomials b
*              - poly *v: pointer to the output polynomial v
*              - const uint8_t *c: pointer to the input serialized ciphertext
**************************************************/
/*
static void unpack_ciphertext(polyvec *b, poly *v, const uint8_t c[KYBER_INDCPA_BYTES])
{
  polyvec_decompress(b, c);
  poly_decompress(v, c+KYBER_POLYVECCOMPRESSEDBYTES);
}
*/

static void unpack_ciphertext_512(polyvec* b, poly* v, const uint8_t c[KYBER_INDCPA_BYTES_512])
{
    polyvec_decompress_512(b, c);
    poly_decompress_512(v, c + KYBER_POLYVECCOMPRESSEDBYTES_512);
}

static void unpack_ciphertext_768(polyvec* b, poly* v, const uint8_t c[KYBER_INDCPA_BYTES_768])
{
    polyvec_decompress_768(b, c);
    poly_decompress_768(v, c + KYBER_POLYVECCOMPRESSEDBYTES_768);
}

static void unpack_ciphertext_1024(polyvec* b, poly* v, const uint8_t c[KYBER_INDCPA_BYTES_1024])
{
    polyvec_decompress_1024(b, c);
    poly_decompress_1024(v, c + KYBER_POLYVECCOMPRESSEDBYTES_1024);
}

/*************************************************
* Name:        rej_uniform
*
* Description: Run rejection sampling on uniform random bytes to generate
*              uniform random integers mod q
*
* Arguments:   - int16_t *r: pointer to output buffer
*              - unsigned int len: requested number of 16-bit integers (uniform mod q)
*              - const uint8_t *buf: pointer to input buffer (assumed to be uniformly random bytes)
*              - unsigned int buflen: length of input buffer in bytes
*
* Returns number of sampled 16-bit integers (at most len)
**************************************************/
static unsigned int rej_uniform(int16_t *r,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen)
{
  unsigned int ctr, pos;
  uint16_t val0, val1;

  ctr = pos = 0;
  while(ctr < len && pos + 3 <= buflen) {
    val0 = ((buf[pos+0] >> 0) | ((uint16_t)buf[pos+1] << 8)) & 0xFFF;
    val1 = ((buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4)) & 0xFFF;
    pos += 3;

    if(val0 < KYBER_Q)
      r[ctr++] = val0;
    if(ctr < len && val1 < KYBER_Q)
      r[ctr++] = val1;
  }

  return ctr;
}

#define gen_a(A,B,C)  gen_matrix(A,B,0,C)
#define gen_at(A,B,C) gen_matrix(A,B,1,C)

/*************************************************
* Name:        gen_matrix
*
* Description: Deterministically generate matrix A (or the transpose of A)
*              from a seed. Entries of the matrix are polynomials that look
*              uniformly random. Performs rejection sampling on output of
*              a XOF
*
* Arguments:   - polyvec *a: pointer to ouptput matrix A
*              - const uint8_t *seed: pointer to input seed
*              - int transposed: boolean deciding whether A or A^T is generated
**************************************************/
#define GEN_MATRIX_NBLOCKS ((12*KYBER_N/8*(1 << 12)/KYBER_Q + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)
// Not static for benchmarking
void gen_matrix(polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed, int kyber_k)
{
  unsigned int ctr, i, j, k;
  unsigned int buflen, off;
  uint8_t buf[GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES+2];
  xof_state state;

  for(i=0;i< kyber_k;i++) {
    for(j=0;j< kyber_k;j++) {
      if(transposed)
        xof_absorb(&state, seed, i, j);
      else
        xof_absorb(&state, seed, j, i);


      xof_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, &state);

      buflen = GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES;
      ctr = rej_uniform(a[i].vec[j].coeffs, KYBER_N, buf, buflen);

      while(ctr < KYBER_N) {
        xof_squeezeblocks(buf, 1, &state);
        buflen = XOF_BLOCKBYTES;
        ctr += rej_uniform(a[i].vec[j].coeffs + ctr, KYBER_N - ctr, buf, buflen);
      }
    }
  }
}

/*************************************************
* Name:        indcpa_keypair
*
* Description: Generates public and private key for the CPA-secure
*              public-key encryption scheme underlying Kyber
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                             (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
                              (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
**************************************************/
/*
void indcpa_keypair(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES])
{
  unsigned int i;
  uint8_t buf[2*KYBER_SYMBYTES];
  const uint8_t *publicseed = buf;
  const uint8_t *noiseseed = buf+KYBER_SYMBYTES;
  uint8_t nonce = 0;
  polyvec a[KYBER_K], e, pkpv, skpv;

  randombytes(buf, KYBER_SYMBYTES);
  hash_g(buf, buf, KYBER_SYMBYTES);

  gen_a(a, publicseed);

  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(&skpv.vec[i], noiseseed, nonce++);
  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(&e.vec[i], noiseseed, nonce++);

  polyvec_ntt(&skpv);
  polyvec_ntt(&e);

  // matrix-vector multiplication
  for(i=0;i<KYBER_K;i++) {
    polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
    poly_tomont(&pkpv.vec[i]);
  }

  polyvec_add(&pkpv, &pkpv, &e);
  polyvec_reduce(&pkpv);

  pack_sk(sk, &skpv);
  pack_pk(pk, &pkpv, publicseed);
}
*/

void indcpa_keypair_512(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES_512],
    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES_512],
    const uint8_t coins[KYBER_SYMBYTES])
{
    unsigned int i;
    uint8_t buf[2 * KYBER_SYMBYTES];
    const uint8_t* publicseed = buf;
    const uint8_t* noiseseed = buf + KYBER_SYMBYTES;
    uint8_t nonce = 0;
    polyvec a[2], e, pkpv, skpv;

    memcpy(buf, coins, KYBER_SYMBYTES);
    buf[KYBER_SYMBYTES] = 2;
    hash_g(buf, buf, KYBER_SYMBYTES + 1);

    gen_a(a, publicseed, 2);

    for (i = 0; i < 2; i++)
        poly_getnoise_eta1_512(&skpv.vec[i], noiseseed, nonce++);
    for (i = 0; i < 2; i++)
        poly_getnoise_eta1_512(&e.vec[i], noiseseed, nonce++);

    polyvec_ntt_512(&skpv);
    polyvec_ntt_512(&e);

    // matrix-vector multiplication
    for (i = 0; i < 2; i++) {
        polyvec_basemul_acc_montgomery_512(&pkpv.vec[i], &a[i], &skpv);
        poly_tomont(&pkpv.vec[i]);
    }

    polyvec_add_512(&pkpv, &pkpv, &e);
    polyvec_reduce_512(&pkpv);

    pack_sk_512(sk, &skpv);
    pack_pk_512(pk, &pkpv, publicseed);
}

void indcpa_keypair_768(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES_768],
    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES_768],
    const uint8_t coins[KYBER_SYMBYTES])
{
    unsigned int i;
    uint8_t buf[2 * KYBER_SYMBYTES];
    const uint8_t* publicseed = buf;
    const uint8_t* noiseseed = buf + KYBER_SYMBYTES;
    uint8_t nonce = 0;
    polyvec a[3], e, pkpv, skpv;

    memcpy(buf, coins, KYBER_SYMBYTES);
    buf[KYBER_SYMBYTES] = 3;
    hash_g(buf, buf, KYBER_SYMBYTES + 1);

    gen_a(a, publicseed, 3);

    for (i = 0; i < 3; i++)
        poly_getnoise_eta1_768(&skpv.vec[i], noiseseed, nonce++);
    for (i = 0; i < 3; i++)
        poly_getnoise_eta1_768(&e.vec[i], noiseseed, nonce++);

    polyvec_ntt_768(&skpv);
    polyvec_ntt_768(&e);

    // matrix-vector multiplication
    for (i = 0; i < 3; i++) {
        polyvec_basemul_acc_montgomery_768(&pkpv.vec[i], &a[i], &skpv);
        poly_tomont(&pkpv.vec[i]);
    }

    polyvec_add_768(&pkpv, &pkpv, &e);
    polyvec_reduce_768(&pkpv);

    pack_sk_768(sk, &skpv);
    pack_pk_768(pk, &pkpv, publicseed);
}

void indcpa_keypair_1024(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES_1024],
    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES_1024],
    const uint8_t coins[KYBER_SYMBYTES])
{
    unsigned int i;
    uint8_t buf[2 * KYBER_SYMBYTES];
    const uint8_t* publicseed = buf;
    const uint8_t* noiseseed = buf + KYBER_SYMBYTES;
    uint8_t nonce = 0;
    polyvec a[4], e, pkpv, skpv;

    memcpy(buf, coins, KYBER_SYMBYTES);
    buf[KYBER_SYMBYTES] = 4;
    hash_g(buf, buf, KYBER_SYMBYTES + 1);

    gen_a(a, publicseed, 4);

    for (i = 0; i < 4; i++)
        poly_getnoise_eta1_1024(&skpv.vec[i], noiseseed, nonce++);
    for (i = 0; i < 4; i++)
        poly_getnoise_eta1_1024(&e.vec[i], noiseseed, nonce++);

    polyvec_ntt_1024(&skpv);
    polyvec_ntt_1024(&e);

    // matrix-vector multiplication
    for (i = 0; i < 4; i++) {
        polyvec_basemul_acc_montgomery_1024(&pkpv.vec[i], &a[i], &skpv);
        poly_tomont(&pkpv.vec[i]);
    }

    polyvec_add_1024(&pkpv, &pkpv, &e);
    polyvec_reduce_1024(&pkpv);

    pack_sk_1024(sk, &skpv);
    pack_pk_1024(pk, &pkpv, publicseed);
}

/*************************************************
* Name:        indcpa_enc
*
* Description: Encryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *c: pointer to output ciphertext
*                            (of length KYBER_INDCPA_BYTES bytes)
*              - const uint8_t *m: pointer to input message
*                                  (of length KYBER_INDCPA_MSGBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                                   (of length KYBER_INDCPA_PUBLICKEYBYTES)
*              - const uint8_t *coins: pointer to input random coins used as seed
*                                      (of length KYBER_SYMBYTES) to deterministically
*                                      generate all randomness
**************************************************/

/*
void indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES])
{
  unsigned int i;
  uint8_t seed[KYBER_SYMBYTES];
  uint8_t nonce = 0;
  polyvec sp, pkpv, ep, at[KYBER_K], b;
  poly v, k, epp;

  unpack_pk(&pkpv, seed, pk);
  poly_frommsg(&k, m);
  gen_at(at, seed);

  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(sp.vec+i, coins, nonce++);
  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta2(ep.vec+i, coins, nonce++);
  poly_getnoise_eta2(&epp, coins, nonce++);

  polyvec_ntt(&sp);

  // matrix-vector multiplication
  for(i=0;i<KYBER_K;i++)
    polyvec_basemul_acc_montgomery(&b.vec[i], &at[i], &sp);

  polyvec_basemul_acc_montgomery(&v, &pkpv, &sp);

  polyvec_invntt_tomont(&b);
  poly_invntt_tomont(&v);

  polyvec_add(&b, &b, &ep);
  poly_add(&v, &v, &epp);
  poly_add(&v, &v, &k);
  polyvec_reduce(&b);
  poly_reduce(&v);

  pack_ciphertext(c, &b, &v);
}

void indcpa_enc_DBG(uint8_t c[KYBER_INDCPA_BYTES],
    const uint8_t m[KYBER_INDCPA_MSGBYTES],
    const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
    const uint8_t coins[KYBER_SYMBYTES],
    int DBG)
{
    unsigned int i;
    uint8_t seed[KYBER_SYMBYTES];
    uint8_t nonce = 0;
    polyvec sp, pkpv, ep, at[KYBER_K], b;
    poly v, k, epp;

    unpack_pk(&pkpv, seed, pk);
    poly_frommsg(&k, m);
    if (DBG == 2) show_array(m, KYBER_INDCPA_MSGBYTES, 32);
    if (DBG == 2) show_poly(&k, 4);

    gen_at(at, seed);

    for (i = 0; i < KYBER_K; i++)
        poly_getnoise_eta1(sp.vec + i, coins, nonce++);
    for (i = 0; i < KYBER_K; i++)
        poly_getnoise_eta2(ep.vec + i, coins, nonce++);
    poly_getnoise_eta2(&epp, coins, nonce++);

    polyvec_ntt(&sp);

    // matrix-vector multiplication
    for (i = 0; i < KYBER_K; i++)
        polyvec_basemul_acc_montgomery(&b.vec[i], &at[i], &sp);

    polyvec_basemul_acc_montgomery(&v, &pkpv, &sp);

    polyvec_invntt_tomont(&b);
    poly_invntt_tomont(&v);

    polyvec_add(&b, &b, &ep);
    poly_add(&v, &v, &epp);
    poly_add(&v, &v, &k);
    polyvec_reduce(&b);
    poly_reduce(&v);

    pack_ciphertext(c, &b, &v);
}

*/


void indcpa_enc_512(uint8_t c[KYBER_INDCPA_BYTES_512],
    const uint8_t m[KYBER_INDCPA_MSGBYTES],
    const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES_512],
    const uint8_t coins[KYBER_SYMBYTES])
{
    unsigned int i;
    uint8_t seed[KYBER_SYMBYTES];
    uint8_t nonce = 0;
    polyvec sp, pkpv, ep, at[2], b;
    poly v, k, epp;

    unpack_pk_512(&pkpv, seed, pk);
    poly_frommsg(&k, m);
    gen_at(at, seed, 2);

    for (i = 0; i < 2; i++)
        poly_getnoise_eta1_512(sp.vec + i, coins, nonce++);
    for (i = 0; i < 2; i++)
        poly_getnoise_eta2(ep.vec + i, coins, nonce++);
    poly_getnoise_eta2(&epp, coins, nonce++);

    polyvec_ntt_512(&sp);

    // matrix-vector multiplication
    for (i = 0; i < 2; i++)
        polyvec_basemul_acc_montgomery_512(&b.vec[i], &at[i], &sp);

    polyvec_basemul_acc_montgomery_512(&v, &pkpv, &sp);

    polyvec_invntt_tomont_512(&b);
    poly_invntt_tomont(&v);

    polyvec_add_512(&b, &b, &ep);
    poly_add(&v, &v, &epp);
    poly_add(&v, &v, &k);
    polyvec_reduce_512(&b);
    poly_reduce(&v);

    pack_ciphertext_512(c, &b, &v);
}

void indcpa_enc_768(uint8_t c[KYBER_INDCPA_BYTES_768],
    const uint8_t m[KYBER_INDCPA_MSGBYTES],
    const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES_768],
    const uint8_t coins[KYBER_SYMBYTES])
{
    unsigned int i;
    uint8_t seed[KYBER_SYMBYTES];
    uint8_t nonce = 0;
    polyvec sp, pkpv, ep, at[3], b;
    poly v, k, epp;

    unpack_pk_768(&pkpv, seed, pk);
    poly_frommsg(&k, m);
    gen_at(at, seed, 3);

    for (i = 0; i < 3; i++)
        poly_getnoise_eta1_768(sp.vec + i, coins, nonce++);
    for (i = 0; i < 3; i++)
        poly_getnoise_eta2(ep.vec + i, coins, nonce++);
    poly_getnoise_eta2(&epp, coins, nonce++);

    polyvec_ntt_768(&sp);

    // matrix-vector multiplication
    for (i = 0; i < 3; i++)
        polyvec_basemul_acc_montgomery_768(&b.vec[i], &at[i], &sp);

    polyvec_basemul_acc_montgomery_768(&v, &pkpv, &sp);

    polyvec_invntt_tomont_768(&b);
    poly_invntt_tomont(&v);

    polyvec_add_768(&b, &b, &ep);
    poly_add(&v, &v, &epp);
    poly_add(&v, &v, &k);
    polyvec_reduce_768(&b);
    poly_reduce(&v);

    pack_ciphertext_768(c, &b, &v);
}

void indcpa_enc_1024(uint8_t c[KYBER_INDCPA_BYTES_1024],
    const uint8_t m[KYBER_INDCPA_MSGBYTES],
    const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES_1024],
    const uint8_t coins[KYBER_SYMBYTES])
{
    unsigned int i;
    uint8_t seed[KYBER_SYMBYTES];
    uint8_t nonce = 0;
    polyvec sp, pkpv, ep, at[4], b;
    poly v, k, epp;

    unpack_pk_1024(&pkpv, seed, pk);
    poly_frommsg(&k, m);
    gen_at(at, seed, 4);

    for (i = 0; i < 4; i++)
        poly_getnoise_eta1_1024(sp.vec + i, coins, nonce++);
    for (i = 0; i < 4; i++)
        poly_getnoise_eta2(ep.vec + i, coins, nonce++);
    poly_getnoise_eta2(&epp, coins, nonce++);

    polyvec_ntt_1024(&sp);

    // matrix-vector multiplication
    for (i = 0; i < 4; i++)
        polyvec_basemul_acc_montgomery_1024(&b.vec[i], &at[i], &sp);

    polyvec_basemul_acc_montgomery_1024(&v, &pkpv, &sp);

    polyvec_invntt_tomont_1024(&b);
    poly_invntt_tomont(&v);

    polyvec_add_1024(&b, &b, &ep);
    poly_add(&v, &v, &epp);
    poly_add(&v, &v, &k);
    polyvec_reduce_1024(&b);
    poly_reduce(&v);

    pack_ciphertext_1024(c, &b, &v);
}

/*************************************************
* Name:        indcpa_dec
*
* Description: Decryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *m: pointer to output decrypted message
*                            (of length KYBER_INDCPA_MSGBYTES)
*              - const uint8_t *c: pointer to input ciphertext
*                                  (of length KYBER_INDCPA_BYTES)
*              - const uint8_t *sk: pointer to input secret key
*                                   (of length KYBER_INDCPA_SECRETKEYBYTES)
**************************************************/
/*
void indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES])
{
  polyvec b, skpv;
  poly v, mp;

  unpack_ciphertext(&b, &v, c);
  unpack_sk(&skpv, sk);

  polyvec_ntt(&b);
  polyvec_basemul_acc_montgomery(&mp, &skpv, &b);
  poly_invntt_tomont(&mp);

  poly_sub(&mp, &v, &mp);
  poly_reduce(&mp);

  poly_tomsg(m, &mp);
}
*/

void indcpa_dec_512(uint8_t m[KYBER_INDCPA_MSGBYTES],
    const uint8_t c[KYBER_INDCPA_BYTES_512],
    const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES_512])
{
    polyvec b, skpv;
    poly v, mp;

    unpack_ciphertext_512(&b, &v, c);
    unpack_sk_512(&skpv, sk);

    polyvec_ntt_512(&b);
    polyvec_basemul_acc_montgomery_512(&mp, &skpv, &b);
    poly_invntt_tomont(&mp);

    poly_sub(&mp, &v, &mp);
    poly_reduce(&mp);

    poly_tomsg(m, &mp);
}

void indcpa_dec_768(uint8_t m[KYBER_INDCPA_MSGBYTES],
    const uint8_t c[KYBER_INDCPA_BYTES_768],
    const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES_768])
{
    polyvec b, skpv;
    poly v, mp;

    unpack_ciphertext_768(&b, &v, c);
    unpack_sk_768(&skpv, sk);

    polyvec_ntt_768(&b);
    polyvec_basemul_acc_montgomery_768(&mp, &skpv, &b);
    poly_invntt_tomont(&mp);

    poly_sub(&mp, &v, &mp);
    poly_reduce(&mp);

    poly_tomsg(m, &mp);
}

void indcpa_dec_1024(uint8_t m[KYBER_INDCPA_MSGBYTES],
    const uint8_t c[KYBER_INDCPA_BYTES_1024],
    const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES_1024])
{
    polyvec b, skpv;
    poly v, mp;

    unpack_ciphertext_1024(&b, &v, c);
    unpack_sk_1024(&skpv, sk);

    polyvec_ntt_1024(&b);
    polyvec_basemul_acc_montgomery_1024(&mp, &skpv, &b);
    poly_invntt_tomont(&mp);

    poly_sub(&mp, &v, &mp);
    poly_reduce(&mp);

    poly_tomsg(m, &mp);
}