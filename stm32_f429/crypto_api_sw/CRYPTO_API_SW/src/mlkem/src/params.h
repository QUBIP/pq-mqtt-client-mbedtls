#ifndef PARAMS_H
#define PARAMS_H


#if KYBER_K == 2
#define KYBER_ETA1 3
#define KYBER_POLYCOMPRESSEDBYTES    128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#elif KYBER_K == 3
#define KYBER_ETA1 2
#define KYBER_POLYCOMPRESSEDBYTES    128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#elif KYBER_K == 4
#define KYBER_ETA1 2
#define KYBER_POLYCOMPRESSEDBYTES    160
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 352)
#endif


#define KYBER_N								256
#define KYBER_Q								3329
#define KYBER_SYMBYTES						32   /* size in bytes of hashes, and seeds */
#define KYBER_SSBYTES						32   /* size in bytes of shared key */
#define KYBER_POLYBYTES						384
#define KYBER_ETA2							2
#define KYBER_INDCPA_MSGBYTES				(KYBER_SYMBYTES)

// ----- 512 ----- //
#define KYBER_POLYVECBYTES_512				(2 * KYBER_POLYBYTES)
#define KYBER_ETA1_512						3
#define KYBER_POLYCOMPRESSEDBYTES_512		128
#define KYBER_POLYVECCOMPRESSEDBYTES_512	(2 * 320)
#define KYBER_INDCPA_PUBLICKEYBYTES_512		(KYBER_POLYVECBYTES_512 + KYBER_SYMBYTES)
#define KYBER_INDCPA_SECRETKEYBYTES_512		(KYBER_POLYVECBYTES_512)
#define KYBER_INDCPA_BYTES_512				(KYBER_POLYVECCOMPRESSEDBYTES_512 + KYBER_POLYCOMPRESSEDBYTES_512)
#define KYBER_PUBLICKEYBYTES_512			(KYBER_INDCPA_PUBLICKEYBYTES_512)
/* 32 bytes of additional space to save H(pk) */
#define KYBER_SECRETKEYBYTES_512			(KYBER_INDCPA_SECRETKEYBYTES_512 + KYBER_INDCPA_PUBLICKEYBYTES_512 + 2*KYBER_SYMBYTES)
#define KYBER_CIPHERTEXTBYTES_512			(KYBER_INDCPA_BYTES_512)

// ----- 768 ----- //
#define KYBER_POLYVECBYTES_768				(3 * KYBER_POLYBYTES)
#define KYBER_ETA1_768						2
#define KYBER_POLYCOMPRESSEDBYTES_768		128
#define KYBER_POLYVECCOMPRESSEDBYTES_768	(3 * 320)
#define KYBER_INDCPA_PUBLICKEYBYTES_768		(KYBER_POLYVECBYTES_768 + KYBER_SYMBYTES)
#define KYBER_INDCPA_SECRETKEYBYTES_768		(KYBER_POLYVECBYTES_768)
#define KYBER_INDCPA_BYTES_768				(KYBER_POLYVECCOMPRESSEDBYTES_768 + KYBER_POLYCOMPRESSEDBYTES_768)
#define KYBER_PUBLICKEYBYTES_768			(KYBER_INDCPA_PUBLICKEYBYTES_768)
/* 32 bytes of additional space to save H(pk) */
#define KYBER_SECRETKEYBYTES_768			(KYBER_INDCPA_SECRETKEYBYTES_768 + KYBER_INDCPA_PUBLICKEYBYTES_768 + 2*KYBER_SYMBYTES)
#define KYBER_CIPHERTEXTBYTES_768			(KYBER_INDCPA_BYTES_768)

// ----- 1024 ----- //
#define KYBER_POLYVECBYTES_1024				(4 * KYBER_POLYBYTES)
#define KYBER_ETA1_1024						2
#define KYBER_POLYCOMPRESSEDBYTES_1024		160
#define KYBER_POLYVECCOMPRESSEDBYTES_1024	(4 * 352)
#define KYBER_INDCPA_PUBLICKEYBYTES_1024	(KYBER_POLYVECBYTES_1024 + KYBER_SYMBYTES)
#define KYBER_INDCPA_SECRETKEYBYTES_1024	(KYBER_POLYVECBYTES_1024)
#define KYBER_INDCPA_BYTES_1024				(KYBER_POLYVECCOMPRESSEDBYTES_1024 + KYBER_POLYCOMPRESSEDBYTES_1024)
#define KYBER_PUBLICKEYBYTES_1024			(KYBER_INDCPA_PUBLICKEYBYTES_1024)
/* 32 bytes of additional space to save H(pk) */
#define KYBER_SECRETKEYBYTES_1024			(KYBER_INDCPA_SECRETKEYBYTES_1024 + KYBER_INDCPA_PUBLICKEYBYTES_1024 + 2*KYBER_SYMBYTES)
#define KYBER_CIPHERTEXTBYTES_1024			(KYBER_INDCPA_BYTES_1024)

#endif
