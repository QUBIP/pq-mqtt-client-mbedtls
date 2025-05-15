CC = /usr/bin/cc -fPIC -fno-stack-protector
CCARM = /usr/bin/arm-none-eabi-gcc -mcpu=cortex-m4 -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb -g3 -O3
AR = ar rcs

OPENSSL_DIR = /opt/openssl/
MBEDTLS_DIR = /home/eros/mbedtls/

LDFLAGS_DEMO = -lcrypto -lm -DOPENSSL
LDFLAGS_DEMO_LIB= -I$(OPENSSL_DIR)include $(OPENSSL_DIR)lib/libcrypto.so.3 -lm -DOPENSSL
LDFLAGS_LIB_MBEDTLS = -I$(MBEDTLS_DIR)include $(MBEDTLS_DIR)library/libmbedcrypto.a $(MBEDTLS_DIR)library/libmbedtls.a $(MBEDTLS_DIR)library/libmbedx509.a -lm -DMBEDTLS

CFLAGS_DEMO = 

LDFLAGS_DEMO_BUILD			= -L../CRYPTO_API_SW/build -lcryptoapi -lm -DOPENSSL
LDFLAGS_DEMO_BUILD_MBEDTLS	= -L../CRYPTO_API_SW/build -lcryptoapimbedtls -lm -DMBEDTLS
LDFLAGS_DEMO_BUILD_ALT		= -L../CRYPTO_API_SW/build -lcryptoapialt -lm
CFLAGS_DEMO_BUILD = 

SRCDIR = ../CRYPTO_API_SW/src/

LIB_AES_SOURCES = $(SRCDIR)aes/aes_cbc.c $(SRCDIR)aes/aes_ccm.c $(SRCDIR)aes/aes_cmac.c $(SRCDIR)aes/aes_ecb.c $(SRCDIR)aes/aes_gcm.c
LIB_AES_HEADERS = $(SRCDIR)aes/aes.h
LIB_AES_ALT_SOURCES = $(SRCDIR)aes/alt/aes_base.c 
LIB_AES_ALT_HEADERS = $(SRCDIR)aes/alt/aes_base.h

LIB_SHA2_SOURCES = $(SRCDIR)sha2/sha2.c
LIB_SHA2_HEADERS = $(SRCDIR)sha2/sha2.h
LIB_SHA2_ALT_SOURCES = $(SRCDIR)sha2/alt/sha224.c $(SRCDIR)sha2/alt/sha256.c $(SRCDIR)sha2/alt/sha384.c $(SRCDIR)sha2/alt/sha512.c $(SRCDIR)sha2/alt/sha512_224.c $(SRCDIR)sha2/alt/sha512_256.c
LIB_SHA2_ALT_HEADERS = $(SRCDIR)sha2/alt/sha224.h $(SRCDIR)sha2/alt/sha256.h $(SRCDIR)sha2/alt/sha384.h $(SRCDIR)sha2/alt/sha512.h $(SRCDIR)sha2/alt/sha512_224.h $(SRCDIR)sha2/alt/sha512_256.h $(SRCDIR)sha2/alt/sha2_base.h

LIB_SHA3_SOURCES = $(SRCDIR)sha3/sha3.c
LIB_SHA3_HEADERS = $(SRCDIR)sha3/sha3.h
LIB_SHA3_ALT_SOURCES = $(SRCDIR)sha3/alt/sha3_224.c $(SRCDIR)sha3/alt/sha3_256.c $(SRCDIR)sha3/alt/sha3_384.c $(SRCDIR)sha3/alt/sha3_512.c $(SRCDIR)sha3/alt/shake.c $(SRCDIR)sha3/alt/keccak.c
LIB_SHA3_ALT_HEADERS = $(SRCDIR)sha3/alt/sha3_224.h $(SRCDIR)sha3/alt/sha3_256.h $(SRCDIR)sha3/alt/sha3_384.h $(SRCDIR)sha3/alt/sha3_512.h $(SRCDIR)sha3/alt/shake.h $(SRCDIR)sha3/alt/keccak.h

LIB_EDDSA_SOURCES = $(SRCDIR)eddsa/eddsa.c
LIB_EDDSA_HEADERS = $(SRCDIR)eddsa/eddsa.h
LIB_EDDSA_ALT_SOURCES = $(SRCDIR)eddsa/alt/ed25519.c $(SRCDIR)eddsa/alt/curve25519.c $(SRCDIR)eddsa/alt/ed448.c $(SRCDIR)eddsa/alt/curve448.c $(SRCDIR)eddsa/alt/mpi.c
LIB_EDDSA_ALT_HEADERS = $(SRCDIR)eddsa/alt/ed25519.h $(SRCDIR)eddsa/alt/curve25519.h $(SRCDIR)eddsa/alt/ed448.h $(SRCDIR)eddsa/alt/curve448.h $(SRCDIR)eddsa/alt/mpi.h

LIB_TRNG_SOURCES = $(SRCDIR)trng/trng.c
LIB_TRNG_HEADERS = $(SRCDIR)trng/trng.h

LIB_X25519_SOURCES = $(SRCDIR)x25519/x25519.c
LIB_X25519_HEADERS = $(SRCDIR)x25519/x25519.h
LIB_X25519_ALT_SOURCES = $(SRCDIR)x25519/alt/x25519.c $(SRCDIR)x25519/alt/x448.c $(SRCDIR)x25519/alt/ecdh.c 
LIB_X25519_ALT_HEADERS = $(SRCDIR)x25519/alt/x25519.h $(SRCDIR)x25519/alt/x448.h $(SRCDIR)x25519/alt/ecdh.h

LIB_HKDF_SOURCES = $(SRCDIR)hkdf/hkdf.c
LIB_HKDF_HEADERS = $(SRCDIR)hkdf/hkdf.h
LIB_HKDF_ALT_SOURCES = $(SRCDIR)hkdf/alt/hmac.c
LIB_HKDF_ALT_HEADERS = $(SRCDIR)hkdf/alt/hmac.h

LIB_RSA_SOURCES = $(SRCDIR)rsa/rsa.c
LIB_RSA_HEADERS = $(SRCDIR)rsa/rsa.h
LIB_RSA_ALT_SOURCES = $(SRCDIR)rsa/alt/rsa_base.c $(SRCDIR)rsa/alt/bignum.c
LIB_RSA_ALT_HEADERS = $(SRCDIR)rsa/alt/rsa_base.h $(SRCDIR)rsa/alt/bignum.h

LIB_MLKEM_SOURCES = $(SRCDIR)mlkem/src/cbd.c	$(SRCDIR)mlkem/src/fips202.c $(SRCDIR)mlkem/src/indcpa.c		$(SRCDIR)mlkem/src/ntt.c \
					$(SRCDIR)mlkem/src/poly.c	$(SRCDIR)mlkem/src/polyvec.c $(SRCDIR)mlkem/src/randombytes.c	$(SRCDIR)mlkem/src/reduce.c \
					$(SRCDIR)mlkem/src/symmetric-shake.c $(SRCDIR)mlkem/src/verify.c \
					$(SRCDIR)mlkem/mlkem_gen.c	$(SRCDIR)mlkem/mlkem_enc.c $(SRCDIR)mlkem/mlkem_dec.c

LIB_MLKEM_HEADERS = $(SRCDIR)mlkem/src/cbd.h	$(SRCDIR)mlkem/src/fips202.h	$(SRCDIR)mlkem/src/indcpa.h			$(SRCDIR)mlkem/src/ntt.h  \
					$(SRCDIR)mlkem/src/poly.h	$(SRCDIR)mlkem/src/polyvec.h	$(SRCDIR)mlkem/src/randombytes.h	$(SRCDIR)mlkem/src/reduce.h \
					$(SRCDIR)mlkem/src/params.h $(SRCDIR)mlkem/src/symmetric.h \
					$(SRCDIR)mlkem/mlkem.h

LIB_MLDSA_SOURCES = $(SRCDIR)mldsa/src/fips202.c	$(SRCDIR)mldsa/src/ntt.c		$(SRCDIR)mldsa/src/packing.c \
					$(SRCDIR)mldsa/src/poly.c		$(SRCDIR)mldsa/src/polyvec.c	$(SRCDIR)mldsa/src/randombytes.c	$(SRCDIR)mldsa/src/reduce.c \
					$(SRCDIR)mldsa/src/rounding.c	$(SRCDIR)mldsa/src/symmetric-shake.c \
					$(SRCDIR)mldsa/mldsa_gen.c		$(SRCDIR)mldsa/mldsa_sig.c		$(SRCDIR)mldsa/mldsa_ver.c 

LIB_MLDSA_HEADERS = $(SRCDIR)mldsa/src/fips202.h	$(SRCDIR)mldsa/src/ntt.h		$(SRCDIR)mldsa/src/packing.h \
					$(SRCDIR)mldsa/src/poly.h		$(SRCDIR)mldsa/src/polyvec.h	$(SRCDIR)mldsa/src/randombytes.h	$(SRCDIR)mldsa/src/reduce.h \
					$(SRCDIR)mldsa/src/rounding.h	$(SRCDIR)mldsa/src/symmetric.h \
					$(SRCDIR)mldsa/mldsa.h

LIB_SLHDSA_SOURCES =	$(SRCDIR)slhdsa/src/address.c				$(SRCDIR)slhdsa/src/context_shake.c $(SRCDIR)slhdsa/src/fips202.c		$(SRCDIR)slhdsa/src/fors.c \
						$(SRCDIR)slhdsa/src/hash_shake.c			$(SRCDIR)slhdsa/src/merkle.c		$(SRCDIR)slhdsa/src/randombytes.c	$(SRCDIR)slhdsa/src/sign.c \
						$(SRCDIR)slhdsa/src/thash_shake_simple.c	$(SRCDIR)slhdsa/src/utils.c			$(SRCDIR)slhdsa/src/utilsx1.c		$(SRCDIR)slhdsa/src/wots.c \
						$(SRCDIR)slhdsa/src/wotsx1.c \
						$(SRCDIR)slhdsa/slhdsa_gen.c $(SRCDIR)slhdsa/slhdsa_sig.c $(SRCDIR)slhdsa/slhdsa_ver.c 
LIB_SLHDSA_HEADERS =	$(SRCDIR)slhdsa/src/address.h				$(SRCDIR)slhdsa/src/context.h		$(SRCDIR)slhdsa/src/compat.h		$(SRCDIR)slhdsa/src/fips202.h \
						$(SRCDIR)slhdsa/src/fors.h					$(SRCDIR)slhdsa/src/hash.h			$(SRCDIR)slhdsa/src/merkle.h		$(SRCDIR)slhdsa/src/nistapi.h \
						$(SRCDIR)slhdsa/src/params.h				$(SRCDIR)slhdsa/src/randombytes.h	$(SRCDIR)slhdsa/src/shake_offsets.h	$(SRCDIR)slhdsa/src/thash.h \
						$(SRCDIR)slhdsa/src/wotsx1.h				$(SRCDIR)slhdsa/src/utils.h			$(SRCDIR)slhdsa/src/utilsx1.h		$(SRCDIR)slhdsa/src/wots.h \
						$(SRCDIR)slhdsa/slhdsa.h

LIB_HEADER = ../crypto_api_sw.h

LIB_SOURCES = $(LIB_AES_SOURCES) $(LIB_EDDSA_SOURCES) $(LIB_X25519_SOURCES) $(LIB_RSA_SOURCES) $(LIB_SHA2_SOURCES) $(LIB_SHA3_SOURCES) $(LIB_TRNG_SOURCES) $(LIB_HKDF_SOURCES) $(LIB_MLKEM_SOURCES) $(LIB_MLDSA_SOURCES) $(LIB_SLHDSA_SOURCES) $(SRCDIR)common/cpu_endian.c
LIB_HEADERS = $(LIB_AES_HEADERS) $(LIB_EDDSA_HEADERS) $(LIB_X25519_HEADERS) $(LIB_RSA_HEADERS) $(LIB_SHA2_HEADERS) $(LIB_SHA3_HEADERS) $(LIB_TRNG_HEADERS) $(LIB_HKDF_HEADERS) $(LIB_MLKEM_HEADERS) $(LIB_MLDSA_HEADERS) $(LIB_SLHDSA_HEADERS) $(SRCDIR)common/cpu_endian.h $(LIB_HEADER)

LIB_SOURCES_ALT =	$(LIB_SOURCES) $(LIB_AES_ALT_SOURCES) $(LIB_SHA2_ALT_SOURCES) $(LIB_SHA3_ALT_SOURCES) $(LIB_EDDSA_ALT_SOURCES) \
					$(LIB_X25519_ALT_SOURCES) $(LIB_HKDF_ALT_SOURCES)

LIB_HEADERS_ALT =	$(LIB_HEADERS) $(LIB_AES_ALT_HEADERS) $(LIB_SHA2_ALT_HEADERS) $(LIB_SHA3_ALT_HEADERS) $(LIB_EDDSA_ALT_HEADERS) \
					$(LIB_X25519_ALT_HEADERS) $(LIB_HKDF_ALT_HEADERS) $(LIB_RSA_ALT_HEADERS)

SRC_DEMO = src/

DEMO_SOURCES =	$(SRC_DEMO)demo_aes.c \
				$(SRC_DEMO)demo_eddsa.c \
				$(SRC_DEMO)demo_x25519.c \
				$(SRC_DEMO)demo_mlkem.c \
				$(SRC_DEMO)demo_mldsa.c \
				$(SRC_DEMO)demo_slhdsa.c \
				$(SRC_DEMO)demo_rsa.c \
				$(SRC_DEMO)demo_sha2.c \
				$(SRC_DEMO)demo_sha3.c \
				$(SRC_DEMO)demo_trng.c \
				$(SRC_DEMO)demo_hkdf.c \
				$(SRC_DEMO)test_func.c

DEMO_SPEED_SOURCES =	$(SRC_DEMO)demo_aes_speed.c \
						$(SRC_DEMO)demo_sha2_speed.c \
						$(SRC_DEMO)demo_sha3_speed.c \
						$(SRC_DEMO)demo_rsa_speed.c \
						$(SRC_DEMO)demo_eddsa_speed.c \
						$(SRC_DEMO)demo_x25519_speed.c \
						$(SRC_DEMO)demo_hkdf_speed.c \
						$(SRC_DEMO)demo_mlkem_speed.c \
						$(SRC_DEMO)demo_mldsa_speed.c \
						$(SRC_DEMO)demo_slhdsa_speed.c \
						$(SRC_DEMO)demo_trng_speed.c \
						$(SRC_DEMO)test_func.c

DEMO_NIST_SOURCES =		$(SRC_DEMO)demo_mldsa_nist.c \
						$(SRC_DEMO)test_func.c

DEMO_HEADERS = $(SRC_DEMO)demo.h $(SRC_DEMO)test_func.h

SOURCES = $(LIB_SOURCES) $(DEMO_SOURCES)
HEADERS = $(LIB_HEADERS) $(DEMO_HEADERS)
SOURCES_ALT = $(LIB_SOURCES_ALT) $(DEMO_SOURCES)
HEADERS_ALT = $(LIB_HEADERS_ALT) $(DEMO_HEADERS)

SOURCES_SPEED = $(LIB_SOURCES) $(DEMO_SPEED_SOURCES)
HEADERS_SPEED = $(LIB_HEADERS) $(DEMO_SPEED_HEADERS)
SOURCES_SPEED_ALT = $(LIB_SOURCES_ALT) $(DEMO_SPEED_SOURCES)
HEADERS_SPEED_ALT = $(LIB_HEADERS_ALT) $(DEMO_SPEED_HEADERS)

SOURCES_NIST = $(LIB_SOURCES) $(DEMO_NIST_SOURCES)
HEADERS_NIST = $(LIB_HEADERS) $(DEMO_NIST_HEADERS)
SOURCES_NIST_ALT = $(LIB_SOURCES_ALT) $(DEMO_NIST_SOURCES)
HEADERS_NIST_ALT = $(LIB_HEADERS_ALT) $(DEMO_NIST_HEADERS)



DEMO_SOURCES_ARM = $(SOURCES_ALT) demo_arm.c
OBJ_ALT_ARM = $(patsubst %.c,%.o,$(DEMO_SOURCES_ARM))

DEMO_SPEED_SOURCES_ARM = $(SOURCES_SPEED_ALT) demo_speed_arm.c
OBJ_ALT_SPEED_ARM = $(patsubst %.c,%.o,$(DEMO_SPEED_SOURCES_ARM))

demo-all-openssl: $(SOURCES) demo.c $(HEADERS)
	$(CC) -o $@ $(CFLAGS_DEMO) $(SOURCES) demo.c $(LDFLAGS_DEMO)

demo-all-lib-openssl: $(SOURCES) demo.c $(HEADERS)
	$(CC) -o $@ $(CFLAGS_DEMO) $(SOURCES) demo.c $(LDFLAGS_DEMO_LIB)

demo-all-mbedtls: $(SOURCES) demo.c $(HEADERS)
	$(CC) -o $@ $(CFLAGS_DEMO) $(SOURCES) demo.c $(LDFLAGS_LIB_MBEDTLS)

demo-all-alt: $(SOURCES_ALT) demo.c $(HEADERS_ALT)
	$(CC) -o $@ $(CFLAGS_DEMO) $(SOURCES_ALT) demo.c -lm

demo-build-openssl: $(DEMO_SOURCES) demo.c $(DEMO_HEADERS)
	$(CC) -o $@ $(CFLAGS_DEMO_BUILD) $(DEMO_SOURCES) demo.c $(LDFLAGS_DEMO_BUILD)

demo-build-lib-openssl: $(DEMO_SOURCES) demo.c $(DEMO_HEADERS)
	$(CC) -o $@ $(CFLAGS_DEMO_BUILD) $(DEMO_SOURCES) demo.c $(LDFLAGS_DEMO_LIB) $(LDFLAGS_DEMO_BUILD)

demo-build-mbedtls: $(DEMO_SOURCES) demo.c $(DEMO_HEADERS)
	$(CC) -o $@ $(CFLAGS_DEMO_BUILD) $(DEMO_SOURCES) demo.c $(LDFLAGS_LIB_MBEDTLS) $(LDFLAGS_DEMO_BUILD_MBEDTLS)

demo-build-alt: $(DEMO_SOURCES) demo.c $(DEMO_HEADERS)
	$(CC) -o $@ $(CFLAGS_DEMO_BUILD) $(DEMO_SOURCES) demo.c $(LDFLAGS_DEMO_BUILD_ALT)

demo-install-openssl: $(DEMO_SOURCES) demo.c $(DEMO_HEADERS)
	$(CC) -o $@ $(DEMO_SOURCES) demo.c -lcryptoapi -lm -DCRYPTO_INST

demo-install-lib-openssl: $(DEMO_SOURCES) demo.c $(DEMO_HEADERS)
	$(CC) -o $@ $(DEMO_SOURCES) demo.c -lcryptoapi -lm -DCRYPTO_INST

demo-install-mbedtls: $(DEMO_SOURCES) demo.c $(DEMO_HEADERS)
	$(CC) -o $@ $(DEMO_SOURCES) demo.c -lcryptoapimbedtls -lm -DCRYPTO_INST

demo-install-alt: $(DEMO_SOURCES) demo.c $(DEMO_HEADERS)
	$(CC) -o $@ $(DEMO_SOURCES) demo.c -lcryptoapialt -lm -DCRYPTO_INST

demo-install-static-openssl: $(DEMO_SOURCES) demo.c $(DEMO_HEADERS)
	$(CC) -o $@ $(DEMO_SOURCES) demo.c -lcryptoapi-static -lm -DCRYPTO_INST

demo-install-static-lib-openssl: $(DEMO_SOURCES) demo.c $(DEMO_HEADERS)
	$(CC) -o $@ $(DEMO_SOURCES) demo.c -lcryptoapi-static -lm -DCRYPTO_INST

demo-install-static-mbedtls: $(DEMO_SOURCES) demo.c $(DEMO_HEADERS)
	$(CC) -o $@ $(DEMO_SOURCES) demo.c -lcryptoapimbedtls-static -lm -DCRYPTO_INST

demo-install-static-alt: $(DEMO_SOURCES) demo.c $(DEMO_HEADERS)
	$(CC) -o $@ $(DEMO_SOURCES) demo.c -lcryptoapialt-static -lm -DCRYPTO_INST

demo-speed-all-openssl: $(SOURCES_SPEED) demo_speed.c $(HEADERS_SPEED)
	$(CC) -o $@ $(CFLAGS_DEMO) $(SOURCES_SPEED) demo_speed.c $(LDFLAGS_DEMO)

demo-speed-all-lib-openssl: $(SOURCES_SPEED) demo_speed.c $(HEADERS_SPEED)
	$(CC) -o $@ $(CFLAGS_DEMO) $(SOURCES_SPEED) demo_speed.c $(LDFLAGS_DEMO_LIB)

demo-speed-all-mbedtls: $(SOURCES_SPEED) demo_speed.c $(HEADERS_SPEED)
	$(CC) -o $@ $(CFLAGS_DEMO) $(SOURCES_SPEED) demo_speed.c $(LDFLAGS_LIB_MBEDTLS)

demo-speed-all-alt: $(SOURCES_SPEED_ALT) demo_speed.c $(HEADERS_SPEED_ALT)
	$(CC) -o $@ $(CFLAGS_DEMO) $(SOURCES_SPEED_ALT) demo_speed.c -lm

demo-speed-build-openssl: $(DEMO_SPEED_SOURCES) demo_speed.c $(DEMO_HEADERS)
	$(CC) -o $@ $(CFLAGS_DEMO_BUILD) $(DEMO_SPEED_SOURCES) demo_speed.c $(LDFLAGS_DEMO_BUILD)

demo-speed-build-lib-openssl: $(DEMO_SPEED_SOURCES) demo_speed.c $(DEMO_HEADERS)
	$(CC) -o $@ $(CFLAGS_DEMO_BUILD) $(DEMO_SPEED_SOURCES) demo_speed.c $(LDFLAGS_DEMO_LIB) $(LDFLAGS_DEMO_BUILD)

demo-speed-build-mbedtls: $(DEMO_SPEED_SOURCES) demo_speed.c $(DEMO_HEADERS)
	$(CC) -o $@ $(CFLAGS_DEMO_BUILD) $(DEMO_SPEED_SOURCES) demo_speed.c $(LDFLAGS_LIB_MBEDTLS) $(LDFLAGS_DEMO_BUILD_MBEDTLS)

demo-speed-build-alt: $(DEMO_SPEED_SOURCES) demo_speed.c $(DEMO_HEADERS)
	$(CC) -o $@ $(CFLAGS_DEMO_BUILD) $(DEMO_SPEED_SOURCES) demo_speed.c $(LDFLAGS_DEMO_BUILD_ALT)

demo-speed-install-openssl: $(DEMO_SPEED_SOURCES) demo_speed.c $(DEMO_HEADERS)
	$(CC) -o $@ $(DEMO_SPEED_SOURCES) demo_speed.c -lcryptoapi -lm -DCRYPTO_INST

demo-speed-install-lib-openssl: $(DEMO_SPEED_SOURCES) demo_speed.c $(DEMO_HEADERS)
	$(CC) -o $@ $(DEMO_SPEED_SOURCES) demo_speed.c -lcryptoapi -lm -DCRYPTO_INST

demo-speed-install-mbedtls: $(DEMO_SPEED_SOURCES) demo_speed.c $(DEMO_HEADERS)
	$(CC) -o $@ $(DEMO_SPEED_SOURCES) demo_speed.c -lcryptoapimbedtls -lm -DCRYPTO_INST

demo-speed-install-alt: $(DEMO_SPEED_SOURCES) demo_speed.c $(DEMO_HEADERS)
	$(CC) -o $@ $(DEMO_SPEED_SOURCES) demo_speed.c -lcryptoapialt -lm -DCRYPTO_INST

demo-nist-all-alt: $(SOURCES_NIST_ALT) demo_nist.c $(HEADERS_NIST_ALT)
	$(CC) -o $@ $(CFLAGS_DEMO) $(SOURCES_NIST_ALT) demo_nist.c -lm

build-demo-arm:
	for src in $(basename $(DEMO_SOURCES_ARM)); do \
		echo $(CCARM) -c $$src.c -DCRYPTO_ARM -o $$src.o; \
		$(CCARM) -c $$src.c -DCRYPTO_ARM -o $$src.o; \
	done
	$(AR) libdemo-static-arm.a $(OBJ_ALT_ARM)
	find ../. -type f -name '*.o' -exec rm {} +

build-demo-speed-arm:
	for src in $(basename $(DEMO_SPEED_SOURCES_ARM)); do \
		echo $(CCARM) -c $$src.c -DCRYPTO_ARM -o $$src.o; \
		$(CCARM) -c $$src.c -DCRYPTO_ARM -o $$src.o; \
	done
	$(AR) libdemo-speed-static-arm.a $(OBJ_ALT_SPEED_ARM)
	find ../. -type f -name '*.o' -exec rm {} +

.PHONY: all demo clean

clean:
	-rm demo-*
