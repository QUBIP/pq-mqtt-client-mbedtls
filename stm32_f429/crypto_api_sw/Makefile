# -- COMPILERS (-DCPU_BIG_ENDIAN for bigendianness)
CC=/usr/bin/cc -fPIC
CCARM=/opt/st/stm32cubeide_1.14.0/plugins/com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.11.3.rel1.linux64_1.1.100.202309141235/tools/bin/arm-none-eabi-gcc -mcpu=cortex-m4 -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb -g3 -O0 
AR = ar rcs

# -- DIRECTORIES
OPENSSL_DIR = /opt/openssl/
MBEDTLS_DIR = /home/eros/mbedtls/

# -- LDFLAGS
LDFLAGS_OPENSSL = -lcrypto -lm -DOPENSSL
LDFLAGS_LIB_OPENSSL = -lm -I$(OPENSSL_DIR)include $(OPENSSL_DIR)lib/libcrypto.so.3 -DOPENSSL
LDFLAGS_LIB_MBEDTLS = -lm -I$(MBEDTLS_DIR)include $(MBEDTLS_DIR)library/libmbedcrypto.a $(MBEDTLS_DIR)library/libmbedtls.a $(MBEDTLS_DIR)library/libmbedx509.a -DMBEDTLS
CFLAGS = 

# -- LIB SOURCES
BLDDIR = CRYPTO_API_SW/build/
SRCDIR = CRYPTO_API_SW/src/

# -- SOURCES & HEADERS
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

LIB_HEADER = crypto_api_sw.h

LIB_SOURCES = $(LIB_AES_SOURCES) $(LIB_EDDSA_SOURCES) $(LIB_X25519_SOURCES) $(LIB_RSA_SOURCES) $(LIB_SHA2_SOURCES) $(LIB_SHA3_SOURCES) $(LIB_TRNG_SOURCES) $(LIB_HKDF_SOURCES) $(LIB_MLKEM_SOURCES) $(LIB_MLDSA_SOURCES) $(LIB_SLHDSA_SOURCES) $(SRCDIR)common/cpu_endian.c
LIB_HEADERS = $(LIB_AES_HEADERS) $(LIB_EDDSA_HEADERS) $(LIB_X25519_HEADERS) $(LIB_RSA_HEADERS) $(LIB_SHA2_HEADERS) $(LIB_SHA3_HEADERS) $(LIB_TRNG_HEADERS) $(LIB_HKDF_HEADERS) $(LIB_MLKEM_HEADERS) $(LIB_MLDSA_HEADERS) $(LIB_SLHDSA_HEADERS) $(SRCDIR)common/cpu_endian.h

LIB_SOURCES_ALT =	$(LIB_SOURCES) $(LIB_AES_ALT_SOURCES) $(LIB_SHA2_ALT_SOURCES) $(LIB_SHA3_ALT_SOURCES) $(LIB_EDDSA_ALT_SOURCES) \
					$(LIB_X25519_ALT_SOURCES) $(LIB_HKDF_ALT_SOURCES)

LIB_HEADERS_ALT =	$(LIB_HEADERS) $(LIB_AES_ALT_HEADERS) $(LIB_SHA2_ALT_HEADERS) $(LIB_SHA3_ALT_HEADERS) $(LIB_EDDSA_ALT_HEADERS) \
					$(LIB_X25519_ALT_HEADERS) $(LIB_HKDF_ALT_HEADERS) $(LIB_RSA_ALT_HEADERS)

SOURCES = $(LIB_SOURCES)
HEADERS = $(LIB_HEADERS) $(LIB_HEADER)
SOURCES_ALT = $(LIB_SOURCES_ALT)
HEADERS_ALT = $(LIB_HEADERS_ALT)

BUILD_LIB_OPENSSL	= libcryptoapi
BUILD_LIB_MBEDTLS	= libcryptoapimbedtls
BUILD_LIB_ALT		= libcryptoapialt

# -- SHARED LIB
build-openssl: $(SOURCES) $(HEADERS)
	mkdir -p $(BLDDIR)
	$(CC) -shared -Wl,-soname,$(BUILD_LIB_OPENSSL).so -o $(BLDDIR)$(BUILD_LIB_OPENSSL).so $(SOURCES) $(LDFLAGS_OPENSSL)
	ar rcs $(BLDDIR)$(BUILD_LIB_OPENSSL).a $(BLDDIR)$(BUILD_LIB_OPENSSL).so

build-mbedtls: $(SOURCES) $(HEADERS)
	mkdir -p $(BLDDIR)
	$(CC) -shared -Wl,-soname,$(BUILD_LIB_MBEDTLS).so -o $(BLDDIR)$(BUILD_LIB_MBEDTLS).so $(SOURCES) $(LDFLAGS_LIB_MBEDTLS)
	ar rcs $(BLDDIR)$(BUILD_LIB_MBEDTLS).a $(BLDDIR)$(BUILD_LIB_MBEDTLS).so

build-lib-openssl: $(SOURCES) $(HEADERS)
	mkdir -p $(BLDDIR)
	$(CC) -shared -Wl,-soname,$(BUILD_LIB_OPENSSL).so -o $(BLDDIR)$(BUILD_LIB_OPENSSL).so $(SOURCES) $(LDFLAGS_LIB_OPENSSL)
	ar rcs $(BLDDIR)$(BUILD_LIB_OPENSSL).a $(BLDDIR)$(BUILD_LIB_OPENSSL).so

build-alt: $(SOURCES_ALT) $(HEADERS_ALT)
	mkdir -p $(BLDDIR)
	$(CC) -shared -Wl,-soname,$(BUILD_LIB_ALT).so -o $(BLDDIR)$(BUILD_LIB_ALT).so $(SOURCES_ALT)
	ar rcs $(BLDDIR)$(BUILD_LIB_ALT).a $(BLDDIR)$(BUILD_LIB_ALT).so

install-openssl:
	cp $(BLDDIR)$(BUILD_LIB_OPENSSL).so /usr/lib/.
	cp $(BLDDIR)$(BUILD_LIB_OPENSSL).a /usr/lib/.
	cp crypto_api_sw.h /usr/include/.
	cp -r CRYPTO_API_SW /usr/include/CRYPTO_API_SW

install-lib-openssl:
	cp $(BLDDIR)$(BUILD_LIB_OPENSSL).so /usr/lib/.
	cp $(BLDDIR)$(BUILD_LIB_OPENSSL).a /usr/lib/.
	cp crypto_api_sw.h /usr/include/.
	cp -r CRYPTO_API_SW /usr/include/CRYPTO_API_SW

install-mbedtls:
	cp $(BLDDIR)$(BUILD_LIB_MBEDTLS).so /usr/lib/.
	cp $(BLDDIR)$(BUILD_LIB_MBEDTLS).a /usr/lib/.
	cp crypto_api_sw.h /usr/include/.
	cp -r CRYPTO_API_SW /usr/include/CRYPTO_API_SW

install-alt:
	cp $(BLDDIR)$(BUILD_LIB_ALT).so /usr/lib/.
	cp $(BLDDIR)$(BUILD_LIB_ALT).a /usr/lib/.
	cp crypto_api_sw.h /usr/include/.
	cp -r CRYPTO_API_SW /usr/include/CRYPTO_API_SW

uninstall-openssl: 
	rm -f /usr/lib/$(BUILD_LIB_OPENSSL).so
	rm -f /usr/lib/$(BUILD_LIB_OPENSSL).a
	rm -f /usr/include/crypto_api_sw.h
	rm -rf /usr/include/CRYPTO_API_SW

uninstall-lib-openssl: 
	rm -f /usr/lib/$(BUILD_LIB_OPENSSL).so
	rm -f /usr/lib/$(BUILD_LIB_OPENSSL).a
	rm -f /usr/include/crypto_api_sw.h
	rm -rf /usr/include/CRYPTO_API_SW

uninstall-mbedtls: 
	rm -f /usr/lib/$(BUILD_LIB_MBEDTLS).so
	rm -f /usr/lib/$(BUILD_LIB_MBEDTLS).a
	rm -f /usr/include/crypto_api_sw.h
	rm -rf /usr/include/CRYPTO_API_SW

uninstall-alt: 
	rm -f /usr/lib/$(BUILD_LIB_ALT).so
	rm -f /usr/lib/$(BUILD_LIB_ALT).a
	rm -f /usr/include/crypto_api_sw.h
	rm -rf /usr/include/CRYPTO_API_SW

# -- STATIC LIB 
BUILD_STATIC_LIB_OPENSSl	= libcryptoapi-static
BUILD_STATIC_LIB_MBEDTLS	= libcryptoapimbedtls-static
BUILD_STATIC_LIB_ALT		= libcryptoapialt-static

OBJ = $(patsubst %.c,%.o,$(SOURCES))
OBJ_ALT = $(patsubst %.c,%.o,$(SOURCES_ALT))

build-static-openssl:
	for src in $(basename $(SOURCES)); do \
		echo $(CC) -c $$src.c -o $$src.o; \
		$(CC) -c $$src.c -o $$src.o; \
	done
	$(AR) $(BLDDIR)$(BUILD_STATIC_LIB_OPENSSl).a $(OBJ) 
	find . -type f -name '*.o' -exec rm {} +

build-static-mbedtls:
	for src in $(basename $(SOURCES)); do \
		echo $(CC) -c $$src.c -o $$src.o; \
		$(CC) -c $$src.c -o $$src.o; \
	done
	$(AR) $(BLDDIR)$(BUILD_STATIC_LIB_MBEDTLS).a $(OBJ) 
	find . -type f -name '*.o' -exec rm {} +

build-static-lib-openssl:
	for src in $(basename $(SOURCES)); do \
		echo $(CC) -c $$src.c -o $$src.o; \
		$(CC) -c $$src.c -o $$src.o; \
	done
	$(AR) $(BLDDIR)$(BUILD_STATIC_LIB_OPENSSl).a $(OBJ) 
	find . -type f -name '*.o' -exec rm {} +

build-static-alt:
	for src in $(basename $(SOURCES_ALT)); do \
		echo $(CC) -c $$src.c -o $$src.o; \
		$(CC) -c $$src.c -o $$src.o; \
	done
	$(AR) $(BLDDIR)$(BUILD_STATIC_LIB_ALT).a $(OBJ_ALT)
	find . -type f -name '*.o' -exec rm {} +

build-static-arm-alt:
	for src in $(basename $(SOURCES_ALT)); do \
		echo $(CCARM) -c $$src.c -o $$src.o; \
		$(CCARM) -c $$src.c -o $$src.o; \
	done
	$(AR) $(BLDDIR)libcryptoapialt-static-arm.a $(OBJ_ALT)
	find . -type f -name '*.o' -exec rm {} +

install-static-openssl:
	cp $(BLDDIR)$(BUILD_STATIC_LIB_OPENSSL).a /usr/lib/.
	cp crypto_api_sw.h /usr/include/.
	cp -r CRYPTO_API_SW /usr/include/CRYPTO_API_SW

install-static-lib-openssl:
	cp $(BLDDIR)$(BUILD_STATIC_LIB_OPENSSL).a /usr/lib/.
	cp crypto_api_sw.h /usr/include/.
	cp -r CRYPTO_API_SW /usr/include/CRYPTO_API_SW

install-static-mbedtls:
	cp $(BLDDIR)$(BUILD_STATIC_LIB_MBEDTLS).a /usr/lib/.
	cp crypto_api_sw.h /usr/include/.
	cp -r CRYPTO_API_SW /usr/include/CRYPTO_API_SW

install-static-alt:
	cp $(BLDDIR)$(BUILD_STATIC_LIB_ALT).a /usr/lib/.
	cp crypto_api_sw.h /usr/include/.
	cp -r CRYPTO_API_SW /usr/include/CRYPTO_API_SW

uninstall-static-openssl: 
	rm -f /usr/lib/$(BUILD_STATIC_LIB_OPENSSL).a
	rm -f /usr/include/crypto_api_sw.h
	rm -rf /usr/include/CRYPTO_API_SW

uninstall-static-lib-openssl: 
	rm -f /usr/lib/$(BUILD_STATIC_LIB_OPENSSL).a
	rm -f /usr/include/crypto_api_sw.h
	rm -rf /usr/include/CRYPTO_API_SW

uninstall-static-mbedtls: 
	rm -f /usr/lib/$(BUILD_STATIC_LIB_MBEDTLS).a
	rm -f /usr/include/crypto_api_sw.h
	rm -rf /usr/include/CRYPTO_API_SW

uninstall-static-alt: 
	rm -f /usr/lib/$(BUILD_STATIC_LIB_ALT).a
	rm -f /usr/include/crypto_api_sw.h
	rm -rf /usr/include/CRYPTO_API_SW

clean:
	-rm -r $(BLDDIR)
