# MQTTs client with Post-Quantum TLS Using mbedtls
The project is meant to showcase the Hybrid Post-Quantum capabilities of an MQTTs client using TLS 1.3 and the mbedtls library.  \
A local PQ openssl server can be setup to test the TLS handshake between the board and the server by compiling a version of openssl with the support of PQ cryptography. \
The server can be only used to test the handshake as it is not a MQTTs client. 

To do so, the following components need to be compiled: 

## Build OQS-Components

```
mkdir -p installs/{openssl,liboqs}

sudo apt install build-essential linux-headers-$(uname -r) \
            libtool automake autoconf \
            make cmake ninja-build \
            git wget libssl-dev

export INSTALL_DIR=$(pwd)/installs
```
## Build Openssl

```
cd openssl

LDFLAGS="-Wl,-rpath -Wl,$INSTALL_DIR/openssl/lib64" ./config shared --prefix=$INSTALL_DIR/openssl
make 
make install

cd ..

```

## Build Liboqs

```
cd liboqs
mkdir build 
cd build
cmake -G"Ninja" .. -DOPENSSL_ROOT_DIR=$INSTALL_DIR/openssl -DOQS_DIST_BUILD=ON -DCMAKE_INSTALL_PREFIX=$INSTALL_DIR/liboqs
ninja install
```

## Build Oqs-Provider

```
cd ../oqs-provider

liboqs_DIR=$INSTALL_DIR/liboqs cmake -DOPENSSL_ROOT_DIR=$INSTALL_DIR/openssl -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=$INSTALL_DIR/openssl -S . -B _build
cmake --build _build
cp _build/lib/oqsprovider.so $INSTALL_DIR/openssl/lib64/ossl-modules

sed -i "s/default = default_sect/default = default_sect\noqsprovider = oqsprovider_sect/g" $INSTALL_DIR/openssl/ssl/openssl.cnf && \
sed -i "s/\[default_sect\]/\[default_sect\]\nactivate = 1\n\[oqsprovider_sect\]\nactivate = 1\n/g" $INSTALL_DIR/openssl/ssl/openssl.cnf && \
sed -i "s/providers = provider_sect/providers = provider_sect\nssl_conf = ssl_sect\n\n\[ssl_sect\]\nsystem_default = system_default_sect\n\n\[system_default_sect\]\nGroups = \$ENV\:\:DEFAULT_GROUPS\n/g" $INSTALL_DIR/openssl/ssl/openssl.cnf && \
sed -i "s/HOME\t\t\t= ./HOME           = .\nDEFAULT_GROUPS = kyber768/g" $INSTALL_DIR/openssl/ssl/openssl.cnf
```

## Launch Server

A series of shell scripts can be used to launch the chosen vesion of the server.
The options differ in the certificates used to perform mutual authentication.
- Classic TLS
- MLDSA44
- MLDSA65
- Production-like PKI setup by PoliTO

The certificates are provided in the relative folders under [certificates](https://github.com/QUBIP/pq-mqtt-client-mbedtls/tree/refactor/certificates)

## CSIC Post-Quantum Software Library
- A precompiled binary for the STM32F4 is provided in [libcryptoapialt-static-arm.a](https://github.com/QUBIP/pq-mqtt-client-mbedtls/blob/refactor/stm32_f429/crypto_api_sw/CRYPTO_API_SW/build/libcryptoapialt-static-arm.a)
- This is linked with the binary that will run onto the STM32F4 in the CubeIDE project 

## STM32 CUBE Ide Project

The project can be imported into CubeIDE and run onto the STM32F4

A few parameters can be configured in the file [qubip.h](https://github.com/QUBIP/pq-mqtt-client-mbedtls/blob/refactor/stm32_f429/Middlewares/Third_Party/MBEDTLS/include/mbedtls/qubip.h)

To choose whether or not to use the physical SE
```
#define HW_IMPLEMENTATION 0 //1=ON, 0=OFF
```

To choose which certificates to use. They need to match the server ones. 
```
// OPTIONS: CERTS_PQ_44, CERTS_PQ_65, CERTS_CLASSIC
#define CERTS_PQ_44
```
The remote server IP and hostname can be configured as:
```

//#define BROKER_IP		"192.168.1.12"
#define BROKER_IP		"broker.dm.qubip.eu"
#define BROKER_HOSTNAME "broker.dm.qubip.eu"
```

The STM32 prints its output onto its serial port on PIN PD8 which can be found on the back of the board

# mbedtls
## Introduction of Hybrid Post-Quantum cryptography 

The TLS handshake has been agumented with Hybrid PQ capabilities by introducing a new KEM and a new signature mechanism. \
These are, respectively X25519-MLKEM768 and Ed25519-MLDSA.

The functions responsible for the KEM can be found in [qubip.c](https://github.com/QUBIP/pq-mqtt-client-mbedtls/blob/refactor/stm32_f429/Middlewares/Third_Party/MBEDTLS/library/qubip.c):
```
HybridKeyKEM *hybrid_key_gen();
void hybrid_key_free(HybridKeyKEM *);
```
The signature and signature verification functions are implemented in the already present mbedtls file [pk_wrap.c](https://github.com/QUBIP/pq-mqtt-client-mbedtls/blob/8651821b60df32601ef3e36d88d89c398002bf2e/stm32_f429/Middlewares/Third_Party/MBEDTLS/library/pk_wrap.c#L1363) that get called several times during the TLS handshake.

```
static int ed25519_mlds44_sign_wrap(mbedtls_pk_context *pk,
		mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len,
		unsigned char *sig, size_t sig_size, size_t *sig_len,
		int (*f_rng)(void*, unsigned char*, size_t), void *p_rng);

static int ed25519_mlds44_verify_wrap(mbedtls_pk_context *pk,
		mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len,
		const unsigned char *sig, size_t sig_len);
```

Furthermore, the certificate parsing functionalities have been expanded to include support for Hybrid PQ certificates in file [pk_parse.c](https://github.com/QUBIP/pq-mqtt-client-mbedtls/blob/3630bfed4f078bb3ca768471d9a94a54948cf460/stm32_f429/Middlewares/Third_Party/MBEDTLS/library/pkparse.c#L594)

A few examples of Hybrid PQ certificates have been hardcoded in file [MQTTInterfacte.c](https://github.com/QUBIP/pq-mqtt-client-mbedtls/blob/3630bfed4f078bb3ca768471d9a94a54948cf460/stm32_f429/Middlewares/Third_Party/MQTT/MQTTInterface.c#L485)
