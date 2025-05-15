# MQTTs client with Post-Quantum TLS Using mbedtls
The project is meant to showcase the Hybrid Post-Quantum capabilities of an MQTTs client using TLS 1.3


# Build CSIC

- Change Makefile to use the right **CC** compiler
- Update Include of machine/endian.h
- A precompiled binary for the STM32F4 is provided under stm32_f429/crypto_api_sw/CRYPTO_API_SW/build/libcryptoapialt-static-arm.a

```
cd crypto\_api\_sw
make build-static-arm-alt
```

# Build OQS-Components

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

# Launch Server

From the base directory
```
CERTS_DIR=./certs/certs_ecc #can change if other directory is needed

sudo ./installs/openssl/bin/openssl s_server -cert $CERTS_DIR/server.crt -groups x25519_kyber768 -CAfile $CERTS_DIR/ca.crt -key $CERTS_DIR/server.key -accept 192.168.178.46:443 -debug

```


# STM32 CUBE Ide Project

Import project
Properties -> Settings -> MCU GCC Compiler -> Include Path -> Remove "/home/vagrant/QBIP/crypto_api_sw" -> Add csic crypto lib folder


Properties -> Settings -> MCU GCC Linker -> Libraries -> Change library search path ("/home/vagrant/QBIP/crypto_api_sw/CRYPTO_API_SW/build")

Change BROKER_IP in main.h

UART Tx on PD8 (back of the board)

