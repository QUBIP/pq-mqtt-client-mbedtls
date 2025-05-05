# qubip_csic_mbedtls

# Generate Keys and Certs
cd certs/certs_25519

Server Key: `openssl genpkey -algorithm ed25519 -out server.key`

Server Csr: `openssl req -new -key server.key -out server.csr`

Server Crt: `openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 3650`


Client Key: `openssl genpkey -algorithm ed25519 -out client.key`

Client Csr: `openssl req -new -key client.key -out client.csr`

Client Crt: `openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 3650`

# Build CSIC

- Change Makefile to use the right **CC** compiler
- Update Include of machine/endian.h


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

