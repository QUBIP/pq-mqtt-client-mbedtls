# CRYPTO_API_SW

## Introduction

This SW API is a compilation of different crypto primitives described in SW that will work as a basic elements for HW implementations. This library is going to work as a SW reference of HW developing. 

This API has been developed using **OpenSSL v3.3.1**, **MbedTLS v3.6.0** and **ALT**ernative definition of algorithms.

## Description

The content of the CRYPTO-API SW library is depicted in the next container tree:
    
    .
    ├── CRYPTO_API_SW       # folder that all the files of the API.
        .
        ├── build           # folder to store the shared libraries 
        └── src             # folder that contains the sources files
            .
            ├── aes         # AES files
            ├── eddsa       # EdDSA files 
            ├── hkdf        # HKDF-SHA256 files 
            ├── mlkem       # ML-KEM files 
            ├── mldsa       # ML-DSA files 
            ├── slhdsa      # SLH-DSA files 
            ├── rsa         # RSA files 
            ├── sha2        # SHA2 files 
            ├── sha3        # SHA3 files 
            ├── x25519      # ECDH files 
            └── trng        # TRNG files
    ├── demo                # folder that contains the demo
    ├── results             # performance results in several platforms
    ├── CRYPTO_API_SW.h     # header of the library
    ├── Makefile            # To compile the library
    ├── CubeIDE-Project.zip # The STM32 Cube IDE Project for the CRYPTO-API
    └── README.md  

For now (**v6.3**) the list of supported algorithms are:

| Key    | Meaning  |
| -----  | --------- |
| ✅     | Supported |
| 🔜     | Not yet supported |
| 🔶     | Supporting under discussion |
| ❌     | Not supported at all |

- **Symmetric Cryptography**

| Algorithms    | OpenSSL 3 | MbedTLS   | ALT       | SE-QUBIP  |
| ----------    | --------- | -------   | --------  | --------  |
| AES-128-ECB   | ✅        | ✅        | ✅       | 🔜       |
| AES-128-CBC   | ✅        | ✅        | ✅       | 🔜       |
| AES-128-CMAC  | ✅        | ✅        | ✅       | 🔜       |
| AES-128-GCM   | ✅        | ✅        | ✅       | 🔜       |
| AES-128-CCM-8 | ✅        | ✅        | ✅       | 🔜       |
| AES-192-ECB   | ✅        | ✅        | ✅       | ❌       |
| AES-192-CBC   | ✅        | ✅        | ✅       | ❌       |
| AES-192-CMAC  | ✅        | ✅        | ✅       | ❌       |
| AES-192-GCM   | ✅        | ✅        | ✅       | ❌       |
| AES-192-CCM-8 | ✅        | ✅        | ✅       | ❌       |
| AES-256-ECB   | ✅        | ✅        | ✅       | 🔜       |
| AES-256-CBC   | ✅        | ✅        | ✅       | 🔜       |
| AES-256-CMAC  | ✅        | ✅        | ✅       | 🔜       |
| AES-256-GCM   | ✅        | ✅        | ✅       | 🔜       |
| AES-256-CCM-8 | ✅        | ✅        | ✅       | 🔜       |

- **Classical Asymmetric Cryptography**
 
| Algorithms    | OpenSSL 3 | MbedTLS   | ALT       | SE-QUBIP  |
| ----------    | --------- | -------   | --------  | --------  |
| RSA-2048-PKE  | ✅        | ✅        | 🔜       | ❌       |
| RSA-3072-PKE  | ✅        | ✅        | 🔜       | ❌       |
| RSA-4096-PKE  | ✅        | ✅        | 🔜       | ❌       |
| RSA-6144-PKE  | ✅        | ✅        | 🔜       | ❌       |
| RSA-8192-PKE  | ✅        | ✅        | 🔜       | ❌       |
| EdDSA-25519   | ✅        | 🔜*       | ✅       | ✅       |
| EdDSA-448     | ✅        | 🔜*       | ✅       | ❌       |
| X25519        | ✅        | ✅        | ✅       | ✅       |
| X448          | ✅        | ✅        | ✅       | ❌       |

\* _EdDSA is not yet supported by MbedTLS (check [MbedTLS #5819](https://github.com/Mbed-TLS/mbedtls/pull/5819)_

- **Hash Functions**

| Algorithms    | OpenSSL 3 | MbedTLS   | ALT       | SE-QUBIP  |
| ----------    | --------- | -------   | --------  | --------  |
| SHA-224       | ✅        | ✅        | ✅       | ❌       |
| SHA-256       | ✅        | ✅        | ✅       | ✅       |
| SHA-384       | ✅        | ✅        | ✅       | ✅       |
| SHA-512       | ✅        | ✅        | ✅       | ✅       |
| SHA-512/224   | ✅        | 🔜*       | ✅       | ❌       |
| SHA-512/256   | ✅        | 🔜*       | ✅       | ✅       |
| SHA3-224      | ✅        | ✅        | ✅       | ❌       |
| SHA3-256      | ✅        | ✅        | ✅       | ✅       |
| SHA3-384      | ✅        | ✅        | ✅       | ❌       |
| SHA3-512      | ✅        | ✅        | ✅       | ✅       |
| SHAKE-128     | ✅        | 🔜*       | ✅       | ✅       |
| SHAKE-256     | ✅        | 🔜*       | ✅       | ✅       |

\* _SHA-512/224 & SHA-512/256 are not yet supported by MbedTLS (check [MbedTLS #1653](https://github.com/Mbed-TLS/mbedtls/issues/1653)_

\* _SHAKE-128 & SHAKE-256 are not yet supported by MbedTLS (check [MbedTLS #1549](https://github.com/Mbed-TLS/mbedtls/pull/1549/)_

- **Key Derivation Function**

| Algorithms    | OpenSSL 3 | MbedTLS   | ALT       | SE-QUBIP  |
| ----------    | --------- | -------   | --------  | --------  |
| HKDF-SHA256   | ✅        | ✅       | ✅        | 🔜        |

- **Random Number Generators**

| Algorithms    | OpenSSL 3 | MbedTLS   | ALT       | SE-QUBIP  |
| ----------    | --------- | -------   | --------  | --------  |
| TRNG          | ✅        | ✅        | ✅       | ✅       |
| CTR-DRBG      | ✅        | ✅        | ✅       | 🔜       |
| HASH-DRBG     | ✅        | ✅        | ✅       | 🔜       |

- **Post-Quantum Cryptography**

| Algorithms                | OpenSSL 3 | MbedTLS    | ALT      | SE-QUBIP  |
| ----------                | --------- | -------    | -------- | --------  |
| MLKEM-512                 | ✅        | ✅        | ✅       | ✅       |
| MLKEM-768                 | ✅        | ✅        | ✅       | ✅       |
| MLKEM-1024                | ✅        | ✅        | ✅       | ✅       |
| MLDSA-44                  | ✅        | ✅        | ✅       | 🔜       |
| MLDSA-65                  | ✅        | ✅        | ✅       | 🔜       |
| MLDSA-87                  | ✅        | ✅        | ✅       | 🔜       |
| SLH-DSA-SHA2-128s         | 🔜        | 🔜        | ✅       | 🔶       |
| SLH-DSA-SHAKE-128s        | 🔜        | 🔜        | ✅       | 🔶       |
| SLH-DSA-SHA2-128f         | 🔜        | 🔜        | ✅       | 🔶       |
| SLH-DSA-SHAKE-128f        | 🔜        | 🔜        | ✅       | 🔶       |
| SLH-DSA-SHA2-192s         | 🔜        | 🔜        | ✅       | 🔶       |
| SLH-DSA-SHAKE-192s        | 🔜        | 🔜        | ✅       | 🔶       |
| SLH-DSA-SHA2-192f         | 🔜        | 🔜        | ✅       | 🔶       |
| SLH-DSA-SHAKE-192f        | 🔜        | 🔜        | ✅       | 🔶       |
| SLH-DSA-SHA2-256s         | 🔜        | 🔜        | ✅       | 🔶       |
| SLH-DSA-SHAKE-256s        | 🔜        | 🔜        | ✅       | 🔶       |
| SLH-DSA-SHA2-256f         | 🔜        | 🔜        | ✅       | 🔶       |
| SLH-DSA-SHAKE-256f        | 🔜        | 🔜        | ✅       | 🔶       |


## Installation

Check the Installation section that you are using: MbedTLS or OpenSSL.

### OpenSSL 3

The library requires the latest version of OpenSSL. Visit the [OpenSSL Website](https://www.openssl.org/source/) to download and install it. 

We recommend the following installation settings: 

1. After downloading the OpenSSL distribution go to the `openssl` folder. 

```bash
git clone https://github.com/openssl/openssl.git
cd openssl
```

2. If you are using a different version of OpenSSL, ***we strongly recommend to not overwrite the OS version.*** For that, type: 
```bash
./Configure --prefix=/opt/openssl --openssldir=/usr/local/ssl
```

3. Then, initiate the installation:
```bash
make install
```

4. After that, we recommend to add the libraries to the `LD_LIBRARY_PATH`. In our case: 
```bash
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/xilinx/openssl/
```

### MbedTLS

The library requires the latest version of MbedTLS. Visit the [MbedTLS Github repository](https://github.com/Mbed-TLS/mbedtls) to download and install it. This API has been developed using the v3.6.0.

We recommend the following installation settings: 

1. After downloading the OpenSSL distribution go to the `mbedtls` folder. 

```bash
git clone https://github.com/Mbed-TLS/mbedtls.git --branch v3.6.0
cd mbedtls
```

2. Then, initiate the installation:
```bash
make
```

3. After that, you ***should*** modify the variable `MBEDTLS_DIR` to the local folder of the MbedTLS software application. In our case: 
```bash
MBEDTLS_DIR = /home/eros/mbedtls/
```

### ALT

The ALTernative defition of algorithms does not require extra libraries installation. 

### Library Installation

For the installation, it is necessary to follow the next steps: 

1. Download the repository
```bash
sudo git clone https://gitlab.com/hwsec/crypto_api_sw
```

2. At this point there are two ways to installation. You can generate the shared libraries directly after the downloading and use them in any other program. For that, 
```bash
make build-openssl
```
The shared libraries will be generated in `CRYPTO_API_SW/build/` folder. 

- If you are using a local OpenSSL library (as it is detailed in the Installation section), you can modify the `OPENSSL_DIR` variable in the Makefile, and type: 
```bash
make build-lib-openssl
```

It might be necessary to add the output libraries to the `LD_LIBRARY_PATH`. In our case: 
```bash
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/xilinx/crypto_api_sw/CRYPTO_API_SW/build
```

- If you are using the MbedTLS library, after the modification of the `MBEDTLS_DIR` variable in the Makefile, you can type: 
```bash
make build-mbedtls
```

All these commands will generate two different types of libraries: libcryptoapisw.so/a or libcryptoapiswmbedtls.so/a depending on the use of OpenSSL or MbedTLS.

3. You can install these libraries into the system local folder with ```make install-openssl```, ```make install-lib-openssl``` or ```make install-mbedtls```.

*Note: It is possible to install several different types of libraries in the system like -lcryptoapi and -lcryptoapialt.*

4. If you decide to remove these libraries from the system local folder you can type: ```make uninstall-openssl```, ```make uninstall-lib-openssl``` or ```make uninstall-mbedtls```.

### Makefile Overview

The commands of ```make XXX-YYY-ZZZ``` can be resumed in the next table: 

| XXX           | Meaning   |
| ----------    | --------- |
| build         | Generation of the libraries                               |
| install       | Installation of libraries into the system local folder    |
| uninstall     | Removing libraries from the system local folder           |

| YYY           | Meaning   |
| ----------    | --------- |
| static        | Generation of static libraries                            |
| static-arm    | Generation of static libraries for STM32                  |
| *none*        | Generation of shared libraries                            |

| ZZZ           | Meaning   |
| ----------    | --------- |
| openssl       | Using the version of OpenSSL already installed in the system  |
| lib-openssl   | Using the version of OpenSSL installed in a local folder (```OPENSSL_DIR``` from Makefile) |
| mbedtls       | Using the version of MbedTLS installed in a local folder (```MBEDTLS_DIR``` from Makefile) |
| alt           | Using the alternative definition of the algorithms                                         |

### Fast Compilation

Files `compile_rasp4b.sh`, `compile_pynqz2.sh` and `compile_zcu104.sh` have been added to ease the compilation and installation process of the library into the system. They include all possible flavours have been added for each platform. 

**Remove the line what it is not implemented for your case**.

## Demo

### Functionality Demo 

The Demo presented in this repository is working just showing the functionality of the SW API. It will return a ✅ in case the implemented algorithm is working properly or ❌ in other case. Because the demo is general for each flavour (i.e., OpenSSL or MbedTLS) it also return a message in case this specific algorithm is not yet implemented in the repository.

### Demo Speed

This functionality returns the execution time of each part of each algorithm. For the execution, you must follow the same ```make``` rules of Demo section but changing ```demo``` to ```demo-speed```. 
So, for example, it can be: 
```bash
make demo-speed-build-openssl
./demo-speed-build-openssl
```
The results will also show performance in term of Elapsed Time (ET) of each cryptograhic algorithm. 

It is possible to change the behaviour of test with the file ```config.conf```. The variables ```SHA-2```, ```SHA-3```, etc. represent the type of algorithm to be tested. If ```1``` is set the test will be performed, while a ```0``` will point out that this test won't be performed. The variable ```N_TEST``` set the number of test to be performed to calculate the average execution time.  

### Demo NIST ACVP

It is possible to run the ACVP NIST tests for MLDSA (***only*** in v6.2) by running this type of demo. 

### STM32 Cube IDE Demo

In v6.3 it has been added the possibility to compile the ```demo``` and the ```demo_speed``` for the ARM Cortex-M4. 
Now it is possible to use the ```make build-demo-arm``` or the ```make build-demo-speed-arm``` to compile the ```demo_arm``` and the ```demo_speed_arm```. 
There is a list of definitions on the top of these folders that contains the algorithms to be under test.  
It will generate the ```libdemo-static-arm.a``` or the ```libdemo-speed-static-arm.a``` that contain the demo files as well as the CRYPTO-API library. 
In the file ```CUBEIDE-demo.zip``` it is possible to find the project to run the demo. Keep in mind that designer has to add the corresponding compiled libraries and the included folder manually in the CubeIDE project.

### Demo Makefile Overview

The commands of ```make DDD-XXX-YYY``` can be resumed in the next table: 

| DDD           | Meaning   |
| ----------    | --------- |
| demo          | Functionality Demo                                            |
| demo-speed    | Execution Time Demo                                           |
| demo-nist     | ACVP Test (*Only MLDSA*) (only for all-alt)                   |

| XXX            | Meaning   |
| ----------     | --------- |
| all            | Local compilation of the whole CRYPTO_API library                  |
| build          | Use of the local shared libraries in build/ folder                 |
| install        | Use of the *already* installed library in the system local folder  |
| install-static | Use of the *already* installed library in the system local folder (static generated)  |

| YYY           | Meaning   |
| ----------    | --------- |
| openssl       | Using the version of OpenSSL already installed in the system  |
| lib-openssl   | Using the version of OpenSSL installed in a local folder (```OPENSSL_DIR``` from Makefile) |
| mbedtls       | Using the version of MbedTLS installed in a local folder (```MBEDTLS_DIR``` from Makefile) |
| alt           | Using the alternative definition of the algorithms                                         |

For any demo it is possible to type `-v` or `-vv` for different verbose level. For example, `./demo-install -vv`. *We do not recommend that for long test.*  

### Fast Compilation

Files `demo_rasp4b.sh`, `demo_pynqz2.sh` and `demo_zcu104.sh` have been added to ease the demo compilation with all possible flavours for each platform. 

**Remove the line what it is not implemented for your case**.

## Results of Performance

The next section describe the average Execution Time of different platforms and libraries of the cryptography algorithms after ***1000*** tests. This results are shown in the `results` folder.  

| Plattform         | OpenSSL 3                                 | MbedTLS                                   | ALT                                   |
| ----------        | ---------                                 | -------                                   | ---------                             |
| *Raspberry Pi 4B* | [link](results/rasp4b/rasp4b_openssl.txt)    | [link](results/rasp4b/rasp4b_mbedtls.txt)    | [link](results/rasp4b/rasp4b_alt.txt)    |
| *Pynq-Z2*         | [link](results/pynqz2/pynqz2_openssl.txt)    | TBD    | [link](results/pynqz2/pynqz2_alt.txt)    |
| *ZCU-104*         | [link](results/zcu104/zcu104_openssl.txt)    | TBD    | [link](results/zcu104/zcu104_alt.txt)    |

\* _TBD: To Be Done_

## Contact

**Eros Camacho-Ruiz** - (camacho@imse-cnm.csic.es)

_Hardware Cryptography Researcher_ 

_Instituto de Microelectrónica de Sevilla (IMSE-CNM), CSIC, Universidad de Sevilla, Seville, Spain_

## Developers

Eros Camacho-Ruiz

_Hardware Cryptography Researcher_

_Instituto de Microelectrónica de Sevilla (IMSE-CNM), CSIC, Universidad de Sevilla, Seville, Spain_