export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/xilinx/crypto_api_sw/CRYPTO_API_SW/build
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/xilinx/openssl/
make demo-all-lib-openssl
make demo-all-alt
make demo-build-lib-openssl
make demo-build-alt
make demo-install-lib-openssl
make demo-install-alt
make demo-speed-all-lib-openssl
make demo-speed-all-alt
make demo-speed-build-lib-openssl
make demo-speed-build-alt
make demo-speed-install-lib-openssl
make demo-speed-install-alt
./demo-all-lib-openssl
./demo-all-alt
./demo-build-lib-openssl
./demo-build-alt
./demo-install-lib-openssl
./demo-install-alt 
./demo-speed-all-lib-openssl
./demo-speed-all-alt
./demo-speed-build-lib-openssl
./demo-speed-build-alt
./demo-speed-install-lib-openssl
./demo-speed-install-alt
