#!/bin/sh
# Launching server on 0.0.0.0 (!!)
sudo ./installs/openssl/bin/openssl s_server -cert certificates/mldsa65/server_mpu.crt -groups X25519MLKEM768  -sigalgs mldsa65_ed25519 -CAfile certificates/mldsa65/CA_mpu.crt -key certificates/mldsa65/server_mpu.key -accept 0.0.0.0:8883 -trace -verify 1 -verify_return_error
