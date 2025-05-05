#!/bin/sh
# Launching server on 0.0.0.0 (!!)
sudo ./installs/openssl/bin/openssl s_server -cert certificates/mldsa44/server_mcu.crt -groups X25519MLKEM768  -sigalgs mldsa44_ed25519 -CAfile certificates/mldsa44/CA_mcu.crt -key certificates/mldsa44/server_mcu.key -accept 0.0.0.0:8884 -trace -verify 1 -verify_return_error
