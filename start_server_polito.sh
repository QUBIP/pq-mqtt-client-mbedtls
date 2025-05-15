#!/bin/sh
# Launching server on 0.0.0.0 (!!)
sudo ./installs/openssl/bin/openssl s_server  -CAfile certificates/polito/server/server-chain.pem  -cert certificates/polito/server/server.pem -key certificates/polito/server/server.key -groups X25519MLKEM768  -sigalgs mldsa44_ed25519  -accept 0.0.0.0:8884 -trace -verify 1 -verify_return_error
