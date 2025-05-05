#!/bin/sh
# Launching server on 0.0.0.0 (!!)
sudo ./installs/openssl/bin/openssl s_server  -CAfile certificates/testing_new/server/server-chain.pem  -cert certificates/testing_new/server/server.pem -key certificates/testing_new/server/server.key -groups X25519MLKEM768  -sigalgs mldsa44_ed25519  -accept 0.0.0.0:8884 -trace -verify 1 -verify_return_error

# --cert_chain certificates/polito/int-ca.pem
#
#certificates/polito/int-ca.pem