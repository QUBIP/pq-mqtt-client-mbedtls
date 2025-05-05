#!/bin/sh
./installs/openssl/bin/openssl s_client -trace -connect localhost:8884  -CAfile certificates/testing_new/root-ca.pem -cert certificates/testing_new/client/client.pem -key certificates/testing_new/client/client.key  -sigalgs mldsa44_ed25519 -groups X25519MLKEM768  -verify 1 -verify_return_error -servername broker.dm.qubip.eu
