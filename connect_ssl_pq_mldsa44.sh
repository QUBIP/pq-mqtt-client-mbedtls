#!/bin/sh
./installs/openssl/bin/openssl s_client -trace -debug -connect broker.dm.qubip.eu:8884 -CAfile certificates/mldsa44/CA_mcu.crt -cert certificates/mldsa44/client_mcu.crt -key certificates/mldsa44/client_mcu.key  -sigalgs mldsa44_ed25519 -groups X25519MLKEM768 -verify 1 -verify_return_error 
