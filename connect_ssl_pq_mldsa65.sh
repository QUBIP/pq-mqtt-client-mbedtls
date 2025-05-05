#!/bin/sh
./installs/openssl/bin/openssl s_client -trace -connect broker.dm.qubip.eu:8883 -CAfile certificates/mldsa65/CA_mpu.crt -cert certificates/mldsa65/client_mpu.crt -key certificates/mldsa65/client_mpu.key  -sigalgs mldsa65_ed25519 -groups X25519MLKEM768
