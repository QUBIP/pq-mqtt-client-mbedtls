#!/bin/sh
#openssl s_client -trace -debug -connect 185.56.9.94:8884 -CAfile server-ca-chain.pem -cert 175a289907-client-cert.pem -key 175a289907-client.key  -sigalgs mldsa44_ed25519 -groups X25519MLKEM768 -verify 1 -verify_return_error

openssl s_client -trace -debug -connect 185.56.9.94:8884 -CAfile ca-server.pem -partial_chain  -cert client-cert.pem -key client.key  -sigalgs mldsa44_ed25519 -groups X25519MLKEM768 -verify 1 -verify_return_error 
