#!/bin/sh
./installs/openssl/bin/openssl s_client -trace -debug -connect localhost:443 -CAfile certificates/classic/ca.crt -cert certificates/classic/client.crt -key certificates/classic/client.key  -verify 1 -verify_return_error 
