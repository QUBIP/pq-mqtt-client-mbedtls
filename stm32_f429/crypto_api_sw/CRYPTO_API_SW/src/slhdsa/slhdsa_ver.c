/**
  * @file mldsa_ver.c
  * @brief SLH-DSA Verification code
  *
  * @section License
  *
  * MIT License
  *
  * Copyright (c) 2024 Eros Camacho
  *
  * Permission is hereby granted, free of charge, to any person obtaining a copy
  * of this software and associated documentation files (the "Software"), to deal
  * in the Software without restriction, including without limitation the rights
  * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  * copies of the Software, and to permit persons to whom the Software is
  * furnished to do so, subject to the following conditions:
  *
  * The above copyright notice and this permission notice shall be included in all
  * copies or substantial portions of the Software.
  *
  * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  * SOFTWARE.
  *
  *
  *
  * @author Eros Camacho-Ruiz (camacho@imse-cnm.csic.es)
  * @version 6.0
  **/

#include "slhdsa.h"

void SLHDSA_SHAKE_128_F_VERIFY(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pub_key, const unsigned char* sig, const unsigned int sig_len, unsigned int* result) {
    /*
    // The API caller does not necessarily know what size a signature should be but SPHINCS+ signatures are always exactly SPX_BYTES.
    if (sig_len < SPX_BYTES_SHAKE_128_F) {
        memset(msg, 0, sig_len);
        *msg_len = 0;
        *result = -1;
        return;
    }

    *msg_len = sig_len - SPX_BYTES_SHAKE_128_F;

    if (crypto_sign_verify_shake_128_f(sig, SPX_BYTES_SHAKE_128_F, sig + SPX_BYTES_SHAKE_128_F, *msg_len, pub_key)) {
        memset(msg, 0, sig_len);
        *msg_len = 0;
        *result = -1;
        return;
    }

    // If verification was successful, move the message to the right place. 
    memmove(msg, sig + SPX_BYTES_SHAKE_128_F, *msg_len);

    *result = 0;
    */

    *result = crypto_sign_verify_shake_128_f(sig, sig_len, msg, msg_len, pub_key);


}
void SLHDSA_SHAKE_128_S_VERIFY(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pub_key, const unsigned char* sig, const unsigned int sig_len, unsigned int* result) {
    /*
    // The API caller does not necessarily know what size a signature should be but SPHINCS+ signatures are always exactly SPX_BYTES.
    if (sig_len < SPX_BYTES_SHAKE_128_S) {
        memset(msg, 0, sig_len);
        *msg_len = 0;
        *result = -1;
        return;
    }

    *msg_len = sig_len - SPX_BYTES_SHAKE_128_S;

    if (crypto_sign_verify_shake_128_s(sig, SPX_BYTES_SHAKE_128_S, sig + SPX_BYTES_SHAKE_128_S, *msg_len, pub_key)) {
        memset(msg, 0, sig_len);
        *msg_len = 0;
        *result = -1;
        return;
    }

    // If verification was successful, move the message to the right place.
    memmove(msg, sig + SPX_BYTES_SHAKE_128_S, *msg_len);

    *result = 0;
    * */

    *result = crypto_sign_verify_shake_128_s(sig, sig_len, msg, msg_len, pub_key);

}

void SLHDSA_SHAKE_192_F_VERIFY(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pub_key, const unsigned char* sig, const unsigned int sig_len, unsigned int* result) {

    *result = crypto_sign_verify_shake_192_f(sig, sig_len, msg, msg_len, pub_key);

}
void SLHDSA_SHAKE_192_S_VERIFY(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pub_key, const unsigned char* sig, const unsigned int sig_len, unsigned int* result) {
    
    *result = crypto_sign_verify_shake_192_s(sig, sig_len, msg, msg_len, pub_key);

}

void SLHDSA_SHAKE_256_F_VERIFY(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pub_key, const unsigned char* sig, const unsigned int sig_len, unsigned int* result) {

    *result = crypto_sign_verify_shake_256_f(sig, sig_len, msg, msg_len, pub_key);

}
void SLHDSA_SHAKE_256_S_VERIFY(const unsigned char* msg, const unsigned int msg_len, const unsigned char* pub_key, const unsigned char* sig, const unsigned int sig_len, unsigned int* result) {
    
    *result = crypto_sign_verify_shake_256_s(sig, sig_len, msg, msg_len, pub_key);

}