////////////////////////////////////////////////////////////////////////////////////
// Company: IMSE-CNM CSIC
// Description: Host-side implementation of SCP-03 Key Derivation Function
////////////////////////////////////////////////////////////////////////////////////

#ifndef SCP03_KDF_H
#define SCP03_KDF_H

#include "../aes/aes.h" // Your provided AES header

#ifdef __cplusplus
extern "C" {
#endif

// Key Length Constants
#define AES_128_BITS            128
#define AES_192_BITS            192
#define AES_256_BITS            256

// Derivation Constants
#define SCP03_CONST_CARD_CRYPT  0x00
#define SCP03_CONST_HOST_CRYPT  0x01
#define SCP03_CONST_ENC         0x04
#define SCP03_CONST_MAC         0x06
#define SCP03_CONST_RMAC        0x07

/**
 * @brief Generates all three session keys (S-ENC, S-MAC, S-RMAC)
 * 
 * @param key_bits        128, 192, or 256
 * @param static_enc_key  Pointer to Static K-ENC key
 * @param static_mac_key  Pointer to Static K-MAC key
 * @param host_challenge  Pointer to 8-byte Host Challenge
 * @param card_challenge  Pointer to 8-byte Card Challenge
 * @param session_enc     Output buffer for Session S-ENC (Must be key_bits/8 bytes)
 * @param session_mac     Output buffer for Session S-MAC
 * @param session_rmac    Output buffer for Session S-RMAC
 */
void scp03_derive_session_keys(int key_bits,
                               unsigned char* static_enc_key,
                               unsigned char* static_mac_key,
                               unsigned char* host_challenge,
                               unsigned char* card_challenge,
                               unsigned char* session_enc,
                               unsigned char* session_mac,
                               unsigned char* session_rmac);



/**
 * @brief Generates Authentication Cryptograms using the Session MAC Key
 * @param s_mac          Pointer to the derived S-MAC session key
 * @param host_challenge Pointer to 8-byte Host Challenge
 * @param card_challenge Pointer to 8-byte Card Challenge
 * @param card_crypt     Output: 8-byte Card Cryptogram
 * @param host_crypt     Output: 8-byte Host Cryptogram
 */
void scp03_calc_cryptograms(int key_bits,
                            unsigned char* s_mac,
                            unsigned char* host_challenge,
                            unsigned char* card_challenge,
                            unsigned char* card_crypt,
                            unsigned char* host_crypt);

#ifdef __cplusplus
}
#endif

#endif // SCP03_KDF_H
