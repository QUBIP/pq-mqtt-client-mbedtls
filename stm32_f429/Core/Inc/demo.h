
#ifndef DEMO_H
#define DEMO_H

#include "se-qubip.h"

#include "test_func.h"

void demo_mldsa(unsigned int mode, unsigned int verb);

void demo_eddsa_hw(unsigned int mode, unsigned int verb, INTF interface);
void demo_x25519_hw(unsigned int mode, unsigned int verb, INTF interface);
void demo_aes_hw(unsigned int bits, unsigned int verb, INTF interface);
void demo_sha2_hw(unsigned int verb, INTF interface);
void demo_sha3_hw(unsigned int verb, INTF interface);
void demo_trng_hw(unsigned int bits, unsigned verb, INTF interface);
void demo_mlkem_hw(unsigned int mode, unsigned int verb, INTF interface);
void kyber768_kat();
// test - speed
void test_aes_hw(unsigned char mode[4], unsigned int bits, unsigned int n_test, unsigned int verb, time_result* tr_en, time_result* tr_de, INTF interface);
void test_sha3_hw(unsigned int sel, unsigned int n_test, time_result* tr, unsigned int verb, INTF interface);
void test_sha2_hw(unsigned int sel, unsigned int n_test, time_result* tr, unsigned int verb, INTF interface);
void test_eddsa_hw(unsigned int mode, unsigned int n_test, unsigned int verb, time_result* tr_kg, time_result* tr_si, time_result* tr_ve, INTF interface);
void test_x25519_hw(unsigned int mode, unsigned int n_test, unsigned int verb, time_result* tr_kg, time_result* tr_ss, INTF interface);
void test_trng_hw(unsigned int mode, unsigned int bits, unsigned int n_test, time_result* tr, unsigned int verb, INTF interface);
void test_mlkem_hw(unsigned int mode, unsigned int n_test, unsigned int verb, time_result* tr_kg, time_result* tr_en, time_result* tr_de, INTF interface);

// test - acc
void test_aes_acc(unsigned char mode[4], unsigned int bits, unsigned int n_test, unsigned int verb, time_result* tr_en_hw, time_result* tr_de_hw, time_result* tr_en_sw, time_result* tr_de_sw, INTF interface);
void test_sha3_acc(unsigned int sel, unsigned int n_test, time_result* tr_hw, time_result* tr_sw, unsigned int verb, INTF interface);
void test_sha2_acc(unsigned int sel, unsigned int n_test, time_result* tr_hw, time_result* tr_sw, unsigned int verb, INTF interface);
void test_eddsa_acc(unsigned int mode, unsigned int n_test, unsigned int verb, time_result* tr_kg_hw, time_result* tr_si_hw, time_result* tr_ve_hw, time_result* tr_kg_sw, time_result* tr_si_sw, time_result* tr_ve_sw, INTF interface);
void test_x25519_acc(unsigned int mode, unsigned int n_test, unsigned int verb, time_result* tr_kg_hw, time_result* tr_ss_hw, time_result* tr_kg_sw, time_result* tr_ss_sw, INTF interface);
void test_mlkem_acc(unsigned int mode, unsigned int n_test, unsigned int verb, time_result* tr_kg_hw, time_result* tr_en_hw, time_result* tr_de_hw, time_result* tr_kg_sw, time_result* tr_en_sw, time_result* tr_de_sw, INTF interface);
void test_trng_acc(unsigned int mode, unsigned int bits, unsigned int n_test, time_result* tr_hw, time_result* tr_sw, unsigned int verb, INTF interface);

#endif
