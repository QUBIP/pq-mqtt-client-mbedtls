#ifndef __BIGNUM_H__
#define __BIGNUM_H__

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "../../trng/trng.h"

typedef int64_t integer;
/* B is the base of the bignum system, it has to be an exponention of 2 */
#define BASE 256
#define EXP_RSA 8      // B = 2^E, E = 1, 2, ..., 31
#define MASK 0xff


// This is the security parameter t in fermats test
#define TEST_CNT 10

#define NUMBER_FORMAT_ERROR "invalid input (input should only be numbers)"
#define NUMBER_FORMAT_ERROR_1 "invalid number (number should range between 1...9)"

/*
 * This structure is used to store a bignum.
 * sign: If sign of a number is -ve then this sign is stored as -1 and if
 * 		 bignum is +ve then the sign is stored as +1
 * size: If is the size of the array tab
 * tab : This array is used to store the bignum
 * */

typedef struct {
	int sign;
	int size;
	integer *tab;
} bignum;


bignum str2bignum(char * str);
bignum add(bignum a, bignum b);
bignum sub(bignum a, bignum b);
bignum mult(bignum a, bignum b);
bignum reminder(bignum a, bignum n);
bignum addmod(bignum a, bignum b, bignum n);
bignum multmod(bignum a, bignum b, bignum n);
bignum expmod(bignum a, bignum b, bignum n);
int fermat(bignum a,int t);
bignum genrandom(int len);
bignum genrandomprime(int len);


// other utility functions

int length(bignum a);
bignum digit2bignum(int d);
void printbignum(bignum a);
int iszero(bignum a);
int isone(bignum a);
int isnormalized(bignum a);
int compare(bignum a, bignum b);
void copy(bignum *dest, bignum src);
bignum leftshift(bignum a, int k);
bignum rightshift(bignum a, int k);
bignum inverse(bignum a, bignum n);
bignum gcd(bignum a, bignum b);
bignum divi(bignum a, bignum n);
bignum * normalized_divi(bignum a, bignum b);


// Test methods
void testStr2bignum();
void testAddition();
void testSubtraction();
void testMultiplication();
void testRemainder();
void testAdditionModulus();
void testMultiplicationModulus();
void testExponentialModulus();
void testFermat();
void testGenerateRandom();
void testGenerateRandomPrime();

#endif
