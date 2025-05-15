#include "bignum.h"

// https://github.com/venkateshwarant/BigNum-RSA/tree/main

/*
 * This method converts a string bignum to the bignum variable.
 * Example usage str2bignum("12345678901234")
 * If the base B is 16 then the above number corresponds to the hex
 * value of 0xb3a73ce2ff2
 *
 * */
bignum str2bignum(char * str){
    int i, j;
    bignum b[11],bignum_primitives[11], output;
    // We will initialise 0...9 as bignums and store it as array of bignums
    i=0;
    while(i < 10){
    	bignum_primitives[i] = digit2bignum(i);
    	i++;
    }
    // initialize bignum 10
    bignum_primitives[10].tab = (integer *)malloc(sizeof(integer) * 4);
    bignum_primitives[10].sign = 1;

    if (BASE < 10) {
    	// We initialise the primitive bignum only when the base is less than 10, else the base
    	// primitive number array size would be very large, thus decreasing the code performance.
    	i = 0;
    	        int int_ten = 10;
    	        bignum_primitives[10].size = 1;
    	        while (int_ten >= BASE) {
    	        	bignum_primitives[10].size++;
    	        	bignum_primitives[10].tab[i++] = int_ten % BASE;
    	        	int_ten /= BASE;
    	        }
    	        bignum_primitives[10].tab[i] = int_ten;
    } else {
    	bignum_primitives[10].tab[0] = 10;
    	bignum_primitives[10].size = 1;
    }

    j = 0;
    output.sign = 1;
    output.size = 1;
    output.tab = (integer *)malloc(sizeof(integer));
    output.tab[0] = 0;
    if (str[0] == '-') {
        j = 1;
    }
    integer *temp;
    temp = output.tab;
    output = add(output, bignum_primitives[str[j++]-'0']);
    free(temp);
    for (i = j; i < strlen(str); i++) {
        int digit = str[i] - '0';
        if (digit < 0 || digit > 9) {
            perror(NUMBER_FORMAT_ERROR);
            exit(0);
        }

        temp = output.tab;
        output = mult(output, bignum_primitives[10]);
        free(temp);

        temp = output.tab;
        output = add(output, bignum_primitives[str[i]-'0']);
        free(temp);
    }
    // If the sign of the string number is -ve, we set the sign int as -1
    if (str[0] == '-')
    	output.sign = -1;

    for (i = 0; i <= 10; i++) {
        free(bignum_primitives[i].tab);
        bignum_primitives[i].tab = NULL;
    }
    return output;
}

/*
 * Returns the sum of the two input bignums.
 * */
bignum add(bignum a, bignum b){
	if (a.sign == 1 && b.sign == -1) {
	    	// else if b input is negative we return a-b
	    	b.sign = 1;
	        return sub(a, b);
	}else if (a.sign == -1 && b.sign == 1) {
	    	// if a is negative we return b-a
	    	a.sign = 1;
	        return sub(b, a);
	}else if (b.size > a.size){
		return add(b, a);
	}

    bignum sum;
    sum.sign = a.sign;
    sum.size = a.size;
    sum.tab = (integer *)malloc((a.size + 1) * sizeof(integer));

    //
    int i;
    integer  tmp;
    integer carry = 0;
    for (i  = 0; i < b.size; i++) {
        tmp = a.tab[i] + b.tab[i] + carry;
        sum.tab[i] = tmp % BASE;
        carry = tmp / BASE;
    }
    for (; i < a.size; i++) {
        tmp = a.tab[i] + carry;
        carry = tmp / BASE;
        sum.tab[i] = tmp % BASE;
    }

    sum.tab[i] = carry;
    if (carry)
        sum.size++;

    return sum;
}

/*
 * Returns (a-b)
 * */
bignum sub(bignum a, bignum b){
    bignum difference;

    if (a.sign == 1 && b.sign == -1) {// Since a-(-b) = a+b
        b.sign = 1;
        return add(a, b);
    } else if (a.sign == -1 && b.sign == 1) {// Since -a-b= -(a+b)
        b.sign = -1;
        return add(a, b);
    }else if (a.sign == -1 && b.sign == -1) {// Since -a-(-b)= b-a
        a.sign = 1;
        b.sign = 1;
        return sub(b, a);
    }
    if (b.size > a.size) {// if b>a then a-b= -(b-a)
    	difference = sub(b, a);
    	difference.sign = -1;
        return difference;
    }
    int i;
    integer carry, temp;
    if (a.size == b.size) {
        for (i = a.size-1; (i >=0) && (a.tab[i] == b.tab[i]); i--);// i will be -1, if both a and b are exactly same bignum
        if (i == -1) {
        	difference.sign = 1;
        	difference.size = 1;
        	difference.tab = (integer *)malloc(sizeof(integer));
        	difference.tab[0] = 0;
            return difference;
        }

        difference.size = i + 1;
        difference.tab = (integer *)malloc(difference.size * sizeof(integer));
        carry = 0;
        int j;
        if (a.tab[i] > b.tab[i]) {// If a particular element of an array of the bignum "a" is larger than the bignum "b", we perform subtraction till this larger number in the array and put the difference sign as +ve else -ve
        	difference.sign = 1;
            for (j = 0; j <= i; j++) {
            	temp = a.tab[j] - b.tab[j] + carry;
                carry = (temp < 0) ? -1 : 0;
                difference.tab[j] = (temp + BASE) % BASE;
            }
        } else {// It will enter here only if a>b, other cases are covered before. If so, we set the sign of the difference as the sign of a and follow the classic algorithm
        	difference.sign = -1;
            for (j = 0; j <= i; j++) {
            	temp = b.tab[j] - a.tab[j] + carry;
                carry = (temp < 0) ? -1 : 0;
                difference.tab[j] = (temp + BASE) % BASE;
            }
        }
    } else {
    	difference.sign = a.sign;
    	difference.size = a.size;
    	difference.tab = (integer *)malloc((difference.size)*sizeof(integer));
        carry = 0;
        for (i = 0; i < b.size; i++) {
        	temp = a.tab[i] - b.tab[i] + carry;
            carry = (temp < 0) ? -1 : 0;
            difference.tab[i] = (temp + BASE) % BASE;
        }

        for (; i < a.size; i++) {
        	temp = a.tab[i] + carry;
            carry = (temp < 0) ? -1 : 0;
            difference.tab[i] = (temp + BASE) % BASE;
        }
    }
    for (i = difference.size-1; difference.tab[i] == 0; i--);
    difference.size = i + 1;// We update the size of the difference with the size of difference.tab array
    return difference;
}
/*
 * Returns the product of inputs a and b
 * */
bignum mult(bignum a, bignum b){
    bignum product;

    if (iszero(a) || iszero(b)) {// product is zero if any of its input is zero
    	product.tab = (integer *)malloc(product.size * sizeof(integer));
    	product.tab[0] = 0;
    	product.sign = 1;
    	product.size = 1;
        return product;
    }

    if (b.size > a.size) //If b>a, we swap the values of a and b
         return mult(b, a);

    product.sign = a.sign * b.sign;
    product.size = a.size + b.size;
    product.tab = (integer *)malloc((product.size)*sizeof(integer));
    int i;
    for (i = 0; i < product.size; i++)
    	product.tab[i] = 0;
    integer carry;
    for (i = 0; i < b.size; i++) {//Classical bignum multiplication algorithm
        carry = 0;
        int j;
        integer tmp;
        for (j = 0; j < a.size; j++) {
            tmp = b.tab[i] * a.tab[j] + product.tab[i+j] + carry;
            carry = tmp / BASE;
            product.tab[i+j] = tmp % BASE;
        }
        product.tab[i+a.size] = carry;
    }

    for (i = product.size-1; product.tab[i] == 0; i--);
    product.size = i + 1;
    return product;
}

/*
 *  This method divides a by n and returns the remainder.
 *	We have not implemented the algorithm given in slide, rather we followed the algorithm given in reference.(With an exponent)
 *	We have implemented so because, it computes remainder in linear time scale.
 * */
bignum reminder(bignum a, bignum n){
    int isEqual;
    bignum remainder;
    isEqual = compare(a, n);
    if (isEqual == 0) {// return 0 if both a and n are same
    	remainder.tab = (integer *)malloc(sizeof(integer));
    	remainder.tab[0] = 0;
    	remainder.size = 1;
    	remainder.sign = 1;
        return remainder;
    }else if (isEqual == -1) {// isEqual is -1 when a<n, so we return a as reminder in this case
        copy(&remainder, a);
        return remainder;
    }

    bignum *temp_quorem;
    if (isnormalized(n)) {// If n is normalised then we perform normalised division and return the intermediate quorem as remainder
    	temp_quorem = normalized_divi(a, n);
        remainder = temp_quorem[1];
        free(temp_quorem[0].tab);
        free(temp_quorem);
        return remainder;
    }
    int i;
    for (i = E-1; i >= 0; i--)// E is the log2(Base), for hexadecimal value, E is 4.
        if ((n.tab[n.size-1] >> i) & 0x1)
            break;
    bignum lshifted_a, lshifted_n, lshifted_r;
    lshifted_a = leftshift(a, E-i-1);
    lshifted_n = leftshift(n, E-i-1);
    temp_quorem = normalized_divi(lshifted_a, lshifted_n);
    lshifted_r = temp_quorem[1];
    remainder = rightshift(lshifted_r, E-i-1);

    free(lshifted_a.tab);
    free(lshifted_n.tab);
    free(lshifted_r.tab);
    free(temp_quorem[0].tab);
    free(temp_quorem);

    return remainder;
}

/*
 * Returns (a + b) mod n
 * */
bignum addmod(bignum a, bignum b, bignum n){
    bignum sum = add(a, b);
    bignum output = reminder(sum, n);// we find remainder using the linear time algorithm
    sum.tab = NULL;
    free(sum.tab);
    return output;
}

/*
 * Returns ( a * b ) mod n
 * */
bignum multmod(bignum a, bignum b, bignum n){
    bignum prd = mult(a, b);
    bignum res = reminder(prd, n);
    prd.tab = NULL;
    free(prd.tab);
    return res;
}

/*
 * Returns (a^b) mod n
 * */
bignum expmod(bignum a, bignum b, bignum n){
    integer *t;
    int start;
    start = length(b) % E;
    if (start == 0) // if length of b is divisible by E, we take start as E.
        start = E;
    int j;
    bignum result = reminder(a, n); // We first start with a mod n
    for (j = start-2; j >= 0; j--) {
        t = result.tab;
        result = multmod(result, result, n); // Then we square the mod result
        free(t);
        if (((b.tab[b.size-1] >> j) & 0x1) == 1) { // We right shift the last part of b j times and check if the right-most-bit. if so result is result*a mod n
            t = result.tab;
            result = multmod(result, a, n);
            free(t);
        }
    }
    int i;
    for(i = b.size-2; i >= 0; i--){
        for(j = E-1; j >= 0; j--){
            t = result.tab;
            result = multmod(result, result, n);
            free(t);
            if (((b.tab[i] >> j) & 0x1) == 1){
                t = result.tab;
                result = multmod(result, a, n);
                free(t);
            }
        }
    }
    return result;
}

/*
 * Returns 0 if a is composite and returns 1 if a is prime
 * This performs fermats test to check the primality of "a"
 * */
int fermat(bignum a, int t){
    int i;
	for(i=0; i<t; i++){
		bignum n;
		while(1){
			n= genrandom(length(a)-1);// Random number between 2 to a-2
			if((compare(n,sub(a,digit2bignum(2))) == -1)&& (compare(n,digit2bignum(2)) == 1)){ //check if 2 < n < (a-2)
				break;
			}
		}
		bignum r= expmod(n, sub(a,digit2bignum(1)), a);
		if(compare(r, digit2bignum(1)) != 0){ // if r = 1, then n is composite
			return 0;
		}
	}
	return 1; // if r!=1 for t runs, then n is prime
}

/*
 * Returns a positive random number of given length
 * */
bignum genrandom(int length){
    bignum output;
    if (length == 0) {// if length is 0, we always return 0
    	output.sign = 1;
    	output.size = 1;
    	output.tab = (integer *)malloc(sizeof(integer));
    	output.tab[0] = 0;
        return output;
    }
    output.size = length / E;
    output.sign = 1;// we always return +ve random number
    if (length % E != 0)
    	output.size++; // we fix the size of tab to be |length/E| + length%E
    output.tab = (integer *)malloc(sizeof(integer)*output.size);
    int i;

    for (i = 0; (i+1) * E < length; i++) {
    	output.tab[i] = rand() % BASE; //we fill the tab array with random integers of given base
    }
    int n;
    n = length - i*E;
    output.tab[i] = rand() % BASE;
    output.tab[i] |= ((integer)0x1 << (n-1));
    int j;
    for (j = n; j < E; j++)
    	output.tab[i] &= ~((integer)0x1 << j);

    return output;
}

/*
 * Returns a positive random number of given length
 * */
bignum genrandom_prev(int length) {
    bignum output;
    if (length == 0) {// if length is 0, we always return 0
        output.sign = 1;
        output.size = 1;
        output.tab = (integer*)malloc(sizeof(integer));
        output.tab[0] = 0;
        return output;
    }
    output.size = length / E;
    output.sign = 1;// we always return +ve random number
    if (length % E != 0)
        output.size++; // we fix the size of tab to be |length/E| + length%E
    output.tab = (integer*)malloc(sizeof(integer) * output.size);
    int i;
    for (i = 0; (i + 1) * E < length; i++) {
        output.tab[i] = rand() % BASE; //we fill the tab array with random integers of given base
    }
    int n;
    n = length - i * E;
    output.tab[i] = ((integer)rand()) % BASE;
    output.tab[i] |= ((integer)0x1 << (n - 1));
    int j;
    for (j = n; j < E; j++)
        output.tab[i] &= ~((integer)0x1 << j);

    return output;
}
/*
 * Returns a positive random prime number
 * Uses fermats test to check for primality
 * */
bignum genrandomprime(int length){
    bignum p = genrandom(length);
    while (!fermat(p, TEST_CNT)) { //1 -
        free(p.tab);
        p.tab = NULL;
        p = genrandom(length);
    }

    return p;
}
/*
 * This method prints the value of the input bignum
 * For E.g. The
 * */
void printbignum(bignum num){
    int i;
    if (B != 16) {
    	i = num.size-1;
    	while(i >= 0){
            printf("[%3d] - %lu\n", i, num.tab[i]);
    		i--;
    	}
        printf("Base = %ld, %s\n", BASE, num.sign==1?"+ve":"-ve");
    } else {
    	// Hexadecimal value, since base is 16
        if (num.sign == -1) printf("-");
        printf("0x");
        i = num.size-1;
        while(i >= 0){
            printf("%x", num.tab[i]);
            i--;
        }
        printf("\n");
    }
}

/*
 * This method prints the value of the input bignum
 * For E.g. The
 * */
void bignum_to_string(bignum num, unsigned char* str) {
    int i;
        // Hexadecimal value, since base is 16
        if (num.sign == -1) printf("-");
        printf("0x");
        i = num.size - 1;
        while (i >= 0) {
            printf("%x", num.tab[i]);
            i--;
        }
        printf("\n");
}

/*
 * This is a utility method to convert a single digit int to a bignum variable
 */
bignum digit2bignum(int digit){
    if (digit < 0 || digit > 9) {
        perror(NUMBER_FORMAT_ERROR_1);
        exit(1);
    }

    bignum output;
    int i = 0;

    output.sign = 1;
    output.tab = (integer *)malloc(sizeof(integer) * 4);
    output.size = 1;
    while (digit >= BASE) {
    	output.tab[i++] = digit % BASE;
        digit /= BASE;
    	output.size++;
    }
    output.tab[i] = digit;

    return output;
}

// ************************************************************* Other Utility functions *******************************************************

/*
 * Copies bignum from source to destination
 * */
void copy(bignum *destination, bignum source){
    if (destination == &source) // If address of both are same, do nothing
        return;
    *destination = source;
    destination->tab = (integer *)malloc(destination->size * sizeof(integer));
    memcpy(destination->tab, source.tab, destination->size*sizeof(integer));
}

/*
 * Returns 1 if a is 0 and returns 0 if a!=0
 * */
int iszero(bignum a){
    return (a.size == 1) && (a.tab[0] == 0);
}

/*
 * Returns 1 if a is 1 and returns 0 if a!=1
 * */
int isone(bignum a){
    return (a.size == 1) && (a.sign == 1) && (a.tab[0] == 1);
}

/*
 * This method is used to compare two bignum a and b
 * Returns  1: if a > b
 * Returns  0: if a = b
 * Returns -1: if a < b
 */
int compare(bignum a, bignum b){
    if (a.sign == -1 && b.sign == 1) // If a is -ve and b is +ve, then return -1 (implies a is smaller than b)
        return -1;
    if (a.sign == 1 && b.sign == -1) // If a is +ve and b is -ve, then return 1 (implies b is smaller than a)
        return 1;

    if (a.sign == -1 && b.sign == -1) {// If both a and b are -ve, then inverse the sign of both and call same method with this inverted value
        a.sign = b.sign = 1;
        return compare(b, a);
    }

    if (a.size < b.size)
        return -1;
    if (a.size > b.size)
        return 1;

    int i; // it reaches here only if size of a and b are same
    for (i = a.size - 1; i >= 0; i--) // If so, we compare from the most significant digit
        if (a.tab[i] < b.tab[i])
            return -1;
        else if (a.tab[i] > b.tab[i])
            return 1;

    return 0;
}


/*
 * Leftshifts a by k index and returns the output
 * */
bignum leftshift(bignum a, int k){
    int i, len = length(a)+k;

    bignum res;
    res.sign = 1;
    res.size = (len/E) + ((len%E == 0) ? 0 : 1);
    res.tab = (integer *)malloc((res.size) * sizeof(integer));

    int m = k/E, n = k%E;
    for (i = 0; i < m; i++)
        res.tab[i] = 0;
    if (n == 0) 
        for (i = m; i < res.size; i++)
            res.tab[i] = a.tab[i-m];
    else {
        res.tab[m] = (((a.tab[0] << n) & (integer)MASK));
        for (i = m+1; i < res.size-1; i++) {
            res.tab[i] = a.tab[i-m-1] >> (E-n);
            res.tab[i] |= (((a.tab[i-m] << n) & (integer)MASK));
        }
        res.tab[i] = a.tab[i-m-1] >> (E-n);
        if (i-m < a.size)
            res.tab[i] |= (((a.tab[i-m] << n) & (integer)MASK));
    }

    return res;
}
/*
 * Rightshifts a by k index and returns the output
 * */
bignum rightshift(bignum a, int k){
    int i, len = length(a)-k;

    bignum res;
    res.sign = 1;

    if (len <= 0) {
        res.size = 1;
        res.tab = (integer *)malloc(sizeof(integer));
        res.tab[0] = 0;

        return res;
    } 
    
    res.size = (len/E) + ((len%E == 0) ? 0 : 1);
    res.tab = (integer *)malloc((res.size) * sizeof(integer));
    
    int m = k/E, n = k%E;
    if (n == 0) {
        for (i = 0; i < res.size; i++)
            res.tab[i] = a.tab[i+m];
    } else {
        for (i = 0; i < res.size-1; i++) {
            res.tab[i] = a.tab[i+m] >> n;
            res.tab[i] |= ((a.tab[i+m+1] << (E-n)) & MASK);
        }
        res.tab[i] = a.tab[i+m] >> n;
        if (i+m+1 < a.size)
            res.tab[i] |= ((a.tab[i+m+1] << (E-n)) & MASK);
    }

    return res;
}



/*
 * Performs bignum division and returns a/n
 * */
bignum divi(bignum a, bignum n){
    int comp;
    bignum output;

    comp = compare(a, n);
    if (comp == -1) { // if a<n, return 0
    	output.sign = output.size = 1;
    	output.tab = (integer *)malloc(sizeof(integer));
    	output.tab[0] = 0;
        return output;
    }
    if (comp == 0) {// if a==n, return 1
    	output.sign = output.size = 1;
        output.tab = (integer *)malloc(sizeof(integer));
        output.tab[0] = 1;
        return output;
    }
    bignum  *temp_quorem;;

    if (isnormalized(n)) {// if n is normalised, then we perform normalised division (a/n) and return quorem
    	temp_quorem = normalized_divi(a, n);
        output = temp_quorem[0];
        free(temp_quorem[1].tab);
        free(temp_quorem);

        return output;
    }
    int i;
    for (i = E-1; i >= 0; i--)
        if ((n.tab[n.size-1] >> i) & 0x1)
            break;
    bignum leftshifted_a, leftshifted_n;
    leftshifted_a = leftshift(a, E-i-1);
    leftshifted_n = leftshift(n, E-i-1);
    temp_quorem = normalized_divi(leftshifted_a, leftshifted_n);
    output = temp_quorem[0];

    free(temp_quorem[1].tab);
    free(temp_quorem);
    free(leftshifted_a.tab);
    free(leftshifted_n.tab);
    return output;
}

/*
 * Returns the length of bignum a
 * */
int length(bignum a){
    int length = a.size * E;
    integer n = a.tab[a.size-1];
    int i;
    for (i = E-1; i > 0; i--)
        if (((n >> i) & 0x1) == 0)
        	length--;
        else
            break;
    return length;
}
/*
 * Returns inverse of a mod n
 * */
bignum inverse(bignum a, bignum n){
    bignum r[2], v[2], q;

    r[0] = reminder(n, a);
    copy(&r[1], a);
    q = divi(n, a);
    
    v[1] = digit2bignum(1);

    copy(&v[0], q);
    free(q.tab);
    if (!iszero(v[0]))
        v[0].sign *= -1;

    integer *t;

    bignum tmp0, tmp1;
    int mark = 0, mark1 = 1;
    while (!iszero(r[mark])) {
        mark ^= 1;
        mark1 ^= 1;

        q = divi(r[mark], r[mark1]);

        t = r[mark].tab;
        r[mark] = reminder(r[mark], r[mark1]); 
        free(t);

        tmp0 = mult(q, v[mark1]);
        tmp1 = sub(v[mark], tmp0);

        free(v[mark].tab);
        v[mark] = reminder(tmp1, n);

        free(q.tab);
        free(tmp0.tab);
        free(tmp1.tab);
    }

    tmp0 = add(v[mark^1], n);
    bignum output = reminder(tmp0, n);

    free(tmp0.tab);
    free(v[0].tab);
    free(v[1].tab);
    free(r[0].tab);
    free(r[1].tab);

    return output;
}

/*
 * Returns GCD of two bignums a and b
 * */
bignum gcd(bignum a, bignum b){
    bignum output;
    output.sign = 1;

    if (iszero(b)) { // if b==0, then gcd(a,b)=a
    	output.tab = (integer *)malloc((output.size) * sizeof(integer));
        copy(&output, a);
        return output;
    }
    if (iszero(a)) {// if a==0, then gcd(a,b)=b
    	output.tab = (integer *)malloc((output.size) * sizeof(integer));
        copy(&output, b);
        return output;
    }
    bignum tmp;

    if (compare(a, b)) {//if a!=b, we
        tmp = reminder(a, b);
        output = gcd(b, tmp);
        free(tmp.tab);
        return output;
    } else {
        tmp = reminder(b, a);
        output = gcd(a, tmp);
        free(tmp.tab);
        return output;
    }
}

/*
 * A bignum is normalised when its MSB is 1
 */
int isnormalized(bignum a){
    if (a.sign == -1)
        return 0;
    return  0x1 & (a.tab[a.size-1] >> (E-1));
}

// We can perform normalised division only if a > b > 0, and b is normalized;
/*
 * Returns an array, with quotient as first element and remainder as second element
 * */
bignum * normalized_divi(bignum a, bignum b){
    bignum r, remainder;

    remainder.sign = 1;
    remainder.size = a.size;
    remainder.tab = (integer *)malloc(sizeof(integer)*(remainder.size+1));

    int i,k = a.size;
    for (i = 0; i < k; i++)
    	remainder.tab[i] = a.tab[i];
    remainder.tab[k] = 0;
    int l = b.size;
    bignum quotient;
    quotient.sign = 1;
    quotient.size = k - l + 1;
    quotient.tab = (integer *)malloc(sizeof(integer)*quotient.size);
    integer temp;
    for (i = k-l; i >= 0; i--){
    	quotient.tab[i] = (remainder.tab[i+l]*B + remainder.tab[i+l-1]) / b.tab[l-1];
        if (quotient.tab[i] >= BASE)
        	quotient.tab[i] = BASE-1;

        int carry = 0;
        int j;
        for (j = 0; j < l; j++) {
        	temp = remainder.tab[i+j] - quotient.tab[i]*b.tab[j] + carry;
            carry = temp / BASE;
            remainder.tab[i+j] = temp % BASE;
            if (temp < 0 && remainder.tab[i+j] != 0) {
                carry -= 1;
                remainder.tab[i+j] = remainder.tab[i+j] + BASE;
            }
        }
        remainder.tab[i+l] += carry;

        while (remainder.tab[i+l] < 0) {
            carry = 0;
            for (j = 0; j < l; j++) {
            	temp = remainder.tab[i+j] + b.tab[j] + carry;
                carry = temp / BASE;
                remainder.tab[i+j] = temp % BASE;
            }
            remainder.tab[i+l] += carry;
            quotient.tab[i]--;
        }
    }

    for (i = k-l; i >= 1 && quotient.tab[i] == 0; i--);
    quotient.size = i+1;
    for (i = l-1; i >= 1 && remainder.tab[i] == 0; i--);
    remainder.size = i+1;

    bignum * output = (bignum *)malloc(sizeof(bignum)*2);
    output[0] = quotient;
    output[1] = remainder;
    return output;
}

void testStr2bignum(){
    printf("\n*************************** Test string to bignum and print bignum - Start ***************************");
    char strNum[]="12345678901234";
    bignum a= str2bignum(strNum);
    printf("\nstring a :\n %s", strNum);
    printf("\nbignum a :\n");
    printbignum(a);
    printf("*************************** Test string to bignum and print bignum  -  End  ***************************\n");
}

void testAddition(){
    printf("\n*************************** Test Addition - Start ***************************\n");
    bignum a= str2bignum("12345678901234");
    bignum b= str2bignum("1");
    bignum output= add(a,b);
    printf("a :\n");
    printbignum(a);
    printf("\nb :\n");
    printbignum(b);
    printf("\n(a+b) :\n");
    printbignum(output);
    printf("*************************** Test Addition -  End  ***************************\n");
}

void testSubtraction(){
    printf("\n*************************** Test Subtraction - Start ***************************\n");
    bignum a= str2bignum("12345678901234");
    bignum b= str2bignum("1");
    bignum output= sub(a,b);
    printf("a :\n");
    printbignum(a);
    printf("\nb :\n");
    printbignum(b);
    printf("\n(a-b) :\n");
    printbignum(output);
    printf("*************************** Test Subtraction -  End  ***************************\n");
}

void testMultiplication(){
    printf("\n*************************** Test Multiplication - Start ***************************\n");
    bignum a= str2bignum("12345678901234");
    bignum b= str2bignum("16");
    bignum output= mult(a,b);
    printf("a :\n");
    printbignum(a);
    printf("\nb :\n");
    printbignum(b);
    printf("\n(a*b) :\n");
    printbignum(output);
    printf("*************************** Test Multiplication -  End  ***************************\n");
}

void testRemainder(){
    printf("\n*************************** Test Remainder - Start ***************************\n");
    bignum a= str2bignum("12345678901234");
    bignum n= str2bignum("16");
    bignum output= reminder(a,n);
    printf("a :\n");
    printbignum(a);
    printf("\nn :\n");
    printbignum(n);
    printf("\nremainder(a,n) :\n");
    printbignum(output);
    printf("*************************** Test Remainder -  End  ***************************\n");
}

void testAdditionModulus(){
    printf("\n*************************** Test Addition Modulus - Start ***************************\n");
    bignum a= str2bignum("12345678901234");
    bignum b= str2bignum("1");
    bignum n= str2bignum("16");

    bignum output= addmod(a, b, n);
    printf("a :\n");
    printbignum(a);
    printf("\nb :\n");
    printbignum(b);
    printf("\nn :\n");
    printbignum(n);
    printf("\n(a+b) mod n :\n");
    printbignum(output);
    printf("*************************** Test Addition Modulus -  End  ***************************\n");
}

void testMultiplicationModulus(){
    printf("\n*************************** Test Multiplication Modulus - Start ***************************\n");
    bignum a= str2bignum("12345678901234");
    bignum b= str2bignum("16");
    bignum n= str2bignum("16");

    bignum output= multmod(a, b, n);
    printf("a :\n");
    printbignum(a);
    printf("\nb :\n");
    printbignum(b);
    printf("\nn :\n");
    printbignum(n);
    printf("\n(a*b) mod n :\n");
    printbignum(output);
    printf("*************************** Test Addition Modulus -  End  ***************************\n");
}
void testExponentialModulus(){
    printf("\n*************************** Test Exponential Modulus - Start ***************************\n");
    bignum a= str2bignum("12345678901234");
    bignum b= str2bignum("16");
    bignum n= str2bignum("16");

    bignum output= expmod(a, b, n);
    printf("a :\n");
    printbignum(a);
    printf("\nb :\n");
    printbignum(b);
    printf("\nn :\n");
    printbignum(n);
    printf("\n(a^b) mod n :\n");
    printbignum(output);
    printf("*************************** Test Exponential Modulus -  End  ***************************\n");
}

void testFermat(){
    printf("\n*************************** Test Fermat - Start ***************************\n");
    bignum a= genrandomprime(100);
    printf("a :\n");
    printbignum(a);
    int t=10;
    printf("t : %d\n", t);
    int res= fermat( a ,t);
    if(res==0){
    	printf("%d is composite \n", a);
    }else{
    	printf("%d is prime \n", a);
    }
    printf("\n");
    a= str2bignum("100");
    printf("a :\n");
    printbignum(a);
    printf("t : %d\n", t);
    res= fermat( a ,t);
    if(res==0){
    	printf("%d is composite \n", a);
    }else{
    	printf("%d is prime \n", a);
    }
	printf("\n*************************** Test Fermat - End ***************************\n");
}

void testGenerateRandom(){
    printf("\n*************************** Test GenerateRandom - Start ***************************\n");
    int length= 10;
    printf("length is: %d", length);
    bignum a= genrandom(length);
    printf("\nrandom number of length %d :\n", length);
    printbignum(a);
    printf("\n*************************** Test GenerateRandom - End ***************************\n");
}

void testGenerateRandomPrime(){
    printf("\n*************************** Test Generate Random Prime- Start ***************************\n");
    int length= 10;
    printf("length is: %d", length);
    bignum a= genrandomprime(length);
    printf("\nrandom prime number of length %d :\n", length);
    printbignum(a);
    printf("\n*************************** Test GenerateRandom - End ***************************\n");
}
