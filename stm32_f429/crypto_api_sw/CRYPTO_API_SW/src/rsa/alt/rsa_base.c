#include "rsa_base.h"


void rsaGenerateKeyPair(size_t k, uint32_t e, unsigned char** pri_key, unsigned int* len_pri,
	unsigned char** pub_key, unsigned int* len_pub)
{

    srand(time(NULL));

    bignum p, q, phi_n;
    bignum t0, t1, bgcd, tmp;
    bignum ONE = digit2bignum(1);
    bignum be;
    bignum d;
    bignum n;

    p = genrandomprime(k);
    q = genrandomprime(k);

    while (compare(p, q) == 0) {
        free(q.tab);
        q = genrandomprime(k);
    }

    n = mult(p, q);
    t0 = sub(p, ONE);
    t1 = sub(q, ONE);
    phi_n = mult(t0, t1);
    free(t0.tab);
    free(t1.tab);

    be = digit2bignum(e);

    while (1) {
        bgcd = gcd(be, phi_n);
        if (compare(bgcd, ONE) == 0) {
            free(bgcd.tab);

            d = inverse(be, phi_n);
            break;
        }

        int e_len;
        do {
            e_len = rand() % (length(n));
        } while (e_len <= 1);

        do {
            free(be.tab);
            be = genrandom(e_len);
        } while (iszero(be) || isone(be));
    }

    free(ONE.tab);
    free(p.tab);
    free(q.tab);
    free(phi_n.tab);


    size_t sd = d.size;
    size_t sn = n.size;
    *len_pri = sd + sn + 8;
    *pri_key = malloc(*len_pri);
    unsigned char* pk; pk = malloc(*len_pri);
    for (int i = 0; i < d.size; i++) pk[i] = d.tab[i];
    // memcpy(pk, (uint8_t*)d.tab, d.size);

    for (int i = d.size; i < *len_pri; i++) pk[i] = n.tab[i - d.size];
    // memcpy(pk + d.size, n.tab, n.size);

    unsigned char size[8];
    size[*len_pri - 1] = (d.size >> 0);
    size[*len_pri - 2] = (d.size >> 8);
    size[*len_pri - 3] = (d.size >> 16);
    size[*len_pri - 4] = (d.size >> 24);
    size[*len_pri - 5] = (n.size >> 0);
    size[*len_pri - 6] = (n.size >> 8);
    size[*len_pri - 7] = (n.size >> 16);
    size[*len_pri - 8] = (n.size >> 24);
    memcpy(pk + sd + sn, size, 8);
    // printf("\n "); for (int i = 0; i < *len_pri; i++) printf("%02x", pk[i]);

    memcpy(*pri_key, pk, *len_pri);
    free(pk);

    size_t se = be.size;
    *len_pub = sn + se;
    pk = malloc(*len_pub);
    *pub_key = malloc(*len_pub);
    for (int i = 0; i < n.size; i++) pk[i] = n.tab[i];
    // memcpy(pk, n.tab, n.size);
    for (int i = n.size; i < *len_pub; i++) pk[i] = be.tab[i - n.size];
    // memcpy(pk + n.size, be.tab, se);

    memcpy(*pub_key, pk, *len_pub);
    free(pk);
    
}

void rsaEncrypt(unsigned char* plaintext, unsigned int plaintext_len, const unsigned char** pub_key, unsigned int pub_len,
    unsigned char** ciphertext, unsigned int* ciphertext_len) {
    
    bignum m;
    bignum e;
    bignum n;
    bignum en;

    unsigned char* pk; pk = malloc(pub_len); memcpy(pk, *pub_key, pub_len);


    // plaintext to bignum
    m.sign = 0;
    m.size = plaintext_len;
    m.tab = malloc(m.size);
    memcpy(m.tab, plaintext, m.size);
    // for (int i = 0; i < m.size; i++) m.tab[i] = plaintext[i];
    printf("\n "); for (int i = 0; i < m.size; i++) printf("%02x", m.tab[i]);

    // pubkey to bignum
    n.sign = 0;
    n.size = pub_len - 1;
    n.tab = malloc(n.size);
    // for (int i = 0; i < n.size; i++) n.tab[i] = pk[i];
    memcpy(n.tab, pk, n.size);

    printf("\n "); for (int i = 0; i < n.size; i++) printf("%02x", n.tab[i]);

    // pubkey to bignum
    e.sign = 0;
    e.size = 1;
    e.tab = malloc(16);
    // for (int i = 0; i < e.size; i++) e.tab[i] = pk[i + n.size];
    memcpy(e.tab, pk + n.size, e.size);

    en = expmod(m, e, n);

    unsigned char* en_mem;
    en_mem = malloc(en.size);
    // for (int i = 0; i < en.size; i++) en_mem[i] = en.tab[i];
    memcpy(en_mem, en.tab, en.size);

    *ciphertext_len = en.size;
    *ciphertext = malloc(en.size);
    memcpy(*ciphertext, en_mem, en.size);

    free(m.tab);
    free(e.tab);
    free(n.tab);
    free(en.tab);
    free(pk);
    free(en_mem);
}

void rsaDecrypt(unsigned char** result, unsigned int* result_len, const unsigned char** pri_key, unsigned int pri_len,
    unsigned char* ciphertext, unsigned int ciphertext_len) {


    bignum c;
    bignum d;
    bignum n;
    bignum de;

    unsigned char* pk; pk = malloc(pri_len); memcpy(pk, *pri_key, pri_len);


    // plaintext to bignum
    c.sign = 0;
    c.size = ciphertext_len;
    c.tab = malloc(c.size);
    // for (int i = 0; i < c.size; i++) c.tab[i] = ciphertext[i];
    memcpy(c.tab, ciphertext, c.size);

    // pubkey to bignum
    d.sign = 0;
    d.size =    ((unsigned int)pk[pri_len - 1] << 0)  | 
                ((unsigned int)pk[pri_len - 2] << 8)  | 
                ((unsigned int)pk[pri_len - 3] << 16) |
                ((unsigned int)pk[pri_len - 4] << 24);
    d.tab = malloc(d.size);
    // for (int i = 0; i < d.size; i++) d.tab[i] = pk[i];
    memcpy(d.tab, pk, d.size);

    // pubkey to bignum
    n.sign = 0;
    n.size =    ((unsigned int)pk[pri_len - 5] << 0) |
                ((unsigned int)pk[pri_len - 6] << 8) |
                ((unsigned int)pk[pri_len - 7] << 16) |
                ((unsigned int)pk[pri_len - 8] << 24);
    n.tab = malloc(n.size);
    // for (int i = 0; i < n.size; i++) n.tab[i] = pk[i + d.size];
    memcpy(n.tab, pk + d.size, n.size);

    for (int i = 0; i < pri_len; i++) printf("\n %d: %02x", i, pk[i]);

    de = expmod(c, d, n);

    unsigned char* de_mem;
    de_mem = malloc(de.size);
    // for (int i = 0; i < de.size; i++) de_mem[i] = de.tab[i];
    memcpy(de_mem, de.tab, de.size);

    *result_len = de.size;
    *result = malloc(de.size);
    memcpy(*result, de_mem, de.size);

    free(c.tab);
    free(d.tab);
    free(n.tab);
    free(de.tab);
    free(pk);
    free(de_mem);

}