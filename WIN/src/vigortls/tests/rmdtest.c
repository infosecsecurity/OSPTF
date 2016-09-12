/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
 
#include <stdcompat.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef OPENSSL_NO_RIPEMD
int main(int argc, char *argv[])
{
    printf("No ripemd support\n");
    return (0);
}
#else
#include <openssl/ripemd.h>
#include <openssl/evp.h>

static const char *test[] = {
    "",
    "a",
    "abc",
    "message digest",
    "abcdefghijklmnopqrstuvwxyz",
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
    NULL,
};

static const char *ret[] = {
    "9c1185a5c5e9fc54612808977ee8f548b2258d31",
    "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe",
    "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
    "5d0689ef49d2fae572b881b123a85ffa21595f36",
    "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
    "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
    "b0e20b6e3116640286ed3a87a5713079b21f5189",
    "9b752e45573d4b39f4dbd3323cab82bf63326bfb",
};

static char *pt(uint8_t *md);
int main(int argc, char *argv[])
{
    int i, err = 0;
    const char **P, **R;
    const char *p;
    uint8_t md[RIPEMD160_DIGEST_LENGTH];

    P = test;
    R = ret;
    i = 1;
    while (*P != NULL) {
        EVP_Digest(&(P[0][0]), strlen((char *)*P), md, NULL, EVP_ripemd160(), NULL);
        p = pt(md);
        if (strcmp(p, (char *)*R) != 0) {
            printf("error calculating RIPEMD160 on '%s'\n", *P);
            printf("got %s instead of %s\n", p, *R);
            err++;
        } else
            printf("test %d ok\n", i);
        i++;
        R++;
        P++;
    }
    exit(err);
    return (0);
}

static char *pt(uint8_t *md)
{
    int i;
    static char buf[80];

    for (i = 0; i < RIPEMD160_DIGEST_LENGTH; i++)
        snprintf(buf + i * 2, sizeof(buf) - i * 2, "%02x", md[i]);
    return (buf);
}
#endif
