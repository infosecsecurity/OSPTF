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

#include <openssl/evp.h>
#include <openssl/md5.h>

static const char *test[] = {
    "",
    "a",
    "abc",
    "message digest",
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
    NULL,
};

static const char *ret[] = {
    "d41d8cd98f00b204e9800998ecf8427e",
    "0cc175b9c0f1b6a831c399e269772661",
    "900150983cd24fb0d6963f7d28e17f72",
    "f96b697d7cb7938d525a2f31aaf161d0",
    "c3fcd3d76192e4007dfb496cca67e13b",
    "d174ab98d277d9f5a5611c2c9f419d9f",
    "57edf4a22be3c955ac49da2e2107b67a",
};

static char *pt(uint8_t *md);
int main(int argc, char *argv[])
{
    int i, err = 0;
    const char **P, **R, *p;
    uint8_t md[MD5_DIGEST_LENGTH];

    P = test;
    R = ret;
    i = 1;
    while (*P != NULL) {
        EVP_Digest(&(P[0][0]), strlen((char *)*P), md, NULL, EVP_md5(), NULL);
        p = pt(md);
        if (strcmp(p, (char *)*R) != 0) {
            printf("error calculating MD5 on '%s'\n", *P);
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

    for (i = 0; i < MD5_DIGEST_LENGTH; i++)
        snprintf(buf + i * 2, sizeof(buf) - i * 2, "%02x", md[i]);
    return (buf);
}
