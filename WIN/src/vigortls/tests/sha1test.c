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
#include <openssl/sha.h>

static const char *test[] = {
    "abc",
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    NULL,
};

static const char *ret[] = {
    "a9993e364706816aba3e25717850c26c9cd0d89d",
    "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
};
static const char *bigret = "34aa973cd4c4daa4f61eeb2bdbad27316534016f";

static char *pt(uint8_t *md);
int main(int argc, char *argv[])
{
    int i, err = 0;
    const char **P, **R, *p, *r;
    static uint8_t buf[1000];
    EVP_MD_CTX c;
    uint8_t md[SHA_DIGEST_LENGTH];

    EVP_MD_CTX_init(&c);
    P = test;
    R = ret;
    i = 1;
    do {
        EVP_Digest(*P, strlen((char *)*P), md, NULL, EVP_sha1(), NULL);
        p = pt(md);
        if (strcmp(p, (char *)*R) != 0) {
            printf("error calculating SHA1 on '%s'\n", *P);
            printf("got %s instead of %s\n", p, *R);
            err++;
        } else
            printf("test %d ok\n", i);
        i++;
        R++;
        P++;
    } while (*P != NULL);

    memset(buf, 'a', 1000);
    EVP_DigestInit_ex(&c, EVP_sha1(), NULL);
    for (i = 0; i < 1000; i++)
        EVP_DigestUpdate(&c, buf, 1000);
    EVP_DigestFinal_ex(&c, md, NULL);
    p = pt(md);

    r = bigret;
    if (strcmp(p, r) != 0) {
        printf("error calculating SHA1 on 'a' * 1000\n");
        printf("got %s instead of %s\n", p, r);
        err++;
    } else
        printf("test 3 ok\n");

    EVP_MD_CTX_cleanup(&c);
    exit(err);
    return (0);
}

static char *pt(uint8_t *md)
{
    int i;
    static char buf[80];

    for (i = 0; i < SHA_DIGEST_LENGTH; i++)
        snprintf(buf + i * 2, sizeof(buf) - i * 2, "%02x", md[i]);
    return (buf);
}
