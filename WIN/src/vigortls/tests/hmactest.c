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
#include <stdlib.h>
#include <string.h>

#include <openssl/hmac.h>
#include <openssl/md5.h>

static struct test_st {
    const char key[16+1];
    const char data[64];
    const char *digest;
} test[8] = {
    {
        "",
        "More text test vectors to stuff up EBCDIC machines :-)",
        "e9139d1e6ee064ef8cf514fc7dc83e86",
    },
    {
        {
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x00,
        },
        "Hi There",
        "9294727a3638bb1c13f48ef8158bfc9d",
    },
    {
        "Jefe",
        "what do ya want for nothing?",
        "750c783e6ab0b503eaa86e310a5db738",
    },
    {
        {
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0x00,
        },
        {
            0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
            0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
            0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
            0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
            0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
            0x00,
        },
        "56be34521d144c88dbb8c733f0e8b3f6",
    },
    {
        "",
        "My test data",
        "61afdecb95429ef494d61fdee15990cabf0826fc"
    },
    {
        "",
        "My test data",
        "2274b195d90ce8e03406f4b526a47e0787a88a65479938f1a5baa3ce0f079776"
    },
    {
        "123456",
        "My test data",
        "bab53058ae861a7f191abe2d0145cbb123776a6369ee3f9d79ce455667e411dd"
        },
    {
        "12345",
        "My test data again",
        "a12396ceddd2a85f4c656bc1e0aa50c78cffde3e"
    }
};

static char *pt(uint8_t *md, unsigned int len);

int main(int argc, char *argv[])
{
    int i;
    char *p;
    int err = 0;
    HMAC_CTX ctx, ctx2;
    uint8_t buf[EVP_MAX_MD_SIZE];
    unsigned int len;

    for (i = 0; i < 4; i++) {
        p = pt(HMAC(EVP_md5(), (uint8_t *)test[i].key, strlen(test[i].key),
               (uint8_t *)test[i].data, strlen(test[i].data), NULL, NULL),
               MD5_DIGEST_LENGTH);

        if (strcmp(p, test[i].digest) != 0) {
            printf("Error calculating HMAC on %d entry'\n", i);
            printf("got %s instead of %s\n", p, test[i].digest);
            err++;
        }
        else
            printf("test %d ok\n", i);
    }

    /* test4 */
    HMAC_CTX_init(&ctx);
    if (HMAC_Init_ex(&ctx, NULL, 0, NULL, NULL)) {
        printf(
            "Should fail to initialise HMAC with empty MD and key (test 4)\n");
        err++;
        goto test5;
    }
    if (HMAC_Update(&ctx, (uint8_t *)test[4].data, strlen(test[4].data))) {
        printf("Should fail HMAC_Update with ctx not set up (test 4)\n");
        err++;
        goto test5;
    }
    if (HMAC_Init_ex(&ctx, NULL, 0, EVP_sha1(), NULL)) {
        printf("Should fail to initialise HMAC with empty key (test 4)\n");
        err++;
        goto test5;
    }
    if (HMAC_Update(&ctx, (uint8_t *)test[4].data, strlen(test[4].data))) {
        printf("Should fail HMAC_Update with ctx not set up (test 4)\n");
        err++;
        goto test5;
    }
    printf("test 4 ok\n");
test5:
    HMAC_CTX_init(&ctx);
    if (HMAC_Init_ex(&ctx, (uint8_t *)test[4].key, strlen(test[4].key), NULL, NULL)) {
        printf("Should fail to initialise HMAC with empty MD (test 5)\n");
        err++;
        goto test6;
    }
    if (HMAC_Update(&ctx, (uint8_t *)test[4].data, strlen(test[4].data))) {
        printf("Should fail HMAC_Update with ctx not set up (test 5)\n");
        err++;
        goto test6;
    }
    if (HMAC_Init_ex(&ctx, (uint8_t *)test[4].key, -1, EVP_sha1(), NULL)) {
        printf("Should fail to initialise HMAC with invalid key len(test 5)\n");
        err++;
        goto test6;
    }
    if (!HMAC_Init_ex(&ctx, (uint8_t *)test[4].key, strlen(test[4].key), EVP_sha1(), NULL)) {
        printf("Failed to initialise HMAC (test 5)\n");
        err++;
        goto test6;
    }
    if (!HMAC_Update(&ctx, (uint8_t *)test[4].data, strlen(test[4].data))) {
        printf("Error updating HMAC with data (test 5)\n");
        err++;
        goto test6;
    }
    if (!HMAC_Final(&ctx, buf, &len)) {
        printf("Error finalising data (test 5)\n");
        err++;
        goto test6;
    }
    p = pt(buf, len);
    if (strcmp(p, test[4].digest) != 0) {
        printf("Error calculating interim HMAC on test 5\n");
        printf("got %s instead of %s\n", p, test[4].digest);
        err++;
        goto test6;
    }
    if (!HMAC_Init_ex(&ctx, NULL, 0, EVP_sha256(), NULL)) {
        printf("Failed to reinitialise HMAC (test 5)\n");
        err++;
        goto test6;
    }
    if (!HMAC_Update(&ctx, (uint8_t *)test[5].data, strlen(test[5].data))) {
        printf("Error updating HMAC with data (sha256) (test 5)\n");
        err++;
        goto test6;
    }
    if (!HMAC_Final(&ctx, buf, &len)) {
        printf("Error finalising data (sha256) (test 5)\n");
        err++;
        goto test6;
    }
    p = pt(buf, len);
    if (strcmp(p, test[5].digest) != 0) {
        printf("Error calculating 2nd interim HMAC on test 5\n");
        printf("got %s instead of %s\n", p, test[5].digest);
        err++;
        goto test6;
    }
    if (!HMAC_Init_ex(&ctx, (uint8_t *)test[6].key, strlen(test[6].key), NULL, NULL)) {
        printf("Failed to reinitialise HMAC with key (test 5)\n");
        err++;
        goto test6;
    }
    if (!HMAC_Update(&ctx, (uint8_t *)test[6].data, strlen(test[6].data))) {
        printf("Error updating HMAC with data (new key) (test 5)\n");
        err++;
        goto test6;
    }
    if (!HMAC_Final(&ctx, buf, &len)) {
        printf("Error finalising data (new key) (test 5)\n");
        err++;
        goto test6;
    }
    p = pt(buf, len);
    if (strcmp(p, test[6].digest) != 0) {
        printf("error calculating HMAC on test 5\n");
        printf("got %s instead of %s\n", p, test[6].digest);
        err++;
    }
    else {
        printf("test 5 ok\n");
    }
test6:
    HMAC_CTX_init(&ctx);
    if (!HMAC_Init_ex(&ctx, (uint8_t *)test[7].key, strlen(test[7].key), EVP_sha1(), NULL)) {
        printf("Failed to initialise HMAC (test 6)\n");
        err++;
        goto end;
    }
    if (!HMAC_Update(&ctx, (uint8_t *)test[7].data, strlen(test[7].data))) {
        printf("Error updating HMAC with data (test 6)\n");
        err++;
        goto end;
    }
    if (!HMAC_CTX_copy(&ctx2, &ctx)) {
        printf("Failed to copy HMAC_CTX (test 6)\n");
        err++;
        goto end;
    }
    if (!HMAC_Final(&ctx2, buf, &len)) {
        printf("Error finalising data (test 6)\n");
        err++;
        goto end;
    }
    p = pt(buf, len);
    if (strcmp(p, test[7].digest) != 0) {
        printf("Error calculating HMAC on test 6\n");
        printf("got %s instead of %s\n", p, test[7].digest);
        err++;
    }
    else {
        printf("test 6 ok\n");
    }
end:
    exit(err);
    return (0);
}

static char *pt(uint8_t *md, unsigned int len)
{
    unsigned int i;
    static char buf[80];

    for (i = 0; i < len; i++)
        sprintf(&(buf[i * 2]), "%02x", md[i]);
    return (buf);
}