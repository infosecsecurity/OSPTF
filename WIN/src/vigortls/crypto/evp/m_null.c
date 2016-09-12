/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

static int init(EVP_MD_CTX *ctx)
{
    return 1;
}

static int update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return 1;
}

static int final(EVP_MD_CTX *ctx, uint8_t *md)
{
    return 1;
}

static const EVP_MD null_md = {
    .type = NID_undef,
    .pkey_type = NID_undef,
    .init = init,
    .update = update,
    .final = final,
    .ctx_size = sizeof(EVP_MD *),
};

const EVP_MD *EVP_md_null(void)
{
    return (&null_md);
}
