/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

void PEM_SignInit(EVP_MD_CTX *ctx, EVP_MD *type)
{
    EVP_DigestInit_ex(ctx, type, NULL);
}

void PEM_SignUpdate(EVP_MD_CTX *ctx, uint8_t *data,
                    unsigned int count)
{
    EVP_DigestUpdate(ctx, data, count);
}

int PEM_SignFinal(EVP_MD_CTX *ctx, uint8_t *sigret, unsigned int *siglen,
                  EVP_PKEY *pkey)
{
    uint8_t *m;
    int i, ret = 0;
    unsigned int m_len;

    m = malloc(EVP_PKEY_size(pkey) + 2);
    if (m == NULL) {
        PEMerr(PEM_F_PEM_SIGNFINAL, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (EVP_SignFinal(ctx, m, &m_len, pkey) <= 0)
        goto err;

    i = EVP_EncodeBlock(sigret, m, m_len);
    *siglen = i;
    ret = 1;
err:
    /* ctx has been zeroed by EVP_SignFinal() */
    free(m);
    return (ret);
}
