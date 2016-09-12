/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

#include "internal/threads.h"

X509_PKEY *X509_PKEY_new(void)
{
    X509_PKEY *ret = NULL;

    if ((ret = calloc(1, sizeof(X509_PKEY))) == NULL)
        goto err;

    ret->references = 1;
    ret->lock = CRYPTO_thread_new();
    if (ret->lock == NULL) {
        free(ret);
        return NULL;
    }
    ret->enc_algor = X509_ALGOR_new();
    ret->enc_pkey = ASN1_OCTET_STRING_new();
    if (!ret->enc_algor || !ret->enc_pkey)
        goto err;
    return ret;

err:
    X509_PKEY_free(ret);
    ASN1err(ASN1_F_X509_PKEY_NEW, ERR_R_MALLOC_FAILURE);
    return NULL;
}

void X509_PKEY_free(X509_PKEY *x)
{
    int i;

    if (x == NULL)
        return;

    CRYPTO_atomic_add(&x->references, -1, &i, x->lock);
    if (i > 0)
        return;

    X509_ALGOR_free(x->enc_algor);
    ASN1_OCTET_STRING_free(x->enc_pkey);
    EVP_PKEY_free(x->dec_pkey);
    if (x->key_free)
        free(x->key_data);
    CRYPTO_thread_cleanup(x->lock);
    free(x);
}
