/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "internal/threads.h"

X509_INFO *X509_INFO_new(void)
{
    X509_INFO *ret = NULL;

    ret = calloc(1, sizeof(X509_INFO));
    if (ret == NULL) {
        ASN1err(ASN1_F_X509_INFO_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    ret->references = 1;
    ret->lock = CRYPTO_thread_new();
    if (ret->lock == NULL) {
        ASN1err(ASN1_F_X509_INFO_NEW, ERR_R_MALLOC_FAILURE);
        X509_INFO_free(ret);
        return NULL;
    }

    return ret;
}

void X509_INFO_free(X509_INFO *x)
{
    int i;

    if (x == NULL)
        return;

    CRYPTO_atomic_add(&x->references, -1, &i, x->lock);
    if (i > 0)
        return;

    X509_free(x->x509);
    X509_CRL_free(x->crl);
    X509_PKEY_free(x->x_pkey);
    free(x->enc_data);
    CRYPTO_thread_cleanup(x->lock);
    free(x);
}
