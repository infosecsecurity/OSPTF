/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "internal/threads.h"

int X509_set_version(X509 *x, long version)
{
    if (x == NULL)
        return 0;
    if (version == 0) {
        ASN1_INTEGER_free(x->cert_info->version);
        x->cert_info->version = NULL;
        return 1;
    }
    if (x->cert_info->version == NULL) {
        if ((x->cert_info->version = ASN1_INTEGER_new()) == NULL)
            return 0;
    }
    return ASN1_INTEGER_set(x->cert_info->version, version);
}

int X509_set_serialNumber(X509 *x, ASN1_INTEGER *serial)
{
    ASN1_INTEGER *in;

    if (x == NULL)
        return (0);
    in = x->cert_info->serialNumber;
    if (in != serial) {
        in = ASN1_STRING_dup(serial);
        if (in != NULL) {
            ASN1_INTEGER_free(x->cert_info->serialNumber);
            x->cert_info->serialNumber = in;
        }
    }
    return (in != NULL);
}

int X509_set_issuer_name(X509 *x, X509_NAME *name)
{
    if ((x == NULL) || (x->cert_info == NULL))
        return (0);
    return (X509_NAME_set(&x->cert_info->issuer, name));
}

int X509_set_subject_name(X509 *x, X509_NAME *name)
{
    if ((x == NULL) || (x->cert_info == NULL))
        return (0);
    return (X509_NAME_set(&x->cert_info->subject, name));
}

int X509_set_notBefore(X509 *x, const ASN1_TIME *tm)
{
    ASN1_TIME *in;

    if ((x == NULL) || (x->cert_info->validity == NULL))
        return (0);
    in = x->cert_info->validity->notBefore;
    if (in != tm) {
        in = ASN1_STRING_dup(tm);
        if (in != NULL) {
            ASN1_TIME_free(x->cert_info->validity->notBefore);
            x->cert_info->validity->notBefore = in;
        }
    }
    return (in != NULL);
}

int X509_set_notAfter(X509 *x, const ASN1_TIME *tm)
{
    ASN1_TIME *in;

    if ((x == NULL) || (x->cert_info->validity == NULL))
        return (0);
    in = x->cert_info->validity->notAfter;
    if (in != tm) {
        in = ASN1_STRING_dup(tm);
        if (in != NULL) {
            ASN1_TIME_free(x->cert_info->validity->notAfter);
            x->cert_info->validity->notAfter = in;
        }
    }
    return (in != NULL);
}

int X509_set_pubkey(X509 *x, EVP_PKEY *pkey)
{
    if ((x == NULL) || (x->cert_info == NULL))
        return (0);
    return (X509_PUBKEY_set(&(x->cert_info->key), pkey));
}

void X509_up_ref(X509 *x)
{
    int i;
    CRYPTO_atomic_add(&x->references, 1, &i, x->lock);
}
