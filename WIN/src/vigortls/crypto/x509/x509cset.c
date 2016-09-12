/*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
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

int X509_CRL_set_version(X509_CRL *x, long version)
{
    if (x == NULL)
        return (0);
    if (x->crl->version == NULL) {
        if ((x->crl->version = ASN1_INTEGER_new()) == NULL)
            return (0);
    }
    return (ASN1_INTEGER_set(x->crl->version, version));
}

int X509_CRL_set_issuer_name(X509_CRL *x, X509_NAME *name)
{
    if ((x == NULL) || (x->crl == NULL))
        return (0);
    return (X509_NAME_set(&x->crl->issuer, name));
}

int X509_CRL_set_lastUpdate(X509_CRL *x, const ASN1_TIME *tm)
{
    ASN1_TIME *in;

    if (x == NULL)
        return (0);
    in = x->crl->lastUpdate;
    if (in != tm) {
        in = ASN1_STRING_dup(tm);
        if (in != NULL) {
            ASN1_TIME_free(x->crl->lastUpdate);
            x->crl->lastUpdate = in;
        }
    }
    return (in != NULL);
}

int X509_CRL_set_nextUpdate(X509_CRL *x, const ASN1_TIME *tm)
{
    ASN1_TIME *in;

    if (x == NULL)
        return (0);
    in = x->crl->nextUpdate;
    if (in != tm) {
        in = ASN1_STRING_dup(tm);
        if (in != NULL) {
            ASN1_TIME_free(x->crl->nextUpdate);
            x->crl->nextUpdate = in;
        }
    }
    return (in != NULL);
}

int X509_CRL_sort(X509_CRL *c)
{
    int i;
    X509_REVOKED *r;
    /* sort the data so it will be written in serial
     * number order */
    sk_X509_REVOKED_sort(c->crl->revoked);
    for (i = 0; i < sk_X509_REVOKED_num(c->crl->revoked); i++) {
        r = sk_X509_REVOKED_value(c->crl->revoked, i);
        r->sequence = i;
    }
    c->crl->enc.modified = 1;
    return 1;
}

void X509_CRL_up_ref(X509_CRL *crl)
{
    int i;
    CRYPTO_atomic_add(&crl->references, 1, &i, crl->lock);
}

int X509_REVOKED_set_revocationDate(X509_REVOKED *x, ASN1_TIME *tm)
{
    ASN1_TIME *in;

    if (x == NULL)
        return (0);
    in = x->revocationDate;
    if (in != tm) {
        in = ASN1_STRING_dup(tm);
        if (in != NULL) {
            ASN1_TIME_free(x->revocationDate);
            x->revocationDate = in;
        }
    }
    return (in != NULL);
}

int X509_REVOKED_set_serialNumber(X509_REVOKED *x, ASN1_INTEGER *serial)
{
    ASN1_INTEGER *in;

    if (x == NULL)
        return (0);
    in = x->serialNumber;
    if (in != serial) {
        in = ASN1_STRING_dup(serial);
        if (in != NULL) {
            ASN1_INTEGER_free(x->serialNumber);
            x->serialNumber = in;
        }
    }
    return (in != NULL);
}
