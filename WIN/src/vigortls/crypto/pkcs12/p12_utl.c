/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include <openssl/pkcs12.h>

/* Cheap and nasty Unicode stuff */

uint8_t *OPENSSL_asc2uni(const char *asc, int asclen, uint8_t **uni, int *unilen)
{
    int ulen, i;
    uint8_t *unitmp;
    if (asclen == -1)
        asclen = strlen(asc);
    ulen = asclen * 2 + 2;
    if (!(unitmp = malloc(ulen)))
        return NULL;
    for (i = 0; i < ulen - 2; i += 2) {
        unitmp[i] = 0;
        unitmp[i + 1] = asc[i >> 1];
    }
    /* Make result double null terminated */
    unitmp[ulen - 2] = 0;
    unitmp[ulen - 1] = 0;
    if (unilen)
        *unilen = ulen;
    if (uni)
        *uni = unitmp;
    return unitmp;
}

char *OPENSSL_uni2asc(uint8_t *uni, int unilen)
{
    int asclen, i;
    char *asctmp;
    asclen = unilen / 2;
    /* If no terminating zero allow for one */
    if (!unilen || uni[unilen - 1])
        asclen++;
    uni++;
    if (!(asctmp = malloc(asclen)))
        return NULL;
    for (i = 0; i < unilen; i += 2)
        asctmp[i >> 1] = uni[i];
    asctmp[asclen - 1] = 0;
    return asctmp;
}

int i2d_PKCS12_bio(BIO *bp, PKCS12 *p12)
{
    return ASN1_item_i2d_bio(ASN1_ITEM_rptr(PKCS12), bp, p12);
}

int i2d_PKCS12_fp(FILE *fp, PKCS12 *p12)
{
    return ASN1_item_i2d_fp(ASN1_ITEM_rptr(PKCS12), fp, p12);
}

PKCS12 *d2i_PKCS12_bio(BIO *bp, PKCS12 **p12)
{
    return ASN1_item_d2i_bio(ASN1_ITEM_rptr(PKCS12), bp, p12);
}
PKCS12 *d2i_PKCS12_fp(FILE *fp, PKCS12 **p12)
{
    return ASN1_item_d2i_fp(ASN1_ITEM_rptr(PKCS12), fp, p12);
}

PKCS12_SAFEBAG *PKCS12_x5092certbag(X509 *x509)
{
    return PKCS12_item_pack_safebag(x509, ASN1_ITEM_rptr(X509),
                                    NID_x509Certificate, NID_certBag);
}

PKCS12_SAFEBAG *PKCS12_x509crl2certbag(X509_CRL *crl)
{
    return PKCS12_item_pack_safebag(crl, ASN1_ITEM_rptr(X509_CRL),
                                    NID_x509Crl, NID_crlBag);
}

X509 *PKCS12_certbag2x509(PKCS12_SAFEBAG *bag)
{
    if (M_PKCS12_bag_type(bag) != NID_certBag)
        return NULL;
    if (M_PKCS12_cert_bag_type(bag) != NID_x509Certificate)
        return NULL;
    return ASN1_item_unpack(bag->value.bag->value.octet, ASN1_ITEM_rptr(X509));
}

X509_CRL *PKCS12_certbag2x509crl(PKCS12_SAFEBAG *bag)
{
    if (M_PKCS12_bag_type(bag) != NID_crlBag)
        return NULL;
    if (M_PKCS12_cert_bag_type(bag) != NID_x509Crl)
        return NULL;
    return ASN1_item_unpack(bag->value.bag->value.octet,
                            ASN1_ITEM_rptr(X509_CRL));
}
