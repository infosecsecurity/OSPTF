/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>

/* Minor tweak to operation: zero private key data */
static int pkey_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                   void *exarg)
{
    /* Since the structure must still be valid use ASN1_OP_FREE_PRE */
    if (operation == ASN1_OP_FREE_PRE) {
        PKCS8_PRIV_KEY_INFO *key = (PKCS8_PRIV_KEY_INFO *)*pval;
        if (key->pkey && key->pkey->type == V_ASN1_OCTET_STRING
            && key->pkey->value.octet_string != NULL)
            vigortls_zeroize(key->pkey->value.octet_string->data,
                             key->pkey->value.octet_string->length);
    }
    return 1;
}

ASN1_SEQUENCE_cb(PKCS8_PRIV_KEY_INFO, pkey_cb) = {
    ASN1_SIMPLE(PKCS8_PRIV_KEY_INFO, version, ASN1_INTEGER),
    ASN1_SIMPLE(PKCS8_PRIV_KEY_INFO, pkeyalg, X509_ALGOR),
    ASN1_SIMPLE(PKCS8_PRIV_KEY_INFO, pkey, ASN1_ANY),
    ASN1_IMP_SET_OF_OPT(PKCS8_PRIV_KEY_INFO, attributes, X509_ATTRIBUTE, 0)
} ASN1_SEQUENCE_END_cb(PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO)

PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO(PKCS8_PRIV_KEY_INFO **a, const uint8_t **in, long len)
{
    return (PKCS8_PRIV_KEY_INFO *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(PKCS8_PRIV_KEY_INFO));
}

int i2d_PKCS8_PRIV_KEY_INFO(PKCS8_PRIV_KEY_INFO *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(PKCS8_PRIV_KEY_INFO));
}

PKCS8_PRIV_KEY_INFO *PKCS8_PRIV_KEY_INFO_new(void)
{
    return (PKCS8_PRIV_KEY_INFO *)ASN1_item_new(ASN1_ITEM_rptr(PKCS8_PRIV_KEY_INFO));
}

void PKCS8_PRIV_KEY_INFO_free(PKCS8_PRIV_KEY_INFO *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(PKCS8_PRIV_KEY_INFO));
}

int PKCS8_pkey_set0(PKCS8_PRIV_KEY_INFO *priv, ASN1_OBJECT *aobj,
                    int version, int ptype, void *pval,
                    uint8_t *penc, int penclen)
{
    uint8_t **ppenc = NULL;
    if (version >= 0) {
        if (!ASN1_INTEGER_set(priv->version, version))
            return 0;
    }
    if (penc) {
        int pmtype;
        ASN1_OCTET_STRING *oct;
        oct = ASN1_OCTET_STRING_new();
        if (!oct)
            return 0;
        oct->data = penc;
        ppenc = &oct->data;
        oct->length = penclen;
        if (priv->broken == PKCS8_NO_OCTET)
            pmtype = V_ASN1_SEQUENCE;
        else
            pmtype = V_ASN1_OCTET_STRING;
        ASN1_TYPE_set(priv->pkey, pmtype, oct);
    }
    if (!X509_ALGOR_set0(priv->pkeyalg, aobj, ptype, pval)) {
        /* If call fails do not swallow 'enc' */
        if (ppenc)
            *ppenc = NULL;
        return 0;
    }
    return 1;
}

int PKCS8_pkey_get0(ASN1_OBJECT **ppkalg,
                    const uint8_t **pk, int *ppklen,
                    X509_ALGOR **pa,
                    PKCS8_PRIV_KEY_INFO *p8)
{
    if (ppkalg)
        *ppkalg = p8->pkeyalg->algorithm;
    if (p8->pkey->type == V_ASN1_OCTET_STRING) {
        p8->broken = PKCS8_OK;
        if (pk) {
            *pk = p8->pkey->value.octet_string->data;
            *ppklen = p8->pkey->value.octet_string->length;
        }
    } else if (p8->pkey->type == V_ASN1_SEQUENCE) {
        p8->broken = PKCS8_NO_OCTET;
        if (pk) {
            *pk = p8->pkey->value.sequence->data;
            *ppklen = p8->pkey->value.sequence->length;
        }
    } else
        return 0;
    if (pa)
        *pa = p8->pkeyalg;
    return 1;
}
