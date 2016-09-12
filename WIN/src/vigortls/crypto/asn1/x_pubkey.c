/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>

#include <openssl/asn1t.h>
#ifndef OPENSSL_NO_DSA
#include <openssl/dsa.h>
#endif
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "internal/asn1_int.h"
#include "internal/threads.h"

/* Minor tweak to operation: free up EVP_PKEY */
static int pubkey_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                     void *exarg)
{
    if (operation == ASN1_OP_NEW_POST) {
        X509_PUBKEY *pubkey = (X509_PUBKEY *)*pval;
        pubkey->lock = CRYPTO_thread_new();
        if (pubkey->lock == NULL)
            return 0;
    }
    if (operation == ASN1_OP_FREE_POST) {
        X509_PUBKEY *pubkey = (X509_PUBKEY *)*pval;
        CRYPTO_thread_cleanup(pubkey->lock);
        EVP_PKEY_free(pubkey->pkey);
    }
    return 1;
}

ASN1_SEQUENCE_cb(X509_PUBKEY, pubkey_cb) = {
    ASN1_SIMPLE(X509_PUBKEY, algor, X509_ALGOR),
    ASN1_SIMPLE(X509_PUBKEY, public_key, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END_cb(X509_PUBKEY, X509_PUBKEY)

X509_PUBKEY *d2i_X509_PUBKEY(X509_PUBKEY **a, const uint8_t **in, long len)
{
    return (X509_PUBKEY *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(X509_PUBKEY));
}

int i2d_X509_PUBKEY(X509_PUBKEY *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(X509_PUBKEY));
}

X509_PUBKEY *X509_PUBKEY_new(void)
{
    return (X509_PUBKEY *)ASN1_item_new(ASN1_ITEM_rptr(X509_PUBKEY));
}

void X509_PUBKEY_free(X509_PUBKEY *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(X509_PUBKEY));
}

int X509_PUBKEY_set(X509_PUBKEY * *x, EVP_PKEY *pkey)
{
    X509_PUBKEY *pk = NULL;

    if (x == NULL || pkey == NULL)
        return (0);

    if ((pk = X509_PUBKEY_new()) == NULL)
        goto error;

    if (pkey->ameth) {
        if (pkey->ameth->pub_encode) {
            if (!pkey->ameth->pub_encode(pk, pkey)) {
                X509err(X509_F_X509_PUBKEY_SET,
                        X509_R_PUBLIC_KEY_ENCODE_ERROR);
                goto error;
            }
        } else {
            X509err(X509_F_X509_PUBKEY_SET,
                    X509_R_METHOD_NOT_SUPPORTED);
            goto error;
        }
    } else {
        X509err(X509_F_X509_PUBKEY_SET, X509_R_UNSUPPORTED_ALGORITHM);
        goto error;
    }

    X509_PUBKEY_free(*x);

    *x = pk;

    return 1;
error:
    X509_PUBKEY_free(pk);
    return 0;
}

EVP_PKEY *X509_PUBKEY_get(X509_PUBKEY *key)
{
    EVP_PKEY *ret = NULL;

    if (key == NULL)
        goto error;

    if (key->pkey != NULL) {
        EVP_PKEY_up_ref(key->pkey);
        return key->pkey;
    }

    if (key->public_key == NULL)
        goto error;

    if ((ret = EVP_PKEY_new()) == NULL) {
        X509err(X509_F_X509_PUBKEY_GET, ERR_R_MALLOC_FAILURE);
        goto error;
    }

    if (!EVP_PKEY_set_type(ret, OBJ_obj2nid(key->algor->algorithm))) {
        X509err(X509_F_X509_PUBKEY_GET, X509_R_UNSUPPORTED_ALGORITHM);
        goto error;
    }

    if (ret->ameth->pub_decode) {
        if (!ret->ameth->pub_decode(ret, key)) {
            X509err(X509_F_X509_PUBKEY_GET,
                    X509_R_PUBLIC_KEY_DECODE_ERROR);
            goto error;
        }
    } else {
        X509err(X509_F_X509_PUBKEY_GET, X509_R_METHOD_NOT_SUPPORTED);
        goto error;
    }

    /* Check to see if another thread set key->pkey first */
    CRYPTO_thread_write_lock(key->lock);
    if (key->pkey) {
        CRYPTO_thread_unlock(key->lock);
        EVP_PKEY_free(ret);
        ret = key->pkey;
    } else {
        key->pkey = ret;
        CRYPTO_thread_unlock(key->lock);
    }
    EVP_PKEY_up_ref(ret);

    return ret;

error:
    EVP_PKEY_free(ret);
    return NULL;
}

/* Now two pseudo ASN1 routines that take an EVP_PKEY structure
 * and encode or decode as X509_PUBKEY
 */

EVP_PKEY *d2i_PUBKEY(EVP_PKEY **a, const uint8_t **pp,
                     long length)
{
    X509_PUBKEY *xpk;
    EVP_PKEY *pktmp;
    const uint8_t *q = *pp;

    xpk = d2i_X509_PUBKEY(NULL, &q, length);
    if (xpk == NULL)
        return NULL;
    pktmp = X509_PUBKEY_get(xpk);
    X509_PUBKEY_free(xpk);
    if (pktmp == NULL)
        return NULL;
    if (a != NULL) {
        EVP_PKEY_free(*a);
        *a = pktmp;
    }
    return pktmp;
}

int i2d_PUBKEY(EVP_PKEY *a, uint8_t **pp)
{
    X509_PUBKEY *xpk = NULL;
    int ret;
    if (!a)
        return 0;
    if (!X509_PUBKEY_set(&xpk, a))
        return 0;
    ret = i2d_X509_PUBKEY(xpk, pp);
    X509_PUBKEY_free(xpk);
    return ret;
}

/* The following are equivalents but which return RSA and DSA
 * keys
 */
RSA *d2i_RSA_PUBKEY(RSA **a, const uint8_t **pp,
                    long length)
{
    EVP_PKEY *pkey;
    RSA *key;
    const uint8_t *q;
    q = *pp;
    pkey = d2i_PUBKEY(NULL, &q, length);
    if (!pkey)
        return NULL;
    key = EVP_PKEY_get1_RSA(pkey);
    EVP_PKEY_free(pkey);
    if (!key)
        return NULL;
    *pp = q;
    if (a) {
        RSA_free(*a);
        *a = key;
    }
    return key;
}

int i2d_RSA_PUBKEY(RSA *a, uint8_t **pp)
{
    EVP_PKEY *pktmp;
    int ret;
    if (!a)
        return 0;
    pktmp = EVP_PKEY_new();
    if (!pktmp) {
        ASN1err(ASN1_F_I2D_RSA_PUBKEY, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    EVP_PKEY_set1_RSA(pktmp, a);
    ret = i2d_PUBKEY(pktmp, pp);
    EVP_PKEY_free(pktmp);
    return ret;
}

#ifndef OPENSSL_NO_DSA
DSA *d2i_DSA_PUBKEY(DSA **a, const uint8_t **pp,
                    long length)
{
    EVP_PKEY *pkey;
    DSA *key;
    const uint8_t *q;
    q = *pp;
    pkey = d2i_PUBKEY(NULL, &q, length);
    if (!pkey)
        return NULL;
    key = EVP_PKEY_get1_DSA(pkey);
    EVP_PKEY_free(pkey);
    if (!key)
        return NULL;
    *pp = q;
    if (a) {
        DSA_free(*a);
        *a = key;
    }
    return key;
}

int i2d_DSA_PUBKEY(DSA *a, uint8_t **pp)
{
    EVP_PKEY *pktmp;
    int ret;
    if (!a)
        return 0;
    pktmp = EVP_PKEY_new();
    if (!pktmp) {
        ASN1err(ASN1_F_I2D_DSA_PUBKEY, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    EVP_PKEY_set1_DSA(pktmp, a);
    ret = i2d_PUBKEY(pktmp, pp);
    EVP_PKEY_free(pktmp);
    return ret;
}
#endif

EC_KEY *d2i_EC_PUBKEY(EC_KEY **a, const uint8_t **pp, long length)
{
    EVP_PKEY *pkey;
    EC_KEY *key;
    const uint8_t *q;
    q = *pp;
    pkey = d2i_PUBKEY(NULL, &q, length);
    if (!pkey)
        return (NULL);
    key = EVP_PKEY_get1_EC_KEY(pkey);
    EVP_PKEY_free(pkey);
    if (!key)
        return (NULL);
    *pp = q;
    if (a) {
        EC_KEY_free(*a);
        *a = key;
    }
    return (key);
}

int i2d_EC_PUBKEY(EC_KEY *a, uint8_t **pp)
{
    EVP_PKEY *pktmp;
    int ret;
    if (!a)
        return (0);
    if ((pktmp = EVP_PKEY_new()) == NULL) {
        ASN1err(ASN1_F_I2D_EC_PUBKEY, ERR_R_MALLOC_FAILURE);
        return (0);
    }
    EVP_PKEY_set1_EC_KEY(pktmp, a);
    ret = i2d_PUBKEY(pktmp, pp);
    EVP_PKEY_free(pktmp);
    return (ret);
}

int X509_PUBKEY_set0_param(X509_PUBKEY *pub, ASN1_OBJECT *aobj,
                           int ptype, void *pval,
                           uint8_t *penc, int penclen)
{
    if (!X509_ALGOR_set0(pub->algor, aobj, ptype, pval))
        return 0;
    if (penc) {
        if (pub->public_key->data)
            free(pub->public_key->data);
        pub->public_key->data = penc;
        pub->public_key->length = penclen;
        /* Set number of unused bits to zero */
        pub->public_key->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
        pub->public_key->flags |= ASN1_STRING_FLAG_BITS_LEFT;
    }
    return 1;
}

int X509_PUBKEY_get0_param(ASN1_OBJECT **ppkalg,
                           const uint8_t **pk, int *ppklen,
                           X509_ALGOR **pa,
                           X509_PUBKEY *pub)
{
    if (ppkalg)
        *ppkalg = pub->algor->algorithm;
    if (pk) {
        *pk = pub->public_key->data;
        *ppklen = pub->public_key->length;
    }
    if (pa)
        *pa = pub->algor;
    return 1;
}
