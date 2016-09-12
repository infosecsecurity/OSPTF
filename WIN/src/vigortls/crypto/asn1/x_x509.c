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
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

ASN1_SEQUENCE_enc(X509_CINF, enc, 0) = {
    ASN1_EXP_OPT(X509_CINF, version, ASN1_INTEGER, 0),
    ASN1_SIMPLE(X509_CINF, serialNumber, ASN1_INTEGER),
    ASN1_SIMPLE(X509_CINF, signature, X509_ALGOR),
    ASN1_SIMPLE(X509_CINF, issuer, X509_NAME),
    ASN1_SIMPLE(X509_CINF, validity, X509_VAL),
    ASN1_SIMPLE(X509_CINF, subject, X509_NAME),
    ASN1_SIMPLE(X509_CINF, key, X509_PUBKEY),
    ASN1_IMP_OPT(X509_CINF, issuerUID, ASN1_BIT_STRING, 1),
    ASN1_IMP_OPT(X509_CINF, subjectUID, ASN1_BIT_STRING, 2),
    ASN1_EXP_SEQUENCE_OF_OPT(X509_CINF, extensions, X509_EXTENSION, 3)
} ASN1_SEQUENCE_END_enc(X509_CINF, X509_CINF)

X509_CINF *d2i_X509_CINF(X509_CINF **a, const uint8_t **in, long len)
{
    return (X509_CINF *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(X509_CINF));
}

int i2d_X509_CINF(X509_CINF *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(X509_CINF));
}

X509_CINF *X509_CINF_new(void)
{
    return (X509_CINF *)ASN1_item_new(ASN1_ITEM_rptr(X509_CINF));
}

void X509_CINF_free(X509_CINF *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(X509_CINF));
}

/* X509 top level structure needs a bit of customisation */

extern void policy_cache_free(X509_POLICY_CACHE * cache);

static int x509_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                   void *exarg)
{
    X509 *ret = (X509 *)*pval;

    switch (operation) {

        case ASN1_OP_NEW_POST:
            ret->valid = 0;
            ret->name = NULL;
            ret->ex_flags = 0;
            ret->ex_pathlen = -1;
            ret->skid = NULL;
            ret->akid = NULL;
            ret->aux = NULL;
            ret->crldp = NULL;
            CRYPTO_new_ex_data(CRYPTO_EX_INDEX_X509, ret, &ret->ex_data);
            break;

        case ASN1_OP_D2I_POST:
            free(ret->name);
            ret->name = X509_NAME_oneline(ret->cert_info->subject, NULL, 0);
            break;

        case ASN1_OP_FREE_POST:
            CRYPTO_free_ex_data(CRYPTO_EX_INDEX_X509, ret, &ret->ex_data);
            X509_CERT_AUX_free(ret->aux);
            ASN1_OCTET_STRING_free(ret->skid);
            AUTHORITY_KEYID_free(ret->akid);
            CRL_DIST_POINTS_free(ret->crldp);
            policy_cache_free(ret->policy_cache);
            GENERAL_NAMES_free(ret->altname);
            NAME_CONSTRAINTS_free(ret->nc);
            free(ret->name);
            break;
    }

    return 1;
}

ASN1_SEQUENCE_ref(X509, x509_cb) = {
    ASN1_SIMPLE(X509, cert_info, X509_CINF),
    ASN1_SIMPLE(X509, sig_alg, X509_ALGOR),
    ASN1_SIMPLE(X509, signature, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END_ref(X509, X509)

X509 *d2i_X509(X509 **a, const uint8_t **in, long len)
{
    return (X509 *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(X509));
}

int i2d_X509(X509 *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(X509));
}

X509 *X509_new(void)
{
    return (X509 *)ASN1_item_new(ASN1_ITEM_rptr(X509));
}

void X509_free(X509 *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(X509));
}

X509 *X509_dup(X509 *x)
{
    return ASN1_item_dup(ASN1_ITEM_rptr(X509), x);
}

int X509_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
                          CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
{
    return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509, argl, argp,
                                   new_func, dup_func, free_func);
}

int X509_set_ex_data(X509 *r, int idx, void *arg)
{
    return (CRYPTO_set_ex_data(&r->ex_data, idx, arg));
}

void *X509_get_ex_data(X509 *r, int idx)
{
    return (CRYPTO_get_ex_data(&r->ex_data, idx));
}

/* X509_AUX ASN1 routines. X509_AUX is the name given to
 * a certificate with extra info tagged on the end. Since these
 * functions set how a certificate is trusted they should only
 * be used when the certificate comes from a reliable source
 * such as local storage.
 *
 */

X509 *d2i_X509_AUX(X509 **a, const uint8_t **pp, long length)
{
    const uint8_t *q;
    X509 *ret;
    int freeret = 0;
    
    /* Save start position */
    q = *pp;
    
    if (!a || *a == NULL) {
        freeret = 1;
    }
    ret = d2i_X509(a, &q, length);
    /* If certificate unreadable then forget it */
    if (!ret)
        return NULL;
    /* update length */
    length -=  q - *pp;
    if (length > 0 && !d2i_X509_CERT_AUX(&ret->aux, &q, length))
        goto err;
    *pp = q;
    return ret;
err:
    if (freeret) {
        X509_free(ret);
        if (a)
            *a = NULL;
    }
    return NULL;
}

int i2d_X509_AUX(X509 *a, uint8_t **pp)
{
    int length, tmplen;
    uint8_t *start = pp != NULL ? *pp : NULL;
    
    length = i2d_X509(a, pp);
    if (length < 0 || a == NULL)
        return length;
    
    tmplen = i2d_X509_CERT_AUX(a->aux, pp);
    if (tmplen < 0) {
        if (start != NULL)
            *pp = start;
        return tmplen;
    }
    length += tmplen;

    return length;
}

int i2d_re_X509_tbs(X509 *x, uint8_t **pp)
{
    x->cert_info->enc.modified = 1;
    return i2d_X509_CINF(x->cert_info, pp);
}

void X509_get0_signature(ASN1_BIT_STRING **psig, X509_ALGOR **palg,
                         const X509 *x)
{
    if (psig)
        *psig = x->signature;
    if (palg)
        *palg = x->sig_alg;
}

int X509_get_signature_nid(const X509 *x)
{
    return OBJ_obj2nid(x->sig_alg->algorithm);
}
