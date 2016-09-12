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

#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

/* PKCS#5 password based encryption structure */

ASN1_SEQUENCE(PBEPARAM) = {
    ASN1_SIMPLE(PBEPARAM, salt, ASN1_OCTET_STRING),
    ASN1_SIMPLE(PBEPARAM, iter, ASN1_INTEGER)
} ASN1_SEQUENCE_END(PBEPARAM)

PBEPARAM *d2i_PBEPARAM(PBEPARAM **a, const uint8_t **in, long len)
{
    return (PBEPARAM *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(PBEPARAM));
}

int i2d_PBEPARAM(PBEPARAM *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(PBEPARAM));
}

PBEPARAM *PBEPARAM_new(void)
{
    return (PBEPARAM *)ASN1_item_new(ASN1_ITEM_rptr(PBEPARAM));
}

void PBEPARAM_free(PBEPARAM *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(PBEPARAM));
}

/* Set an algorithm identifier for a PKCS#5 PBE algorithm */

int PKCS5_pbe_set0_algor(X509_ALGOR * algor, int alg, int iter,
                         const uint8_t *salt, int saltlen)
{
    PBEPARAM *pbe = NULL;
    ASN1_STRING *pbe_str = NULL;
    uint8_t *sstr;

    pbe = PBEPARAM_new();
    if (!pbe) {
        ASN1err(ASN1_F_PKCS5_PBE_SET0_ALGOR, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (iter <= 0)
        iter = PKCS5_DEFAULT_ITER;
    if (!ASN1_INTEGER_set(pbe->iter, iter)) {
        ASN1err(ASN1_F_PKCS5_PBE_SET0_ALGOR, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (!saltlen)
        saltlen = PKCS5_SALT_LEN;
    if (!ASN1_STRING_set(pbe->salt, NULL, saltlen)) {
        ASN1err(ASN1_F_PKCS5_PBE_SET0_ALGOR, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    sstr = ASN1_STRING_data(pbe->salt);
    if (salt)
        memcpy(sstr, salt, saltlen);
    else if (RAND_bytes(sstr, saltlen) <= 0)
        goto err;

    if (!ASN1_item_pack(pbe, ASN1_ITEM_rptr(PBEPARAM), &pbe_str)) {
        ASN1err(ASN1_F_PKCS5_PBE_SET0_ALGOR, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    PBEPARAM_free(pbe);
    pbe = NULL;

    if (X509_ALGOR_set0(algor, OBJ_nid2obj(alg), V_ASN1_SEQUENCE, pbe_str))
        return 1;

err:
    PBEPARAM_free(pbe);
    ASN1_STRING_free(pbe_str);
    return 0;
}

/* Return an algorithm identifier for a PKCS#5 PBE algorithm */

X509_ALGOR *PKCS5_pbe_set(int alg, int iter,
                          const uint8_t *salt, int saltlen)
{
    X509_ALGOR *ret;
    ret = X509_ALGOR_new();
    if (!ret) {
        ASN1err(ASN1_F_PKCS5_PBE_SET, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (PKCS5_pbe_set0_algor(ret, alg, iter, salt, saltlen))
        return ret;

    X509_ALGOR_free(ret);
    return NULL;
}
