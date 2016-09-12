/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/err.h>
#include <openssl/x509v3.h>

static ASN1_OCTET_STRING *s2i_skey_id(X509V3_EXT_METHOD *method, X509V3_CTX *ctx, char *str);
const X509V3_EXT_METHOD v3_skey_id = {
    NID_subject_key_identifier, 0, ASN1_ITEM_ref(ASN1_OCTET_STRING),
    0, 0, 0, 0,
    (X509V3_EXT_I2S)i2s_ASN1_OCTET_STRING,
    (X509V3_EXT_S2I)s2i_skey_id,
    0, 0, 0, 0,
    NULL
};

char *i2s_ASN1_OCTET_STRING(X509V3_EXT_METHOD *method,
                            ASN1_OCTET_STRING *oct)
{
    return hex_to_string(oct->data, oct->length);
}

ASN1_OCTET_STRING *s2i_ASN1_OCTET_STRING(X509V3_EXT_METHOD *method,
                                         X509V3_CTX *ctx, char *str)
{
    ASN1_OCTET_STRING *oct;
    long length;

    if (!(oct = ASN1_OCTET_STRING_new())) {
        X509V3err(X509V3_F_S2I_ASN1_OCTET_STRING, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!(oct->data = string_to_hex(str, &length))) {
        ASN1_OCTET_STRING_free(oct);
        return NULL;
    }

    oct->length = length;

    return oct;
}

static ASN1_OCTET_STRING *s2i_skey_id(X509V3_EXT_METHOD *method,
                                      X509V3_CTX *ctx, char *str)
{
    ASN1_OCTET_STRING *oct;
    ASN1_BIT_STRING *pk;
    uint8_t pkey_dig[EVP_MAX_MD_SIZE];
    unsigned int diglen;

    if (strcmp(str, "hash"))
        return s2i_ASN1_OCTET_STRING(method, ctx, str);

    if (!(oct = ASN1_OCTET_STRING_new())) {
        X509V3err(X509V3_F_S2I_SKEY_ID, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (ctx && (ctx->flags == CTX_TEST))
        return oct;

    if (!ctx || (!ctx->subject_req && !ctx->subject_cert)) {
        X509V3err(X509V3_F_S2I_SKEY_ID, X509V3_R_NO_PUBLIC_KEY);
        goto err;
    }

    if (ctx->subject_req)
        pk = ctx->subject_req->req_info->pubkey->public_key;
    else
        pk = ctx->subject_cert->cert_info->key->public_key;

    if (!pk) {
        X509V3err(X509V3_F_S2I_SKEY_ID, X509V3_R_NO_PUBLIC_KEY);
        goto err;
    }

    if (!EVP_Digest(pk->data, pk->length, pkey_dig, &diglen, EVP_sha1(), NULL))
        goto err;

    if (!ASN1_OCTET_STRING_set(oct, pkey_dig, diglen)) {
        X509V3err(X509V3_F_S2I_SKEY_ID, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    return oct;

err:
    ASN1_OCTET_STRING_free(oct);
    return NULL;
}
