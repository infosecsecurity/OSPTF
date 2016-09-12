/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <stdcompat.h>

static STACK_OF(CONF_VALUE) *i2v_AUTHORITY_INFO_ACCESS(X509V3_EXT_METHOD *method,
                                                        AUTHORITY_INFO_ACCESS *ainfo,
                                                        STACK_OF(CONF_VALUE) *ret);
static AUTHORITY_INFO_ACCESS *v2i_AUTHORITY_INFO_ACCESS(X509V3_EXT_METHOD *method,
                                                        X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval);

const X509V3_EXT_METHOD v3_info = { NID_info_access, X509V3_EXT_MULTILINE, ASN1_ITEM_ref(AUTHORITY_INFO_ACCESS),
                                    0, 0, 0, 0,
                                    0, 0,
                                    (X509V3_EXT_I2V)i2v_AUTHORITY_INFO_ACCESS,
                                    (X509V3_EXT_V2I)v2i_AUTHORITY_INFO_ACCESS,
                                    0, 0,
                                    NULL };

const X509V3_EXT_METHOD v3_sinfo = { NID_sinfo_access, X509V3_EXT_MULTILINE, ASN1_ITEM_ref(AUTHORITY_INFO_ACCESS),
                                     0, 0, 0, 0,
                                     0, 0,
                                     (X509V3_EXT_I2V)i2v_AUTHORITY_INFO_ACCESS,
                                     (X509V3_EXT_V2I)v2i_AUTHORITY_INFO_ACCESS,
                                     0, 0,
                                     NULL };

ASN1_SEQUENCE(ACCESS_DESCRIPTION) = {
    ASN1_SIMPLE(ACCESS_DESCRIPTION, method, ASN1_OBJECT),
    ASN1_SIMPLE(ACCESS_DESCRIPTION, location, GENERAL_NAME)
} ASN1_SEQUENCE_END(ACCESS_DESCRIPTION)

ACCESS_DESCRIPTION *d2i_ACCESS_DESCRIPTION(ACCESS_DESCRIPTION **a, const uint8_t **in, long len)
{
    return (ACCESS_DESCRIPTION *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(ACCESS_DESCRIPTION));
}

int i2d_ACCESS_DESCRIPTION(ACCESS_DESCRIPTION *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(ACCESS_DESCRIPTION));
}

ACCESS_DESCRIPTION *ACCESS_DESCRIPTION_new(void)
{
    return (ACCESS_DESCRIPTION *)ASN1_item_new(ASN1_ITEM_rptr(ACCESS_DESCRIPTION));
}

void ACCESS_DESCRIPTION_free(ACCESS_DESCRIPTION *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(ACCESS_DESCRIPTION));
}

ASN1_ITEM_TEMPLATE(AUTHORITY_INFO_ACCESS) = ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, GeneralNames, ACCESS_DESCRIPTION)
ASN1_ITEM_TEMPLATE_END(AUTHORITY_INFO_ACCESS)

AUTHORITY_INFO_ACCESS *d2i_AUTHORITY_INFO_ACCESS(AUTHORITY_INFO_ACCESS **a, const uint8_t **in, long len)
{
    return (AUTHORITY_INFO_ACCESS *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(AUTHORITY_INFO_ACCESS));
}

int i2d_AUTHORITY_INFO_ACCESS(AUTHORITY_INFO_ACCESS *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(AUTHORITY_INFO_ACCESS));
}

AUTHORITY_INFO_ACCESS *AUTHORITY_INFO_ACCESS_new(void)
{
    return (AUTHORITY_INFO_ACCESS *)ASN1_item_new(ASN1_ITEM_rptr(AUTHORITY_INFO_ACCESS));
}

void AUTHORITY_INFO_ACCESS_free(AUTHORITY_INFO_ACCESS *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(AUTHORITY_INFO_ACCESS));
}

static STACK_OF(CONF_VALUE) *i2v_AUTHORITY_INFO_ACCESS(X509V3_EXT_METHOD *method,
                                                       AUTHORITY_INFO_ACCESS * ainfo,
                                                       STACK_OF(CONF_VALUE) *ret)
{
    ACCESS_DESCRIPTION *desc;
    int i, nlen;
    char objtmp[80], *ntmp;
    CONF_VALUE *vtmp;
    for (i = 0; i < sk_ACCESS_DESCRIPTION_num(ainfo); i++) {
        desc = sk_ACCESS_DESCRIPTION_value(ainfo, i);
        ret = i2v_GENERAL_NAME(method, desc->location, ret);
        if (!ret)
            break;
        vtmp = sk_CONF_VALUE_value(ret, i);
        i2t_ASN1_OBJECT(objtmp, sizeof objtmp, desc->method);
        nlen = strlen(objtmp) + strlen(vtmp->name) + 5;
        ntmp = malloc(nlen);
        if (!ntmp) {
            X509V3err(X509V3_F_I2V_AUTHORITY_INFO_ACCESS,
                      ERR_R_MALLOC_FAILURE);
            return NULL;
        }
        snprintf(ntmp, nlen, "%s - %s", objtmp, vtmp->name);
        free(vtmp->name);
        vtmp->name = ntmp;
    }
    if (!ret)
        return sk_CONF_VALUE_new_null();
    return ret;
}

static AUTHORITY_INFO_ACCESS *v2i_AUTHORITY_INFO_ACCESS(X509V3_EXT_METHOD *method,
                                                        X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval)
{
    AUTHORITY_INFO_ACCESS *ainfo = NULL;
    CONF_VALUE *cnf, ctmp;
    ACCESS_DESCRIPTION *acc;
    int i, objlen;
    char *objtmp, *ptmp;
    if (!(ainfo = sk_ACCESS_DESCRIPTION_new_null())) {
        X509V3err(X509V3_F_V2I_AUTHORITY_INFO_ACCESS, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    for (i = 0; i < sk_CONF_VALUE_num(nval); i++) {
        cnf = sk_CONF_VALUE_value(nval, i);
        if (!(acc = ACCESS_DESCRIPTION_new())
            || !sk_ACCESS_DESCRIPTION_push(ainfo, acc)) {
            X509V3err(X509V3_F_V2I_AUTHORITY_INFO_ACCESS, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        ptmp = strchr(cnf->name, ';');
        if (!ptmp) {
            X509V3err(X509V3_F_V2I_AUTHORITY_INFO_ACCESS, X509V3_R_INVALID_SYNTAX);
            goto err;
        }
        objlen = ptmp - cnf->name;
        ctmp.name = ptmp + 1;
        ctmp.value = cnf->value;
        if (!v2i_GENERAL_NAME_ex(acc->location, method, ctx, &ctmp, 0))
            goto err;
        if (!(objtmp = malloc(objlen + 1))) {
            X509V3err(X509V3_F_V2I_AUTHORITY_INFO_ACCESS, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        strlcpy(objtmp, cnf->name, objlen + 1);
        acc->method = OBJ_txt2obj(objtmp, 0);
        if (!acc->method) {
            X509V3err(X509V3_F_V2I_AUTHORITY_INFO_ACCESS, X509V3_R_BAD_OBJECT);
            ERR_asprintf_error_data("value=%s", objtmp);
            free(objtmp);
            goto err;
        }
        free(objtmp);
    }
    return ainfo;
err:
    sk_ACCESS_DESCRIPTION_pop_free(ainfo, ACCESS_DESCRIPTION_free);
    return NULL;
}

int i2a_ACCESS_DESCRIPTION(BIO *bp, ACCESS_DESCRIPTION *a)
{
    i2a_ASN1_OBJECT(bp, a->method);
    return 2;
}
