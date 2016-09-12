/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stddef.h>
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/asn1t.h>
#include <string.h>

#include "asn1_locl.h"

static int asn1_primitive_new(ASN1_VALUE **pval, const ASN1_ITEM *it);
static void asn1_item_clear(ASN1_VALUE **pval, const ASN1_ITEM *it);
static int asn1_template_new(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt);
static void asn1_template_clear(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt);
static void asn1_primitive_clear(ASN1_VALUE **pval, const ASN1_ITEM *it);

ASN1_VALUE *ASN1_item_new(const ASN1_ITEM *it)
{
    ASN1_VALUE *ret = NULL;
    if (ASN1_item_ex_new(&ret, it) > 0)
        return ret;
    return NULL;
}

/* Allocate an ASN1 structure */

int ASN1_item_ex_new(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    const ASN1_TEMPLATE *tt = NULL;
    const ASN1_EXTERN_FUNCS *ef;
    const ASN1_AUX *aux = it->funcs;
    ASN1_aux_cb *asn1_cb;
    ASN1_VALUE **pseqval;
    int i;
    if (aux && aux->asn1_cb)
        asn1_cb = aux->asn1_cb;
    else
        asn1_cb = 0;

    *pval = NULL;

    switch (it->itype) {

        case ASN1_ITYPE_EXTERN:
            ef = it->funcs;
            if (ef && ef->asn1_ex_new) {
                if (!ef->asn1_ex_new(pval, it))
                    goto memerr;
            }
            break;

        case ASN1_ITYPE_PRIMITIVE:
            if (it->templates) {
                if (!asn1_template_new(pval, it->templates))
                    goto memerr;
            } else if (!asn1_primitive_new(pval, it))
                goto memerr;
            break;

        case ASN1_ITYPE_MSTRING:
            if (!asn1_primitive_new(pval, it))
                goto memerr;
            break;

        case ASN1_ITYPE_CHOICE:
            if (asn1_cb) {
                i = asn1_cb(ASN1_OP_NEW_PRE, pval, it, NULL);
                if (!i)
                    goto auxerr;
                if (i == 2)
                    return 1;
            }
            *pval = calloc(1, it->size);
            if (*pval == NULL)
                goto memerr;
            asn1_set_choice_selector(pval, -1, it);
            if (asn1_cb && !asn1_cb(ASN1_OP_NEW_POST, pval, it, NULL))
                goto auxerr;
            break;

        case ASN1_ITYPE_NDEF_SEQUENCE:
        case ASN1_ITYPE_SEQUENCE:
            if (asn1_cb) {
                i = asn1_cb(ASN1_OP_NEW_PRE, pval, it, NULL);
                if (i == 0)
                    goto auxerr;
                if (i == 2)
                    return 1;
            }
            *pval = calloc(1, it->size);
            if (*pval == NULL)
                goto memerr;
            asn1_do_lock(pval, 0, it);
            asn1_enc_init(pval, it);
            for (i = 0, tt = it->templates; i < it->tcount; tt++, i++) {
                pseqval = asn1_get_field_ptr(pval, tt);
                if (!asn1_template_new(pseqval, tt))
                    goto memerr;
            }
            if (asn1_cb && !asn1_cb(ASN1_OP_NEW_POST, pval, it, NULL))
                goto auxerr;
            break;
    }
    return 1;

memerr:
    ASN1err(ASN1_F_ASN1_ITEM_EX_NEW, ERR_R_MALLOC_FAILURE);
    return 0;

auxerr:
    ASN1err(ASN1_F_ASN1_ITEM_EX_NEW, ASN1_R_AUX_ERROR);
    ASN1_item_ex_free(pval, it);
    return 0;
}

static void asn1_item_clear(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    const ASN1_EXTERN_FUNCS *ef;

    switch (it->itype) {

        case ASN1_ITYPE_EXTERN:
            ef = it->funcs;
            if (ef && ef->asn1_ex_clear)
                ef->asn1_ex_clear(pval, it);
            else
                *pval = NULL;
            break;

        case ASN1_ITYPE_PRIMITIVE:
            if (it->templates)
                asn1_template_clear(pval, it->templates);
            else
                asn1_primitive_clear(pval, it);
            break;

        case ASN1_ITYPE_MSTRING:
            asn1_primitive_clear(pval, it);
            break;

        case ASN1_ITYPE_CHOICE:
        case ASN1_ITYPE_SEQUENCE:
        case ASN1_ITYPE_NDEF_SEQUENCE:
            *pval = NULL;
            break;
    }
}

int asn1_template_new(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt)
{
    const ASN1_ITEM *it = ASN1_ITEM_ptr(tt->item);
    int ret;
    if (tt->flags & ASN1_TFLG_OPTIONAL) {
        asn1_template_clear(pval, tt);
        return 1;
    }
    /* If ANY DEFINED BY nothing to do */

    if (tt->flags & ASN1_TFLG_ADB_MASK) {
        *pval = NULL;
        return 1;
    }
    /* If SET OF or SEQUENCE OF, its a STACK */
    if (tt->flags & ASN1_TFLG_SK_MASK) {
        STACK_OF(ASN1_VALUE) *skval;
        skval = sk_ASN1_VALUE_new_null();
        if (!skval) {
            ASN1err(ASN1_F_ASN1_TEMPLATE_NEW, ERR_R_MALLOC_FAILURE);
            ret = 0;
            goto done;
        }
        *pval = (ASN1_VALUE *)skval;
        ret = 1;
        goto done;
    }
    /* Otherwise pass it back to the item routine */
    ret = ASN1_item_ex_new(pval, it);
done:
    return ret;
}

static void asn1_template_clear(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt)
{
    /* If ADB or STACK just NULL the field */
    if (tt->flags & (ASN1_TFLG_ADB_MASK | ASN1_TFLG_SK_MASK))
        *pval = NULL;
    else
        asn1_item_clear(pval, ASN1_ITEM_ptr(tt->item));
}

/* NB: could probably combine most of the real XXX_new() behaviour and junk
 * all the old functions.
 */

int asn1_primitive_new(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    ASN1_TYPE *typ;
    ASN1_STRING *str;
    int utype;

    if (it && it->funcs) {
        const ASN1_PRIMITIVE_FUNCS *pf = it->funcs;
        if (pf->prim_new)
            return pf->prim_new(pval, it);
    }

    if (!it || (it->itype == ASN1_ITYPE_MSTRING))
        utype = V_ASN1_UNDEF;
    else
        utype = it->utype;
    switch (utype) {
        case V_ASN1_OBJECT:
            *pval = (ASN1_VALUE *)OBJ_nid2obj(NID_undef);
            return 1;

        case V_ASN1_BOOLEAN:
            *(ASN1_BOOLEAN *)pval = it->size;
            return 1;

        case V_ASN1_NULL:
            *pval = (ASN1_VALUE *)1;
            return 1;

        case V_ASN1_ANY:
            typ = malloc(sizeof(ASN1_TYPE));
            if (typ != NULL) {
                typ->value.ptr = NULL;
                typ->type = V_ASN1_UNDEF;
            }
            *pval = (ASN1_VALUE *)typ;
            break;

        default:
            str = ASN1_STRING_type_new(utype);
            if (it != NULL && it->itype == ASN1_ITYPE_MSTRING && str)
                str->flags |= ASN1_STRING_FLAG_MSTRING;
            *pval = (ASN1_VALUE *)str;
            break;
    }
    if (*pval)
        return 1;
    return 0;
}

static void asn1_primitive_clear(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    int utype;
    if (it && it->funcs) {
        const ASN1_PRIMITIVE_FUNCS *pf = it->funcs;
        if (pf->prim_clear)
            pf->prim_clear(pval, it);
        else
            *pval = NULL;
        return;
    }
    if (!it || (it->itype == ASN1_ITYPE_MSTRING))
        utype = V_ASN1_UNDEF;
    else
        utype = it->utype;
    if (utype == V_ASN1_BOOLEAN)
        *(ASN1_BOOLEAN *)pval = it->size;
    else
        *pval = NULL;
}
