/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

/* Declarations for string types */

IMPLEMENT_ASN1_TYPE(ASN1_INTEGER)

ASN1_INTEGER *d2i_ASN1_INTEGER(ASN1_INTEGER **a, const uint8_t **in, long len)
{
    return (ASN1_INTEGER *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(ASN1_INTEGER));
}

int i2d_ASN1_INTEGER(ASN1_INTEGER *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(ASN1_INTEGER));
}

ASN1_INTEGER *ASN1_INTEGER_new(void)
{
    return (ASN1_INTEGER *)ASN1_item_new(ASN1_ITEM_rptr(ASN1_INTEGER));
}

void ASN1_INTEGER_free(ASN1_INTEGER *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(ASN1_INTEGER));
}

IMPLEMENT_ASN1_TYPE(ASN1_ENUMERATED)

ASN1_ENUMERATED *d2i_ASN1_ENUMERATED(ASN1_ENUMERATED **a, const uint8_t **in, long len)
{
    return (ASN1_ENUMERATED *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(ASN1_ENUMERATED));
}

int i2d_ASN1_ENUMERATED(ASN1_ENUMERATED *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(ASN1_ENUMERATED));
}

ASN1_ENUMERATED *ASN1_ENUMERATED_new(void)
{
    return (ASN1_ENUMERATED *)ASN1_item_new(ASN1_ITEM_rptr(ASN1_ENUMERATED));
}

void ASN1_ENUMERATED_free(ASN1_ENUMERATED *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(ASN1_ENUMERATED));
}

IMPLEMENT_ASN1_TYPE(ASN1_BIT_STRING)

ASN1_BIT_STRING *d2i_ASN1_BIT_STRING(ASN1_BIT_STRING **a, const uint8_t **in, long len)
{
    return (ASN1_BIT_STRING *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(ASN1_BIT_STRING));
}

int i2d_ASN1_BIT_STRING(ASN1_BIT_STRING *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(ASN1_BIT_STRING));
}

ASN1_BIT_STRING *ASN1_BIT_STRING_new(void)
{
    return (ASN1_BIT_STRING *)ASN1_item_new(ASN1_ITEM_rptr(ASN1_BIT_STRING));
}

void ASN1_BIT_STRING_free(ASN1_BIT_STRING *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(ASN1_BIT_STRING));
}

IMPLEMENT_ASN1_TYPE(ASN1_OCTET_STRING)

ASN1_OCTET_STRING *d2i_ASN1_OCTET_STRING(ASN1_OCTET_STRING **a, const uint8_t **in, long len)
{
    return (ASN1_OCTET_STRING *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(ASN1_OCTET_STRING));
}

int i2d_ASN1_OCTET_STRING(ASN1_OCTET_STRING *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(ASN1_OCTET_STRING));
}

ASN1_OCTET_STRING *ASN1_OCTET_STRING_new(void)
{
    return (ASN1_OCTET_STRING *)ASN1_item_new(ASN1_ITEM_rptr(ASN1_OCTET_STRING));
}

void ASN1_OCTET_STRING_free(ASN1_OCTET_STRING *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(ASN1_OCTET_STRING));
}

IMPLEMENT_ASN1_TYPE(ASN1_NULL)

ASN1_NULL *d2i_ASN1_NULL(ASN1_NULL **a, const uint8_t **in, long len)
{
    return (ASN1_NULL *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(ASN1_NULL));
}

int i2d_ASN1_NULL(ASN1_NULL *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(ASN1_NULL));
}

ASN1_NULL *ASN1_NULL_new(void)
{
    return (ASN1_NULL *)ASN1_item_new(ASN1_ITEM_rptr(ASN1_NULL));
}

void ASN1_NULL_free(ASN1_NULL *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(ASN1_NULL));
}

IMPLEMENT_ASN1_TYPE(ASN1_OBJECT)

IMPLEMENT_ASN1_TYPE(ASN1_UTF8STRING)

ASN1_UTF8STRING *d2i_ASN1_UTF8STRING(ASN1_UTF8STRING **a, const uint8_t **in, long len)
{
    return (ASN1_UTF8STRING *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(ASN1_UTF8STRING));
}

int i2d_ASN1_UTF8STRING(ASN1_UTF8STRING *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(ASN1_UTF8STRING));
}

ASN1_UTF8STRING *ASN1_UTF8STRING_new(void)
{
    return (ASN1_UTF8STRING *)ASN1_item_new(ASN1_ITEM_rptr(ASN1_UTF8STRING));
}

void ASN1_UTF8STRING_free(ASN1_UTF8STRING *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(ASN1_UTF8STRING));
}

IMPLEMENT_ASN1_TYPE(ASN1_PRINTABLESTRING)

ASN1_PRINTABLESTRING *d2i_ASN1_PRINTABLESTRING(ASN1_PRINTABLESTRING **a, const uint8_t **in, long len)
{
    return (ASN1_PRINTABLESTRING *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(ASN1_PRINTABLESTRING));
}

int i2d_ASN1_PRINTABLESTRING(ASN1_PRINTABLESTRING *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(ASN1_PRINTABLESTRING));
}

ASN1_PRINTABLESTRING *ASN1_PRINTABLESTRING_new(void)
{
    return (ASN1_PRINTABLESTRING *)ASN1_item_new(ASN1_ITEM_rptr(ASN1_PRINTABLESTRING));
}

void ASN1_PRINTABLESTRING_free(ASN1_PRINTABLESTRING *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(ASN1_PRINTABLESTRING));
}

IMPLEMENT_ASN1_TYPE(ASN1_T61STRING)

ASN1_T61STRING *d2i_ASN1_T61STRING(ASN1_T61STRING **a, const uint8_t **in, long len)
{
    return (ASN1_T61STRING *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(ASN1_T61STRING));
}

int i2d_ASN1_T61STRING(ASN1_T61STRING *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(ASN1_T61STRING));
}

ASN1_T61STRING *ASN1_T61STRING_new(void)
{
    return (ASN1_T61STRING *)ASN1_item_new(ASN1_ITEM_rptr(ASN1_T61STRING));
}

void ASN1_T61STRING_free(ASN1_T61STRING *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(ASN1_T61STRING));
}

IMPLEMENT_ASN1_TYPE(ASN1_IA5STRING)

ASN1_IA5STRING *d2i_ASN1_IA5STRING(ASN1_IA5STRING **a, const uint8_t **in, long len)
{
    return (ASN1_IA5STRING *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(ASN1_IA5STRING));
}

int i2d_ASN1_IA5STRING(ASN1_IA5STRING *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(ASN1_IA5STRING));
}

ASN1_IA5STRING *ASN1_IA5STRING_new(void)
{
    return (ASN1_IA5STRING *)ASN1_item_new(ASN1_ITEM_rptr(ASN1_IA5STRING));
}

void ASN1_IA5STRING_free(ASN1_IA5STRING *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(ASN1_IA5STRING));
}

IMPLEMENT_ASN1_TYPE(ASN1_GENERALSTRING)

ASN1_GENERALSTRING *d2i_ASN1_GENERALSTRING(ASN1_GENERALSTRING **a, const uint8_t **in, long len)
{
    return (ASN1_GENERALSTRING *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(ASN1_GENERALSTRING));
}

int i2d_ASN1_GENERALSTRING(ASN1_GENERALSTRING *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(ASN1_GENERALSTRING));
}

ASN1_GENERALSTRING *ASN1_GENERALSTRING_new(void)
{
    return (ASN1_GENERALSTRING *)ASN1_item_new(ASN1_ITEM_rptr(ASN1_GENERALSTRING));
}

void ASN1_GENERALSTRING_free(ASN1_GENERALSTRING *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(ASN1_GENERALSTRING));
}

IMPLEMENT_ASN1_TYPE(ASN1_UTCTIME)

ASN1_UTCTIME *d2i_ASN1_UTCTIME(ASN1_UTCTIME **a, const uint8_t **in, long len)
{
    return (ASN1_UTCTIME *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(ASN1_UTCTIME));
}

int i2d_ASN1_UTCTIME(ASN1_UTCTIME *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(ASN1_UTCTIME));
}

ASN1_UTCTIME *ASN1_UTCTIME_new(void)
{
    return (ASN1_UTCTIME *)ASN1_item_new(ASN1_ITEM_rptr(ASN1_UTCTIME));
}

void ASN1_UTCTIME_free(ASN1_UTCTIME *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(ASN1_UTCTIME));
}

IMPLEMENT_ASN1_TYPE(ASN1_GENERALIZEDTIME)

ASN1_GENERALIZEDTIME *d2i_ASN1_GENERALIZEDTIME(ASN1_GENERALIZEDTIME **a, const uint8_t **in, long len)
{
    return (ASN1_GENERALIZEDTIME *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(ASN1_GENERALIZEDTIME));
}

int i2d_ASN1_GENERALIZEDTIME(ASN1_GENERALIZEDTIME *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(ASN1_GENERALIZEDTIME));
}

ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_new(void)
{
    return (ASN1_GENERALIZEDTIME *)ASN1_item_new(ASN1_ITEM_rptr(ASN1_GENERALIZEDTIME));
}

void ASN1_GENERALIZEDTIME_free(ASN1_GENERALIZEDTIME *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(ASN1_GENERALIZEDTIME));
}

IMPLEMENT_ASN1_TYPE(ASN1_VISIBLESTRING)

ASN1_VISIBLESTRING *d2i_ASN1_VISIBLESTRING(ASN1_VISIBLESTRING **a, const uint8_t **in, long len)
{
    return (ASN1_VISIBLESTRING *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(ASN1_VISIBLESTRING));
}

int i2d_ASN1_VISIBLESTRING(ASN1_VISIBLESTRING *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(ASN1_VISIBLESTRING));
}

ASN1_VISIBLESTRING *ASN1_VISIBLESTRING_new(void)
{
    return (ASN1_VISIBLESTRING *)ASN1_item_new(ASN1_ITEM_rptr(ASN1_VISIBLESTRING));
}

void ASN1_VISIBLESTRING_free(ASN1_VISIBLESTRING *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(ASN1_VISIBLESTRING));
}

IMPLEMENT_ASN1_TYPE(ASN1_UNIVERSALSTRING)

ASN1_UNIVERSALSTRING *d2i_ASN1_UNIVERSALSTRING(ASN1_UNIVERSALSTRING **a, const uint8_t **in, long len)
{
    return (ASN1_UNIVERSALSTRING *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(ASN1_UNIVERSALSTRING));
}

int i2d_ASN1_UNIVERSALSTRING(ASN1_UNIVERSALSTRING *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(ASN1_UNIVERSALSTRING));
}

ASN1_UNIVERSALSTRING *ASN1_UNIVERSALSTRING_new(void)
{
    return (ASN1_UNIVERSALSTRING *)ASN1_item_new(ASN1_ITEM_rptr(ASN1_UNIVERSALSTRING));
}

void ASN1_UNIVERSALSTRING_free(ASN1_UNIVERSALSTRING *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(ASN1_UNIVERSALSTRING));
}

IMPLEMENT_ASN1_TYPE(ASN1_BMPSTRING)

ASN1_BMPSTRING *d2i_ASN1_BMPSTRING(ASN1_BMPSTRING **a, const uint8_t **in, long len)
{
    return (ASN1_BMPSTRING *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(ASN1_BMPSTRING));
}

int i2d_ASN1_BMPSTRING(ASN1_BMPSTRING *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(ASN1_BMPSTRING));
}

ASN1_BMPSTRING *ASN1_BMPSTRING_new(void)
{
    return (ASN1_BMPSTRING *)ASN1_item_new(ASN1_ITEM_rptr(ASN1_BMPSTRING));
}

void ASN1_BMPSTRING_free(ASN1_BMPSTRING *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(ASN1_BMPSTRING));
}

IMPLEMENT_ASN1_TYPE(ASN1_ANY)

/* Just swallow an ASN1_SEQUENCE in an ASN1_STRING */
IMPLEMENT_ASN1_TYPE(ASN1_SEQUENCE)

ASN1_TYPE *d2i_ASN1_TYPE(ASN1_TYPE **a, const uint8_t **in, long len)
{
    return (ASN1_TYPE *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(ASN1_ANY));
}

int i2d_ASN1_TYPE(ASN1_TYPE *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(ASN1_ANY));
}

ASN1_TYPE *ASN1_TYPE_new(void)
{
    return (ASN1_TYPE *)ASN1_item_new(ASN1_ITEM_rptr(ASN1_ANY));
}

void ASN1_TYPE_free(ASN1_TYPE *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(ASN1_ANY));
}

/* Multistring types */

IMPLEMENT_ASN1_MSTRING(ASN1_PRINTABLE, B_ASN1_PRINTABLE)

ASN1_STRING *d2i_ASN1_PRINTABLE(ASN1_STRING **a, const uint8_t **in, long len)
{
    return (ASN1_STRING *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(ASN1_PRINTABLE));
}

int i2d_ASN1_PRINTABLE(ASN1_STRING *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(ASN1_PRINTABLE));
}

ASN1_STRING *ASN1_PRINTABLE_new(void)
{
    return (ASN1_STRING *)ASN1_item_new(ASN1_ITEM_rptr(ASN1_PRINTABLE));
}

void ASN1_PRINTABLE_free(ASN1_STRING *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(ASN1_PRINTABLE));
}

IMPLEMENT_ASN1_MSTRING(DISPLAYTEXT, B_ASN1_DISPLAYTEXT)

ASN1_STRING *d2i_DISPLAYTEXT(ASN1_STRING **a, const uint8_t **in, long len)
{
    return (ASN1_STRING *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(DISPLAYTEXT));
}

int i2d_DISPLAYTEXT(ASN1_STRING *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(DISPLAYTEXT));
}

ASN1_STRING *DISPLAYTEXT_new(void)
{
    return (ASN1_STRING *)ASN1_item_new(ASN1_ITEM_rptr(DISPLAYTEXT));
}

void DISPLAYTEXT_free(ASN1_STRING *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(DISPLAYTEXT));
}

IMPLEMENT_ASN1_MSTRING(DIRECTORYSTRING, B_ASN1_DIRECTORYSTRING)

ASN1_STRING *d2i_DIRECTORYSTRING(ASN1_STRING **a, const uint8_t **in, long len)
{
    return (ASN1_STRING *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(DIRECTORYSTRING));
}

int i2d_DIRECTORYSTRING(ASN1_STRING *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(DIRECTORYSTRING));
}

ASN1_STRING *DIRECTORYSTRING_new(void)
{
    return (ASN1_STRING *)ASN1_item_new(ASN1_ITEM_rptr(DIRECTORYSTRING));
}

void DIRECTORYSTRING_free(ASN1_STRING *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(DIRECTORYSTRING));
}

/* Three separate BOOLEAN type: normal, DEFAULT TRUE and DEFAULT FALSE */
IMPLEMENT_ASN1_TYPE_ex(ASN1_BOOLEAN, ASN1_BOOLEAN, -1)
IMPLEMENT_ASN1_TYPE_ex(ASN1_TBOOLEAN, ASN1_BOOLEAN, 1)
IMPLEMENT_ASN1_TYPE_ex(ASN1_FBOOLEAN, ASN1_BOOLEAN, 0)

/* Special, OCTET STRING with indefinite length constructed support */

IMPLEMENT_ASN1_TYPE_ex(ASN1_OCTET_STRING_NDEF, ASN1_OCTET_STRING, ASN1_TFLG_NDEF)

ASN1_ITEM_TEMPLATE(ASN1_SEQUENCE_ANY) = ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, ASN1_SEQUENCE_ANY, ASN1_ANY)
ASN1_ITEM_TEMPLATE_END(ASN1_SEQUENCE_ANY)

ASN1_ITEM_TEMPLATE(ASN1_SET_ANY) = ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SET_OF, 0, ASN1_SET_ANY, ASN1_ANY)
ASN1_ITEM_TEMPLATE_END(ASN1_SET_ANY)

ASN1_SEQUENCE_ANY *d2i_ASN1_SEQUENCE_ANY(ASN1_SEQUENCE_ANY **a, const uint8_t **in, long len)
{
    return (ASN1_SEQUENCE_ANY *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
                                              ASN1_ITEM_rptr(ASN1_SEQUENCE_ANY));
}

int i2d_ASN1_SEQUENCE_ANY(const ASN1_SEQUENCE_ANY *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(ASN1_SEQUENCE_ANY));
}

ASN1_SEQUENCE_ANY *d2i_ASN1_SET_ANY(ASN1_SEQUENCE_ANY **a, const uint8_t **in, long len)
{
    return (ASN1_SEQUENCE_ANY *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
                                              ASN1_ITEM_rptr(ASN1_SET_ANY));
}

int i2d_ASN1_SET_ANY(const ASN1_SEQUENCE_ANY *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(ASN1_SET_ANY));
}
