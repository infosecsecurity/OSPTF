/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

int EVP_CIPHER_param_to_asn1(EVP_CIPHER_CTX *c, ASN1_TYPE *type)
{
    int ret;

    if (c->cipher->set_asn1_parameters != NULL)
        ret = c->cipher->set_asn1_parameters(c, type);
    else if (c->cipher->flags & EVP_CIPH_FLAG_DEFAULT_ASN1)
        switch (EVP_CIPHER_CTX_mode(c)) {
            case EVP_CIPH_WRAP_MODE:
                if (EVP_CIPHER_CTX_nid(c) == NID_id_smime_alg_CMS3DESwrap)
                    ASN1_TYPE_set(type, V_ASN1_NULL, NULL);
                ret = 1;
                break;

            case EVP_CIPH_GCM_MODE:
            case EVP_CIPH_CCM_MODE:
            case EVP_CIPH_XTS_MODE:
                ret = -1;
                break;
            default:
                ret = EVP_CIPHER_set_asn1_iv(c, type);
                break;
        }
    else
        ret = -1;
    return ret;
}

int EVP_CIPHER_asn1_to_param(EVP_CIPHER_CTX *c, ASN1_TYPE *type)
{
    int ret;

    if (c->cipher->get_asn1_parameters != NULL)
        ret = c->cipher->get_asn1_parameters(c, type);
    else if (c->cipher->flags & EVP_CIPH_FLAG_DEFAULT_ASN1) {
        switch (EVP_CIPHER_CTX_mode(c)) {
            case EVP_CIPH_WRAP_MODE:
                ret = 1;
                break;

            case EVP_CIPH_GCM_MODE:
            case EVP_CIPH_CCM_MODE:
            case EVP_CIPH_XTS_MODE:
                ret = -1;
                break;
            default:
                ret = EVP_CIPHER_get_asn1_iv(c, type);
                break;
        }
    } else
        ret = -1;
    return (ret);
}

int EVP_CIPHER_get_asn1_iv(EVP_CIPHER_CTX *c, ASN1_TYPE *type)
{
    int i = 0;
    unsigned int l;

    if (type != NULL) {
        l = EVP_CIPHER_CTX_iv_length(c);
        OPENSSL_assert(l <= sizeof(c->iv));
        i = ASN1_TYPE_get_octetstring(type, c->oiv, l);
        if (i != (int)l)
            return (-1);
        else if (i > 0)
            memcpy(c->iv, c->oiv, l);
    }
    return (i);
}

int EVP_CIPHER_set_asn1_iv(EVP_CIPHER_CTX *c, ASN1_TYPE *type)
{
    int i = 0;
    unsigned int j;

    if (type != NULL) {
        j = EVP_CIPHER_CTX_iv_length(c);
        OPENSSL_assert(j <= sizeof(c->iv));
        i = ASN1_TYPE_set_octetstring(type, c->oiv, j);
    }
    return (i);
}

/* Convert the various cipher NIDs and dummies to a proper OID NID */
int EVP_CIPHER_type(const EVP_CIPHER *ctx)
{
    int nid;
    ASN1_OBJECT *otmp;
    nid = EVP_CIPHER_nid(ctx);

    switch (nid) {

        case NID_rc2_cbc:
        case NID_rc2_64_cbc:
        case NID_rc2_40_cbc:

            return NID_rc2_cbc;

        case NID_rc4:
        case NID_rc4_40:

            return NID_rc4;

        case NID_aes_128_cfb128:
        case NID_aes_128_cfb8:
        case NID_aes_128_cfb1:

            return NID_aes_128_cfb128;

        case NID_aes_192_cfb128:
        case NID_aes_192_cfb8:
        case NID_aes_192_cfb1:

            return NID_aes_192_cfb128;

        case NID_aes_256_cfb128:
        case NID_aes_256_cfb8:
        case NID_aes_256_cfb1:

            return NID_aes_256_cfb128;

        case NID_des_ede3_cfb64:
        case NID_des_ede3_cfb8:
        case NID_des_ede3_cfb1:

            return NID_des_cfb64;

        default:
            /* Check it has an OID and it is valid */
            otmp = OBJ_nid2obj(nid);
            if (OBJ_get0_data(otmp) == NULL)
                nid = NID_undef;
            ASN1_OBJECT_free(otmp);
            return nid;
    }
}

int EVP_CIPHER_block_size(const EVP_CIPHER *e)
{
    return e->block_size;
}

int EVP_CIPHER_CTX_block_size(const EVP_CIPHER_CTX *ctx)
{
    return ctx->cipher->block_size;
}

int EVP_Cipher(EVP_CIPHER_CTX *ctx, uint8_t *out, const uint8_t *in, unsigned int inl)
{
    return ctx->cipher->do_cipher(ctx, out, in, inl);
}

const EVP_CIPHER *EVP_CIPHER_CTX_cipher(const EVP_CIPHER_CTX *ctx)
{
    return ctx->cipher;
}

unsigned long EVP_CIPHER_flags(const EVP_CIPHER *cipher)
{
    return cipher->flags;
}

unsigned long EVP_CIPHER_CTX_flags(const EVP_CIPHER_CTX *ctx)
{
    return ctx->cipher->flags;
}

void *EVP_CIPHER_CTX_get_app_data(const EVP_CIPHER_CTX *ctx)
{
    return ctx->app_data;
}

void EVP_CIPHER_CTX_set_app_data(EVP_CIPHER_CTX *ctx, void *data)
{
    ctx->app_data = data;
}

int EVP_CIPHER_iv_length(const EVP_CIPHER *cipher)
{
    return cipher->iv_len;
}

int EVP_CIPHER_CTX_iv_length(const EVP_CIPHER_CTX *ctx)
{
    return ctx->cipher->iv_len;
}

int EVP_CIPHER_key_length(const EVP_CIPHER *cipher)
{
    return cipher->key_len;
}

int EVP_CIPHER_CTX_key_length(const EVP_CIPHER_CTX *ctx)
{
    return ctx->key_len;
}

int EVP_CIPHER_nid(const EVP_CIPHER *cipher)
{
    return cipher->nid;
}

int EVP_CIPHER_CTX_nid(const EVP_CIPHER_CTX *ctx)
{
    return ctx->cipher->nid;
}

int EVP_MD_block_size(const EVP_MD *md)
{
    return md->block_size;
}

int EVP_MD_type(const EVP_MD *md)
{
    return md->type;
}

int EVP_MD_pkey_type(const EVP_MD *md)
{
    return md->pkey_type;
}

int EVP_MD_size(const EVP_MD *md)
{
    if (!md) {
        EVPerr(EVP_F_EVP_MD_SIZE, EVP_R_MESSAGE_DIGEST_IS_NULL);
        return -1;
    }
    return md->md_size;
}

unsigned long EVP_MD_flags(const EVP_MD *md)
{
    return md->flags;
}

const EVP_MD *EVP_MD_CTX_md(const EVP_MD_CTX *ctx)
{
    if (!ctx)
        return NULL;
    return ctx->digest;
}

void EVP_MD_CTX_set_flags(EVP_MD_CTX *ctx, int flags)
{
    ctx->flags |= flags;
}

void EVP_MD_CTX_clear_flags(EVP_MD_CTX *ctx, int flags)
{
    ctx->flags &= ~flags;
}

int EVP_MD_CTX_test_flags(const EVP_MD_CTX *ctx, int flags)
{
    return (ctx->flags & flags);
}

void EVP_CIPHER_CTX_set_flags(EVP_CIPHER_CTX *ctx, int flags)
{
    ctx->flags |= flags;
}

void EVP_CIPHER_CTX_clear_flags(EVP_CIPHER_CTX *ctx, int flags)
{
    ctx->flags &= ~flags;
}

int EVP_CIPHER_CTX_test_flags(const EVP_CIPHER_CTX *ctx, int flags)
{
    return (ctx->flags & flags);
}
