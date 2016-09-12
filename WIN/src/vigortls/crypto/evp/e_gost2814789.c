/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2014 Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 * Copyright (c) 2005-2006 Cryptocom LTD
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_GOST
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/gost.h>
#include "evp_locl.h"

typedef struct {
    GOST2814789_KEY ks;
    int param_nid;
} EVP_GOST2814789_CTX;

static int gost2814789_ctl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    EVP_GOST2814789_CTX *c = ctx->cipher_data;

    switch (type) {
        case EVP_CTRL_PBE_PRF_NID:
            if (ptr) {
                *((int *)ptr) = NID_id_HMACGostR3411_94;
                return 1;
            } else {
                return 0;
            }
        case EVP_CTRL_INIT:
            /* Default value to have any s-box set at all */
            c->param_nid = NID_id_Gost28147_89_CryptoPro_A_ParamSet;
            return Gost2814789_set_sbox(&c->ks, c->param_nid);
        case EVP_CTRL_GOST_SET_SBOX:
            return Gost2814789_set_sbox(&c->ks, arg);
        default:
            return -1;
    }
}

static int gost2814789_init_key(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                                const uint8_t *iv, int enc)
{
    EVP_GOST2814789_CTX *c = ctx->cipher_data;

    return Gost2814789_set_key(&c->ks, key, ctx->key_len * 8);
}

int gost2814789_set_asn1_params(EVP_CIPHER_CTX *ctx, ASN1_TYPE *params)
{
    int len = 0;
    uint8_t *buf = NULL;
    uint8_t *p = NULL;
    EVP_GOST2814789_CTX *c = ctx->cipher_data;
    GOST_CIPHER_PARAMS *gcp = GOST_CIPHER_PARAMS_new();
    ASN1_OCTET_STRING *os = NULL;
    if (!gcp) {
        GOSTerr(GOST_F_GOST89_SET_ASN1_PARAMETERS, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if (!ASN1_OCTET_STRING_set(gcp->iv, ctx->iv, ctx->cipher->iv_len)) {
        GOST_CIPHER_PARAMS_free(gcp);
        GOSTerr(GOST_F_GOST89_SET_ASN1_PARAMETERS, ERR_R_ASN1_LIB);
        return 0;
    }
    ASN1_OBJECT_free(gcp->enc_param_set);
    gcp->enc_param_set = OBJ_nid2obj(c->param_nid);

    len = i2d_GOST_CIPHER_PARAMS(gcp, NULL);
    p = buf = malloc(len);
    if (!buf) {
        GOST_CIPHER_PARAMS_free(gcp);
        GOSTerr(GOST_F_GOST89_SET_ASN1_PARAMETERS, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    i2d_GOST_CIPHER_PARAMS(gcp, &p);
    GOST_CIPHER_PARAMS_free(gcp);

    os = ASN1_OCTET_STRING_new();

    if (!os || !ASN1_OCTET_STRING_set(os, buf, len)) {
        free(buf);
        GOSTerr(GOST_F_GOST89_SET_ASN1_PARAMETERS, ERR_R_ASN1_LIB);
        return 0;
    }
    free(buf);

    ASN1_TYPE_set(params, V_ASN1_SEQUENCE, os);
    return 1;
}

int gost2814789_get_asn1_params(EVP_CIPHER_CTX *ctx, ASN1_TYPE *params)
{
    int ret = -1;
    int len;
    GOST_CIPHER_PARAMS *gcp = NULL;
    EVP_GOST2814789_CTX *c = ctx->cipher_data;
    uint8_t *p;

    if (ASN1_TYPE_get(params) != V_ASN1_SEQUENCE) {
        return ret;
    }

    p = params->value.sequence->data;

    gcp = d2i_GOST_CIPHER_PARAMS(NULL, (const uint8_t **)&p,
                                 params->value.sequence->length);

    len = gcp->iv->length;
    if (len != ctx->cipher->iv_len) {
        GOST_CIPHER_PARAMS_free(gcp);
        GOSTerr(GOST_F_GOST89_GET_ASN1_PARAMETERS, GOST_R_INVALID_IV_LENGTH);
        return -1;
    }

    if (!Gost2814789_set_sbox(&c->ks, OBJ_obj2nid(gcp->enc_param_set))) {
        GOST_CIPHER_PARAMS_free(gcp);
        return -1;
    }
    c->param_nid = OBJ_obj2nid(gcp->enc_param_set);

    memcpy(ctx->oiv, gcp->iv->data, len);
    memcpy(ctx->iv, gcp->iv->data, len);

    GOST_CIPHER_PARAMS_free(gcp);

    return 1;
}

BLOCK_CIPHER_func_ecb(gost2814789, Gost2814789, EVP_GOST2814789_CTX, ks)
    BLOCK_CIPHER_func_cfb(gost2814789, Gost2814789, 64, EVP_GOST2814789_CTX, ks)

        static int gost2814789_cnt_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out,
                                          const uint8_t *in, size_t inl)
{
    EVP_GOST2814789_CTX *c = ctx->cipher_data;

    while (inl >= EVP_MAXCHUNK) {
        Gost2814789_cnt_encrypt(in, out, (long)EVP_MAXCHUNK, &c->ks, ctx->iv,
                                ctx->buf, &ctx->num);
        inl -= EVP_MAXCHUNK;
        in += EVP_MAXCHUNK;
        out += EVP_MAXCHUNK;
    }

    if (inl)
        Gost2814789_cnt_encrypt(in, out, inl, &c->ks, ctx->iv, ctx->buf, &ctx->num);
    return 1;
}

/* gost89 is CFB-64 */
#define NID_gost89_cfb64 NID_id_Gost28147_89

BLOCK_CIPHER_def_ecb(gost2814789, EVP_GOST2814789_CTX, NID_gost89, 8, 32,
                     EVP_CIPH_NO_PADDING | EVP_CIPH_CTRL_INIT, gost2814789_init_key,
                     NULL, gost2814789_set_asn1_params, gost2814789_get_asn1_params,
                     gost2814789_ctl)
BLOCK_CIPHER_def_cfb(gost2814789, EVP_GOST2814789_CTX, NID_gost89, 32, 8, 64,
                     EVP_CIPH_NO_PADDING | EVP_CIPH_CTRL_INIT,
                     gost2814789_init_key, NULL, gost2814789_set_asn1_params,
                     gost2814789_get_asn1_params, gost2814789_ctl)
BLOCK_CIPHER_def1(gost2814789, cnt, cnt, OFB, EVP_GOST2814789_CTX,
                  NID_gost89, 1, 32, 8, EVP_CIPH_NO_PADDING | EVP_CIPH_CTRL_INIT,
                  gost2814789_init_key, NULL, gost2814789_set_asn1_params,
                  gost2814789_get_asn1_params, gost2814789_ctl)
#endif
