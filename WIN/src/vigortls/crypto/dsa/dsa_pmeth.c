/*
 * Copyright 2006-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <limits.h>
#include <stdio.h>
#include <string.h>

#include <openssl/asn1t.h>
#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "internal/evp_int.h"

/* defined in dsa_gen.c */
extern int dsa_builtin_paramgen(DSA *ret, size_t bits, size_t qbits,
                                const EVP_MD *evpmd, const uint8_t *seed_in,
                                size_t seed_len, uint8_t *seed_out,
                                int *counter_ret, unsigned long *h_ret,
                                BN_GENCB *cb);

/* DSA pkey context structure */

typedef struct
    {
    /* Parameter gen parameters */
    int nbits;         /* size of p in bits (default: 1024) */
    int qbits;         /* size of q in bits (default: 160)  */
    const EVP_MD *pmd; /* MD for parameter generation */
    /* Keygen callback info */
    int gentmp[2];
    /* message digest */
    const EVP_MD *md; /* MD for the signature */
} DSA_PKEY_CTX;

static int pkey_dsa_init(EVP_PKEY_CTX *ctx)
{
    DSA_PKEY_CTX *dctx;
    dctx = malloc(sizeof(DSA_PKEY_CTX));
    if (!dctx)
        return 0;
    dctx->nbits = 1024;
    dctx->qbits = 160;
    dctx->pmd = NULL;
    dctx->md = NULL;

    ctx->data = dctx;
    ctx->keygen_info = dctx->gentmp;
    ctx->keygen_info_count = 2;

    return 1;
}

static int pkey_dsa_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    DSA_PKEY_CTX *dctx, *sctx;
    if (!pkey_dsa_init(dst))
        return 0;
    sctx = src->data;
    dctx = dst->data;
    dctx->nbits = sctx->nbits;
    dctx->qbits = sctx->qbits;
    dctx->pmd = sctx->pmd;
    dctx->md = sctx->md;
    return 1;
}

static void pkey_dsa_cleanup(EVP_PKEY_CTX *ctx)
{
    DSA_PKEY_CTX *dctx = ctx->data;
    if (dctx)
        free(dctx);
}

static int pkey_dsa_sign(EVP_PKEY_CTX *ctx, uint8_t *sig, size_t *siglen,
                         const uint8_t *tbs, size_t tbslen)
{
    int ret, type;
    unsigned int sltmp;
    DSA_PKEY_CTX *dctx = ctx->data;
    DSA *dsa = ctx->pkey->pkey.dsa;

    if (dctx->md)
        type = EVP_MD_type(dctx->md);
    else
        type = NID_sha1;

    ret = DSA_sign(type, tbs, tbslen, sig, &sltmp, dsa);

    if (ret <= 0)
        return ret;
    *siglen = sltmp;
    return 1;
}

static int pkey_dsa_verify(EVP_PKEY_CTX *ctx,
                           const uint8_t *sig, size_t siglen,
                           const uint8_t *tbs, size_t tbslen)
{
    int ret, type;
    DSA_PKEY_CTX *dctx = ctx->data;
    DSA *dsa = ctx->pkey->pkey.dsa;

    if (dctx->md)
        type = EVP_MD_type(dctx->md);
    else
        type = NID_sha1;

    ret = DSA_verify(type, tbs, tbslen, sig, siglen, dsa);

    return ret;
}

static int pkey_dsa_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    DSA_PKEY_CTX *dctx = ctx->data;
    switch (type) {
        case EVP_PKEY_CTRL_DSA_PARAMGEN_BITS:
            if (p1 < 256)
                return -2;
            dctx->nbits = p1;
            return 1;

        case EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS:
            if (p1 != 160 && p1 != 224 && p1 && p1 != 256)
                return -2;
            dctx->qbits = p1;
            return 1;

        case EVP_PKEY_CTRL_DSA_PARAMGEN_MD:
            if (EVP_MD_type((const EVP_MD *)p2) != NID_sha1 &&
                EVP_MD_type((const EVP_MD *)p2) != NID_sha224 &&
                EVP_MD_type((const EVP_MD *)p2) != NID_sha256) {
                DSAerr(DSA_F_PKEY_DSA_CTRL, DSA_R_INVALID_DIGEST_TYPE);
                return 0;
            }
            dctx->md = p2;
            return 1;

        case EVP_PKEY_CTRL_MD:
            if (EVP_MD_type((const EVP_MD *)p2) != NID_sha1 &&
                EVP_MD_type((const EVP_MD *)p2) != NID_dsa &&
                EVP_MD_type((const EVP_MD *)p2) != NID_dsaWithSHA &&
                EVP_MD_type((const EVP_MD *)p2) != NID_sha224 &&
                EVP_MD_type((const EVP_MD *)p2) != NID_sha256 &&
                EVP_MD_type((const EVP_MD *)p2) != NID_sha384 &&
                EVP_MD_type((const EVP_MD *)p2) != NID_sha512) {
                DSAerr(DSA_F_PKEY_DSA_CTRL, DSA_R_INVALID_DIGEST_TYPE);
                return 0;
            }
            dctx->md = p2;
            return 1;

        case EVP_PKEY_CTRL_GET_MD:
            *(const EVP_MD **)p2 = dctx->md;
            return 1;

        case EVP_PKEY_CTRL_DIGESTINIT:
        case EVP_PKEY_CTRL_PKCS7_SIGN:
        case EVP_PKEY_CTRL_CMS_SIGN:
            return 1;

        case EVP_PKEY_CTRL_PEER_KEY:
            DSAerr(DSA_F_PKEY_DSA_CTRL,
                   EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
            return -2;
        default:
            return -2;
    }
}

static int pkey_dsa_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value)
{
    long lval;
    char *ep;
    if (strcmp(type, "dsa_paramgen_bits") == 0) {
        int nbits;
        
        errno = 0;
        lval = strtol(value, &ep, 10);
        if (value[0] == '\0' || *ep != '\0')
            goto invalid_number;
        if ((errno == ERANGE && (lval == LONG_MAX || lval == LONG_MIN)) ||
            (lval > INT_MAX || lval < INT_MIN))
            goto out_of_range;
        nbits = lval;
        return EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, nbits);
    }
    if (strcmp(type, "dsa_paramgen_q_bits") == 0) {
        int qbits;

        lval = strtol(value, &ep, 10);
        if (value[0] == '\0' || *ep != '\0')
            goto invalid_number;
        if ((errno == ERANGE && (lval == LONG_MAX || lval == LONG_MIN)) ||
            (lval > INT_MAX || lval < INT_MIN))
            goto out_of_range;
        qbits = lval;
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN,
                                 EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS, qbits, NULL);
    }
    if (strcmp(type, "dsa_paramgen_md") == 0) {
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN,
                                 EVP_PKEY_CTRL_DSA_PARAMGEN_MD, 0,
                                 (void *)EVP_get_digestbyname(value));
    }

invalid_number:
out_of_range:
    return -2;
}

static int pkey_dsa_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    DSA *dsa = NULL;
    DSA_PKEY_CTX *dctx = ctx->data;
    BN_GENCB *pcb, cb;
    int ret;
    if (ctx->pkey_gencb) {
        pcb = &cb;
        evp_pkey_set_cb_translate(pcb, ctx);
    } else
        pcb = NULL;
    dsa = DSA_new();
    if (!dsa)
        return 0;
    ret = dsa_builtin_paramgen(dsa, dctx->nbits, dctx->qbits, dctx->pmd,
                               NULL, 0, NULL, NULL, NULL, pcb);
    if (ret)
        EVP_PKEY_assign_DSA(pkey, dsa);
    else
        DSA_free(dsa);
    return ret;
}

static int pkey_dsa_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    DSA *dsa = NULL;
    if (ctx->pkey == NULL) {
        DSAerr(DSA_F_PKEY_DSA_KEYGEN, DSA_R_NO_PARAMETERS_SET);
        return 0;
    }
    dsa = DSA_new();
    if (!dsa)
        return 0;
    EVP_PKEY_assign_DSA(pkey, dsa);
    /* Note: if error return, pkey is freed by parent routine */
    if (!EVP_PKEY_copy_parameters(pkey, ctx->pkey))
        return 0;
    return DSA_generate_key(pkey->pkey.dsa);
}

const EVP_PKEY_METHOD dsa_pkey_meth = {
    .pkey_id = EVP_PKEY_DSA,
    .flags = EVP_PKEY_FLAG_AUTOARGLEN,

    .init = pkey_dsa_init,
    .copy = pkey_dsa_copy,
    .cleanup = pkey_dsa_cleanup,

    .paramgen = pkey_dsa_paramgen,

    .keygen = pkey_dsa_keygen,

    .sign = pkey_dsa_sign,

    .verify = pkey_dsa_verify,

    .ctrl = pkey_dsa_ctrl,
    .ctrl_str = pkey_dsa_ctrl_str
};
