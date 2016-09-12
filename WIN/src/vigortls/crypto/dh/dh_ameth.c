/*
 * Copyright 2006-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bn.h>
#ifndef OPENSSL_NO_CMS
#include <openssl/cms.h>
#endif
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include "internal/asn1_int.h"

extern const EVP_PKEY_ASN1_METHOD dhx_asn1_meth;

/* i2d/d2i like DH parameter functions which use the appropriate routine
 * for PKCS#3 DH or X9.42 DH.
 */

static DH *d2i_dhp(const EVP_PKEY *pkey, const unsigned char **pp, long length)
{
    if (pkey->ameth == &dhx_asn1_meth)
        return d2i_DHxparams(NULL, pp, length);
    return d2i_DHparams(NULL, pp, length);
}

static int i2d_dhp(const EVP_PKEY *pkey, const DH *a, unsigned char **pp)
{
    if (pkey->ameth == &dhx_asn1_meth)
        return i2d_DHxparams(a, pp);
    return i2d_DHparams(a, pp);
}

static void int_dh_free(EVP_PKEY *pkey)
{
    DH_free(pkey->pkey.dh);
}

static int dh_pub_decode(EVP_PKEY *pkey, X509_PUBKEY *pubkey)
{
    const uint8_t *p, *pm;
    int pklen, pmlen;
    int ptype;
    void *pval;
    ASN1_STRING *pstr;
    X509_ALGOR *palg;
    ASN1_INTEGER *public_key = NULL;

    DH *dh = NULL;

    if (!X509_PUBKEY_get0_param(NULL, &p, &pklen, &palg, pubkey))
        return 0;
    X509_ALGOR_get0(NULL, &ptype, &pval, palg);

    if (ptype != V_ASN1_SEQUENCE) {
        DHerr(DH_F_DH_PUB_DECODE, DH_R_PARAMETER_ENCODING_ERROR);
        goto err;
    }

    pstr = pval;
    pm = pstr->data;
    pmlen = pstr->length;

    if (!(dh = d2i_dhp(pkey, &pm, pmlen))) {
        DHerr(DH_F_DH_PUB_DECODE, DH_R_DECODE_ERROR);
        goto err;
    }

    if (!(public_key = d2i_ASN1_INTEGER(NULL, &p, pklen))) {
        DHerr(DH_F_DH_PUB_DECODE, DH_R_DECODE_ERROR);
        goto err;
    }

    /* We have parameters now set public key */
    if (!(dh->pub_key = ASN1_INTEGER_to_BN(public_key, NULL))) {
        DHerr(DH_F_DH_PUB_DECODE, DH_R_BN_DECODE_ERROR);
        goto err;
    }

    ASN1_INTEGER_free(public_key);
    EVP_PKEY_assign(pkey, pkey->ameth->pkey_id, dh);
    return 1;

err:
    if (public_key)
        ASN1_INTEGER_free(public_key);
    if (dh)
        DH_free(dh);
    return 0;
}

static int dh_pub_encode(X509_PUBKEY *pk, const EVP_PKEY *pkey)
{
    DH *dh;
    int ptype;
    uint8_t *penc = NULL;
    int penclen;
    ASN1_STRING *str;
    ASN1_INTEGER *pub_key = NULL;

    dh = pkey->pkey.dh;

    str = ASN1_STRING_new();
    if (str == NULL) {
        DHerr(DH_F_DH_PUB_ENCODE, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    str->length = i2d_dhp(pkey, dh, &str->data);
    if (str->length <= 0) {
        DHerr(DH_F_DH_PUB_ENCODE, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    ptype = V_ASN1_SEQUENCE;

    pub_key = BN_to_ASN1_INTEGER(dh->pub_key, NULL);
    if (!pub_key)
        goto err;

    penclen = i2d_ASN1_INTEGER(pub_key, &penc);

    ASN1_INTEGER_free(pub_key);

    if (penclen <= 0) {
        DHerr(DH_F_DH_PUB_ENCODE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (X509_PUBKEY_set0_param(pk, OBJ_nid2obj(pkey->ameth->pkey_id), ptype,
                               str, penc, penclen))
        return 1;

err:
    free(penc);
    ASN1_STRING_free(str);

    return 0;
}

/* PKCS#8 DH is defined in PKCS#11 of all places. It is similar to DH in
 * that the AlgorithmIdentifier contains the paramaters, the private key
 * is explcitly included and the pubkey must be recalculated.
 */

static int dh_priv_decode(EVP_PKEY *pkey, PKCS8_PRIV_KEY_INFO *p8)
{
    const uint8_t *p, *pm;
    int pklen, pmlen;
    int ptype;
    void *pval;
    ASN1_STRING *pstr;
    X509_ALGOR *palg;
    ASN1_INTEGER *privkey = NULL;

    DH *dh = NULL;

    if (!PKCS8_pkey_get0(NULL, &p, &pklen, &palg, p8))
        return 0;

    X509_ALGOR_get0(NULL, &ptype, &pval, palg);

    if (ptype != V_ASN1_SEQUENCE)
        goto decerr;

    if (!(privkey = d2i_ASN1_INTEGER(NULL, &p, pklen)))
        goto decerr;

    pstr = pval;
    pm = pstr->data;
    pmlen = pstr->length;
    if (!(dh = d2i_dhp(pkey, &pm, pmlen)))
        goto decerr;
    /* We have parameters now set private key */
    if (!(dh->priv_key = ASN1_INTEGER_to_BN(privkey, NULL))) {
        DHerr(DH_F_DH_PRIV_DECODE, DH_R_BN_ERROR);
        goto dherr;
    }
    /* Calculate public key */
    if (!DH_generate_key(dh))
        goto dherr;

    EVP_PKEY_assign(pkey, pkey->ameth->pkey_id, dh);

    ASN1_STRING_clear_free(privkey);

    return 1;

decerr:
    DHerr(DH_F_DH_PRIV_DECODE, EVP_R_DECODE_ERROR);
dherr:
    DH_free(dh);
    ASN1_STRING_clear_free(privkey);
    return 0;
}

static int dh_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)
{
    ASN1_STRING *params = NULL;
    ASN1_INTEGER *prkey = NULL;
    uint8_t *dp = NULL;
    int dplen;

    params = ASN1_STRING_new();

    if (!params) {
        DHerr(DH_F_DH_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    params->length = i2d_dhp(pkey, pkey->pkey.dh, &params->data);
    if (params->length <= 0) {
        DHerr(DH_F_DH_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    params->type = V_ASN1_SEQUENCE;

    /* Get private key into integer */
    prkey = BN_to_ASN1_INTEGER(pkey->pkey.dh->priv_key, NULL);

    if (!prkey) {
        DHerr(DH_F_DH_PRIV_ENCODE, DH_R_BN_ERROR);
        goto err;
    }

    dplen = i2d_ASN1_INTEGER(prkey, &dp);

    ASN1_STRING_clear_free(prkey);
    prkey = NULL;

    if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(pkey->ameth->pkey_id), 0,
                         V_ASN1_SEQUENCE, params, dp, dplen))
        goto err;

    return 1;

err:
    free(dp);
    ASN1_STRING_free(params);
    ASN1_STRING_clear_free(prkey);
    return 0;
}

static void update_buflen(const BIGNUM *b, size_t *pbuflen)
{
    size_t i;
    if (!b)
        return;
    if (*pbuflen < (i = (size_t)BN_num_bytes(b)))
        *pbuflen = i;
}

static int dh_param_decode(EVP_PKEY *pkey,
                           const uint8_t **pder, int derlen)
{
    DH *dh;
    if (!(dh = d2i_dhp(pkey, pder, derlen))) {
        DHerr(DH_F_DH_PARAM_DECODE, ERR_R_DH_LIB);
        return 0;
    }
    EVP_PKEY_assign(pkey, pkey->ameth->pkey_id, dh);
    return 1;
}

static int dh_param_encode(const EVP_PKEY *pkey, uint8_t **pder)
{
    return i2d_DHparams(pkey->pkey.dh, pder);
}

static int do_dh_print(BIO *bp, const DH *x, int indent,
                       ASN1_PCTX *ctx, int ptype)
{
    uint8_t *m = NULL;
    int reason = ERR_R_BUF_LIB, ret = 0;
    size_t buf_len = 0;

    const char *ktype = NULL;

    BIGNUM *priv_key, *pub_key;

    if (ptype == 2)
        priv_key = x->priv_key;
    else
        priv_key = NULL;

    if (ptype > 0)
        pub_key = x->pub_key;
    else
        pub_key = NULL;

    update_buflen(x->p, &buf_len);

    if (buf_len == 0) {
        reason = ERR_R_PASSED_NULL_PARAMETER;
        goto err;
    }

    update_buflen(x->g, &buf_len);
    update_buflen(x->q, &buf_len);
    update_buflen(x->j, &buf_len);
    update_buflen(x->counter, &buf_len);
    update_buflen(pub_key, &buf_len);
    update_buflen(priv_key, &buf_len);

    if (ptype == 2)
        ktype = "DH Private-Key";
    else if (ptype == 1)
        ktype = "DH Public-Key";
    else
        ktype = "DH Parameters";

    m = malloc(buf_len + 10);
    if (m == NULL) {
        reason = ERR_R_MALLOC_FAILURE;
        goto err;
    }

    if (BIO_indent(bp, indent, 128) == 0)
        goto err;
    if (BIO_printf(bp, "%s: (%d bit)\n", ktype, BN_num_bits(x->p)) <= 0)
        goto err;
    indent += 4;

    if (!ASN1_bn_print(bp, "private-key:", priv_key, m, indent))
        goto err;
    if (!ASN1_bn_print(bp, "public-key:", pub_key, m, indent))
        goto err;

    if (!ASN1_bn_print(bp, "prime:", x->p, m, indent))
        goto err;
    if (!ASN1_bn_print(bp, "generator:", x->g, m, indent))
        goto err;
    if (x->q && !ASN1_bn_print(bp, "subgroup order:", x->q, m, indent))
        goto err;
    if (x->j && !ASN1_bn_print(bp, "subgroup factor:", x->j, m, indent))
        goto err;
    if (x->seed) {
        int i;
        BIO_indent(bp, indent, 128);
        BIO_puts(bp, "seed:");
        for (i = 0; i < x->seedlen; i++) {
            if ((i % 15) == 0) {
                if (BIO_puts(bp, "\n") <= 0 ||
                    !BIO_indent(bp, indent + 4, 128))
                    goto err;
            }
            if (BIO_printf(bp, "%02x%s", x->seed[i],
                           ((i + 1) == x->seedlen) ? "" : ":") <= 0)
                goto err;
        }
        if (BIO_write(bp, "\n", 1) <= 0)
            return 0;
    }
    if (x->counter && !ASN1_bn_print(bp, "counter:", x->counter, m, indent))
        goto err;
    if (x->length != 0) {
        BIO_indent(bp, indent, 128);
        if (BIO_printf(bp, "recommended-private-length: %d bits\n",
                       (int)x->length) <= 0)
            goto err;
    }

    ret = 1;
    if (0) {
    err:
        DHerr(DH_F_DO_DH_PRINT, reason);
    }
    free(m);
    return (ret);
}

static int int_dh_size(const EVP_PKEY *pkey)
{
    return (DH_size(pkey->pkey.dh));
}

static int dh_bits(const EVP_PKEY *pkey)
{
    return BN_num_bits(pkey->pkey.dh->p);
}

static int dh_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b)
{
    if (BN_cmp(a->pkey.dh->p, b->pkey.dh->p) ||
        BN_cmp(a->pkey.dh->g, b->pkey.dh->g))
    {
        return 0;
    } else if (a->ameth == &dhx_asn1_meth) {
        if (BN_cmp(a->pkey.dh->q,b->pkey.dh->q))
            return 0;
    }
    return 1;
}

static int int_dh_bn_cpy(BIGNUM **dst, const BIGNUM *src)
{
    BIGNUM *a;

    if (src != NULL) {
        a = BN_dup(src);
        if (a == NULL)
            return 0;
    } else
        a = NULL;

    BN_free(*dst);
    *dst = a;

    return 1;
}

static int int_dh_param_copy(DH *to, const DH *from, int is_x942)
{
    if (is_x942 == -1)
        is_x942 = !!from->q;
    if (!int_dh_bn_cpy(&to->p, from->p))
        return 0;
    if (!int_dh_bn_cpy(&to->g, from->g))
        return 0;
    if (is_x942) {
        if (!int_dh_bn_cpy(&to->q, from->q))
            return 0;
        if (!int_dh_bn_cpy(&to->j, from->j))
            return 0;
        free(to->seed);
        to->seed = NULL;
        to->seedlen = 0;
        to->seed = malloc(from->seedlen);
        if (to->seed == NULL)
            return 0;
        memcpy(from->seed, from->seed, from->seedlen);
        to->seedlen = from->seedlen;
    } else
        to->length = from->length;

    return 1;
}

DH *DHparams_dup(DH *dh)
{
    DH *ret;

    ret = DH_new();
    if (ret == NULL)
        return NULL;
    if (!int_dh_param_copy(ret, dh, -1)) {
        DH_free(ret);
        return NULL;
    }
    return ret;
}

static int dh_copy_parameters(EVP_PKEY *to, const EVP_PKEY *from)
{
    return int_dh_param_copy(to->pkey.dh, from->pkey.dh,
                             from->ameth == &dhx_asn1_meth);
}

static int dh_missing_parameters(const EVP_PKEY *a)
{
    if (!a->pkey.dh->p || !a->pkey.dh->g)
        return 1;
    return 0;
}

static int dh_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
    if (dh_cmp_parameters(a, b) == 0)
        return 0;
    if (BN_cmp(b->pkey.dh->pub_key, a->pkey.dh->pub_key) != 0)
        return 0;
    else
        return 1;
}

static int dh_param_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                          ASN1_PCTX *ctx)
{
    return do_dh_print(bp, pkey->pkey.dh, indent, ctx, 0);
}

static int dh_public_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                           ASN1_PCTX *ctx)
{
    return do_dh_print(bp, pkey->pkey.dh, indent, ctx, 1);
}

static int dh_private_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                            ASN1_PCTX *ctx)
{
    return do_dh_print(bp, pkey->pkey.dh, indent, ctx, 2);
}

int DHparams_print(BIO *bp, const DH *x)
{
    return do_dh_print(bp, x, 4, NULL, 0);
}

#ifndef OPENSSL_NO_CMS
static int dh_cms_decrypt(CMS_RecipientInfo *ri);
static int dh_cms_encrypt(CMS_RecipientInfo *ri);
#endif

static int dh_pkey_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2)
{
    switch (op) {
#ifndef OPENSSL_NO_CMS
        case ASN1_PKEY_CTRL_CMS_ENVELOPE:
            if (arg1 == 1)
                return dh_cms_decrypt(arg2);
            else if (arg1 == 0)
                return dh_cms_encrypt(arg2);
            return -2;

        case ASN1_PKEY_CTRL_CMS_RI_TYPE:
            *(int *)arg2 = CMS_RECIPINFO_AGREE;
            return 1;
#endif
        default:
            return -2;
    }

}

const EVP_PKEY_ASN1_METHOD dh_asn1_meth = {
    .pkey_id = EVP_PKEY_DH,
    .pkey_base_id = EVP_PKEY_DH,

    .pem_str = (char *)"DH",
    .info = (char *)"OpenSSL PKCS#3 DH method",

    .pub_decode = dh_pub_decode,
    .pub_encode = dh_pub_encode,
    .pub_cmp = dh_pub_cmp,
    .pub_print = dh_public_print,

    .priv_decode = dh_priv_decode,
    .priv_encode = dh_priv_encode,
    .priv_print = dh_private_print,

    .pkey_size = int_dh_size,
    .pkey_bits = dh_bits,

    .param_decode = dh_param_decode,
    .param_encode = dh_param_encode,
    .param_missing = dh_missing_parameters,
    .param_copy = dh_copy_parameters,
    .param_cmp = dh_cmp_parameters,
    .param_print = dh_param_print,

    .pkey_free = int_dh_free,
};

const EVP_PKEY_ASN1_METHOD dhx_asn1_meth = {
    .pkey_id = EVP_PKEY_DHX,
    .pkey_base_id = EVP_PKEY_DHX,
    .pem_str = (char *)"X9.42 DH",
    .info = (char *)"OpenSSL X9.42 DH method",

    .pub_decode = dh_pub_decode,
    .pub_encode = dh_pub_encode,
    .pub_cmp = dh_pub_cmp,
    .pub_print = dh_public_print,

    .priv_decode = dh_priv_decode,
    .priv_encode = dh_priv_encode,
    .priv_print = dh_private_print,

    .pkey_size = int_dh_size,
    .pkey_bits = dh_bits,

    .param_decode = dh_param_decode,
    .param_encode = dh_param_encode,
    .param_missing = dh_missing_parameters,
    .param_copy = dh_copy_parameters,
    .param_cmp = dh_cmp_parameters,
    .param_print = dh_param_print,

    .pkey_free = int_dh_free,
    .pkey_ctrl = dh_pkey_ctrl,
};

#ifndef OPENSSL_NO_CMS

static int dh_cms_set_peerkey(EVP_PKEY_CTX *pctx, X509_ALGOR *alg,
                              ASN1_BIT_STRING *pubkey)
{
    ASN1_OBJECT *aoid;
    int atype;
    void *aval;
    ASN1_INTEGER *public_key = NULL;
    int rv = 0;
    EVP_PKEY *pkpeer = NULL, *pk = NULL;
    DH *dhpeer = NULL;
    const unsigned char *p;
    int plen;
    X509_ALGOR_get0(&aoid, &atype, &aval, alg);
    if (OBJ_obj2nid(aoid) != NID_dhpublicnumber)
        goto err;
    /* Only absent parameters allowed in RFC XXXX */
    if (atype != V_ASN1_UNDEF && atype == V_ASN1_NULL)
        goto err;

    pk = EVP_PKEY_CTX_get0_pkey(pctx);
    if (pk == NULL)
        goto err;
    if (pk->type != EVP_PKEY_DHX)
        goto err;
    /* Get parameters from parent key */
    dhpeer = DHparams_dup(pk->pkey.dh);
    /* We have parameters now set public key */
    plen = ASN1_STRING_length(pubkey);
    p = ASN1_STRING_data(pubkey);
    if (p == NULL || plen == 0)
        goto err;

    if (!(public_key = d2i_ASN1_INTEGER(NULL, &p, plen))) {
        DHerr(DH_F_DH_CMS_SET_PEERKEY, DH_R_DECODE_ERROR);
        goto err;
    }

    /* We have parameters now set public key */
    if (!(dhpeer->pub_key = ASN1_INTEGER_to_BN(public_key, NULL))) {
        DHerr(DH_F_DH_CMS_SET_PEERKEY, DH_R_BN_DECODE_ERROR);
        goto err;
    }

    pkpeer = EVP_PKEY_new();
    if (pkpeer == NULL)
        goto err;
    EVP_PKEY_assign(pkpeer, pk->ameth->pkey_id, dhpeer);
    dhpeer = NULL;
    if (EVP_PKEY_derive_set_peer(pctx, pkpeer) > 0)
        rv = 1;
err:
    ASN1_INTEGER_free(public_key);
    EVP_PKEY_free(pkpeer);
    DH_free(dhpeer);
    return rv;
}

static int dh_cms_set_shared_info(EVP_PKEY_CTX *pctx, CMS_RecipientInfo *ri)
{
    int rv = 0;

    X509_ALGOR *alg, *kekalg = NULL;
    ASN1_OCTET_STRING *ukm;
    const unsigned char *p;
    unsigned char *dukm = NULL;
    size_t dukmlen = 0;
    int keylen, plen;
    const EVP_CIPHER *kekcipher;
    EVP_CIPHER_CTX *kekctx;

    if (!CMS_RecipientInfo_kari_get0_alg(ri, &alg, &ukm))
        goto err;

    /*
     * For DH we only have one OID permissible. If ever any more get
     * defined we will need something cleverer.
     */
    if (OBJ_obj2nid(alg->algorithm) != NID_id_smime_alg_ESDH) {
        DHerr(DH_F_DH_CMS_SET_SHARED_INFO, DH_R_KDF_PARAMETER_ERROR);
        goto err;
    }

    if (EVP_PKEY_CTX_set_dh_kdf_type(pctx, EVP_PKEY_DH_KDF_X9_42) <= 0)
        goto err;

    if (EVP_PKEY_CTX_set_dh_kdf_md(pctx, EVP_sha1()) <= 0)
        goto err;

    if (alg->parameter->type != V_ASN1_SEQUENCE)
        goto err;

    p = alg->parameter->value.sequence->data;
    plen = alg->parameter->value.sequence->length;
    kekalg = d2i_X509_ALGOR(NULL, &p, plen);
    if (kekalg == NULL)
        goto err;
    kekctx = CMS_RecipientInfo_kari_get0_ctx(ri);
    if (kekctx == NULL)
        goto err;
    kekcipher = EVP_get_cipherbyobj(kekalg->algorithm);
    if (!kekcipher || EVP_CIPHER_mode(kekcipher) != EVP_CIPH_WRAP_MODE)
        goto err;
    if (!EVP_EncryptInit_ex(kekctx, kekcipher, NULL, NULL, NULL))
        goto err;
    if (EVP_CIPHER_asn1_to_param(kekctx, kekalg->parameter) <= 0)
        goto err;

    keylen = EVP_CIPHER_CTX_key_length(kekctx);
    if (EVP_PKEY_CTX_set_dh_kdf_outlen(pctx, keylen) <= 0)
        goto err;
    /* Use OBJ_nid2obj to ensure we use built in OID that isn't freed */
    if (EVP_PKEY_CTX_set0_dh_kdf_oid(
            pctx, OBJ_nid2obj(EVP_CIPHER_type(kekcipher))) <= 0)
        goto err;

    if (ukm != NULL) {
        dukmlen = ASN1_STRING_length(ukm);
        dukm = malloc(dukmlen);
        if (dukm == NULL)
            goto err;
        memcpy(dukm, ASN1_STRING_data(ukm), dukmlen);
    }

    if (EVP_PKEY_CTX_set0_dh_kdf_ukm(pctx, dukm, dukmlen) <= 0)
        goto err;
    dukm = NULL;

    rv = 1;
err:
    X509_ALGOR_free(kekalg);
    free(dukm);
    return rv;
}

static int dh_cms_decrypt(CMS_RecipientInfo *ri)
{
    EVP_PKEY_CTX *pctx;
    pctx = CMS_RecipientInfo_get0_pkey_ctx(ri);
    if (pctx == NULL)
        return 0;
    /* See if we need to set peer key */
    if (!EVP_PKEY_CTX_get0_peerkey(pctx)) {
        X509_ALGOR *alg;
        ASN1_BIT_STRING *pubkey;
        if (!CMS_RecipientInfo_kari_get0_orig_id(ri, &alg, &pubkey, NULL, NULL,
                                                 NULL))
            return 0;
        if (alg == NULL || pubkey == NULL)
            return 0;
        if (!dh_cms_set_peerkey(pctx, alg, pubkey)) {
            DHerr(DH_F_DH_CMS_DECRYPT, DH_R_PEER_KEY_ERROR);
            return 0;
        }
    }
    /* Set DH derivation parameters and initialise unwrap context */
    if (!dh_cms_set_shared_info(pctx, ri)) {
        DHerr(DH_F_DH_CMS_DECRYPT, DH_R_SHARED_INFO_ERROR);
        return 0;
    }
    return 1;
}

static int dh_cms_encrypt(CMS_RecipientInfo *ri)
{
    EVP_PKEY_CTX *pctx;
    EVP_PKEY *pkey;
    EVP_CIPHER_CTX *ctx;
    int keylen;
    X509_ALGOR *talg, *wrap_alg = NULL;
    ASN1_OBJECT *aoid;
    ASN1_BIT_STRING *pubkey;
    ASN1_STRING *wrap_str;
    ASN1_OCTET_STRING *ukm;
    unsigned char *penc = NULL, *dukm = NULL;
    int penclen;
    size_t dukmlen = 0;
    int rv = 0;
    int kdf_type, wrap_nid;
    const EVP_MD *kdf_md;
    pctx = CMS_RecipientInfo_get0_pkey_ctx(ri);
    if (!pctx)
        return 0;
    /* Get ephemeral key */
    pkey = EVP_PKEY_CTX_get0_pkey(pctx);
    if (!CMS_RecipientInfo_kari_get0_orig_id(ri, &talg, &pubkey, NULL, NULL,
                                             NULL))
        goto err;
    X509_ALGOR_get0(&aoid, NULL, NULL, talg);
    /* Is everything uninitialised? */
    if (aoid == OBJ_nid2obj(NID_undef)) {
        ASN1_INTEGER *pubk;
        pubk = BN_to_ASN1_INTEGER(pkey->pkey.dh->pub_key, NULL);
        if (pubk == NULL)
            goto err;
        /* Set the key */

        penclen = i2d_ASN1_INTEGER(pubk, &penc);
        ASN1_INTEGER_free(pubk);
        if (penclen <= 0)
            goto err;
        ASN1_STRING_set0(pubkey, penc, penclen);
        pubkey->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
        pubkey->flags |= ASN1_STRING_FLAG_BITS_LEFT;

        penc = NULL;
        X509_ALGOR_set0(talg, OBJ_nid2obj(NID_dhpublicnumber), V_ASN1_UNDEF,
                        NULL);
    }

    /* See if custom paraneters set */
    kdf_type = EVP_PKEY_CTX_get_dh_kdf_type(pctx);
    if (kdf_type <= 0)
        goto err;
    if (!EVP_PKEY_CTX_get_dh_kdf_md(pctx, &kdf_md))
        goto err;

    if (kdf_type == EVP_PKEY_DH_KDF_NONE) {
        kdf_type = EVP_PKEY_DH_KDF_X9_42;
        if (EVP_PKEY_CTX_set_dh_kdf_type(pctx, kdf_type) <= 0)
            goto err;
    } else if (kdf_type != EVP_PKEY_DH_KDF_X9_42)
        /* Unknown KDF */
        goto err;
    if (kdf_md == NULL) {
        /* Only SHA1 supported */
        kdf_md = EVP_sha1();
        if (EVP_PKEY_CTX_set_dh_kdf_md(pctx, kdf_md) <= 0)
            goto err;
    } else if (EVP_MD_type(kdf_md) != NID_sha1)
        /* Unsupported digest */
        goto err;

    if (!CMS_RecipientInfo_kari_get0_alg(ri, &talg, &ukm))
        goto err;

    /* Get wrap NID */
    ctx = CMS_RecipientInfo_kari_get0_ctx(ri);
    wrap_nid = EVP_CIPHER_CTX_type(ctx);
    if (EVP_PKEY_CTX_set0_dh_kdf_oid(pctx, OBJ_nid2obj(wrap_nid)) <= 0)
        goto err;
    keylen = EVP_CIPHER_CTX_key_length(ctx);

    /* Package wrap algorithm in an AlgorithmIdentifier */

    wrap_alg = X509_ALGOR_new();
    if (wrap_alg == NULL)
        goto err;
    wrap_alg->algorithm = OBJ_nid2obj(wrap_nid);
    wrap_alg->parameter = ASN1_TYPE_new();
    if (wrap_alg->parameter == NULL)
        goto err;
    if (EVP_CIPHER_param_to_asn1(ctx, wrap_alg->parameter) <= 0)
        goto err;
    if (ASN1_TYPE_get(wrap_alg->parameter) == NID_undef) {
        ASN1_TYPE_free(wrap_alg->parameter);
        wrap_alg->parameter = NULL;
    }

    if (EVP_PKEY_CTX_set_dh_kdf_outlen(pctx, keylen) <= 0)
        goto err;

    if (ukm != NULL) {
        dukmlen = ASN1_STRING_length(ukm);
        dukm = malloc(dukmlen);
        if (dukm == NULL)
            goto err;
        memcpy(dukm, ASN1_STRING_data(ukm), dukmlen);
    }

    if (EVP_PKEY_CTX_set0_dh_kdf_ukm(pctx, dukm, dukmlen) <= 0)
        goto err;
    dukm = NULL;

    /*
     * Now need to wrap encoding of wrap AlgorithmIdentifier into
     * parameter of another AlgorithmIdentifier.
     */
    penc = NULL;
    penclen = i2d_X509_ALGOR(wrap_alg, &penc);
    if (!penc || !penclen)
        goto err;
    wrap_str = ASN1_STRING_new();
    if (wrap_str == NULL)
        goto err;
    ASN1_STRING_set0(wrap_str, penc, penclen);
    penc = NULL;
    X509_ALGOR_set0(talg, OBJ_nid2obj(NID_id_smime_alg_ESDH), V_ASN1_SEQUENCE,
                    wrap_str);

    rv = 1;

err:
    free(penc);
    X509_ALGOR_free(wrap_alg);
    return rv;
}

#endif