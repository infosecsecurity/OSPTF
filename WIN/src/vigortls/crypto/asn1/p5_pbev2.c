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

/* PKCS#5 v2.0 password based encryption structures */

ASN1_SEQUENCE(PBE2PARAM) = {
    ASN1_SIMPLE(PBE2PARAM, keyfunc, X509_ALGOR),
    ASN1_SIMPLE(PBE2PARAM, encryption, X509_ALGOR)
} ASN1_SEQUENCE_END(PBE2PARAM)

PBE2PARAM *d2i_PBE2PARAM(PBE2PARAM **a, const uint8_t **in, long len)
{
    return (PBE2PARAM *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(PBE2PARAM));
}

int i2d_PBE2PARAM(PBE2PARAM *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(PBE2PARAM));
}

PBE2PARAM *PBE2PARAM_new(void)
{
    return (PBE2PARAM *)ASN1_item_new(ASN1_ITEM_rptr(PBE2PARAM));
}

void PBE2PARAM_free(PBE2PARAM *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(PBE2PARAM));
}

ASN1_SEQUENCE(PBKDF2PARAM) = {
    ASN1_SIMPLE(PBKDF2PARAM, salt, ASN1_ANY),
    ASN1_SIMPLE(PBKDF2PARAM, iter, ASN1_INTEGER),
    ASN1_OPT(PBKDF2PARAM, keylength, ASN1_INTEGER),
    ASN1_OPT(PBKDF2PARAM, prf, X509_ALGOR)
} ASN1_SEQUENCE_END(PBKDF2PARAM)

PBKDF2PARAM *d2i_PBKDF2PARAM(PBKDF2PARAM **a, const uint8_t **in, long len)
{
    return (PBKDF2PARAM *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(PBKDF2PARAM));
}

int i2d_PBKDF2PARAM(PBKDF2PARAM *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(PBKDF2PARAM));
}

PBKDF2PARAM *PBKDF2PARAM_new(void)
{
    return (PBKDF2PARAM *)ASN1_item_new(ASN1_ITEM_rptr(PBKDF2PARAM));
}

void PBKDF2PARAM_free(PBKDF2PARAM *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(PBKDF2PARAM));
}

/* Return an algorithm identifier for a PKCS#5 v2.0 PBE algorithm:
 * yes I know this is horrible!
 *
 * Extended version to allow application supplied PRF NID and IV.
 */

X509_ALGOR *PKCS5_pbe2_set_iv(const EVP_CIPHER *cipher, int iter,
                              uint8_t *salt, int saltlen,
                              uint8_t *aiv, int prf_nid)
{
    X509_ALGOR *scheme = NULL, *kalg = NULL, *ret = NULL;
    int alg_nid, keylen;
    EVP_CIPHER_CTX ctx;
    uint8_t iv[EVP_MAX_IV_LENGTH];
    PBE2PARAM *pbe2 = NULL;
    ASN1_OBJECT *obj;

    alg_nid = EVP_CIPHER_type(cipher);
    if (alg_nid == NID_undef) {
        ASN1err(ASN1_F_PKCS5_PBE2_SET_IV,
                ASN1_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER);
        goto err;
    }
    obj = OBJ_nid2obj(alg_nid);

    if (!(pbe2 = PBE2PARAM_new()))
        goto merr;

    /* Setup the AlgorithmIdentifier for the encryption scheme */
    scheme = pbe2->encryption;

    scheme->algorithm = obj;
    if (!(scheme->parameter = ASN1_TYPE_new()))
        goto merr;

    /* Create random IV */
    if (EVP_CIPHER_iv_length(cipher)) {
        if (aiv)
            memcpy(iv, aiv, EVP_CIPHER_iv_length(cipher));
        else if (RAND_bytes(iv, EVP_CIPHER_iv_length(cipher)) <= 0)
            goto err;
    }

    EVP_CIPHER_CTX_init(&ctx);

    /* Dummy cipherinit to just setup the IV, and PRF */
    if (!EVP_CipherInit_ex(&ctx, cipher, NULL, NULL, iv, 0))
        goto err;
    if (EVP_CIPHER_param_to_asn1(&ctx, scheme->parameter) < 0) {
        ASN1err(ASN1_F_PKCS5_PBE2_SET_IV,
                ASN1_R_ERROR_SETTING_CIPHER_PARAMS);
        EVP_CIPHER_CTX_cleanup(&ctx);
        goto err;
    }
    /* If prf NID unspecified see if cipher has a preference.
     * An error is OK here: just means use default PRF.
     */
    if ((prf_nid == -1) && EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_PBE_PRF_NID, 0, &prf_nid) <= 0) {
        ERR_clear_error();
        prf_nid = NID_hmacWithSHA1;
    }
    EVP_CIPHER_CTX_cleanup(&ctx);

    /* If its RC2 then we'd better setup the key length */

    if (alg_nid == NID_rc2_cbc)
        keylen = EVP_CIPHER_key_length(cipher);
    else
        keylen = -1;

    /* Setup keyfunc */

    X509_ALGOR_free(pbe2->keyfunc);

    pbe2->keyfunc = PKCS5_pbkdf2_set(iter, salt, saltlen, prf_nid, keylen);

    if (!pbe2->keyfunc)
        goto merr;

    /* Now set up top level AlgorithmIdentifier */

    if (!(ret = X509_ALGOR_new()))
        goto merr;

    ret->algorithm = OBJ_nid2obj(NID_pbes2);

    /* Encode PBE2PARAM into parameter */

    if (!ASN1_TYPE_pack_sequence(ASN1_ITEM_rptr(PBE2PARAM), pbe2, &ret->parameter))
        goto merr;

    PBE2PARAM_free(pbe2);
    pbe2 = NULL;

    return ret;

merr:
    ASN1err(ASN1_F_PKCS5_PBE2_SET_IV, ERR_R_MALLOC_FAILURE);

err:
    PBE2PARAM_free(pbe2);
    /* Note 'scheme' is freed as part of pbe2 */
    X509_ALGOR_free(kalg);
    X509_ALGOR_free(ret);

    return NULL;
}

X509_ALGOR *PKCS5_pbe2_set(const EVP_CIPHER *cipher, int iter,
                           uint8_t *salt, int saltlen)
{
    return PKCS5_pbe2_set_iv(cipher, iter, salt, saltlen, NULL, -1);
}

X509_ALGOR *PKCS5_pbkdf2_set(int iter, uint8_t *salt, int saltlen,
                             int prf_nid, int keylen)
{
    X509_ALGOR *keyfunc = NULL;
    PBKDF2PARAM *kdf = NULL;
    ASN1_OCTET_STRING *osalt = NULL;

    if (!(kdf = PBKDF2PARAM_new()))
        goto merr;
    if (!(osalt = ASN1_OCTET_STRING_new()))
        goto merr;

    kdf->salt->value.octet_string = osalt;
    kdf->salt->type = V_ASN1_OCTET_STRING;

    if (!saltlen)
        saltlen = PKCS5_SALT_LEN;
    if (!(osalt->data = malloc(saltlen)))
        goto merr;

    osalt->length = saltlen;

    if (salt)
        memcpy(osalt->data, salt, saltlen);
    else if (RAND_bytes(osalt->data, saltlen) <= 0)
        goto merr;

    if (iter <= 0)
        iter = PKCS5_DEFAULT_ITER;

    if (!ASN1_INTEGER_set(kdf->iter, iter))
        goto merr;

    /* If have a key len set it up */

    if (keylen > 0) {
        if (!(kdf->keylength = ASN1_INTEGER_new()))
            goto merr;
        if (!ASN1_INTEGER_set(kdf->keylength, keylen))
            goto merr;
    }

    /* prf can stay NULL if we are using hmacWithSHA1 */
    if (prf_nid > 0 && prf_nid != NID_hmacWithSHA1) {
        kdf->prf = X509_ALGOR_new();
        if (!kdf->prf)
            goto merr;
        X509_ALGOR_set0(kdf->prf, OBJ_nid2obj(prf_nid),
                        V_ASN1_NULL, NULL);
    }

    /* Finally setup the keyfunc structure */

    keyfunc = X509_ALGOR_new();
    if (!keyfunc)
        goto merr;

    keyfunc->algorithm = OBJ_nid2obj(NID_id_pbkdf2);

    /* Encode PBKDF2PARAM into parameter of pbe2 */

    if (!ASN1_TYPE_pack_sequence(ASN1_ITEM_rptr(PBKDF2PARAM), kdf, &keyfunc->parameter))
        goto merr;

    PBKDF2PARAM_free(kdf);
    return keyfunc;

merr:
    ASN1err(ASN1_F_PKCS5_PBKDF2_SET, ERR_R_MALLOC_FAILURE);
    PBKDF2PARAM_free(kdf);
    X509_ALGOR_free(keyfunc);
    return NULL;
}
