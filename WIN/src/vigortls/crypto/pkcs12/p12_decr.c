/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>

#include <openssl/err.h>
#include <openssl/pkcs12.h>

/* Encrypt/Decrypt a buffer based on password and algor, result in a
 * malloc'ed buffer
 */

uint8_t *PKCS12_pbe_crypt(X509_ALGOR *algor, const char *pass,
                                int passlen, uint8_t *in, int inlen, uint8_t **data,
                                int *datalen, int en_de)
{
    uint8_t *out;
    int outlen, i;
    EVP_CIPHER_CTX ctx;

    EVP_CIPHER_CTX_init(&ctx);
    /* Decrypt data */
    if (!EVP_PBE_CipherInit(algor->algorithm, pass, passlen,
                            algor->parameter, &ctx, en_de)) {
        PKCS12err(PKCS12_F_PKCS12_PBE_CRYPT, PKCS12_R_PKCS12_ALGOR_CIPHERINIT_ERROR);
        return NULL;
    }

    if (!(out = malloc(inlen + EVP_CIPHER_CTX_block_size(&ctx)))) {
        PKCS12err(PKCS12_F_PKCS12_PBE_CRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EVP_CipherUpdate(&ctx, out, &i, in, inlen)) {
        free(out);
        out = NULL;
        PKCS12err(PKCS12_F_PKCS12_PBE_CRYPT, ERR_R_EVP_LIB);
        goto err;
    }

    outlen = i;
    if (!EVP_CipherFinal_ex(&ctx, out + i, &i)) {
        free(out);
        out = NULL;
        PKCS12err(PKCS12_F_PKCS12_PBE_CRYPT, PKCS12_R_PKCS12_CIPHERFINAL_ERROR);
        goto err;
    }
    outlen += i;
    if (datalen)
        *datalen = outlen;
    if (data)
        *data = out;
err:
    EVP_CIPHER_CTX_cleanup(&ctx);
    return out;
}

/* Decrypt an OCTET STRING and decode ASN1 structure
 * if zbuf set zero buffer after use.
 */

void *PKCS12_item_decrypt_d2i(X509_ALGOR *algor, const ASN1_ITEM *it,
                              const char *pass, int passlen, ASN1_OCTET_STRING *oct, int zbuf)
{
    uint8_t *out;
    const uint8_t *p;
    void *ret;
    int outlen;

    if (!PKCS12_pbe_crypt(algor, pass, passlen, oct->data, oct->length,
                          &out, &outlen, 0)) {
        PKCS12err(PKCS12_F_PKCS12_ITEM_DECRYPT_D2I, PKCS12_R_PKCS12_PBE_CRYPT_ERROR);
        return NULL;
    }
    p = out;
    ret = ASN1_item_d2i(NULL, &p, outlen, it);
    if (zbuf)
        vigortls_zeroize(out, outlen);
    if (!ret)
        PKCS12err(PKCS12_F_PKCS12_ITEM_DECRYPT_D2I, PKCS12_R_DECODE_ERROR);
    free(out);
    return ret;
}

/* Encode ASN1 structure and encrypt, return OCTET STRING
 * if zbuf set zero encoding.
 */

ASN1_OCTET_STRING *PKCS12_item_i2d_encrypt(X509_ALGOR *algor, const ASN1_ITEM *it,
                                           const char *pass, int passlen,
                                           void *obj, int zbuf)
{
    ASN1_OCTET_STRING *oct = NULL;
    uint8_t *in = NULL;
    int inlen;
    if (!(oct = ASN1_OCTET_STRING_new())) {
        PKCS12err(PKCS12_F_PKCS12_ITEM_I2D_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    inlen = ASN1_item_i2d(obj, &in, it);
    if (!in) {
        PKCS12err(PKCS12_F_PKCS12_ITEM_I2D_ENCRYPT, PKCS12_R_ENCODE_ERROR);
        ASN1_OCTET_STRING_free(oct);
        goto err;
    }
    if (!PKCS12_pbe_crypt(algor, pass, passlen, in, inlen, &oct->data,
                          &oct->length, 1)) {
        PKCS12err(PKCS12_F_PKCS12_ITEM_I2D_ENCRYPT, PKCS12_R_ENCRYPT_ERROR);
        free(in);
        ASN1_OCTET_STRING_free(oct);
        goto err;
    }
    if (zbuf)
        vigortls_zeroize(in, inlen);
    free(in);
    return oct;
err:
    ASN1_OCTET_STRING_free(oct);
    return NULL;
}

IMPLEMENT_PKCS12_STACK_OF(PKCS7)
