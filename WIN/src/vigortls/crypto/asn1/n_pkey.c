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

#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>


typedef struct netscape_pkey_st {
    long version;
    X509_ALGOR *algor;
    ASN1_OCTET_STRING *private_key;
} NETSCAPE_PKEY;

typedef struct netscape_encrypted_pkey_st {
    ASN1_OCTET_STRING *os;
    /* This is the same structure as DigestInfo so use it:
     * although this isn't really anything to do with
     * digests.
     */
    X509_SIG *enckey;
} NETSCAPE_ENCRYPTED_PKEY;

DECLARE_ASN1_FUNCTIONS_const(NETSCAPE_ENCRYPTED_PKEY)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(NETSCAPE_ENCRYPTED_PKEY, NETSCAPE_ENCRYPTED_PKEY)

ASN1_BROKEN_SEQUENCE(NETSCAPE_ENCRYPTED_PKEY) = {
    ASN1_SIMPLE(NETSCAPE_ENCRYPTED_PKEY, os, ASN1_OCTET_STRING),
    ASN1_SIMPLE(NETSCAPE_ENCRYPTED_PKEY, enckey, X509_SIG)
} ASN1_BROKEN_SEQUENCE_END(NETSCAPE_ENCRYPTED_PKEY)

NETSCAPE_ENCRYPTED_PKEY *d2i_NETSCAPE_ENCRYPTED_PKEY(NETSCAPE_ENCRYPTED_PKEY **a, const uint8_t **in, long len)
{
    return (NETSCAPE_ENCRYPTED_PKEY *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(NETSCAPE_ENCRYPTED_PKEY));
}

int i2d_NETSCAPE_ENCRYPTED_PKEY(const NETSCAPE_ENCRYPTED_PKEY *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(NETSCAPE_ENCRYPTED_PKEY));
}

NETSCAPE_ENCRYPTED_PKEY *NETSCAPE_ENCRYPTED_PKEY_new(void)
{
    return (NETSCAPE_ENCRYPTED_PKEY *)ASN1_item_new(ASN1_ITEM_rptr(NETSCAPE_ENCRYPTED_PKEY));
}

void NETSCAPE_ENCRYPTED_PKEY_free(NETSCAPE_ENCRYPTED_PKEY *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(NETSCAPE_ENCRYPTED_PKEY));
}

DECLARE_ASN1_FUNCTIONS_const(NETSCAPE_PKEY)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(NETSCAPE_PKEY, NETSCAPE_PKEY)

ASN1_SEQUENCE(NETSCAPE_PKEY) = {
    ASN1_SIMPLE(NETSCAPE_PKEY, version, LONG),
    ASN1_SIMPLE(NETSCAPE_PKEY, algor, X509_ALGOR),
    ASN1_SIMPLE(NETSCAPE_PKEY, private_key, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(NETSCAPE_PKEY)

NETSCAPE_PKEY *d2i_NETSCAPE_PKEY(NETSCAPE_PKEY **a, const uint8_t **in, long len)
{
    return (NETSCAPE_PKEY *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(NETSCAPE_PKEY));
}

int i2d_NETSCAPE_PKEY(const NETSCAPE_PKEY *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(NETSCAPE_PKEY));
}

NETSCAPE_PKEY *NETSCAPE_PKEY_new(void)
{
    return (NETSCAPE_PKEY *)ASN1_item_new(ASN1_ITEM_rptr(NETSCAPE_PKEY));
}

void NETSCAPE_PKEY_free(NETSCAPE_PKEY *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(NETSCAPE_PKEY));
}

static RSA *d2i_RSA_NET_2(RSA **a, ASN1_OCTET_STRING *os,
                          int (*cb)(char *buf, int len, const char *prompt,int verify),
                          int sgckey);

int i2d_Netscape_RSA(const RSA *a, uint8_t **pp,
                     int (*cb)(char *buf, int len, const char *prompt, int verify))
{
    return i2d_RSA_NET(a, pp, cb, 0);
}

int i2d_RSA_NET(const RSA *a, uint8_t **pp,
                int (*cb)(char *buf, int len, const char *prompt, int verify),
                int sgckey)
{
    int i, j, ret = 0;
    int rsalen, pkeylen, olen;
    NETSCAPE_PKEY *pkey = NULL;
    NETSCAPE_ENCRYPTED_PKEY *enckey = NULL;
    uint8_t buf[256], *zz;
    uint8_t key[EVP_MAX_KEY_LENGTH];
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);

    if (a == NULL)
        return (0);

    if ((pkey = NETSCAPE_PKEY_new()) == NULL)
        goto err;
    if ((enckey = NETSCAPE_ENCRYPTED_PKEY_new()) == NULL)
        goto err;
    pkey->version = 0;

    pkey->algor->algorithm = OBJ_nid2obj(NID_rsaEncryption);
    if ((pkey->algor->parameter = ASN1_TYPE_new()) == NULL)
        goto err;
    pkey->algor->parameter->type = V_ASN1_NULL;

    rsalen = i2d_RSAPrivateKey(a, NULL);

    /* Fake some octet strings just for the initial length
     * calculation.
      */

    pkey->private_key->length = rsalen;

    pkeylen = i2d_NETSCAPE_PKEY(pkey, NULL);

    enckey->enckey->digest->length = pkeylen;

    enckey->os->length = 11; /* "private-key" */

    enckey->enckey->algor->algorithm = OBJ_nid2obj(NID_rc4);
    if ((enckey->enckey->algor->parameter = ASN1_TYPE_new()) == NULL)
        goto err;
    enckey->enckey->algor->parameter->type = V_ASN1_NULL;

    if (pp == NULL) {
        olen = i2d_NETSCAPE_ENCRYPTED_PKEY(enckey, NULL);
        NETSCAPE_PKEY_free(pkey);
        NETSCAPE_ENCRYPTED_PKEY_free(enckey);
        return olen;
    }

    /* Since its RC4 encrypted length is actual length */
    if ((zz = malloc(rsalen)) == NULL) {
        ASN1err(ASN1_F_I2D_RSA_NET, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    pkey->private_key->data = zz;
    /* Write out private key encoding */
    i2d_RSAPrivateKey(a, &zz);

    if ((zz = malloc(pkeylen)) == NULL) {
        ASN1err(ASN1_F_I2D_RSA_NET, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!ASN1_STRING_set(enckey->os, "private-key", -1)) {
        ASN1err(ASN1_F_I2D_RSA_NET, ERR_R_MALLOC_FAILURE);
        free(zz);
        goto err;
    }
    enckey->enckey->digest->data = zz;
    i2d_NETSCAPE_PKEY(pkey, &zz);

    /* Wipe the private key encoding */
    vigortls_zeroize(pkey->private_key->data, rsalen);

    if (cb == NULL)
        cb = EVP_read_pw_string;
    i = cb((char *)buf, 256, "Enter Private Key password:", 1);
    if (i != 0) {
        ASN1err(ASN1_F_I2D_RSA_NET, ASN1_R_BAD_PASSWORD_READ);
        goto err;
    }
    i = strlen((char *)buf);
    /* If the key is used for SGC the algorithm is modified a little. */
    if (sgckey) {
        if (!EVP_Digest(buf, i, buf, NULL, EVP_md5(), NULL))
            goto err;
        memcpy(buf + 16, "SGCKEYSALT", 10);
        i = 26;
    }

    if (!EVP_BytesToKey(EVP_rc4(), EVP_md5(), NULL, buf, i, 1, key, NULL))
        goto err;
    vigortls_zeroize(buf, 256);

    /* Encrypt private key in place */
    zz = enckey->enckey->digest->data;
    if (!EVP_EncryptInit_ex(&ctx, EVP_rc4(), NULL, key, NULL))
        goto err;
    if (!EVP_EncryptUpdate(&ctx, zz, &i, zz, pkeylen))
        goto err;
    if (!EVP_EncryptFinal_ex(&ctx, zz + i, &j))
        goto err;

    ret = i2d_NETSCAPE_ENCRYPTED_PKEY(enckey, pp);
err:
    EVP_CIPHER_CTX_cleanup(&ctx);
    NETSCAPE_ENCRYPTED_PKEY_free(enckey);
    NETSCAPE_PKEY_free(pkey);
    return (ret);
}

RSA *d2i_Netscape_RSA(RSA **a, const uint8_t **pp, long length,
                      int (*cb)(char *buf, int len, const char *prompt,
                                int verify))
{
    return d2i_RSA_NET(a, pp, length, cb, 0);
}

RSA *d2i_RSA_NET(RSA **a, const uint8_t **pp, long length,
                 int (*cb)(char *buf, int len, const char *prompt, int verify),
                 int sgckey)
{
    RSA *ret = NULL;
    const uint8_t *p;
    NETSCAPE_ENCRYPTED_PKEY *enckey = NULL;

    p = *pp;

    enckey = d2i_NETSCAPE_ENCRYPTED_PKEY(NULL, &p, length);
    if (!enckey) {
        ASN1err(ASN1_F_D2I_RSA_NET, ASN1_R_DECODING_ERROR);
        return NULL;
    }

    if ((enckey->os->length != 11) || (strncmp("private-key",
                                               (char *)enckey->os->data, 11) != 0)) {
        ASN1err(ASN1_F_D2I_RSA_NET, ASN1_R_PRIVATE_KEY_HEADER_MISSING);
        NETSCAPE_ENCRYPTED_PKEY_free(enckey);
        return NULL;
    }
    if (OBJ_obj2nid(enckey->enckey->algor->algorithm) != NID_rc4) {
        ASN1err(ASN1_F_D2I_RSA_NET, ASN1_R_UNSUPPORTED_ENCRYPTION_ALGORITHM);
        goto err;
    }
    if (cb == NULL)
        cb = EVP_read_pw_string;
    if ((ret = d2i_RSA_NET_2(a, enckey->enckey->digest, cb, sgckey)) == NULL)
        goto err;

    *pp = p;

err:
    NETSCAPE_ENCRYPTED_PKEY_free(enckey);
    return ret;
}

static RSA *d2i_RSA_NET_2(RSA **a, ASN1_OCTET_STRING *os,
                          int (*cb)(char *buf, int len, const char *prompt,
                                    int verify),
                          int sgckey)
{
    NETSCAPE_PKEY *pkey = NULL;
    RSA *ret = NULL;
    int i, j;
    uint8_t buf[256];
    const uint8_t *zz;
    uint8_t key[EVP_MAX_KEY_LENGTH];
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);

    i = cb((char *)buf, 256, "Enter Private Key password:", 0);
    if (i != 0) {
        ASN1err(ASN1_F_D2I_RSA_NET_2, ASN1_R_BAD_PASSWORD_READ);
        goto err;
    }

    i = strlen((char *)buf);
    if (sgckey) {
        if (!EVP_Digest(buf, i, buf, NULL, EVP_md5(), NULL))
            goto err;
        memcpy(buf + 16, "SGCKEYSALT", 10);
        i = 26;
    }

    if (!EVP_BytesToKey(EVP_rc4(), EVP_md5(), NULL, buf, i, 1, key, NULL))
        goto err;
    vigortls_zeroize(buf, 256);

    if (!EVP_DecryptInit_ex(&ctx, EVP_rc4(), NULL, key, NULL))
        goto err;
    if (!EVP_DecryptUpdate(&ctx, os->data, &i, os->data, os->length))
        goto err;
    if (!EVP_DecryptFinal_ex(&ctx, &(os->data[i]), &j))
        goto err;
    os->length = i + j;

    zz = os->data;

    if ((pkey = d2i_NETSCAPE_PKEY(NULL, &zz, os->length)) == NULL) {
        ASN1err(ASN1_F_D2I_RSA_NET_2, ASN1_R_UNABLE_TO_DECODE_RSA_PRIVATE_KEY);
        goto err;
    }

    zz = pkey->private_key->data;
    if ((ret = d2i_RSAPrivateKey(a, &zz, pkey->private_key->length)) == NULL) {
        ASN1err(ASN1_F_D2I_RSA_NET_2, ASN1_R_UNABLE_TO_DECODE_RSA_KEY);
        goto err;
    }
err:
    EVP_CIPHER_CTX_cleanup(&ctx);
    NETSCAPE_PKEY_free(pkey);
    return (ret);
}

