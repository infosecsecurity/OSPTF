/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include "rsa_locl.h"

/* Size of an SSL signature: MD5+SHA1 */
#define SSL_SIG_LENGTH 36

int RSA_sign(int type, const uint8_t *m, unsigned int m_len,
             uint8_t *sigret, unsigned int *siglen, RSA *rsa)
{
    X509_SIG sig;
    ASN1_TYPE parameter;
    int i, j, ret = 1;
    uint8_t *p, *tmps = NULL;
    const uint8_t *s = NULL;
    X509_ALGOR algor;
    ASN1_OCTET_STRING digest;
    if (rsa->meth->rsa_sign) {
        return rsa->meth->rsa_sign(type, m, m_len,
                                   sigret, siglen, rsa);
    }
    /* Special case: SSL signature, just check the length */
    if (type == NID_md5_sha1) {
        if (m_len != SSL_SIG_LENGTH) {
            RSAerr(RSA_F_RSA_SIGN, RSA_R_INVALID_MESSAGE_LENGTH);
            return (0);
        }
        i = SSL_SIG_LENGTH;
        s = m;
    } else {
        sig.algor = &algor;
        sig.algor->algorithm = OBJ_nid2obj(type);
        if (sig.algor->algorithm == NULL) {
            RSAerr(RSA_F_RSA_SIGN, RSA_R_UNKNOWN_ALGORITHM_TYPE);
            return (0);
        }
        if (OBJ_length(sig.algor->algorithm) == 0) {
            RSAerr(RSA_F_RSA_SIGN, RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD);
            return (0);
        }
        parameter.type = V_ASN1_NULL;
        parameter.value.ptr = NULL;
        sig.algor->parameter = &parameter;

        sig.digest = &digest;
        sig.digest->data = (uint8_t *)m; /* TMP UGLY CAST */
        sig.digest->length = m_len;

        i = i2d_X509_SIG(&sig, NULL);
    }
    j = RSA_size(rsa);
    if (i > (j - RSA_PKCS1_PADDING_SIZE)) {
        RSAerr(RSA_F_RSA_SIGN, RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY);
        return (0);
    }
    if (type != NID_md5_sha1) {
        tmps = malloc((unsigned int)j + 1);
        if (tmps == NULL) {
            RSAerr(RSA_F_RSA_SIGN, ERR_R_MALLOC_FAILURE);
            return (0);
        }
        p = tmps;
        i2d_X509_SIG(&sig, &p);
        s = tmps;
    }
    i = RSA_private_encrypt(i, s, sigret, rsa, RSA_PKCS1_PADDING);
    if (i <= 0)
        ret = 0;
    else
        *siglen = i;

    if (type != NID_md5_sha1) {
        vigortls_zeroize(tmps, (unsigned int)j + 1);
        free(tmps);
    }
    return (ret);
}

/*
 * Check DigestInfo structure does not contain extraneous data by re-encoding
 * using DER and checking the encoding against original.
 */
static int rsa_check_digestinfo(X509_SIG *sig, uint8_t *dinfo, int dinfolen)
{
    uint8_t *der = NULL;
    int derlen;
    int ret = 0;

    derlen = i2d_X509_SIG(sig, &der);
    if (derlen <= 0)
        return 0;
    if (derlen == dinfolen && memcmp(dinfo, der, derlen) == 0)
        ret = 1;
    vigortls_zeroize(der, derlen);
    free(der);
    return ret;
}

int int_rsa_verify(int dtype, const uint8_t *m,
                   unsigned int m_len,
                   uint8_t *rm, size_t *prm_len,
                   const uint8_t *sigbuf, size_t siglen,
                   RSA *rsa)
{
    int i, ret = 0, sigtype;
    uint8_t *s;
    X509_SIG *sig = NULL;

    if (siglen != (unsigned int)RSA_size(rsa)) {
        RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_WRONG_SIGNATURE_LENGTH);
        return (0);
    }

    if ((dtype == NID_md5_sha1) && rm) {
        i = RSA_public_decrypt((int)siglen,
                               sigbuf, rm, rsa, RSA_PKCS1_PADDING);
        if (i <= 0)
            return 0;
        *prm_len = i;
        return 1;
    }

    s = malloc((unsigned int)siglen);
    if (s == NULL) {
        RSAerr(RSA_F_INT_RSA_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if ((dtype == NID_md5_sha1) && (m_len != SSL_SIG_LENGTH)) {
        RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_INVALID_MESSAGE_LENGTH);
        goto err;
    }
    i = RSA_public_decrypt((int)siglen, sigbuf, s, rsa, RSA_PKCS1_PADDING);

    if (i <= 0)
        goto err;

    /* Special case: SSL signature */
    if (dtype == NID_md5_sha1) {
        if ((i != SSL_SIG_LENGTH) || memcmp(s, m, SSL_SIG_LENGTH))
            RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_BAD_SIGNATURE);
        else
            ret = 1;
    } else {
        const uint8_t *p = s;
        sig = d2i_X509_SIG(NULL, &p, (long)i);

        if (sig == NULL)
            goto err;

        /* Excess data can be used to create forgeries */
        if (p != s + i || !rsa_check_digestinfo(sig, s, i)) {
            RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_BAD_SIGNATURE);
            goto err;
        }

        /* Parameters to the signature algorithm can also be used to
           create forgeries */
        if (sig->algor->parameter
            && ASN1_TYPE_get(sig->algor->parameter) != V_ASN1_NULL) {
            RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_BAD_SIGNATURE);
            goto err;
        }

        sigtype = OBJ_obj2nid(sig->algor->algorithm);
        if (sigtype != dtype) {
            RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_ALGORITHM_MISMATCH);
            goto err;
        }
        if (rm) {
            const EVP_MD *md;
            md = EVP_get_digestbynid(dtype);
            if (md && (EVP_MD_size(md) != sig->digest->length))
                RSAerr(RSA_F_INT_RSA_VERIFY,
                       RSA_R_INVALID_DIGEST_LENGTH);
            else {
                memcpy(rm, sig->digest->data,
                       sig->digest->length);
                *prm_len = sig->digest->length;
                ret = 1;
            }
        } else if (((unsigned int)sig->digest->length != m_len) || (memcmp(m, sig->digest->data, m_len) != 0)) {
            RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_BAD_SIGNATURE);
        } else
            ret = 1;
    }
err:
    X509_SIG_free(sig);
    if (s != NULL) {
        vigortls_zeroize(s, (unsigned int)siglen);
        free(s);
    }
    return (ret);
}

int RSA_verify(int dtype, const uint8_t *m, unsigned int m_len,
               const uint8_t *sigbuf, unsigned int siglen,
               RSA *rsa)
{

    if (rsa->meth->rsa_verify) {
        return rsa->meth->rsa_verify(dtype, m, m_len,
                                     sigbuf, siglen, rsa);
    }

    return int_rsa_verify(dtype, m, m_len, NULL, NULL, sigbuf, siglen, rsa);
}
