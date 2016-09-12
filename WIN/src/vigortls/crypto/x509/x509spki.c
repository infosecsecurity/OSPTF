/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/err.h>
#include <openssl/x509.h>
#include <stdcompat.h>

int NETSCAPE_SPKI_set_pubkey(NETSCAPE_SPKI *x, EVP_PKEY *pkey)
{
    if ((x == NULL) || (x->spkac == NULL))
        return (0);
    return (X509_PUBKEY_set(&(x->spkac->pubkey), pkey));
}

EVP_PKEY *NETSCAPE_SPKI_get_pubkey(NETSCAPE_SPKI *x)
{
    if ((x == NULL) || (x->spkac == NULL))
        return (NULL);
    return (X509_PUBKEY_get(x->spkac->pubkey));
}

/* Load a Netscape SPKI from a base64 encoded string */

NETSCAPE_SPKI *NETSCAPE_SPKI_b64_decode(const char *str, int len)
{
    uint8_t *spki_der;
    const uint8_t *p;
    int spki_len;
    NETSCAPE_SPKI *spki;
    if (len <= 0)
        len = strlen(str);
    if (!(spki_der = malloc(len + 1))) {
        X509err(X509_F_NETSCAPE_SPKI_B64_DECODE, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    spki_len = EVP_DecodeBlock(spki_der, (const uint8_t *)str, len);
    if (spki_len < 0) {
        X509err(X509_F_NETSCAPE_SPKI_B64_DECODE,
                X509_R_BASE64_DECODE_ERROR);
        free(spki_der);
        return NULL;
    }
    p = spki_der;
    spki = d2i_NETSCAPE_SPKI(NULL, &p, spki_len);
    free(spki_der);
    return spki;
}

/* Generate a base64 encoded string from an SPKI */

char *NETSCAPE_SPKI_b64_encode(NETSCAPE_SPKI *spki)
{
    uint8_t *der_spki, *p;
    char *b64_str;
    int der_len;
    der_len = i2d_NETSCAPE_SPKI(spki, NULL);
    der_spki = malloc(der_len);
    b64_str = reallocarray(NULL, der_len, 2);
    if (!der_spki || !b64_str) {
        X509err(X509_F_NETSCAPE_SPKI_B64_ENCODE, ERR_R_MALLOC_FAILURE);
        free(der_spki);
        free(b64_str);
        return NULL;
    }
    p = der_spki;
    i2d_NETSCAPE_SPKI(spki, &p);
    EVP_EncodeBlock((uint8_t *)b64_str, der_spki, der_len);
    free(der_spki);
    return b64_str;
}
