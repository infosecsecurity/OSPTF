/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>

#include <openssl/asn1.h>
#include <openssl/buffer.h>
#include <openssl/err.h>

int i2a_ASN1_INTEGER(BIO *bp, ASN1_INTEGER *a)
{
    int i, n = 0;
    static const char *h = "0123456789ABCDEF";
    char buf[2];

    if (a == NULL)
        return (0);

    if (a->type & V_ASN1_NEG) {
        if (BIO_write(bp, "-", 1) != 1)
            goto err;
        n = 1;
    }

    if (a->length == 0) {
        if (BIO_write(bp, "00", 2) != 2)
            goto err;
        n += 2;
    } else {
        for (i = 0; i < a->length; i++) {
            if ((i != 0) && (i % 35 == 0)) {
                if (BIO_write(bp, "\\\n", 2) != 2)
                    goto err;
                n += 2;
            }
            buf[0] = h[((uint8_t)a->data[i] >> 4) & 0x0f];
            buf[1] = h[((uint8_t)a->data[i]) & 0x0f];
            if (BIO_write(bp, buf, 2) != 2)
                goto err;
            n += 2;
        }
    }
    return (n);
err:
    return (-1);
}

int a2i_ASN1_INTEGER(BIO *bp, ASN1_INTEGER *bs, char *buf, int size)
{
    int ret = 0;
    int i, j, k, m, n, again, bufsize;
    uint8_t *s = NULL, *sp = NULL;
    uint8_t *bufp;
    int num = 0, slen = 0, first = 1;

    bs->type = V_ASN1_INTEGER;

    bufsize = BIO_gets(bp, buf, size);
    for (;;) {
        if (bufsize < 1)
            goto err_sl;
        i = bufsize;
        if (buf[i - 1] == '\n')
            buf[--i] = '\0';
        if (i == 0)
            goto err_sl;
        if (buf[i - 1] == '\r')
            buf[--i] = '\0';
        if (i == 0)
            goto err_sl;
        again = (buf[i - 1] == '\\');

        for (j = 0; j < i; j++) {
            if (!(((buf[j] >= '0') && (buf[j] <= '9')) || ((buf[j] >= 'a') && (buf[j] <= 'f')) || ((buf[j] >= 'A') && (buf[j] <= 'F')))) {
                i = j;
                break;
            }
        }
        buf[i] = '\0';
        /* We have now cleared all the crap off the end of the
         * line */
        if (i < 2)
            goto err_sl;

        bufp = (uint8_t *)buf;
        if (first) {
            first = 0;
            if ((bufp[0] == '0') && (buf[1] == '0')) {
                bufp += 2;
                i -= 2;
            }
        }
        k = 0;
        i -= again;
        if (i % 2 != 0) {
            ASN1err(ASN1_F_A2I_ASN1_INTEGER, ASN1_R_ODD_NUMBER_OF_CHARS);
            goto err;
        }
        i /= 2;
        if (num + i > slen) {
            if (s == NULL)
                sp = malloc((unsigned int)num + i * 2);
            else
                sp = OPENSSL_realloc_clean(s, slen, num + i * 2);
            if (sp == NULL) {
                ASN1err(ASN1_F_A2I_ASN1_INTEGER, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            s = sp;
            slen = num + i * 2;
        }
        for (j = 0; j < i; j++, k += 2) {
            for (n = 0; n < 2; n++) {
                m = bufp[k + n];
                if ((m >= '0') && (m <= '9'))
                    m -= '0';
                else if ((m >= 'a') && (m <= 'f'))
                    m = m - 'a' + 10;
                else if ((m >= 'A') && (m <= 'F'))
                    m = m - 'A' + 10;
                else {
                    ASN1err(ASN1_F_A2I_ASN1_INTEGER, ASN1_R_NON_HEX_CHARACTERS);
                    goto err;
                }
                s[num + j] <<= 4;
                s[num + j] |= m;
            }
        }
        num += i;
        if (again)
            bufsize = BIO_gets(bp, buf, size);
        else
            break;
    }
    bs->length = num;
    bs->data = s;
    ret = 1;
err:
    if (0) {
    err_sl:
        ASN1err(ASN1_F_A2I_ASN1_INTEGER, ASN1_R_SHORT_LINE);
    }
    free(s);
    return (ret);
}

int i2a_ASN1_ENUMERATED(BIO *bp, ASN1_ENUMERATED *a)
{
    return i2a_ASN1_INTEGER(bp, a);
}

int a2i_ASN1_ENUMERATED(BIO *bp, ASN1_ENUMERATED *bs, char *buf, int size)
{
    int rv = a2i_ASN1_INTEGER(bp, bs, buf, size);
    if (rv == 1)
        bs->type = V_ASN1_INTEGER | (bs->type & V_ASN1_NEG);
    return rv;
}
