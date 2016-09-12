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

#include <openssl/buffer.h>
#include <openssl/err.h>

/* LIMIT_BEFORE_EXPANSION is the maximum n such that (n+3)/3*4 < 2**31. That
 * function is applied in several functions in this file and this limit ensures
 * that the result fits in an int. */
#define LIMIT_BEFORE_EXPANSION 0x5ffffffc

BUF_MEM *BUF_MEM_new(void)
{
    BUF_MEM *ret;

    ret = calloc(1, sizeof(BUF_MEM));
    if (ret == NULL) {
        BUFerr(BUF_F_BUF_MEM_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    return ret;
}

void BUF_MEM_free(BUF_MEM *a)
{
    if (a == NULL)
        return;

    if (a->data != NULL) {
        vigortls_zeroize(a->data, a->max);
        free(a->data);
    }
    free(a);
}

int BUF_MEM_grow(BUF_MEM *str, size_t len)
{
    char *ret;
    size_t n;

    if (str->length >= len) {
        str->length = len;
        return len;
    }
    if (str->max >= len) {
        memset(&str->data[str->length], 0, len - str->length);
        str->length = len;
        return len;
    }
    /* This limit is sufficient to ensure (len+3)/3*4 < 2**31 */
    if (len > LIMIT_BEFORE_EXPANSION) {
        BUFerr(BUF_F_BUF_MEM_GROW, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    n = (len + 3) / 3 * 4;
    ret = realloc(str->data, n);
    if (ret == NULL) {
        BUFerr(BUF_F_BUF_MEM_GROW, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    str->data = ret;
    str->max = n;
    memset(&str->data[str->length], 0, len - str->length);
    str->length = len;

    return len;
}

int BUF_MEM_grow_clean(BUF_MEM *str, size_t len)
{
    char *ret;
    size_t n;

    if (str->length >= len) {
        memset(&str->data[len], 0, str->length - len);
        str->length = len;
        return len;
    }
    if (str->max >= len) {
        memset(&str->data[str->length], 0, len - str->length);
        str->length = len;
        return len;
    }
    /* This limit is sufficient to ensure (len+3)/3*4 < 2**31 */
    if (len > LIMIT_BEFORE_EXPANSION) {
        BUFerr(BUF_F_BUF_MEM_GROW_CLEAN, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    n = (len + 3) / 3 * 4;
    ret = malloc(n);
    if (ret == NULL) {
        BUFerr(BUF_F_BUF_MEM_GROW_CLEAN, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if (str->data != NULL) {
        memcpy(ret, str->data, str->max);
        vigortls_zeroize(str->data, str->max);
        free(str->data);
    }

    str->data = ret;
    str->max = n;
    memset(&str->data[str->length], 0, len - str->length);
    str->length = len;

    return len;
}

void BUF_reverse(uint8_t *out, const uint8_t *in, size_t size)
{
    size_t i;
    if (in) {
        out += size - 1;
        for (i = 0; i < size; i++)
            *out-- = *in++;
    } else {
        uint8_t *q;
        char c;
        q = out + size - 1;
        for (i = 0; i < size / 2; i++) {
            c = *q;
            *q-- = *out;
            *out++ = c;
        }
    }
}
