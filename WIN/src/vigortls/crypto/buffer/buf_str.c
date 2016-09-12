/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <limits.h>
#include <stdio.h>
#include <string.h>

#include <openssl/buffer.h>
#include <openssl/err.h>
#include <stdcompat.h>

size_t BUF_strnlen(const char *str, size_t maxlen)
{
    return strnlen(str, maxlen);
}

char *BUF_strdup(const char *str)
{
    char *ret = NULL;

    if (str == NULL)
        return NULL;

    ret = strdup(str);
    if (ret == NULL) {
        BUFerr(BUF_F_BUF_STRDUP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    return ret;
}

char *BUF_strndup(const char *str, size_t siz)
{
    char *ret = NULL;

    if (str == NULL)
        return NULL;

    if (siz >= INT_MAX)
        return NULL;

    ret = strndup(str, siz);
    if (ret == NULL) {
        BUFerr(BUF_F_BUF_STRNDUP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    return ret;
}

void *BUF_memdup(const void *data, size_t siz)
{
    void *ret;

    if (data == NULL)
        return NULL;

    ret = malloc(siz);
    if (ret == NULL) {
        BUFerr(BUF_F_BUF_MEMDUP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    return memcpy(ret, data, siz);
}

size_t BUF_strlcpy(char *dst, const char *src, size_t size)
{
    return strlcpy(dst, src, size);
}

size_t BUF_strlcat(char *dst, const char *src, size_t size)
{
    return strlcat(dst, src, size);
}
