/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_STACK_H
#define HEADER_STACK_H

#include <openssl/base.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct stack_st {
    int num;
    char **data;
    int sorted;

    int num_alloc;
    int (*comp)(const void *, const void *);
} _STACK; /* Use STACK_OF(...) instead */

#define M_sk_num(sk) ((sk) ? (sk)->num : -1)
#define M_sk_value(sk, n) ((sk) ? (sk)->data[n] : NULL)

VIGORTLS_EXPORT int sk_num(const _STACK *);
VIGORTLS_EXPORT void *sk_value(const _STACK *, int);

VIGORTLS_EXPORT void *sk_set(_STACK *, int, void *);

VIGORTLS_EXPORT _STACK *sk_new(int (*cmp)(const void *, const void *));
VIGORTLS_EXPORT _STACK *sk_new_null(void);
VIGORTLS_EXPORT void sk_free(_STACK *);
VIGORTLS_EXPORT void sk_pop_free(_STACK *st, void (*func)(void *));
VIGORTLS_EXPORT _STACK *sk_deep_copy(_STACK *, void *(*)(void *),
                                     void (*)(void *));
VIGORTLS_EXPORT int sk_insert(_STACK *sk, void *data, int where);
VIGORTLS_EXPORT void *sk_delete(_STACK *st, int loc);
VIGORTLS_EXPORT void *sk_delete_ptr(_STACK *st, void *p);
VIGORTLS_EXPORT int sk_find(_STACK *st, void *data);
VIGORTLS_EXPORT int sk_find_ex(_STACK *st, void *data);
VIGORTLS_EXPORT int sk_push(_STACK *st, void *data);
VIGORTLS_EXPORT int sk_unshift(_STACK *st, void *data);
VIGORTLS_EXPORT void *sk_shift(_STACK *st);
VIGORTLS_EXPORT void *sk_pop(_STACK *st);
VIGORTLS_EXPORT void sk_zero(_STACK *st);
VIGORTLS_EXPORT int (*sk_set_cmp_func(_STACK *sk,
                                      int (*c)(const void *,
                                               const void *)))(const void *,
                                                               const void *);
VIGORTLS_EXPORT _STACK *sk_dup(_STACK *st);
VIGORTLS_EXPORT void sk_sort(_STACK *st);
VIGORTLS_EXPORT int sk_is_sorted(const _STACK *st);

#ifdef __cplusplus
}
#endif

#endif
