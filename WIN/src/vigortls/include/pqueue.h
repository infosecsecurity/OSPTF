/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_PQUEUE_H
#define HEADER_PQUEUE_H

#include <openssl/base.h>

typedef struct _pqueue *pqueue;

typedef struct _pitem {
    uint8_t priority[8]; /* 64-bit value in big-endian encoding */
    void *data;
    struct _pitem *next;
} pitem;

typedef struct _pitem *piterator;

VIGORTLS_EXPORT pitem *pitem_new(uint8_t *prio64be, void *data);
VIGORTLS_EXPORT void pitem_free(pitem *item);

VIGORTLS_EXPORT pqueue pqueue_new(void);
VIGORTLS_EXPORT void pqueue_free(pqueue pq);

VIGORTLS_EXPORT pitem *pqueue_insert(pqueue pq, pitem *item);
VIGORTLS_EXPORT pitem *pqueue_peek(pqueue pq);
VIGORTLS_EXPORT pitem *pqueue_pop(pqueue pq);
VIGORTLS_EXPORT pitem *pqueue_find(pqueue pq, uint8_t *prio64be);
VIGORTLS_EXPORT pitem *pqueue_iterator(pqueue pq);
VIGORTLS_EXPORT pitem *pqueue_next(piterator *iter);

VIGORTLS_EXPORT int pqueue_size(pqueue pq);

#endif /* ! HEADER_PQUEUE_H */
