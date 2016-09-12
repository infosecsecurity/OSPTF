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
#include <stdlib.h>

#include <openssl/crypto.h>
#include <openssl/lhash.h>
#include <stdcompat.h>

#undef MIN_NODES
#define MIN_NODES 16
#define UP_LOAD (2 * LH_LOAD_MULT) /* load times 256  (default 2) */
#define DOWN_LOAD (LH_LOAD_MULT)   /* load times 256  (default 1) */

static void expand(_LHASH *lh);
static void contract(_LHASH *lh);
static LHASH_NODE **getrn(_LHASH *lh, const void *data, unsigned long *rhash);

_LHASH *lh_new(LHASH_HASH_FN_TYPE h, LHASH_COMP_FN_TYPE c)
{
    _LHASH *ret;
    int i;

    if ((ret = calloc(1, sizeof(_LHASH))) == NULL)
        goto err0;
    if ((ret->b = reallocarray(NULL, MIN_NODES, sizeof(LHASH_NODE *))) == NULL)
        goto err1;
    for (i = 0; i < MIN_NODES; i++)
        ret->b[i] = NULL;
    ret->comp = ((c == NULL) ? (LHASH_COMP_FN_TYPE)strcmp : c);
    ret->hash = ((h == NULL) ? (LHASH_HASH_FN_TYPE)lh_strhash : h);
    ret->num_nodes = MIN_NODES / 2;
    ret->num_alloc_nodes = MIN_NODES;
    ret->pmax = MIN_NODES / 2;
    ret->up_load = UP_LOAD;
    ret->down_load = DOWN_LOAD;

    return ret;
err1:
    free(ret);
err0:
    return NULL;
}

void lh_free(_LHASH *lh)
{
    unsigned int i;
    LHASH_NODE *n, *nn;

    if (lh == NULL)
        return;

    for (i = 0; i < lh->num_nodes; i++) {
        n = lh->b[i];
        while (n != NULL) {
            nn = n->next;
            free(n);
            n = nn;
        }
    }
    free(lh->b);
    free(lh);
}

void *lh_insert(_LHASH *lh, void *data)
{
    unsigned long hash;
    LHASH_NODE *nn, **rn;
    void *ret;

    lh->error = 0;
    if (lh->up_load <= (lh->num_items * LH_LOAD_MULT / lh->num_nodes))
        expand(lh);

    rn = getrn(lh, data, &hash);

    if (*rn == NULL) {
        if ((nn = malloc(sizeof(LHASH_NODE))) == NULL) {
            lh->error++;
            return (NULL);
        }
        nn->data = data;
        nn->next = NULL;
        nn->hash = hash;
        *rn = nn;
        ret = NULL;
        lh->num_insert++;
        lh->num_items++;
    } else /* replace same key */
    {
        ret = (*rn)->data;
        (*rn)->data = data;
        lh->num_replace++;
    }
    return (ret);
}

void *lh_delete(_LHASH *lh, const void *data)
{
    unsigned long hash;
    LHASH_NODE *nn, **rn;
    void *ret;

    lh->error = 0;
    rn = getrn(lh, data, &hash);

    if (*rn == NULL) {
        lh->num_no_delete++;
        return NULL;
    } else {
        nn = *rn;
        *rn = nn->next;
        ret = nn->data;
        free(nn);
        lh->num_delete++;
    }

    lh->num_items--;
    if ((lh->num_nodes > MIN_NODES) &&
        (lh->down_load >= (lh->num_items * LH_LOAD_MULT / lh->num_nodes)))
    {
        contract(lh);
    }

    return ret;
}

void *lh_retrieve(_LHASH *lh, const void *data)
{
    unsigned long hash;
    LHASH_NODE **rn;
    void *ret;

    lh->error = 0;
    rn = getrn(lh, data, &hash);

    if (*rn == NULL) {
        lh->num_retrieve_miss++;
        return (NULL);
    } else {
        ret = (*rn)->data;
        lh->num_retrieve++;
    }
    return (ret);
}

static void doall_util_fn(_LHASH *lh, int use_arg, LHASH_DOALL_FN_TYPE func,
                          LHASH_DOALL_ARG_FN_TYPE func_arg, void *arg)
{
    int i;
    LHASH_NODE *a, *n;

    if (lh == NULL)
        return;

    /* reverse the order so we search from 'top to bottom'
     * We were having memory leaks otherwise */
    for (i = lh->num_nodes - 1; i >= 0; i--) {
        a = lh->b[i];
        while (a != NULL) {
            n = a->next;
            if (use_arg)
                func_arg(a->data, arg);
            else
                func(a->data);
            a = n;
        }
    }
}

void lh_doall(_LHASH *lh, LHASH_DOALL_FN_TYPE func)
{
    doall_util_fn(lh, 0, func, (LHASH_DOALL_ARG_FN_TYPE)0, NULL);
}

void lh_doall_arg(_LHASH *lh, LHASH_DOALL_ARG_FN_TYPE func, void *arg)
{
    doall_util_fn(lh, 1, (LHASH_DOALL_FN_TYPE)0, func, arg);
}

static void expand(_LHASH *lh)
{
    LHASH_NODE **n, **n1, **n2, *np;
    unsigned int p, i, j;
    unsigned long hash, nni;

    lh->num_nodes++;
    lh->num_expands++;
    p = (int)lh->p++;
    n1 = &(lh->b[p]);
    n2 = &(lh->b[p + (int)lh->pmax]);
    *n2 = NULL;
    nni = lh->num_alloc_nodes;

    for (np = *n1; np != NULL;) {
        hash = np->hash;
        if ((hash % nni) != p) { /* move it */
            *n1 = (*n1)->next;
            np->next = *n2;
            *n2 = np;
        } else
            n1 = &((*n1)->next);
        np = *n1;
    }

    if ((lh->p) >= lh->pmax) {
        j = (int)lh->num_alloc_nodes * 2;
        n = reallocarray(lh->b, j, sizeof(LHASH_NODE *));
        if (n == NULL) {
            lh->error++;
            lh->p = 0;
            return;
        }
        /* else */
        for (i = (int)lh->num_alloc_nodes; i < j; i++)
            n[i] = NULL;
        lh->pmax = lh->num_alloc_nodes;
        lh->num_alloc_nodes = j;
        lh->num_expand_reallocs++;
        lh->p = 0;
        lh->b = n;
    }
}

static void contract(_LHASH *lh)
{
    LHASH_NODE **n, *n1, *np;

    np = lh->b[lh->p + lh->pmax - 1];
    lh->b[lh->p + lh->pmax - 1] = NULL;
    if (lh->p == 0) {
        n = reallocarray(lh->b, lh->pmax, sizeof(LHASH_NODE *));
        if (n == NULL) {
            lh->error++;
            return;
        }
        lh->num_contract_reallocs++;
        lh->num_alloc_nodes /= 2;
        lh->pmax /= 2;
        lh->p = lh->pmax - 1;
        lh->b = n;
    } else
        lh->p--;

    lh->num_nodes--;
    lh->num_contracts++;

    n1 = lh->b[(int)lh->p];
    if (n1 == NULL)
        lh->b[(int)lh->p] = np;
    else {
        while (n1->next != NULL)
            n1 = n1->next;
        n1->next = np;
    }
}

static LHASH_NODE **getrn(_LHASH *lh, const void *data, unsigned long *rhash)
{
    LHASH_NODE **ret, *n1;
    unsigned long hash, nn;
    LHASH_COMP_FN_TYPE cf;

    hash = (*(lh->hash))(data);
    lh->num_hash_calls++;
    *rhash = hash;

    nn = hash % lh->pmax;
    if (nn < lh->p)
        nn = hash % lh->num_alloc_nodes;

    cf = lh->comp;
    ret = &(lh->b[(int)nn]);
    for (n1 = *ret; n1 != NULL; n1 = n1->next) {
        lh->num_hash_comps++;
        if (n1->hash != hash) {
            ret = &(n1->next);
            continue;
        }
        lh->num_comp_calls++;
        if (cf(n1->data, data) == 0)
            break;
        ret = &(n1->next);
    }
    return (ret);
}

/* The following hash seems to work very well on normal text strings
 * no collisions on /usr/dict/words and it distributes on %2^n quite
 * well, not as good as MD5, but still good.
 */
unsigned long lh_strhash(const char *c)
{
    unsigned long ret = 0;
    long n;
    unsigned long v;
    int r;

    if ((c == NULL) || (*c == '\0'))
        return (ret);

    n = 0x100;
    while (*c) {
        v = n | (*c);
        n += 0x100;
        r = (int)((v >> 2) ^ v) & 0x0f;
        ret = (ret << r) | (ret >> (32 - r));
        ret &= 0xFFFFFFFFL;
        ret ^= v * v;
        c++;
    }
    return ((ret >> 16) ^ ret);
}

unsigned long lh_num_items(const _LHASH *lh)
{
    return lh ? lh->num_items : 0;
}
