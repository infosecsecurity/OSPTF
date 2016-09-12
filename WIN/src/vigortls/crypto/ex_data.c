/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/lhash.h>
#include <stdcompat.h>

#include "internal/threads.h"

typedef struct {
    long argl;                  /* Arbitary long */
    void *argp;                 /* Arbitary void * */
    CRYPTO_EX_new *new_func;
    CRYPTO_EX_free *free_func;
    CRYPTO_EX_dup *dup_func;
} CRYPTO_EX_DATA_FUNCS;

DECLARE_STACK_OF(CRYPTO_EX_DATA_FUNCS)

/*
 * State for each class; could just be a typedef, but this allows future
 * changes.
 */

typedef struct {
    STACK_OF(CRYPTO_EX_DATA_FUNCS) *meth;
} EX_CLASS_ITEM;
static EX_CLASS_ITEM ex_data[CRYPTO_EX_INDEX__COUNT];

static CRYPTO_MUTEX *ex_data_lock;
static CRYPTO_ONCE ex_data_init = CRYPTO_ONCE_STATIC_INIT;

static void do_ex_data_init(void)
{
    ex_data_lock = CRYPTO_thread_new();
}

/*
 * Return the EX_CLASS_ITEM from the "ex_data" array that corresponds to
 * a given class.  On success, *holds the lock.*
 */
static EX_CLASS_ITEM *def_get_class(int class_index)
{
    EX_CLASS_ITEM *ip;

    if (class_index < 0 || class_index >= CRYPTO_EX_INDEX__COUNT) {
        CRYPTOerr(CRYPTO_F_DEF_GET_CLASS, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    CRYPTO_thread_run_once(&ex_data_init, do_ex_data_init);

    ip = &ex_data[class_index];
    CRYPTO_thread_write_lock(ex_data_lock);
    if (ip->meth == NULL) {
        ip->meth = sk_CRYPTO_EX_DATA_FUNCS_new_null();
        /* We push an initial value on the stack because the SSL
         * "app_data" routines use ex_data index zero.  See RT 3710. */
        if (ip->meth == NULL
            || !sk_CRYPTO_EX_DATA_FUNCS_push(ip->meth, NULL))
        {
            CRYPTOerr(CRYPTO_F_DEF_GET_CLASS, ERR_R_MALLOC_FAILURE);
            CRYPTO_thread_unlock(ex_data_lock);
            return NULL;
        }
    }
    return ip;
}

static void cleanup_cb(CRYPTO_EX_DATA_FUNCS *funcs)
{
    free(funcs);
}

/*
 * Release all "ex_data" state to prevent memory leaks. This can't be made
 * thread-safe without overhauling a lot of stuff, and shouldn't really be
 * called under potential race-conditions anyway (it's for program shutdown
 * after all).
 */
void CRYPTO_cleanup_all_ex_data(void)
{
    unsigned i;

    for (i = 0; i < CRYPTO_EX_INDEX__COUNT; ++i) {
        EX_CLASS_ITEM *ip = &ex_data[i];

        sk_CRYPTO_EX_DATA_FUNCS_pop_free(ip->meth, cleanup_cb);
        ip->meth = NULL;
    }
}

/* Add a new method to the given EX_CLASS_ITEM and return the corresponding
 * index (or -1 for error). Handles locking. */
int CRYPTO_get_ex_new_index(int class_index, long argl, void *argp,
                            CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func,
                            CRYPTO_EX_free *free_func)
{
    int toret = -1;
    CRYPTO_EX_DATA_FUNCS *a;
    EX_CLASS_ITEM *ip = def_get_class(class_index);

    if (!ip)
        return -1;
    a = malloc(sizeof(*a));
    if (a == NULL) {
        CRYPTOerr(CRYPTO_F_CRYPTO_GET_EX_NEW_INDEX, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    a->argl = argl;
    a->argp = argp;
    a->new_func = new_func;
    a->dup_func = dup_func;
    a->free_func = free_func;

    if (!sk_CRYPTO_EX_DATA_FUNCS_push(ip->meth, NULL)) {
        CRYPTOerr(CRYPTO_F_CRYPTO_GET_EX_NEW_INDEX, ERR_R_MALLOC_FAILURE);
        free(a);
        goto err;
    }
    toret = sk_CRYPTO_EX_DATA_FUNCS_num(ip->meth) - 1;
    (void)sk_CRYPTO_EX_DATA_FUNCS_set(ip->meth, toret, a);

err:
    CRYPTO_thread_unlock(ex_data_lock);
    return toret;
}

/*
 * Initialise a new CRYPTO_EX_DATA for use in a particular class - including
 * calling new() callbacks for each index in the class used by this variable
 * Thread-safe by copying a class's array of "CRYPTO_EX_DATA_FUNCS" entries
 * in the lock, then using them outside the lock. Note this only applies
 * to the global "ex_data" state (ie. class definitions), not 'ad' itself.
 */
#define NELEMS(x) (sizeof(x) / sizeof(x[0]))
int CRYPTO_new_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad)
{
    int mx, i;
    void *ptr;
    CRYPTO_EX_DATA_FUNCS **storage = NULL;
    CRYPTO_EX_DATA_FUNCS *stack[10];
    EX_CLASS_ITEM *ip = def_get_class(class_index);

    if (!ip)
        return 0;

    ad->sk = NULL;

    mx = sk_CRYPTO_EX_DATA_FUNCS_num(ip->meth);
    if (mx > 0) {
        if (mx < (int)NELEMS(stack))
            storage = stack;
        else
            storage = reallocarray(NULL, mx, sizeof(CRYPTO_EX_DATA_FUNCS *));
        if (storage) {
            for (i = 0; i < mx; i++)
                storage[i] = sk_CRYPTO_EX_DATA_FUNCS_value(ip->meth, i);
        }
    }
    CRYPTO_thread_unlock(ex_data_lock);

    if ((mx > 0) && storage == NULL) {
        CRYPTOerr(CRYPTO_F_CRYPTO_NEW_EX_DATA, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    for (i = 0; i < mx; i++) {
        if (storage[i] && storage[i]->new_func) {
            ptr = CRYPTO_get_ex_data(ad, i);
            storage[i]->new_func(obj, ptr, ad, i, storage[i]->argl,
                                 storage[i]->argp);
        }
    }
    if (storage != stack)
        free(storage);
    return 1;
}

/*
 * Duplicate a CRYPTO_EX_DATA variable - including calling dup() callbacks
 * for each index in the class used by this variable
 */
int CRYPTO_dup_ex_data(int class_index, CRYPTO_EX_DATA *to,
                       CRYPTO_EX_DATA *from)
{
    int mx, j, i;
    char *ptr;
    CRYPTO_EX_DATA_FUNCS *stack[10];
    CRYPTO_EX_DATA_FUNCS **storage = NULL;
    EX_CLASS_ITEM *ip;

    if (from->sk == NULL)
        /* Nothing to copy over */
        return 1;
    if ((ip = def_get_class(class_index)) == NULL)
        return 0;

    mx = sk_CRYPTO_EX_DATA_FUNCS_num(ip->meth);
    j = sk_void_num(from->sk);
    if (j < mx)
        mx = j;
    if (mx > 0) {
        if (mx < (int)NELEMS(stack))
            storage = stack;
        else
            storage = reallocarray(NULL, mx, sizeof(CRYPTO_EX_DATA_FUNCS *));

        if (storage) {
            for (i = 0; i < mx; i++)
                storage[i] = sk_CRYPTO_EX_DATA_FUNCS_value(ip->meth, i);
        }
    }
    CRYPTO_thread_unlock(ex_data_lock);

    if (mx > 0 && storage == NULL) {
        CRYPTOerr(CRYPTO_F_CRYPTO_DUP_EX_DATA, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    for (i = 0; i < mx; i++) {
        ptr = CRYPTO_get_ex_data(from, i);
        if (storage[i] && storage[i]->dup_func)
            storage[i]->dup_func(to, from, &ptr, i,
                                 storage[i]->argl, storage[i]->argp);
        CRYPTO_set_ex_data(to, i, ptr);
    }
    if (storage != stack)
        free(storage);
    return 1;
}

/*
 * Cleanup a CRYPTO_EX_DATA variable - including calling free() callbacks for
 * each index in the class used by this variable
 */
void CRYPTO_free_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad)
{
    int mx, i;
    EX_CLASS_ITEM *ip;
    void *ptr;
    CRYPTO_EX_DATA_FUNCS *stack[10];
    CRYPTO_EX_DATA_FUNCS **storage = NULL;

    if ((ip = def_get_class(class_index)) == NULL)
        return;
    mx = sk_CRYPTO_EX_DATA_FUNCS_num(ip->meth);
    if (mx > 0) {
        if (mx < (int)NELEMS(stack))
            storage = stack;
        else
            storage = reallocarray(NULL, mx, sizeof(CRYPTO_EX_DATA_FUNCS *));
        if (storage) {
            for (i = 0; i < mx; i++)
                storage[i] = sk_CRYPTO_EX_DATA_FUNCS_value(ip->meth, i);
        }
    }
    CRYPTO_thread_unlock(ex_data_lock);

    if (mx > 0 && storage == NULL) {
        CRYPTOerr(CRYPTO_F_CRYPTO_FREE_EX_DATA, ERR_R_MALLOC_FAILURE);
        return;
    }
    for (i = 0; i < mx; i++) {
        if (storage[i] && storage[i]->free_func) {
            ptr = CRYPTO_get_ex_data(ad, i);
            storage[i]->free_func(obj, ptr, ad, i,
                                  storage[i]->argl, storage[i]->argp);
        }
    }
    if (storage != stack)
        free(storage);
    if (ad->sk) {
        sk_void_free(ad->sk);
        ad->sk = NULL;
    }
}

/* For a given CRYPTO_EX_DATA variable, set the value corresponding to a
 * particular index in the class used by this variable */
int CRYPTO_set_ex_data(CRYPTO_EX_DATA *ad, int idx, void *val)
{
    int i;

    if (ad->sk == NULL) {
        if ((ad->sk = sk_void_new_null()) == NULL) {
            CRYPTOerr(CRYPTO_F_CRYPTO_SET_EX_DATA, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }
    i = sk_void_num(ad->sk);

    for (i = sk_void_num(ad->sk); i <= idx; ++i) {
        if (!sk_void_push(ad->sk, NULL)) {
            CRYPTOerr(CRYPTO_F_CRYPTO_SET_EX_DATA, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }
    sk_void_set(ad->sk, idx, val);
    return 1;
}

/* For a given CRYPTO_EX_DATA_ variable, get the value corresponding to a
 * particular index in the class used by this variable */
void *CRYPTO_get_ex_data(const CRYPTO_EX_DATA *ad, int idx)
{
    if (ad->sk == NULL || idx >= sk_void_num(ad->sk))
        return NULL;
    return sk_void_value(ad->sk, idx);
}
