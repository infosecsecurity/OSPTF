/*
 * Copyright (c) 2016, Kurt Cancemi (kurt@x64architecture.com)
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <openssl/crypto.h>

#include "internal/threads.h"

CRYPTO_MUTEX *CRYPTO_thread_new(void)
{
    CRYPTO_MUTEX *lock = calloc(1, sizeof(unsigned int));
    if (lock == NULL)
        return NULL;

    *(unsigned int *)lock = 1;

    return lock;
}

void CRYPTO_thread_cleanup(CRYPTO_MUTEX *lock)
{
    if (lock == NULL)
        return;

    *(unsigned int *)lock = 0;
    free(lock);
}

int CRYPTO_thread_read_lock(CRYPTO_MUTEX *lock)
{
    return 1;
}

int CRYPTO_thread_write_lock(CRYPTO_MUTEX *lock)
{
    return 1;
}

int CRYPTO_thread_unlock(CRYPTO_MUTEX *lock)
{
    return 1;
}

int CRYPTO_thread_run_once(CRYPTO_ONCE *once, void (*init)(void))
{
    if (*once != 0)
        return 1;

    init();
    *once = 1;

    return 1;
}

#define CRYPTO_TLS_KEY_MAX 255
static void *thread_local_storage[CRYPTO_TLS_KEY_MAX + 1];

int CRYPTO_thread_init_local(CRYPTO_THREAD_LOCAL *key, void (*cleanup)(void *))
{
    static unsigned int thread_local_key = 0;

    if (thread_local_key > CRYPTO_TLS_KEY_MAX)
        return 0;

    *key = thread_local_key++;

    thread_local_storage[*key] = NULL;

    return 1;
}

void *CRYPTO_thread_get_local(CRYPTO_THREAD_LOCAL *key)
{
    if (*key > CRYPTO_TLS_KEY_MAX)
        return NULL;

    return thread_local_storage[*key];
}

int CRYPTO_thread_set_local(CRYPTO_THREAD_LOCAL *key, void *val)
{
    if (*key > CRYPTO_TLS_KEY_MAX)
        return 0;

    thread_local_storage[*key] = val;

    return 1;
}

int CRYPTO_thread_cleanup_local(CRYPTO_THREAD_LOCAL *key)
{
    *key = CRYPTO_TLS_KEY_MAX + 1;

    return 1;
}

CRYPTO_THREAD_ID CRYPTO_thread_get_current_id(void)
{
    return 0;
}

int CRYPTO_thread_compare_id(CRYPTO_THREAD_ID a, CRYPTO_THREAD_ID b)
{
    return (a == b);
}

int CRYPTO_atomic_add(int *val, int amount, int *ret, CRYPTO_MUTEX *lock)
{
    *val += amount;
    *ret  = *val;

    return 1;
}
