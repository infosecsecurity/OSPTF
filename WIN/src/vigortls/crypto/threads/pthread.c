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
    CRYPTO_MUTEX *lock = calloc(1, sizeof(pthread_rwlock_t));
    if (lock == NULL)
        return NULL;

    if (pthread_rwlock_init(lock, NULL) != 0) {
        free(lock);
        return NULL;
    }

    return lock;
}

void CRYPTO_thread_cleanup(CRYPTO_MUTEX *lock)
{
    if (lock == NULL)
        return;

    pthread_rwlock_destroy(lock);
    free(lock);
}

int CRYPTO_thread_read_lock(CRYPTO_MUTEX *lock)
{
    if (pthread_rwlock_rdlock(lock) != 0)
        return 0;

    return 1;
}

int CRYPTO_thread_write_lock(CRYPTO_MUTEX *lock)
{
    if (pthread_rwlock_wrlock(lock) != 0)
        return 0;

    return 1;
}

int CRYPTO_thread_unlock(CRYPTO_MUTEX *lock)
{
    if (pthread_rwlock_unlock(lock) != 0)
        return 0;

    return 1;
}

int CRYPTO_thread_run_once(CRYPTO_ONCE *once, void (*init)(void))
{
    if (pthread_once(once, init) != 0)
        return 0;

    return 1;
}

int CRYPTO_thread_init_local(CRYPTO_THREAD_LOCAL *key, void (*cleanup)(void *))
{
    if (pthread_key_create(key, cleanup) != 0)
        return 0;

    return 1;
}

void *CRYPTO_thread_get_local(CRYPTO_THREAD_LOCAL *key)
{
    return pthread_getspecific(*key);
}

int CRYPTO_thread_set_local(CRYPTO_THREAD_LOCAL *key, void *val)
{
    if (pthread_setspecific(*key, val) != 0)
        return 0;

    return 1;
}

int CRYPTO_thread_cleanup_local(CRYPTO_THREAD_LOCAL *key)
{
    if (pthread_key_delete(*key) != 0)
        return 0;

    return 1;
}

CRYPTO_THREAD_ID CRYPTO_thread_get_current_id(void)
{
    return pthread_self();
}

int CRYPTO_thread_compare_id(CRYPTO_THREAD_ID a, CRYPTO_THREAD_ID b)
{
    return pthread_equal(a, b);
}

int CRYPTO_atomic_add(int *val, int amount, int *ret, CRYPTO_MUTEX *lock)
{
#ifdef __ATOMIC_RELAXED
    *ret = __atomic_add_fetch(val, amount, __ATOMIC_RELAXED);
#else
    if (!CRYPTO_thread_write_lock(lock))
        return 0;

    *val += amount;
    *ret  = *val;

    if (!CRYPTO_thread_unlock(lock))
        return 0;
#endif

    return 1;
}
