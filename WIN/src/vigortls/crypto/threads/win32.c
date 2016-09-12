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

#include <windows.h>

#include <openssl/crypto.h>

#include "internal/threads.h"

CRYPTO_MUTEX *CRYPTO_thread_new(void)
{
    CRYPTO_MUTEX *lock = calloc(1, sizeof(CRITICAL_SECTION));
    if (lock == NULL)
        return NULL;

    if (!InitializeCriticalSectionAndSpinCount(lock, 0x400)) {
        free(lock);
        return NULL;
    }

    return lock;
}

void CRYPTO_thread_cleanup(CRYPTO_MUTEX *lock)
{
    if (lock == NULL)
        return;

    DeleteCriticalSection(lock);
    free(lock);
}

int CRYPTO_thread_read_lock(CRYPTO_MUTEX *lock)
{
    EnterCriticalSection(lock);

    return 1;
}

int CRYPTO_thread_write_lock(CRYPTO_MUTEX *lock)
{
    EnterCriticalSection(lock);

    return 1;
}

int CRYPTO_thread_unlock(CRYPTO_MUTEX *lock)
{
    LeaveCriticalSection(lock);

    return 1;
}

BOOL CALLBACK init_once_callback(PINIT_ONCE init_once, PVOID parameter, PVOID *context)
{
    void (*init)(void) = parameter;

    init();

    return TRUE;
}

int CRYPTO_thread_run_once(CRYPTO_ONCE *once, void (*init)(void))
{
    if (!InitOnceExecuteOnce(once, init_once_callback, init, NULL))
        return 0;

    return 1;
}

int CRYPTO_thread_init_local(CRYPTO_THREAD_LOCAL *key, void (*cleanup)(void *))
{
    *key = TlsAlloc();
    if (*key == TLS_OUT_OF_INDEXES)
        return 0;

    return 1;
}

void *CRYPTO_thread_get_local(CRYPTO_THREAD_LOCAL *key)
{
    return TlsGetValue(*key);
}

int CRYPTO_thread_set_local(CRYPTO_THREAD_LOCAL *key, void *val)
{
    if (TlsSetValue(*key, val) == 0)
        return 0;

    return 1;
}

int CRYPTO_thread_cleanup_local(CRYPTO_THREAD_LOCAL *key)
{
    if (TlsFree(*key) == 0)
        return 0;

    return 1;
}

CRYPTO_THREAD_ID CRYPTO_thread_get_current_id(void)
{
    return GetCurrentThreadId();
}

int CRYPTO_thread_compare_id(CRYPTO_THREAD_ID a, CRYPTO_THREAD_ID b)
{
    return (a == b);
}

int CRYPTO_atomic_add(int *val, int amount, int *ret, CRYPTO_MUTEX *lock)
{
    *ret = InterlockedExchangeAdd(val, amount) + amount;

    return 1;
}
