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

#ifndef _HEADER_INTERNAL_THREADS_H
#define _HEADER_INTERNAL_THREADS_H

#include <openssl/threads.h>

#if !defined(OPENSSL_THREADS)

typedef unsigned int CRYPTO_ONCE;

#define CRYPTO_ONCE_STATIC_INIT 0

#elif defined(_WIN32)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef INIT_ONCE CRYPTO_ONCE;

#define CRYPTO_ONCE_STATIC_INIT INIT_ONCE_STATIC_INIT

#else

#include <pthread.h>

typedef pthread_once_t CRYPTO_ONCE;

#define CRYPTO_ONCE_STATIC_INIT PTHREAD_ONCE_INIT

#endif

VIGORTLS_EXPORT CRYPTO_MUTEX *CRYPTO_thread_new(void);
VIGORTLS_EXPORT void CRYPTO_thread_cleanup(CRYPTO_MUTEX *lock);

VIGORTLS_EXPORT int CRYPTO_thread_read_lock(CRYPTO_MUTEX *lock);
VIGORTLS_EXPORT int CRYPTO_thread_write_lock(CRYPTO_MUTEX *lock);
VIGORTLS_EXPORT int CRYPTO_thread_unlock(CRYPTO_MUTEX *lock);

VIGORTLS_EXPORT int CRYPTO_thread_run_once(CRYPTO_ONCE *once,
                                           void (*init)(void));

VIGORTLS_EXPORT int CRYPTO_thread_init_local(CRYPTO_THREAD_LOCAL *key,
                                             void (*cleanup)(void *));
VIGORTLS_EXPORT void *CRYPTO_thread_get_local(CRYPTO_THREAD_LOCAL *key);
VIGORTLS_EXPORT int CRYPTO_thread_set_local(CRYPTO_THREAD_LOCAL *key,
                                            void *val);
VIGORTLS_EXPORT int CRYPTO_thread_cleanup_local(CRYPTO_THREAD_LOCAL *key);

VIGORTLS_EXPORT CRYPTO_THREAD_ID CRYPTO_thread_get_current_id(void);
VIGORTLS_EXPORT int CRYPTO_thread_compare_id(CRYPTO_THREAD_ID a,
                                             CRYPTO_THREAD_ID b);

VIGORTLS_EXPORT int CRYPTO_atomic_add(int *val, int amount, int *ret,
                                      CRYPTO_MUTEX *lock);

#endif
