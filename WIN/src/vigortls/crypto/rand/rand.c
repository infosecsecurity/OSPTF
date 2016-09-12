/*
 * Copyright (c) 2014 - 2015, Kurt Cancemi (kurt@x64architecture.com)
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

#include <limits.h>
#include <stdint.h>
#include <string.h>

#include <openssl/chacha.h>
#include <openssl/opensslconf.h>
#include <openssl/rand.h>

#include "cryptlib.h"
#include "internal.h"
#include "internal/threads.h"

int RAND_set_rand_method(const RAND_METHOD *meth)
{
    return 1;
}

const RAND_METHOD *RAND_get_rand_method(void)
{
    return NULL;
}

RAND_METHOD *RAND_SSLeay(void)
{
    return NULL;
}

#ifndef OPENSSL_NO_ENGINE
int RAND_set_rand_engine(ENGINE *engine)
{
    return 1;
}
#endif

void RAND_seed(const void *buf, int num)
{
    return;
}

void RAND_add(const void *buf, int num, double entropy)
{
    return;
}

#if defined(VIGORTLS_X86_64) && !defined(OPENSSL_NO_ASM)

extern int vigortls_rdrand(uint8_t *buf);
extern int vigortls_rdrand_mul_of_8(uint8_t *buf, size_t len);

static int CRYPTO_hwrand(uint8_t *buf, size_t len)
{
    if (!(OPENSSL_ia32cap_P[1] & (1U << 30)))
        return 0;

    size_t len_mul_of_8 = len & ~(8 - 1);
    if (len_mul_of_8 != 0) {
        if (!vigortls_rdrand_mul_of_8(buf, len_mul_of_8))
            return 0;
        len -= len_mul_of_8;
    }

    if (len != 0) {
        uint8_t rand_buf[8];
        if (!vigortls_rdrand(rand_buf))
            return 0;
        memcpy(buf + len_mul_of_8, rand_buf, len);
    }

    return 1;
}

#else

static int CRYPTO_hwrand(uint8_t *buf, size_t len)
{
    return 0;
}

#endif

typedef struct {
    uint8_t key[32];
    uint8_t partial_block[64];
    unsigned int partial_block_used;
    size_t bytes_used;
    uint64_t calls_used;
} RAND_STATE;

#define MAX_BYTES_PER_CALL    (0x7FFFFFFF)
#define MAX_CALLS_PER_REFRESH (1024)
#define MAX_BYTES_PER_REFRESH (1024 * 1024)

static CRYPTO_ONCE rand_init = CRYPTO_ONCE_STATIC_INIT;
static CRYPTO_THREAD_LOCAL rand_thread_local;

static void rand_thread_local_cleanup(void *state)
{
    if (state == NULL)
        return;
    vigortls_zeroize(state, sizeof(RAND_STATE));
    free(state);
}

static void rand_do_init(void)
{
    CRYPTO_thread_init_local(&rand_thread_local, rand_thread_local_cleanup);
}

int RAND_bytes(uint8_t *buf, size_t len)
{
    RAND_STATE *state;
    size_t remaining, todo, i;
    int ret;

    if (len == 0)
        return 1;

    if (!CRYPTO_hwrand(buf, len)) {
        ret = CRYPTO_genrandom(buf, len);
        return ret;
    }

    CRYPTO_thread_run_once(&rand_init, rand_do_init);

    state = CRYPTO_thread_get_local(&rand_thread_local);
    if (state == NULL) {
        state = calloc(1, sizeof(RAND_STATE));
        if (state == NULL || !CRYPTO_thread_set_local(&rand_thread_local, state)) {
            ret = CRYPTO_genrandom(buf, len);
            return ret;
        }
        state->calls_used = MAX_CALLS_PER_REFRESH;
    }

    if (state->calls_used >= MAX_CALLS_PER_REFRESH ||
        state->bytes_used >= MAX_BYTES_PER_REFRESH)
    {
        CRYPTO_genrandom(buf, len);
        state->calls_used = 0;
        state->bytes_used = 0;
        state->partial_block_used = sizeof(state->partial_block);
    }

    if (len >= sizeof(state->partial_block)) {
        remaining = len;
        for (todo = remaining; remaining > 0; buf += todo, remaining -= todo,
                                              state->calls_used++)
        {
            if (todo > MAX_BYTES_PER_CALL)
                todo = MAX_BYTES_PER_CALL;
            uint8_t nonce[12];
            memset(nonce, 0, 4);
            memcpy(nonce + 4, &state->calls_used, sizeof(state->calls_used));
            CRYPTO_chacha_20(buf, buf, todo, state->key, nonce, 0);
        }
    } else {
        if (sizeof(state->partial_block) - state->partial_block_used < len) {
            uint8_t nonce[12];
            memset(nonce, 0, 4);
            memcpy(nonce + 4, &state->calls_used, sizeof(state->calls_used));
            CRYPTO_chacha_20(state->partial_block, state->partial_block,
                             sizeof(state->partial_block), state->key, nonce, 0);
            state->partial_block_used = 0;
        }

        for (i = 0; i < len; i++) {
            buf[i] ^= state->partial_block[state->partial_block_used++];
        }
        state->calls_used++;
    }
    state->bytes_used += len;

    return 1;
}

int RAND_status(void)
{
    return 1;
}

int RAND_poll(void)
{
    return 1;
}

int RAND_pseudo_bytes(uint8_t *buf, size_t len)
{
    return RAND_bytes(buf, len);
}

int RAND_load_file(const char *path, long num) {
    if (num < 0) {
        return 1;
    } else if (num <= INT_MAX) {
        return (int)num;
    } else {
        return INT_MAX;
    }
}
