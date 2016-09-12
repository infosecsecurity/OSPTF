/*
 * Copyright (c) 2014 - 2016, Kurt Cancemi (kurt@x64architecture.com)
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

#ifndef HEADER_POLY1305_H
#define HEADER_POLY1305_H

#include <openssl/base.h>

#if defined(OPENSSL_NO_POLY1305)
#error Poly1305 is disabled.
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#define POLY1305_BLOCK_SIZE 16

typedef void (*poly1305_blocks_f)(void *ctx, const uint8_t *in, size_t len,
                                  uint32_t padbit);
typedef void (*poly1305_emit_f)(void *ctx, uint8_t mac[16],
                                const uint32_t nonce[4]);

typedef struct {
    double opaque[24]; /* large enough to hold internal state, declared
                        * 'double' to ensure at least 64-bit invariant
                        * alignment across all platforms and
                        * configurations */
    uint32_t nonce[4];
    uint8_t data[POLY1305_BLOCK_SIZE];
    size_t num;
    struct {
        poly1305_blocks_f blocks;
        poly1305_emit_f emit;
    } func;
} poly1305_state;

VIGORTLS_EXPORT void CRYPTO_poly1305_init(poly1305_state *ctx,
                                          const uint8_t key[32]);
VIGORTLS_EXPORT void CRYPTO_poly1305_update(poly1305_state *ctx,
                                            const uint8_t *in, size_t len);
VIGORTLS_EXPORT void CRYPTO_poly1305_finish(poly1305_state *ctx,
                                            uint8_t mac[16]);

#ifdef __cplusplus
}
#endif
#endif
