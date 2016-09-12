/*
 * Copyright (c) 2015, Kurt Cancemi (kurt@x64architecture.com)
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

#include <openssl/rc4.h>

#if defined(OPENSSL_NO_ASM) || \
    (!defined(VIGORTLS_X86) || !defined(VIGORTLS_X86_64))

/*
 * RC4 as implemented from a posting from
 * Newsgroups: sci.crypt
 * From: sterndark@netcom.com (David Sterndark)
 * Subject: RC4 Algorithm revealed.
 * Message-ID: <sternCvKL4B.Hyy@netcom.com>
 * Date: Wed, 14 Sep 1994 06:35:31 GMT
 */

void RC4(RC4_KEY *key, size_t len, const uint8_t *in, uint8_t *out)
{
    uint32_t *const S = key->data;
    uint32_t x, y, tx, ty;
    size_t i;

    x = key->x;
    y = key->y;

#ifdef SIMPLE_RC4
    for (i = 0; i < len; i++) {
        x = (x + 1) & 0xFF;
        tx = S[x];
        y = (tx + y) & 0xFF;
        S[x] = ty = S[y];
        S[y] = tx;
        out[i] = S[(S[x] + S[y]) & 0xFF] ^ (in[i]);
    }
#else
#define RC4_LOOP(in, out) \
    x = ((x + 1) & 0xFF); \
    tx = S[x];            \
    y = (tx + y) & 0xFF;  \
    S[x] = ty = S[y];     \
    S[y] = tx;            \
    (*(out)++) = S[(tx + ty) & 0xFF] ^ (*(in)++);

#define RC4_BLOOP(in, out) \
    RC4_LOOP(in, out);     \
    if (--i == 0)          \
        break;

    i = len >> 3;
    if (i) {
        do {
            RC4_LOOP(in, out);
            RC4_LOOP(in, out);
            RC4_LOOP(in, out);
            RC4_LOOP(in, out);
            RC4_LOOP(in, out);
            RC4_LOOP(in, out);
            RC4_LOOP(in, out);
            RC4_LOOP(in, out);
        } while (--i != 0);
    }
    i = len & 0x7;
    if (i) {
        for (;;) {
            RC4_BLOOP(in, out);
            RC4_BLOOP(in, out);
            RC4_BLOOP(in, out);
            RC4_BLOOP(in, out);
            RC4_BLOOP(in, out);
            RC4_BLOOP(in, out);
        }
    }
#endif

    key->x = x;
    key->y = y;
}

void RC4_set_key(RC4_KEY *key, int len, const uint8_t *data)
{
    uint32_t *const S = key->data;
    uint32_t tmp;
    unsigned int i, j = 0, k = 0;

    key->x = 0;
    key->y = 0;

    for (i = 0; i < 256; ++i)
        S[i] = i;
    for (i = 0; i < 256; ++i) {
        tmp = S[i];
        j = (j + data[k] + tmp) & 0xFF;
        S[i] = S[j];
        S[j] = tmp;
        if (++k >= (unsigned)len)
            k = 0;
    }
}

#else

void asm_RC4(RC4_KEY *key, size_t len, const uint8_t *in, uint8_t *out);
void RC4(RC4_KEY *key, size_t len, const uint8_t *in, uint8_t *out)
{
    asm_RC4(key, len, in, out);
}

void asm_RC4_set_key(RC4_KEY *rc4key, unsigned len, const uint8_t *key);
void RC4_set_key(RC4_KEY *rc4key, unsigned len, const uint8_t *key)
{
    asm_RC4_set_key(rc4key, len, key);
}

#endif
