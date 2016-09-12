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

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_CHACHA

#include <stdint.h>
#include <string.h>

#include <openssl/chacha.h>

#define ROTATE(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define U8TO32_LITTLE(p)         \
    (((uint32_t)(p)[0]      )  | \
     ((uint32_t)(p)[1] <<  8)  | \
     ((uint32_t)(p)[2] << 16)  | \
     ((uint32_t)(p)[3] << 24))

#define U32TO8_LITTLE(p, v)        \
    {                              \
        (p)[0] = (v >>  0) & 0xff; \
        (p)[1] = (v >>  8) & 0xff; \
        (p)[2] = (v >> 16) & 0xff; \
        (p)[3] = (v >> 24) & 0xff; \
    }

#define QUARTERROUND(a, b, c, d)      \
    x[a] += x[b];                     \
    x[d] = ROTATE((x[d] ^ x[a]), 16); \
    x[c] += x[d];                     \
    x[b] = ROTATE((x[b] ^ x[c]), 12); \
    x[a] += x[b];                     \
    x[d] = ROTATE((x[d] ^ x[a]), 8);  \
    x[c] += x[d];                     \
    x[b] = ROTATE((x[b] ^ x[c]), 7);

/* ChaCha constants */
static const uint8_t sigma[16] = {
    'e', 'x', 'p', 'a', 'n', 'd', ' ', '3',
    '2', '-', 'b', 'y', 't', 'e', ' ', 'k'
};

static void chacha20_core(uint8_t output[64], const uint32_t input[16])
{
    uint32_t x[16];
    int i;

    memcpy(x, input, sizeof(x));

    for (i = 20; i > 0; i -= 2) {
        QUARTERROUND(0, 4, 8, 12);
        QUARTERROUND(1, 5, 9, 13);
        QUARTERROUND(2, 6, 10, 14);
        QUARTERROUND(3, 7, 11, 15);
        QUARTERROUND(0, 5, 10, 15);
        QUARTERROUND(1, 6, 11, 12);
        QUARTERROUND(2, 7, 8, 13);
        QUARTERROUND(3, 4, 9, 14);
    }

    for (i = 0; i < 16; ++i)
        x[i] += input[i];
    for (i = 0; i < 16; ++i)
        U32TO8_LITTLE(output + 4 * i, x[i]);
}

void ChaCha20_ctr32(uint8_t *out, const uint8_t *in, size_t inlen,
                      const uint32_t key[8], uint32_t counter[4])
{
    uint32_t input[16];
    uint8_t buf[64];
    size_t i, todo;

    input[0] = U8TO32_LITTLE(sigma + 0);
    input[1] = U8TO32_LITTLE(sigma + 4);
    input[2] = U8TO32_LITTLE(sigma + 8);
    input[3] = U8TO32_LITTLE(sigma + 12);

    input[4] = key[0];
    input[5] = key[1];
    input[6] = key[2];
    input[7] = key[3];
    input[8] = key[4];
    input[9] = key[5];
    input[10] = key[6];
    input[11] = key[7];

    input[12] = counter[0]; /* counter */
    input[13] = counter[1];
    input[14] = counter[2];
    input[15] = counter[3];

    while (inlen > 0) {
        todo = sizeof(buf);
        if (inlen < todo)
            todo = inlen;

        chacha20_core(buf, input);
        for (i = 0; i < todo; i++)
            out[i] = in[i] ^ buf[i];

        out += todo;
        in += todo;
        inlen -= todo;

        input[12]++;
    }
}

#endif /* !OPENSSL_NO_CHACHA */
