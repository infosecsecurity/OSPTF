/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_IDEA

#include <openssl/idea.h>

#include "../macros.h"

#define idea_mul(r, a, b, ul)           \
    ul = (uint32_t)a * b;          \
    if (ul != 0) {                      \
        r = (ul & 0xffff) - (ul >> 16); \
        r -= ((r) >> 16);               \
    } else                              \
        r = (-(int)a - b + 1); /* assuming a or b is 0 and in range */

#define E_IDEA(num)                       \
    x1 &= 0xffff;                         \
    idea_mul(x1, x1, *p, ul);             \
    p++;                                  \
    x2 += *(p++);                         \
    x3 += *(p++);                         \
    x4 &= 0xffff;                         \
    idea_mul(x4, x4, *p, ul);             \
    p++;                                  \
    t0 = (x1 ^ x3) & 0xffff;              \
    idea_mul(t0, t0, *p, ul);             \
    p++;                                  \
    t1 = (t0 + (x2 ^ x4)) & 0xffff;       \
    idea_mul(t1, t1, *p, ul);             \
    p++;                                  \
    t0 += t1;                             \
    x1 ^= t1;                             \
    x4 ^= t0;                             \
    ul = x2 ^ t0; /* do the swap to x3 */ \
    x2 = x3 ^ t1;                         \
    x3 = ul;

void idea_encrypt(uint32_t *d, IDEA_KEY_SCHEDULE *key)
{
    uint32_t *p;
    uint32_t x1, x2, x3, x4, t0, t1, ul;

    x2 = d[0];
    x1 = (x2 >> 16);
    x4 = d[1];
    x3 = (x4 >> 16);

    p = &(key->data[0][0]);

    E_IDEA(0);
    E_IDEA(1);
    E_IDEA(2);
    E_IDEA(3);
    E_IDEA(4);
    E_IDEA(5);
    E_IDEA(6);
    E_IDEA(7);

    x1 &= 0xffff;
    idea_mul(x1, x1, *p, ul);
    p++;

    t0 = x3 + *(p++);
    t1 = x2 + *(p++);

    x4 &= 0xffff;
    idea_mul(x4, x4, *p, ul);

    d[0] = (t0 & 0xffff) | ((x1 & 0xffff) << 16);
    d[1] = (x4 & 0xffff) | ((t1 & 0xffff) << 16);
}

void idea_cbc_encrypt(const uint8_t *in, uint8_t *out, long length,
                      IDEA_KEY_SCHEDULE *ks, uint8_t *iv, int encrypt)
{
    uint32_t tin0, tin1;
    uint32_t tout0, tout1, xor0, xor1;
    long l = length;
    uint32_t tin[2];

    if (encrypt) {
        n2l(iv, tout0);
        n2l(iv, tout1);
        iv -= 8;
        for (l -= 8; l >= 0; l -= 8) {
            n2l(in, tin0);
            n2l(in, tin1);
            tin0 ^= tout0;
            tin1 ^= tout1;
            tin[0] = tin0;
            tin[1] = tin1;
            idea_encrypt(tin, ks);
            tout0 = tin[0];
            l2n(tout0, out);
            tout1 = tin[1];
            l2n(tout1, out);
        }
        if (l != -8) {
            n2ln(in, tin0, tin1, l + 8);
            tin0 ^= tout0;
            tin1 ^= tout1;
            tin[0] = tin0;
            tin[1] = tin1;
            idea_encrypt(tin, ks);
            tout0 = tin[0];
            l2n(tout0, out);
            tout1 = tin[1];
            l2n(tout1, out);
        }
        l2n(tout0, iv);
        l2n(tout1, iv);
    } else {
        n2l(iv, xor0);
        n2l(iv, xor1);
        iv -= 8;
        for (l -= 8; l >= 0; l -= 8) {
            n2l(in, tin0);
            tin[0] = tin0;
            n2l(in, tin1);
            tin[1] = tin1;
            idea_encrypt(tin, ks);
            tout0 = tin[0] ^ xor0;
            tout1 = tin[1] ^ xor1;
            l2n(tout0, out);
            l2n(tout1, out);
            xor0 = tin0;
            xor1 = tin1;
        }
        if (l != -8) {
            n2l(in, tin0);
            tin[0] = tin0;
            n2l(in, tin1);
            tin[1] = tin1;
            idea_encrypt(tin, ks);
            tout0 = tin[0] ^ xor0;
            tout1 = tin[1] ^ xor1;
            l2nn(tout0, tout1, out, l + 8);
            xor0 = tin0;
            xor1 = tin1;
        }
        l2n(xor0, iv);
        l2n(xor1, iv);
    }
    tin0 = tin1 = tout0 = tout1 = xor0 = xor1 = 0;
    tin[0] = tin[1] = 0;
}

/* The input and output encrypted as though 64bit cfb mode is being
 * used.  The extra state information to record how much of the
 * 64bit block we have used is contained in *num;
 */

void idea_cfb64_encrypt(const uint8_t *in, uint8_t *out, long length,
                        IDEA_KEY_SCHEDULE *schedule, uint8_t *ivec, int *num,
                        int encrypt)
{
    uint32_t v0, v1, t;
    int n = *num;
    long l = length;
    uint32_t ti[2];
    uint8_t *iv, c, cc;

    iv = ivec;
    if (encrypt) {
        while (l--) {
            if (n == 0) {
                n2l(iv, v0);
                ti[0] = v0;
                n2l(iv, v1);
                ti[1] = v1;
                idea_encrypt(ti, schedule);
                iv = ivec;
                t = ti[0];
                l2n(t, iv);
                t = ti[1];
                l2n(t, iv);
                iv = ivec;
            }
            c = *(in++) ^ iv[n];
            *(out++) = c;
            iv[n] = c;
            n = (n + 1) & 0x07;
        }
    } else {
        while (l--) {
            if (n == 0) {
                n2l(iv, v0);
                ti[0] = v0;
                n2l(iv, v1);
                ti[1] = v1;
                idea_encrypt(ti, schedule);
                iv = ivec;
                t = ti[0];
                l2n(t, iv);
                t = ti[1];
                l2n(t, iv);
                iv = ivec;
            }
            cc = *(in++);
            c = iv[n];
            iv[n] = cc;
            *(out++) = c ^ cc;
            n = (n + 1) & 0x07;
        }
    }
    v0 = v1 = ti[0] = ti[1] = t = c = cc = 0;
    *num = n;
}



void idea_ecb_encrypt(const uint8_t *in, uint8_t *out, IDEA_KEY_SCHEDULE *ks)
{
    uint32_t l0, l1, d[2];

    n2l(in, l0);
    d[0] = l0;
    n2l(in, l1);
    d[1] = l1;
    idea_encrypt(d, ks);
    l0 = d[0];
    l2n(l0, out);
    l1 = d[1];
    l2n(l1, out);
    l0 = l1 = d[0] = d[1] = 0;
}

/*
 * The input and output encrypted as though 64bit ofb mode is being
 * used.  The extra state information to record how much of the
 * 64bit block we have used is contained in *num;
 */
void idea_ofb64_encrypt(const uint8_t *in, uint8_t *out, long length,
                        IDEA_KEY_SCHEDULE *schedule, uint8_t *ivec, int *num)
{
    uint32_t v0, v1, t;
    int n = *num;
    long l = length;
    uint8_t d[8];
    int8_t *dp;
    uint32_t ti[2];
    uint8_t *iv;
    int save = 0;

    iv = (uint8_t *)ivec;
    n2l(iv, v0);
    n2l(iv, v1);
    ti[0] = v0;
    ti[1] = v1;
    dp = (int8_t *)d;
    l2n(v0, dp);
    l2n(v1, dp);
    while (l--) {
        if (n == 0) {
            idea_encrypt(ti, schedule);
            dp = (int8_t *)d;
            t = ti[0];
            l2n(t, dp);
            t = ti[1];
            l2n(t, dp);
            save++;
        }
        *(out++) = *(in++) ^ d[n];
        n = (n + 1) & 0x07;
    }
    if (save) {
        v0 = ti[0];
        v1 = ti[1];
        iv = ivec;
        l2n(v0, iv);
        l2n(v1, iv);
    }
    t = v0 = v1 = ti[0] = ti[1] = 0;
    *num = n;
}

/* taken directly from the 'paper' I'll have a look at it later */
static uint32_t inverse(unsigned int xin)
{
    long n1, n2, q, r, b1, b2, t;

    if (xin == 0)
        b2 = 0;
    else {
        n1 = 0x10001;
        n2 = xin;
        b2 = 1;
        b1 = 0;

        do {
            r = (n1 % n2);
            q = (n1 - r) / n2;
            if (r == 0) {
                if (b2 < 0)
                    b2 = 0x10001 + b2;
            } else {
                n1 = n2;
                n2 = r;
                t = b2;
                b2 = b1 - q * b2;
                b1 = t;
            }
        } while (r != 0);
    }
    return ((uint32_t)b2);
}

void idea_set_encrypt_key(const uint8_t *key, IDEA_KEY_SCHEDULE *ks)
{
    int i;
    uint32_t *kt, *kf, r0, r1, r2;

    kt = &(ks->data[0][0]);
    n2s(key, kt[0]);
    n2s(key, kt[1]);
    n2s(key, kt[2]);
    n2s(key, kt[3]);
    n2s(key, kt[4]);
    n2s(key, kt[5]);
    n2s(key, kt[6]);
    n2s(key, kt[7]);

    kf = kt;
    kt += 8;
    for (i = 0; i < 6; i++) {
        r2 = kf[1];
        r1 = kf[2];
        *(kt++) = ((r2 << 9) | (r1 >> 7)) & 0xffff;
        r0 = kf[3];
        *(kt++) = ((r1 << 9) | (r0 >> 7)) & 0xffff;
        r1 = kf[4];
        *(kt++) = ((r0 << 9) | (r1 >> 7)) & 0xffff;
        r0 = kf[5];
        *(kt++) = ((r1 << 9) | (r0 >> 7)) & 0xffff;
        r1 = kf[6];
        *(kt++) = ((r0 << 9) | (r1 >> 7)) & 0xffff;
        r0 = kf[7];
        *(kt++) = ((r1 << 9) | (r0 >> 7)) & 0xffff;
        r1 = kf[0];
        if (i >= 5)
            break;
        *(kt++) = ((r0 << 9) | (r1 >> 7)) & 0xffff;
        *(kt++) = ((r1 << 9) | (r2 >> 7)) & 0xffff;
        kf += 8;
    }
}

void idea_set_decrypt_key(IDEA_KEY_SCHEDULE *ek, IDEA_KEY_SCHEDULE *dk)
{
    int r;
    uint32_t *fp, *tp, t;

    tp = &(dk->data[0][0]);
    fp = &(ek->data[8][0]);
    for (r = 0; r < 9; r++) {
        *(tp++) = inverse(fp[0]);
        *(tp++) = ((int)(0x10000L - fp[2]) & 0xffff);
        *(tp++) = ((int)(0x10000L - fp[1]) & 0xffff);
        *(tp++) = inverse(fp[3]);
        if (r == 8)
            break;
        fp -= 6;
        *(tp++) = fp[4];
        *(tp++) = fp[5];
    }

    tp = &(dk->data[0][0]);
    t = tp[1];
    tp[1] = tp[2];
    tp[2] = t;

    t = tp[49];
    tp[49] = tp[50];
    tp[50] = t;
}
#endif
