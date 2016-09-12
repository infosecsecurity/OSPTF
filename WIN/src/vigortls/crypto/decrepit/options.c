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

#include <stdio.h>


#include <openssl/aes.h>
#include <openssl/blowfish.h>
#include <openssl/bn.h>
#include <openssl/des.h>
#include <openssl/idea.h>
#include <openssl/rc4.h>

const char *AES_options(void)
{
    return "aes(partial)";
}

const char *BF_options(void)
{
#ifdef BF_PTR
    return("blowfish(ptr)");
#elif defined(BF_PTR2)
    return("blowfish(ptr2)");
#else
    return("blowfish(idx)");
#endif
}

char *BN_options(void)
{
    static int init = 0;
    static char data[16];

    if (!init) {
        init++;
#ifdef BN_LLONG
        snprintf(data, sizeof data, "bn(%d,%d)",
                 (int)sizeof(BN_ULLONG) * 8, (int)sizeof(BN_ULONG) * 8);
#else
        snprintf(data, sizeof data, "bn(%d,%d)",
                 (int)sizeof(BN_ULONG) * 8, (int)sizeof(BN_ULONG) * 8);
#endif
    }
    return (data);
}

const char *DES_options(void)
{
        return "des(idx,cisc,unrolled,size)";
}

const char *idea_options(void)
{
    return ("idea(int)");
}

const char *RC4_options(void)
{
    return ("rc4(ptr,int)");
}
