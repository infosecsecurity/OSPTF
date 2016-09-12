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

#include <stdint.h>
#include "cryptlib.h"

#if defined(VIGORTLS_MSVC)
  #include <intrin.h>
  #include <immintrin.h>
#endif

static void vigortls_cpuid(uint32_t eax, uint32_t *regs)
{
    regs[0] = eax;
    regs[1] = regs[2] = regs[3] = 0;
#if defined(VIGORTLS_MSVC)
    int tmp[4];
    __cpuid(tmp, (int)eax);
    regs[0] = (uint32_t)tmp[0];
    regs[1] = (uint32_t)tmp[1];
    regs[2] = (uint32_t)tmp[2];
    regs[3] = (uint32_t)tmp[3];
#elif defined(__pic__) && defined(VIGORTLS_32_BIT)
    /*
     * We have to save and restore the EBX register when
     * PIC is used.
     * https://gcc.gnu.org/bugzilla/show_bug.cgi?id=47602
     */
    __asm__ volatile(
        "xor %%ecx, %%ecx\n"
        "mov %%ebx, %%edi\n"
        "cpuid\n"
        "xchg %%edi, %%ebx\n"
        : "=a"(regs[0]), "=b"(regs[1]), "=c"(regs[2]), "=d"(regs[3])
        : "a"(eax)
    );
#else
    __asm__ volatile(
        "xor %%ecx, %%ecx\n"
        "cpuid\n"
        : "=a"(regs[0]), "=b"(regs[1]), "=c"(regs[2]), "=d"(regs[3])
        : "a"(eax)
    );
#endif
}

static uint64_t vigortls_xgetbv(uint32_t xcr)
{
#if defined(VIGORTLS_MSVC)
    return _xgetbv(xcr);
#else
    uint32_t eax, edx;
    __asm__ volatile(
        ".byte 0x0f, 0x01, 0xd0" /* xgetbv */
        : "=a"(eax), "=d"(edx) : "c"(xcr)
    );
    return ((uint64_t)edx << 32) | eax;
#endif
}

void OPENSSL_cpuid_setup(void)
{
    uint32_t cpuid[8][4];
    uint32_t cpuid_ext[2][4];
    uint32_t cpuid_max_basic;
    uint32_t cpuid_max_ext;
    uint32_t logical_cpus;
    int intel, amd, amd_xop = 0;

    vigortls_cpuid(0, cpuid[0]);
    vigortls_cpuid(1, cpuid[1]);
    vigortls_cpuid(4, cpuid[4]);
    vigortls_cpuid(7, cpuid[7]);
    vigortls_cpuid(0x80000000, cpuid_ext[0]);
    vigortls_cpuid(0x80000001, cpuid_ext[1]);

    /* Get max cpuid level. */
    cpuid_max_basic = cpuid[0][0];
    /* Get max extended level. */
    cpuid_max_ext = cpuid_ext[0][0];

    intel = cpuid[0][1] == 0x756e6547  /* Genu */
         && cpuid[0][3] == 0x49656e69  /* ineI */
         && cpuid[0][2] == 0x6c65746e; /* ntel */
    amd = cpuid[0][1] == 0x68747541  /* Auth */
       && cpuid[0][3] == 0x69746e65  /* enti */
       && cpuid[0][2] == 0x444d4163; /* cAMD */

    /* Check for AMD XOP. */
    if (amd) {
        if (cpuid_max_ext >= 0x80000001) {
            if (cpuid_ext[1][2] & (1 << 11)) {
                amd_xop = 1;
            }
        }
    }

    /*
     * Determine the number of cores sharing an L1 data cache
     * to adjust the HT bit.
     */
    uint32_t cores_per_cache = 0;
    if (amd) {
        cores_per_cache = 1;
    } else if (cpuid_max_basic >= 4) {
        cores_per_cache = 1 + ((cpuid[4][0] >> 26) & 0x3f);
    }
    /* Adjust the HT bit. */
    if (cpuid[1][3] & (1 << 28)) {
        logical_cpus = (cpuid[1][1] >> 16) & 0xff;
        if (cores_per_cache == 1 || logical_cpus <= 1)
            cpuid[1][3] &= ~(1 << 28);
    }

    /*
     * Reserved bit #20 was used to choose among RC4 code paths.
     * Always set it to zero.
     */
    cpuid[1][3] &= ~(1 << 20);

    /* Reserved bit #30 denotes Intel CPUs. */
    if (intel)
        cpuid[1][3] |= (1 << 30);
    else
        cpuid[1][3] &= ~(1 << 30);

    /* Reserved bit #11 denotes AMD XOP support. */
    if (amd_xop)
        cpuid[1][2] |= (1 << 11);
    else
        cpuid[1][2] &= ~(1 << 11);

    uint64_t xcr0 = 0;
    /* Check OSXSAVE bit to verify XGETBV is enabled. */
    if (cpuid[1][2] & (1 << 27))
        xcr0 = vigortls_xgetbv(0);

    /* Verify that XMM and YMM state are enabled in XCR0. */
    if ((xcr0 & 6) != 6) {
        cpuid[1][2] &= ~(1 << 28); /* AVX */
        cpuid[1][2] &= ~(1 << 12); /* FMA */
        cpuid[1][2] &= ~(1 << 11); /* AMD XOP */
        cpuid[7][1] &= ~(1 <<  5); /* AVX2 */
    }

    OPENSSL_ia32cap_P[0] = cpuid[1][3];
    OPENSSL_ia32cap_P[1] = cpuid[1][2];
    OPENSSL_ia32cap_P[2] = cpuid[7][1];
    OPENSSL_ia32cap_P[3] = 0;
}
