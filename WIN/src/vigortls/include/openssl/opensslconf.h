#if defined(__x86_64) || defined(__x86_64__) || defined(_M_AMD64) || \
    defined(_M_X64)
#define VIGORTLS_64_BIT
#define VIGORTLS_X86_64
#elif defined(__x86) || defined(__i386) || defined(__i386__) || defined(_M_IX86)
#define VIGORTLS_32_BIT
#define VIGORTLS_X86
#elif defined(__arm) || defined(__arm__) || defined(_M_ARM)
#define VIGORTLS_32_BIT
#define VIGORTLS_ARM
#elif defined(__aarch64__)
#define VIGORTLS_AARCH64
#else
#error "Unknown target CPU"
#endif

#include <openssl/opensslfeatures.h>

#if defined(HEADER_CRYPTLIB_H) && !defined(OPENSSLDIR)
#define ENGINESDIR "/usr/lib/engines"
#define OPENSSLDIR "/etc/ssl"
#endif

#undef OPENSSL_UNISTD
#define OPENSSL_UNISTD <unistd.h>

#define OPENSSL_CPUID_OBJ

#undef BF_PTR

#define DES_RISC1
#define DES_UNROLL

#ifndef OPENSSL_NO_ASM
#define AES_ASM
#define VPAES_ASM
#define OPENSSL_BN_ASM_MONT
#if (defined(VIGORTLS_X86) || defined(VIGORTLS_X86_64)) && \
    !defined(VIGORTLS_ARM)
#define GHASH_ASM
#define OPENSSL_IA32_SSE2
#endif
#if defined(VIGORTLS_ARM)
#define OPENSSL_BN_ASM_GF2m
#endif
#if defined(VIGORTLS_X86_64)
#define OPENSSL_BN_ASM_MONT5
#define OPENSSL_BN_ASM_GF2m
#define BSAES_ASM
#define ECP_NISTZ256_ASM
#endif
#endif

#if defined(__clang__) || defined(VIGORTLS_MSVC) ||              \
    (defined(__GNUC__) &&                                        \
     (__GNUC__ < 3 || (__GNUC__ == 3 && __GNUC_MINOR__ < 1))) || \
    !defined(VIGORTLS_X86_64)
#define OPENSSL_NO_EC_NISTP_64_GCC_128
#endif
