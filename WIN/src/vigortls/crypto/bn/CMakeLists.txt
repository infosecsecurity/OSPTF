include_directories(../../include ../cpuid)

if (${ARCH} STREQUAL "x86_64")
    set(
        BN_ARCH_SOURCES

        x86_64-mont.${ASM_EXT}
        x86_64-mont5.${ASM_EXT}
        x86_64-gf2m.${ASM_EXT}
        rsaz-x86_64.${ASM_EXT}
        rsaz-avx2.${ASM_EXT}
        rsaz_exp.c
    )
endif()

if (${ARCH} STREQUAL "x86_64" AND CMAKE_COMPILER_IS_GNUCC OR ${CMAKE_C_COMPILER_ID} STREQUAL "Clang")
    set(
        BN_ARCH_SOURCES

        ${BN_ARCH_SOURCES}
        asm/x86_64-gcc.c
    )
elseif(${ARCH} STREQUAL "x86_64")
    set(
        BN_ARCH_SOURCES

        ${BN_ARCH_SOURCES}
        bn_asm.c
    )
endif()

if (${ARCH} STREQUAL "x86")
    set(
        BN_ARCH_SOURCES

        bn-586.${ASM_EXT}
        co-586.${ASM_EXT}
        x86-mont.${ASM_EXT}
    )
endif()

if (${ARCH} STREQUAL "arm")
    set(
        BN_ARCH_SOURCES

        bn_asm.c
        armv4-mont.${ASM_EXT}
        armv4-gf2m.${ASM_EXT}
    )
endif()

if (${ARCH} STREQUAL "generic")
    set(
        BN_ARCH_SOURCES

        bn_asm.c
    )
endif()

add_library(
    bn

    OBJECT

    bn_add.c
    bn_div.c
    bn_exp.c
    bn_lib.c
    bn_ctx.c
    bn_mul.c
    bn_mod.c
    bn_print.c
    bn_rand.c
    bn_shift.c
    bn_word.c
    bn_blind.c
    bn_kron.c
    bn_sqrt.c
    bn_gcd.c
    bn_prime.c
    bn_err.c
    bn_sqr.c
    bn_recp.c
    bn_mont.c
    bn_mpi.c
    bn_exp2.c
    bn_gf2m.c
    bn_nist.c
    bn_depr.c
    bn_const.c

    ${BN_ARCH_SOURCES}
)

perlasm(x86_64-mont.${ASM_EXT} asm/x86_64-mont.pl ${CMAKE_C_COMPILER})
perlasm(x86_64-mont5.${ASM_EXT} asm/x86_64-mont5.pl ${CMAKE_C_COMPILER})
perlasm(x86_64-gf2m.${ASM_EXT} asm/x86_64-gf2m.pl)
perlasm(modexp512-x86_64.${ASM_EXT} asm/modexp512-x86_64.pl)
perlasm(rsaz-x86_64.${ASM_EXT} asm/rsaz-x86_64.pl ${CMAKE_C_COMPILER})
perlasm(rsaz-avx2.${ASM_EXT} asm/rsaz-avx2.pl ${CMAKE_C_COMPILER})
perlasm(bn-586.${ASM_EXT} asm/bn-586.pl)
perlasm(co-586.${ASM_EXT} asm/co-586.pl)
perlasm(x86-mont.${ASM_EXT} asm/x86-mont.pl)
perlasm(armv4-mont.${ASM_EXT} asm/armv4-mont.pl)
perlasm(armv4-gf2m.${ASM_EXT} asm/armv4-gf2m.pl)
