include_directories(../../include ../cpuid)

if (${ARCH} STREQUAL "x86_64")
    set(
        MODES_ARCH_SOURCES

        ghash-x86_64.${ASM_EXT}
        aesni-gcm-x86_64.${ASM_EXT}
    )
endif()

if (${ARCH} STREQUAL "x86")
    set(
        MODES_ARCH_SOURCES

        ghash-x86.${ASM_EXT}
    )
endif()

if (${ARCH} STREQUAL "arm")
    set(
        MODES_ARCH_SOURCES

        ghash-armv4.${ASM_EXT}
    )
endif()

add_library(
    modes

    OBJECT

    cbc128.c
    ccm128.c
    cfb128.c
    ctr128.c
    cts128.c
    gcm128.c
    ofb128.c
    wrap128.c
    xts128.c

    ${MODES_ARCH_SOURCES}
)

perlasm(aesni-gcm-x86_64.${ASM_EXT} asm/aesni-gcm-x86_64.pl ${CMAKE_C_COMPILER})
perlasm(ghash-x86_64.${ASM_EXT} asm/ghash-x86_64.pl ${CMAKE_C_COMPILER})
perlasm(ghash-x86.${ASM_EXT} asm/ghash-x86.pl)
perlasm(ghash-armv4.${ASM_EXT} asm/ghash-armv4.pl)
