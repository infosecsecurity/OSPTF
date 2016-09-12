include_directories(../../include ../cpuid)

if (${ARCH} STREQUAL "x86_64")
    set(
        POLY1305_ARCH_SOURCES

        poly1305-x86_64.${ASM_EXT}
    )
elseif (${ARCH} STREQUAL "x86")
    set(
        POLY1305_ARCH_SOURCES

        poly1305-x86.${ASM_EXT}
    )
elseif (${ARCH} STREQUAL "arm")
    set(
        POLY1305_ARCH_SOURCES

        poly1305-armv4.${ASM_EXT}
    )
endif()

add_library(
    poly1305

    OBJECT

    ${POLY1305_ARCH_SOURCES}

    poly1305.c
)
perlasm(poly1305-x86_64.${ASM_EXT} asm/poly1305-x86_64.pl ${CMAKE_C_COMPILER})
perlasm(poly1305-x86.${ASM_EXT} asm/poly1305-x86.pl ${CMAKE_C_COMPILER})
perlasm(poly1305-armv4.${ASM_EXT} asm/poly1305-armv4.pl)
