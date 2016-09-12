include_directories(../../include ../cpuid)

if (${ARCH} STREQUAL "x86_64")
    set(
        CHACHA_ARCH_SOURCES

        chacha-x86_64.${ASM_EXT}
    )
elseif(${ARCH} STREQUAL "x86")
    set(
        CHACHA_ARCH_SOURCES

        chacha-x86.${ASM_EXT}
    )
elseif(${ARCH} STREQUAL "arm")
    set(
        CHACHA_ARCH_SOURCES

        chacha-armv4.${ASM_EXT}
    )
else()
    set(
        CHACHA_ARCH_SOURCES

        chacha_generic.c
    )
endif()

add_library(
    chacha

    OBJECT

    ${CHACHA_ARCH_SOURCES}

    chacha.c
)
perlasm(chacha-x86_64.${ASM_EXT} asm/chacha-x86_64.pl ${CMAKE_C_COMPILER})
perlasm(chacha-x86.${ASM_EXT} asm/chacha-x86.pl ${CMAKE_C_COMPILER})
perlasm(chacha-armv4.${ASM_EXT} asm/chacha-armv4.pl)
