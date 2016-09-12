include_directories(../../include)

if (${ARCH} STREQUAL "x86_64")
    set(
        CMLL_ARCH_SOURCES

        cmll-x86_64.${ASM_EXT}
    )
elseif (${ARCH} STREQUAL "x86")
    set(
        CMLL_ARCH_SOURCES

        cmll-x86.${ASM_EXT}
    )
endif()

add_library(
    camellia

    OBJECT

    camellia.c
    camellia_modes.c

    ${CMLL_ARCH_SOURCES}
)

perlasm(cmll-x86_64.${ASM_EXT} asm/cmll-x86_64.pl)
perlasm(cmll-x86.${ASM_EXT} asm/cmll-x86.pl)
