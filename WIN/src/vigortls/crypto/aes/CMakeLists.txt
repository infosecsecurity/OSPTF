include_directories(../../include ../cpuid)

if (${ARCH} STREQUAL "x86_64")
    set(
        AES_ARCH_SOURCES

        aes-x86_64.${ASM_EXT}
        aesni-x86_64.${ASM_EXT}
        aesni-sha1-x86_64.${ASM_EXT}
        aesni-sha256-x86_64.${ASM_EXT}
        bsaes-x86_64.${ASM_EXT}
        vpaes-x86_64.${ASM_EXT}
        aesni-mb-x86_64.${ASM_EXT}
    )
elseif (${ARCH} STREQUAL "x86")
    set(
        AES_ARCH_SOURCES

        aes-586.${ASM_EXT}
        vpaes-x86.${ASM_EXT}
        aesni-x86.${ASM_EXT}
    )
elseif (${ARCH} STREQUAL "arm")
    set(
        AES_ARCH_SOURCES

        aes-armv4.${ASM_EXT}
    )
endif()

add_library(
    aes

    OBJECT

    aes.c
    aes_modes.c
    aes_ige.c

    ${AES_ARCH_SOURCES}
)

perlasm(aes-x86_64.${ASM_EXT} asm/aes-x86_64.pl)
perlasm(aesni-x86_64.${ASM_EXT} asm/aesni-x86_64.pl)
perlasm(aesni-sha1-x86_64.${ASM_EXT} asm/aesni-sha1-x86_64.pl ${CMAKE_C_COMPILER})
perlasm(aesni-sha256-x86_64.${ASM_EXT} asm/aesni-sha256-x86_64.pl ${CMAKE_C_COMPILER})
perlasm(bsaes-x86_64.${ASM_EXT} asm/bsaes-x86_64.pl)
perlasm(vpaes-x86_64.${ASM_EXT} asm/vpaes-x86_64.pl)
perlasm(aesni-mb-x86_64.${ASM_EXT} asm/aesni-mb-x86_64.pl ${CMAKE_C_COMPILER})
perlasm(aes-586.${ASM_EXT} asm/aes-586.pl)
perlasm(vpaes-x86.${ASM_EXT} asm/vpaes-x86.pl)
perlasm(aesni-x86.${ASM_EXT} asm/aesni-x86.pl)
perlasm(aes-armv4.${ASM_EXT} asm/aes-armv4.pl)
