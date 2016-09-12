include_directories(../../include)

if (WIN32)
    set(
        RAND_SOURCES

        windows.c
    )

else() # Posix
    set(
        RAND_SOURCES

        urandom.c
    )
endif()

if (${ARCH} STREQUAL "x86_64")
    set(
        RAND_SOURCES

        ${RAND_SOURCES}
        rdrand-x86_64.${ASM_EXT}
    )
endif()

add_library(
    rand

    OBJECT

    ${RAND_SOURCES}

    rand.c
    rand_err.c
)

perlasm(rdrand-x86_64.${ASM_EXT} asm/rdrand-x86_64.pl)
