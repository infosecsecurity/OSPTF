if (WIN32)
    set(
        COMPAT_SOURCES

        gettimeofday_windows.c
        dirent_windows.c
    )
endif()

if (NOT HAVE_VASPRINTF OR NOT HAVE_ASPRINTF)
    set(
        COMPAT_SOURCES

        ${COMPAT_SOURCES}
        vasprintf.c
    )
endif()

if (${ARCH} STREQUAL "x86_64")
    set(ARCHS reallocarray-x86_64.${ASM_EXT})
elseif (${ARCH} STREQUAL "x86")
    set(ARCHS reallocarray-x86.${ASM_EXT})
endif()
if (NOT HAVE_REALLOCARRAY)
    set(
        COMPAT_SOURCES

        ${COMPAT_SOURCES}
        reallocarray.c
        ${ARCHS}
    )

endif()

if (NOT HAVE_SNPRINTF)
    set(
        COMPAT_SOURCES 

        ${COMPAT_SOURCES}
        snprintf.c
    )
endif()

if (NOT HAVE_STRNDUP)
    set(
        COMPAT_SOURCES 

        ${COMPAT_SOURCES}
        strndup.c
    )
endif()

if (NOT HAVE_STRLCPY)
    set(
        COMPAT_SOURCES

        ${COMPAT_SOURCES}
        strlcpy.c
    )
endif()

if (NOT HAVE_STRLCAT)
    set(
        COMPAT_SOURCES 

        ${COMPAT_SOURCES}
        strlcat.c
    )
endif()

if (NOT HAVE_STRTONUM)
    set(
        COMPAT_SOURCES 

        ${COMPAT_SOURCES}
        strtonum.c
    )
endif()

add_library(
    compat

    OBJECT

    ${COMPAT_SOURCES}
)
perlasm(reallocarray-x86.${ASM_EXT} asm/reallocarray-x86.pl)
perlasm(reallocarray-x86_64.${ASM_EXT} asm/reallocarray-x86_64.pl)
