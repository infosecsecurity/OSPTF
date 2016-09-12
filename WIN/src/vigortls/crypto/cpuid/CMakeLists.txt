include_directories(.. ../../include .)

if (${ARCH} STREQUAL "x86_64" OR ${ARCH} STREQUAL "x86")
    set(
        CPUID_ARCH_SOURCES

        x86.c
    )
endif()

if (${ARCH} STREQUAL "arm")
    set(
        CPUID_ARCH_SOURCES

        armcap.c
        armv4cpuid.S
    )
endif()

if (${ARCH} STREQUAL "generic")
    set(
        CPUID_ARCH_SOURCES

        generic.c
    )
endif()

add_library(
    cpuid

    OBJECT

    ${CPUID_ARCH_SOURCES}
)
