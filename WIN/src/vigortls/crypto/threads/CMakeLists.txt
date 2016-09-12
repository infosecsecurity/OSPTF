include_directories(../../include)

if(UNIX)
    set(
        OS_SOURCES

        pthread.c
    )
elseif(WIN32)
    set(
        OS_SOURCES

        win32.c
    )
endif()
if(NOT OPENSSL_THREADS)
    set(
        OS_SOURCES

        none.c
    )
endif()

add_library(
    threads

    OBJECT

    ${OS_SOURCES}
)
