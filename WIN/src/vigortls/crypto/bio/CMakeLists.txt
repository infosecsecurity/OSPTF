include_directories(../../include)

if (WIN32)
    set(
        BIO_SOURCES

        b_win.c
    )
else()
    set(
        BIO_SOURCES

        b_posix.c
    )
endif()

add_library(
    bio

    OBJECT

    ${BIO_SOURCES}

    bf_buff.c
    bio_cb.c
    bio_err.c
    bio_lib.c
    bss_acpt.c
    bss_bio.c
    bss_conn.c
    bss_dgram.c
    bss_fd.c
    bss_file.c
    bss_log.c
    bss_mem.c
    bss_null.c
    bss_sock.c
    b_dump.c
    b_print.c
    b_sock.c
)
