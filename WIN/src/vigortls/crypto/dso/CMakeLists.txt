include_directories(../../include)

add_library(
    dso

    OBJECT

    dso_err.c
    dso_lib.c
    dso_openssl.c
)
