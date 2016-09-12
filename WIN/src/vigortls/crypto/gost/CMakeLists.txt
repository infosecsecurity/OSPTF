include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include)

add_library(
    gost

    OBJECT

    gost89imit_ameth.c
    gost89imit_pmeth.c
    gost89_keywrap.c
    gost89_params.c
    gost2814789.c
    gost_asn1.c
    gost_err.c
    gostr341001.c
    gostr341001_ameth.c
    gostr341001_key.c
    gostr341001_params.c
    gostr341001_pmeth.c
    gostr341194.c
    streebog.c
)
