include_directories(../../include)

add_library(
    hmac

    OBJECT

    hmac.c
    hm_ameth.c
    hm_pmeth.c
)
