include_directories(../../include)

add_library(
    ecdsa

    OBJECT

    ecs_lib.c
    ecs_asn1.c
    ecs_ossl.c
    ecs_sign.c
    ecs_vrf.c
    ecs_err.c
)
