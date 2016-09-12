include_directories(../../include)

add_library(
    dsa

    OBJECT

    dsa_ameth.c
    dsa_asn1.c
    dsa_depr.c
    dsa_err.c
    dsa_gen.c
    dsa_key.c
    dsa_lib.c
    dsa_ossl.c
    dsa_pmeth.c
    dsa_prn.c
    dsa_sign.c
    dsa_vrf.c
)
