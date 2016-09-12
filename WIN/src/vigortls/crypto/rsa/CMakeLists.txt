include_directories( ${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes )

add_library(
    rsa

    OBJECT

    rsa_ameth.c
    rsa_asn1.c
    rsa_chk.c
    rsa_crpt.c
    rsa_depr.c
    rsa_eay.c
    rsa_err.c
    rsa_gen.c
    rsa_lib.c
    rsa_none.c
    rsa_oaep.c
    rsa_pk1.c
    rsa_pmeth.c
    rsa_prn.c
    rsa_pss.c
    rsa_saos.c
    rsa_sign.c
    rsa_ssl.c
    rsa_x931.c
)
