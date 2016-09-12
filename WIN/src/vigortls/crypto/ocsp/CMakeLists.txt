include_directories(../../include)

add_library(
    ocsp

    OBJECT

    ocsp_asn.c
    ocsp_cl.c
    ocsp_err.c
    ocsp_ext.c
    ocsp_ht.c
    ocsp_lib.c
    ocsp_prn.c
    ocsp_srv.c
    ocsp_vfy.c
)
