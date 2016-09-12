include_directories(../../include)

add_library(
    pkcs7

    OBJECT

    bio_pk7.c
    pk7_asn1.c
    pk7_attr.c
    pk7_doit.c
    pk7_lib.c
    pk7_mime.c
    pk7_smime.c
    pkcs7err.c
)
