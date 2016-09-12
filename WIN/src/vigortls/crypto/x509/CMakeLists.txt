include_directories( ${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes )

add_library(
    x509

    OBJECT

    by_dir.c
    by_file.c
    x509cset.c
    x509name.c
    x509rset.c
    x509spki.c
    x509type.c
    x509_att.c
    x509_cmp.c
    x509_d2.c
    x509_def.c
    x509_err.c
    x509_ext.c
    x509_lu.c
    x509_obj.c
    x509_r2x.c
    x509_req.c
    x509_set.c
    x509_trs.c
    x509_txt.c
    x509_v3.c
    x509_vfy.c
    x509_vpm.c
    x_all.c
    x_attrib.c
    x_name.c
)
