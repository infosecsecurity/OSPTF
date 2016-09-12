include_directories(../../include)

add_library(
    cms

    OBJECT

    cms_asn1.c
    cms_att.c
    cms_cd.c
    cms_dd.c
    cms_enc.c
    cms_env.c
    cms_err.c
    cms_ess.c
    cms_io.c
    cms_kari.c
    cms_lib.c
    cms_pwri.c
    cms_sd.c
    cms_smime.c
)
