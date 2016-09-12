include_directories(../../include)

add_library(
    conf

    OBJECT

    conf_err.c
    conf_lib.c
    conf_api.c
    conf_def.c
    conf_mod.c
    conf_mall.c
    conf_sap.c
)
