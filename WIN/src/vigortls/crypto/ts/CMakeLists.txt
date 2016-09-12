include_directories( ${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes )

add_library(
    ts

    OBJECT

    ts_asn1.c
    ts_conf.c
    ts_err.c
    ts_lib.c
    ts_req_print.c
    ts_req_utils.c
    ts_rsp_print.c
    ts_rsp_sign.c
    ts_rsp_utils.c
    ts_rsp_verify.c
    ts_verify_ctx.c
)
