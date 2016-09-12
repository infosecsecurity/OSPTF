include_directories( ${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes )

add_library(
    ui

    OBJECT
    
    ${UI_SYS_SOURCES}

    ui_err.c
    ui_lib.c
    ui_util.c
    ui_compat.c
    ui_openssl_posix.c
    ui_openssl_windows.c
)
