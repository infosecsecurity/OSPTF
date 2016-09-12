include_directories( ${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes )

add_library(
    txt_db

    OBJECT

    txt_db.c
)
