include_directories(../../include)

add_library(
    bytestring

    OBJECT

    ber.c
    cbb.c
    cbs.c
)

add_executable(
  bytestring_test

  bytestring_test.c
)
target_link_libraries(bytestring_test crypto)

add_test(bytestring_test ./bytestring_test)
