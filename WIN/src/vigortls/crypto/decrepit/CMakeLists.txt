include_directories(../../include)

add_library(
    decrepit

    OBJECT

    memory_compat.c
    options.c
    o_str.c
    uid.c
)
