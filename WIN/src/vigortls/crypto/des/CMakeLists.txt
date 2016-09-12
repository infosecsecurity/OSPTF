include_directories(../../include)
  
add_library(
    des

    OBJECT

    cfb64ede.c
    des.c
)
