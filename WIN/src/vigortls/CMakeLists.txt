cmake_minimum_required(VERSION 2.8.8)
project(VigorTLS C)

find_package(Perl REQUIRED)

include(CTest)
include(CMake/ConfigureChecks.cmake)
include(CMake/GenDeps.cmake)

if (CMAKE_COMPILER_IS_GNUCC OR ${CMAKE_C_COMPILER_ID} STREQUAL "Clang"
    OR ${CMAKE_C_COMPILER_ID} STREQUAL "Intel")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -Wundef -g -std=c99")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} -O3")
elseif(MSVC)
  set(CMAKE_C_FLAGS "/W3 /WX /wd4267 /wd4018 /wd4090 /wd4146 /wd4244")
  set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} /MT /Ox /O2 /Ob2")
  add_definitions(-DVIGORTLS_MSVC -D_CRT_SECURE_NO_WARNINGS -D_CRT_NONSTDC_NO_DEPRECATE -D_WINSOCK_DEPRECATED_NO_WARNINGS -Dinline=__inline)
else()
    message(FATAL_ERROR "Unsupported compiler:" ${CMAKE_C_COMPILER_ID})
endif()

if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
	set(ARCH "x86_64")
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "amd64")
	set(ARCH "x86_64")
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "AMD64")
	# cmake reports AMD64 on Windows, but we might be building for 32-bit.
	if (CMAKE_CL_64)
		set(ARCH "x86_64")
	else()
		set(ARCH "x86")
	endif()
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86")
	set(ARCH "x86")
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "i386")
	set(ARCH "x86")
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "i686")
	set(ARCH "x86")
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "arm")
	set(ARCH "arm")
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "armv7l")
    set(ARCH "arm")
else()
    message(FATAL_ERROR "Unsupported processor:" ${CMAKE_SYSTEM_PROCESSOR})
endif()

add_definitions(-DVIGORTLS_IMPLEMENTATION)

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    add_definitions(-D_GNU_SOURCE)
endif()

if (BUILD_SHARED_LIBS)
    # Because we use OBJECT we have to globaly set
    # CMAKE_POSITION_INDEPENDENT_CODE to TRUE
    set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
endif()

# Options that can't be changed are defined here
set(VIGORTLS_OPTIONS
    "OPENSSL_NO_BUF_FREELISTS"
    "OPENSSL_NO_COMP"
    "OPENSSL_NO_DYNAMIC_ENGINE"
    "OPENSSL_NO_GMP"
    "OPENSSL_NO_HEARTBEATS"
    "OPENSSL_NO_JPAKE"
    "OPENSSL_NO_KRB5"
    "OPENSSL_NO_MD2"
    "OPENSSL_NO_MD4"
    "OPENSSL_NO_MDC2"
    "OPENSSL_NO_PSK"
    "OPENSSL_NO_RFC3779"
    "OPENSSL_NO_SCTP"
    "OPENSSL_NO_SEED"
    "OPENSSL_NO_SHA0"
    "OPENSSL_NO_SRP"
    "OPENSSL_NO_SSL2"
    "OPENSSL_NO_SSL3"
    "OPENSSL_NO_STORE"
    "OPENSSL_USE_IPV6"
)

option(OPENSSL_NO_ASM
    "Build without assembler support" FALSE)
option(OPENSSL_NO_CMS
    "Build without CMS support" TRUE)
option(OPENSSL_NO_GOST
    "Build without GOST support" TRUE)
option(OPENSSL_NO_IDEA
    "Build without IDEA support" FALSE)
option(OPENSSL_NO_RC5
    "Build without RC5 support" TRUE)
option(OPENSSL_THREADS
    "Build with multi-threading support" TRUE)
option(OPENSSL_NO_MULTIBLOCK
    "Build without multi-block support" FALSE)
option(OPENSSL_NO_SSL_TRACE
    "Build without TLS record tracing support" TRUE)

if (BUILD_SHARED_LIBS)
    list(APPEND VIGORTLS_OPTIONS "VIGORTLS_SHARED_LIBRARY")
endif()
if (OPENSSL_THREADS)
    list(APPEND VIGORTLS_OPTIONS "OPENSSL_THREADS")
endif()
if (OPENSSL_NO_ASM)
    list(APPEND VIGORTLS_OPTIONS "OPENSSL_NO_ASM")
endif()
if (OPENSSL_NO_CMS)
    list(APPEND VIGORTLS_OPTIONS "OPENSSL_NO_CMS")
endif()
if (OPENSSL_NO_GOST)
    list(APPEND VIGORTLS_OPTIONS "OPENSSL_NO_GOST")
endif()
if (OPENSSL_NO_IDEA)
    list(APPEND VIGORTLS_OPTIONS "OPENSSL_NO_IDEA")
endif()
if (OPENSSL_NO_RC5)
    list(APPEND VIGORTLS_OPTIONS "OPENSSL_NO_RC5")
endif()
if (OPENSSL_NO_MULTIBLOCK)
    list(APPEND VIGORTLS_OPTIONS "OPENSSL_NO_MULTIBLOCK")
endif()
if (OPENSSL_NO_SSL_TRACE)
    list(APPEND VIGORTLS_OPTIONS "OPENSSL_NO_SSL_TRACE")
endif()
list(SORT VIGORTLS_OPTIONS)

foreach (VIGORTLS_OPTION IN LISTS VIGORTLS_OPTIONS)
    list(APPEND VIGORTLS_OPTIONS_PARSED "#define ${VIGORTLS_OPTION}")
endforeach()
string(REPLACE ";" "\n" VIGORTLS_OPTIONS_PARSED "${VIGORTLS_OPTIONS_PARSED}")
file(WRITE include/openssl/opensslfeatures.h "${VIGORTLS_OPTIONS_PARSED}")

if (OPENSSL_NO_ASM)
    set(ARCH "generic")
endif()

install(DIRECTORY include/openssl DESTINATION include)

add_subdirectory(crypto)
add_subdirectory(ssl)
add_subdirectory(apps)
add_subdirectory(tests)
