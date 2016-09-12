include_directories(../include modes .)

if(APPLE)
    set(PERLASM_STYLE macosx)
    set(ASM_EXT S)
    enable_language(ASM)
elseif(UNIX)
    set(PERLASM_STYLE elf)
    set(ASM_EXT S)
    enable_language(ASM)
    set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -Wa,--noexecstack")
else()
    if (CMAKE_CL_64)
        message("Using nasm")
        set(PERLASM_STYLE nasm)
    else()
        message("Using win32n")
        set(PERLASM_STYLE win32n)
    endif()
    # On Windows, we use the NASM output, specifically built with Yasm.
    set(ASM_EXT asm)
    enable_language(ASM_NASM)
else()
    message(FATAL ERROR "Unsupported operating system")
endif()

function(perlasm dest src)
	add_custom_command(
		OUTPUT ${dest}
		COMMAND ${PERL_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/${src} ${PERLASM_STYLE} ${ARGN} > ${dest}
		DEPENDS
		${src}
		${PROJECT_SOURCE_DIR}/crypto/perlasm/x86_64-xlate.pl
		${PROJECT_SOURCE_DIR}/crypto/perlasm/x86asm.pl
		${PROJECT_SOURCE_DIR}/crypto/perlasm/x86gas.pl
		${PROJECT_SOURCE_DIR}/crypto/perlasm/x86nasm.pl
		WORKING_DIRECTORY .
	)
endfunction()

add_subdirectory(aes)
add_subdirectory(asn1)
add_subdirectory(blowfish)
add_subdirectory(bio)
add_subdirectory(bn)
add_subdirectory(buffer)
add_subdirectory(bytestring)
add_subdirectory(camellia)
add_subdirectory(cast)
add_subdirectory(chacha)
add_subdirectory(cmac)
add_subdirectory(cms)
add_subdirectory(conf)
add_subdirectory(compat)
add_subdirectory(cpuid)
add_subdirectory(decrepit)
add_subdirectory(des)
add_subdirectory(dh)
add_subdirectory(dsa)
add_subdirectory(dso)
add_subdirectory(ec)
add_subdirectory(ecdh)
add_subdirectory(ecdsa)
add_subdirectory(engine)
add_subdirectory(err)
add_subdirectory(gost)
add_subdirectory(hmac)
add_subdirectory(idea)
add_subdirectory(lhash)
add_subdirectory(md5)
add_subdirectory(modes)
add_subdirectory(objects)
add_subdirectory(ocsp)
add_subdirectory(pem)
add_subdirectory(pkcs7)
add_subdirectory(pkcs12)
add_subdirectory(poly1305)
add_subdirectory(rand)
add_subdirectory(rc2)
add_subdirectory(rc4)
add_subdirectory(rc5)
add_subdirectory(ripemd)
add_subdirectory(rsa)
add_subdirectory(sha)
add_subdirectory(stack)
add_subdirectory(threads)
add_subdirectory(ts)
add_subdirectory(txt_db)
add_subdirectory(ui)
add_subdirectory(evp)
add_subdirectory(whrlpool)
add_subdirectory(x509)
add_subdirectory(x509v3)

if (WIN32 AND BUILD_SHARED_LIBS)
    set(
        CRYPTO_SOURCES

        dllmain.c
    )
endif()

add_library(
    crypto

    ${CRYPTO_SOURCES}

    cpt_err.c
    cryptlib.c
    ex_data.c
    init.c
    memory.c
    time_support.c

    $<TARGET_OBJECTS:aes>
    $<TARGET_OBJECTS:asn1>
    $<TARGET_OBJECTS:blowfish>
    $<TARGET_OBJECTS:bio>
    $<TARGET_OBJECTS:bn>
    $<TARGET_OBJECTS:buffer>
    $<TARGET_OBJECTS:bytestring>
    $<TARGET_OBJECTS:camellia>
    $<TARGET_OBJECTS:cast>
    $<TARGET_OBJECTS:chacha>
    $<TARGET_OBJECTS:cmac>
    $<TARGET_OBJECTS:cms>
    $<TARGET_OBJECTS:conf>
    $<TARGET_OBJECTS:compat>
    $<TARGET_OBJECTS:cpuid>
    $<TARGET_OBJECTS:decrepit>
    $<TARGET_OBJECTS:des>
    $<TARGET_OBJECTS:dh>
    $<TARGET_OBJECTS:dsa>
    $<TARGET_OBJECTS:dso>
    $<TARGET_OBJECTS:ec>
    $<TARGET_OBJECTS:ecdh>
    $<TARGET_OBJECTS:ecdsa>
    $<TARGET_OBJECTS:engine>
    $<TARGET_OBJECTS:err>
    $<TARGET_OBJECTS:evp>
    $<TARGET_OBJECTS:gost>
    $<TARGET_OBJECTS:hmac>
    $<TARGET_OBJECTS:idea>
    $<TARGET_OBJECTS:lhash>
    $<TARGET_OBJECTS:md5>
    $<TARGET_OBJECTS:modes>
    $<TARGET_OBJECTS:objects>
    $<TARGET_OBJECTS:ocsp>
    $<TARGET_OBJECTS:pem>
    $<TARGET_OBJECTS:pkcs7>
    $<TARGET_OBJECTS:pkcs12>
    $<TARGET_OBJECTS:poly1305>
    $<TARGET_OBJECTS:rand>
    $<TARGET_OBJECTS:rc2>
    $<TARGET_OBJECTS:rc4>
    $<TARGET_OBJECTS:rc5>
    $<TARGET_OBJECTS:ripemd>
    $<TARGET_OBJECTS:rsa>
    $<TARGET_OBJECTS:sha>
    $<TARGET_OBJECTS:stack>
    $<TARGET_OBJECTS:threads>
    $<TARGET_OBJECTS:ts>
    $<TARGET_OBJECTS:txt_db>
    $<TARGET_OBJECTS:ui>
    $<TARGET_OBJECTS:whrlpool>
    $<TARGET_OBJECTS:x509>
    $<TARGET_OBJECTS:x509v3>
)

if(NOT MSVC AND OPENSSL_THREADS)
    target_link_libraries(crypto pthread)
endif()

if (WIN32)
	target_link_libraries(crypto Ws2_32)
endif()

install(TARGETS crypto
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)
