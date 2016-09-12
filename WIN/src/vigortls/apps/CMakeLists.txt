include_directories (../include ${CMAKE_CURRENT_BINARY_DIR})

configure_file(buildinf.h.cmake buildinf.h)

if (WIN32)
    set(
        OS_SOURCES

        apps_windows.c
        poll.c
    )

else() # Posix
    set(
        OS_SOURCES

        apps_posix.c
    )
endif()

add_executable(
    openssl

    ${OS_SOURCES}

    apps.c
    asn1pars.c
    ca.c
    ciphers.c
    cms.c
    crl.c
    crl2p7.c
    dgst.c
    dh.c
    dhparam.c
    dsa.c
    dsaparam.c
    ec.c
    ecparam.c
    enc.c
    engine.c
    errstr.c
    gendh.c
    gendsa.c
    genpkey.c
    genrsa.c
    nseq.c
    ocsp.c
    openssl.c # main
    passwd.c
    pkey.c
    pkeyparam.c
    pkeyutl.c
    pkcs7.c
    pkcs8.c
    pkcs12.c
    prime.c
    rand.c
    req.c
    rsa.c
    rsautl.c
    sess_id.c
    smime.c
    speed.c
    spkac.c
    s_cb.c
    s_client.c
    s_server.c
    s_socket.c
    s_time.c
    ts.c
    verify.c
    version.c
    x509.c
)

target_link_libraries(openssl crypto ssl)
if (WIN32)
	target_link_libraries(openssl ws2_32 wsock32)
endif()

install(TARGETS openssl
        RUNTIME DESTINATION bin)
