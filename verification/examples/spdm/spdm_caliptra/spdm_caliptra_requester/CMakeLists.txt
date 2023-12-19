cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/spdm_caliptra/spdm_caliptra_requester
                    ${PROJECT_SOURCE_DIR}/spdm_caliptra/spdm_caliptra_common
                    ${PROJECT_SOURCE_DIR}/include
                    ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_sample
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/os_stub/include
                    ${LIBSPDM_DIR}/os_stub
)

SET(src_spdm_caliptra_requester
    spdm_requester_spdm.c
    spdm_caliptra_requester_authentication.c
    spdm_requester_session.c
    spdm_requester_mctp.c
    spdm_caliptra_requester.c
    ${PROJECT_SOURCE_DIR}/spdm_caliptra/spdm_caliptra_common/spdm_caliptra.c
    ${PROJECT_SOURCE_DIR}/spdm_caliptra/spdm_caliptra_common/command.c
    ${PROJECT_SOURCE_DIR}/spdm_caliptra/spdm_caliptra_common/key.c
    ${PROJECT_SOURCE_DIR}/spdm_caliptra/spdm_caliptra_common/nv_storage.c
    ${PROJECT_SOURCE_DIR}/spdm_caliptra/spdm_caliptra_common/pcap.c
    ${PROJECT_SOURCE_DIR}/spdm_caliptra/spdm_caliptra_common/support.c
)

SET(spdm_caliptra_requester_LIBRARY
    memlib
    debuglib
    spdm_requester_lib
    spdm_common_lib
    ${CRYPTO_LIB_PATHS}
    rnglib
    cryptlib_${CRYPTO}
    malloclib
    spdm_crypt_lib
    spdm_crypt_ext_lib
    spdm_secured_message_lib
    spdm_transport_mctp_lib
    spdm_device_secret_lib_sample
    mctp_requester_lib
    platform_lib
)


#ADD_EXECUTABLE(spdm_caliptra_requester ${src_spdm_caliptra_requester})
ADD_LIBRARY(spdm_caliptra_requester STATIC ${src_spdm_caliptra_requester})
TARGET_LINK_LIBRARIES(spdm_caliptra_requester ${spdm_caliptra_requester_LIBRARY})
