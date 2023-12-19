cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/spdm_caliptra/spdm_caliptra_responder
                    ${PROJECT_SOURCE_DIR}/spdm_caliptra/spdm_caliptra_common
                    ${PROJECT_SOURCE_DIR}/include
                    ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_sample
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/os_stub/include
                    ${LIBSPDM_DIR}/os_stub
)

SET(src_spdm_caliptra_responder
    spdm_caliptra_cert.c
    spdm_responder_spdm.c
    spdm_responder_session.c
    # spdm_responder_pci_doe.c
    spdm_responder_mctp.c
    # spdm_responder_tcp.c
    spdm_caliptra_responder.c
    ${PROJECT_SOURCE_DIR}/spdm_caliptra/spdm_caliptra_common/spdm_caliptra.c
    ${PROJECT_SOURCE_DIR}/spdm_caliptra/spdm_caliptra_common/command.c
    ${PROJECT_SOURCE_DIR}/spdm_caliptra/spdm_caliptra_common/key.c
    ${PROJECT_SOURCE_DIR}/spdm_caliptra/spdm_caliptra_common/nv_storage.c
    ${PROJECT_SOURCE_DIR}/spdm_caliptra/spdm_caliptra_common/pcap.c
    ${PROJECT_SOURCE_DIR}/spdm_caliptra/spdm_caliptra_common/support.c
)

SET(spdm_caliptra_responder_LIBRARY
    memlib
    debuglib
    spdm_responder_lib
    spdm_common_lib
    ${CRYPTO_LIB_PATHS}
    rnglib
    cryptlib_${CRYPTO}
    malloclib
    spdm_crypt_lib
    spdm_crypt_ext_lib
    spdm_secured_message_lib
    spdm_transport_mctp_lib
    # spdm_transport_pcidoe_lib
    # spdm_transport_tcp_lib
    # spdm_transport_none_lib
    spdm_device_secret_lib_sample
    mctp_responder_lib
    # pci_doe_responder_lib
    # pci_ide_km_responder_lib
    # pci_ide_km_device_lib_sample
    # pci_tdisp_responder_lib
    # pci_tdisp_device_lib_sample
    # cxl_ide_km_responder_lib
    # cxl_ide_km_device_lib_sample
    platform_lib
)

ADD_EXECUTABLE(spdm_caliptra_responder ${src_spdm_caliptra_responder})
#ADD_LIBRARY(spdm_caliptra_responder STATIC ${src_spdm_caliptra_responder})
TARGET_LINK_LIBRARIES(spdm_caliptra_responder ${spdm_caliptra_responder_LIBRARY})


