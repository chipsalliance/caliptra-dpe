/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#ifndef __SPDM_REQUESTER_TEST_H__
#define __SPDM_REQUESTER_TEST_H__

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_mctp_lib.h"
#include "library/mctp_requester_lib.h"

#include "os_include.h"
#include "stdio.h"
#include "spdm_caliptra.h"

extern uint8_t m_other_slot_id;

#endif

void *spdm_client_init(void);
int main1(char* caliptra_dpe_profile, int port_number, void **temp, size_t *cert_chain_data_size);

bool communicate_platform_data(SOCKET socket, uint32_t command,
                               const uint8_t *send_buffer, size_t bytes_to_send,
                               uint32_t *response,
                               size_t *bytes_to_receive,
                               uint8_t *receive_buffer);

libspdm_return_t spdm_authentication(void *context, uint8_t *slot_mask,
                                     void *total_digest_buffer, uint8_t slot_id,
                                     size_t *cert_chain_size, void *cert_chain,
                                     uint8_t measurement_hash_type, void *measurement_hash);

bool communicate_platform_data(SOCKET socket, uint32_t command,
                               const uint8_t *send_buffer, size_t bytes_to_send,
                               uint32_t *response,
                               size_t *bytes_to_receive,
                               uint8_t *receive_buffer);

// #if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
// libspdm_return_t do_measurement_via_spdm(const uint32_t *session_id);
// #endif /*LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/

libspdm_return_t mctp_process_session_message(void *spdm_context, uint32_t session_id);
libspdm_return_t do_certificate_provising_via_spdm(uint32_t *session_id);