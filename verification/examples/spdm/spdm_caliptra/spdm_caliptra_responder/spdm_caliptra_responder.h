/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#ifndef __SPDM_RESPONDER_TEST_H__
#define __SPDM_RESPONDER_TEST_H__

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_responder_lib.h"
#include "library/spdm_transport_mctp_lib.h"
#include "library/mctp_responder_lib.h"

#include "os_include.h"
#include <stdio.h>
#include "spdm_caliptra.h"

#endif

bool caliptra_read_requester_root_public_certificate(uint32_t base_hash_algo,
                                                    uint16_t req_base_asym_alg,
                                                    void **data, size_t *size,
                                                    void **hash,
                                                    size_t *hash_size);

bool caliptra_read_responder_public_certificate_chain(
    uint32_t base_hash_algo, uint32_t base_asym_algo, void **data,
    size_t *size, void **hash, size_t *hash_size);

bool caliptra_read_responder_public_certificate_chain_per_slot(
    uint8_t slot_id, uint32_t base_hash_algo, uint32_t base_asym_algo,
    void **data, size_t *size, void **hash, size_t *hash_size);