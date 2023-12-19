/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_caliptra_requester.h"
#include "internal/libspdm_requester_lib.h"

uint8_t m_receive_buffer[LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE];

extern SOCKET m_socket;

extern void *m_spdm_context;
extern void *m_scratch_buffer;

uint8_t m_other_slot_id = 0;

// #if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
// libspdm_return_t do_measurement_via_spdm(const uint32_t *session_id);
// #endif /*LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/

// #if (LIBSPDM_ENABLE_CAPABILITY_CERT_CAP && LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP)
// libspdm_return_t do_authentication_via_spdm(void);
// #endif /*(LIBSPDM_ENABLE_CAPABILITY_CERT_CAP && LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP)*/

// libspdm_return_t do_session_via_spdm(bool use_psk);
// libspdm_return_t do_certificate_provising_via_spdm(uint32_t *session_id);

bool platform_client_routine(uint16_t port_number, void **m_temp, size_t *cert_chain_data_size, int *a)
{
    printf("%s version 0.1\n", "spdm_requester_emu");
    printf("\nCHECKPOINT 10AAAA111 %p\n", *m_temp);
    srand((unsigned int)time(NULL));

    SOCKET platform_socket;
    bool result;
    uint32_t response;
    size_t response_size;
    libspdm_return_t status;

    //*cert_chain_data_size = 2; // CHECKPOINT2
    result = init_client(&platform_socket, port_number);
    if (!result)
    {
        return false;
    }

    m_socket = platform_socket;

    result = false;

    //*cert_chain_data_size = 3; // CHECKPOINT3
    m_spdm_context = spdm_client_init();
    if (m_spdm_context == NULL)
    {
        goto done;
    }
    //*cert_chain_data_size = 4; // CHECKPOINT4

//     /* Do test - begin*/
#if (LIBSPDM_ENABLE_CAPABILITY_CERT_CAP && LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP)
    // status = do_authentication_via_spdm();
    void *spdm_context;
    uint8_t slot_mask;
    uint8_t total_digest_buffer[LIBSPDM_MAX_HASH_SIZE * SPDM_MAX_SLOT_COUNT];
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];

    spdm_context = m_spdm_context;

    libspdm_zero_mem(total_digest_buffer, sizeof(total_digest_buffer));
    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));
    //*cert_chain_data_size = 5; // CHECKPOINT5
    status = spdm_authentication(spdm_context, &slot_mask,
                                 &total_digest_buffer, m_use_slot_id,
                                 &cert_chain_size, cert_chain,
                                 m_use_measurement_summary_hash_type,
                                 measurement_hash);
    if (LIBSPDM_STATUS_IS_ERROR(status))
    {
        printf("do_authentication_via_spdm - %x\n", (uint32_t)status);
        goto done;
    }
    printf("\nCHECKPOINT 9AAAAAAAA");
    uint8_t *cert_chain_data;
    size_t hash_sizex;
    //*cert_chain_data_size = 6; // CHECKPOINT6

    cert_chain_data = cert_chain;
    *cert_chain_data_size = cert_chain_size;
    printf("\nCHECKPOINT 9AAAAAAAA %ld\n", *cert_chain_data_size);
    hash_sizex = libspdm_get_hash_size(((libspdm_context_t *)m_spdm_context)->connection_info.algorithm.base_hash_algo);

    cert_chain_data = cert_chain_data + sizeof(spdm_cert_chain_t) + hash_sizex;
    *cert_chain_data_size = *cert_chain_data_size - (sizeof(spdm_cert_chain_t) + hash_sizex);

    *m_temp = malloc(sizeof(unsigned char) * (*cert_chain_data_size));
#define MEMORY_ALLOCATION_FAILED 0xF0

    if (NULL == *m_temp)
    {
        printf("Memory allocation failed\n");
        return MEMORY_ALLOCATION_FAILED;
    }
    memcpy(*m_temp, cert_chain_data, *cert_chain_data_size);

    printf("\nCHECKPOINT 9BBB %ld\n", cert_chain_size);

    printf("\nCHECKPOINT 10XXXXXXXXXXXXX11110XXXXXXXXXXXXX11110XXXXXXXXXXXXX11110XXXXXXXXXXXXX111");
    int i;
    int k = *cert_chain_data_size;
    printf("\nCHECKPOINT 9BBB KKKK %d\n", k);

    for (i = 0; i < *cert_chain_data_size; i++)
    {
        printf("%x ", ((uint8_t *)*m_temp)[i]);
    }

    printf("\n\n");
    for (i = 0; i < *cert_chain_data_size; i++)
    {
        printf("%d ", ((uint8_t *)*m_temp)[i]);
    }
    printf("\nCHECKPOINT 9C\n");

#endif /*(LIBSPDM_ENABLE_CAPABILITY_CERT_CAP && LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP)*/
    // #if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
    //     if ((m_exe_connection & EXE_CONNECTION_MEAS) != 0) {
    //         status = do_measurement_via_spdm(NULL);
    //         if (LIBSPDM_STATUS_IS_ERROR(status)) {
    //             printf("do_measurement_via_spdm - %x\n",
    //                    (uint32_t)status);
    //             goto done;
    //         }
    //     }
    // #endif /*LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/
    //     /* when use --trans NONE, skip secure session  */
    //     if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_NONE) {
    //         if (m_use_version >= SPDM_MESSAGE_VERSION_12) {
    //             status = do_certificate_provising_via_spdm(NULL);
    //             if (LIBSPDM_STATUS_IS_ERROR(status)) {
    //                 printf("do_certificate_provising_via_spdm - %x\n",
    //                        (uint32_t)status);
    //                 goto done;
    //             }
    //         }
    //     }
    //     else
    //     {
    // #if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP || LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
    //         if (m_use_version >= SPDM_MESSAGE_VERSION_11) {
    //             if ((m_exe_session & EXE_SESSION_KEY_EX) != 0) {
    //                 status = do_session_via_spdm(false);
    //                 if (LIBSPDM_STATUS_IS_ERROR(status)) {
    //                     printf("do_session_via_spdm - %x\n",
    //                            (uint32_t)status);
    //                     goto done;
    //                 }
    //             }

    //             if ((m_exe_session & EXE_SESSION_PSK) != 0) {
    //                 status = do_session_via_spdm(true);
    //                 if (LIBSPDM_STATUS_IS_ERROR(status)) {
    //                     printf("do_session_via_spdm - %x\n",
    //                            (uint32_t)status);
    //                     goto done;
    //                 }
    //             }
    //             if ((m_exe_session & EXE_SESSION_KEY_EX) != 0) {
    //                 if (m_other_slot_id != 0) {
    //                     m_use_slot_id = m_other_slot_id;
    //                     status = do_session_via_spdm(false);
    //                     if (LIBSPDM_STATUS_IS_ERROR(status)) {
    //                         printf("do_session_via_spdm - %x\n",
    //                                (uint32_t)status);
    //                         goto done;
    //                     }
    //                 }
    //             }
    //         }
    // #endif /*(LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP || LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)*/
    //     }
    /* Do test - end*/

    result = true;
    printf("\n%d\n", *a);
    *a = 10;
    printf("\n%d\n", *a);
    printf("\nCHECKPOINT 10XXXXXXXXXXXXX111 %p\n", *m_temp);
done:
    response_size = 0;
    if (!communicate_platform_data(
            m_socket, SOCKET_SPDM_COMMAND_SHUTDOWN - m_exe_mode,
            NULL, 0, &response, &response_size, NULL))
    {
        return false;
    }

    if (m_spdm_context != NULL)
    {
        libspdm_deinit_context(m_spdm_context);
        free(m_spdm_context);
        free(m_scratch_buffer);
    }

    closesocket(platform_socket);

    printf("Client stopped\n");

    close_pcap_packet_file();

    return result;
}

int main1(char* caliptra_dpe_profile, int port_number, void **temp, size_t *cert_chain_data_size)
{
    bool result;
    int myresult;
    int a;
    a = 5;

    if (strcmp(caliptra_dpe_profile, DPE_PROFILE_IROT_P256_SHA256) == 0){
        m_use_measurement_hash_algo = SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256;
        m_use_hash_algo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
        m_use_asym_algo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
        m_use_req_asym_algo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;
        myresult = 11;
    }else if(strcmp(caliptra_dpe_profile, DPE_PROFILE_IROT_P384_SHA384) == 0){
        m_use_measurement_hash_algo = SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384;
        m_use_hash_algo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384;
        m_use_asym_algo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384;
        m_use_req_asym_algo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;
        myresult = 12;
    }else{
        myresult = 13;
        return myresult;
    } 
    // size_t cert_chain_data_size = 0;
    // void *temp;
    unsigned char *temp1;
    //   temp = malloc(sizeof(unsigned char) * 2000);

    // cert_chain_data_size = 0;
    //*cert_chain_data_size = 1; // CHECKPOINT1
    printf("\nCHECKPOINT 10AAAA %p\n", temp);
    result = platform_client_routine(DEFAULT_SPDM_PLATFORM_PORT, temp, cert_chain_data_size, &a);
    if (!result){ myresult = 14;}

    printf("\nCHECKPOINT 10A\n");

    printf("\n%ld\n", *cert_chain_data_size);
    // printf("\n%ln\n", &cert_chain_data_size);

    temp1 = (uint8_t *)*temp;
    printf("\nCHECKPOINT 1000000000KKKKKKKKKKKKKKKKKKKKKKK %p\n", *temp);
    int i;
    for (i = 0; i < *cert_chain_data_size; i++)
    {
        printf("%x ", (uint8_t)temp1[i]);
    }
    printf("\n\n");
    for (i = 0; i < *cert_chain_data_size; i++)
    {
        printf("%d ", (uint8_t)temp1[i]);
    }
    printf("\nCHECKPOINT 10B\n");
    printf("\n%d\n", a);

    return (myresult);
}

// int main(int argc, char *argv[])
// {
//     bool result;
//     size_t cert_chain_data_size = 0;
//     void *temp;
//     unsigned char *temp1;
//     // unsigned char *temp1;
//     //   temp = malloc(sizeof(unsigned char) * 2000);

//     // cert_chain_data_size = 0;
//     printf("\nCHECKPOINT GAAAAAAAAAAAAAAAAAAA %p\n", temp);
//     result = main1(&temp, &cert_chain_data_size);

//     printf("\nCHECKPOINT HHHHHHHHHHHHHHHHHHA\n");
//     printf("\n%ld\n", cert_chain_data_size);
//     // printf("\n%ln\n", &cert_chain_data_size);

//     temp1 = (uint8_t *)temp;
//     printf("\nCHECKPOINT IIIIIIIIIIIIIIIIIIIIIIIIIIIIII %p\n", temp);
//     int i;
//     for (i = 0; i < cert_chain_data_size; i++)
//     {
//         printf("%x ", (uint8_t)temp1[i]);
//     }
//     printf("\n\n");
//     for (i = 0; i < cert_chain_data_size; i++)
//     {
//         printf("%d ", (uint8_t)temp1[i]);
//     }
//     printf("\nCHECKPOINT JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ\n");

//     return (!result);
// }