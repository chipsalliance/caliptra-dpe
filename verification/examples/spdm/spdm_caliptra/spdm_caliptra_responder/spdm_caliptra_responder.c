/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_caliptra_responder.h"

uint32_t m_command;

SOCKET m_server_socket;

extern void *m_spdm_context;
extern void *m_scratch_buffer;

void *spdm_server_init(void);

bool platform_server(const SOCKET socket)
{
    bool result;
    libspdm_return_t status;

    while (true)
    {
        status = libspdm_responder_dispatch_message(m_spdm_context);
        if (status == LIBSPDM_STATUS_SUCCESS)
        {
            /* success dispatch SPDM message*/
        }
        if ((status == LIBSPDM_STATUS_SEND_FAIL) ||
            (status == LIBSPDM_STATUS_RECEIVE_FAIL))
        {
            printf("Server Critical Error - STOP\n");
            return false;
        }
        if (status != LIBSPDM_STATUS_UNSUPPORTED_CAP)
        {
            continue;
        }
        switch (m_command)
        {
        case SOCKET_SPDM_COMMAND_TEST:
            result = send_platform_data(socket,
                                        SOCKET_SPDM_COMMAND_TEST,
                                        (uint8_t *)"Server Hello!",
                                        sizeof("Server Hello!"));
            if (!result)
            {
                printf("send_platform_data Error - %x\n", errno);
                return true;
            }
            break;

        case SOCKET_SPDM_COMMAND_OOB_ENCAP_KEY_UPDATE:
#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) || (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP)
            libspdm_init_key_update_encap_state(m_spdm_context);
            result = send_platform_data(
                socket,
                SOCKET_SPDM_COMMAND_OOB_ENCAP_KEY_UPDATE, NULL,
                0);
            if (!result)
            {
                printf("send_platform_data Error - %x\n", errno);
                return true;
            }
#endif
            break;

        case SOCKET_SPDM_COMMAND_SHUTDOWN:
            result = send_platform_data(
                socket, SOCKET_SPDM_COMMAND_SHUTDOWN, NULL, 0);
            if (!result)
            {
                printf("send_platform_data Error - %x\n", errno);
                return true;
            }
            return false;
            break;

        case SOCKET_SPDM_COMMAND_CONTINUE:
            result = send_platform_data(
                socket, SOCKET_SPDM_COMMAND_CONTINUE, NULL, 0);
            if (!result)
            {
                printf("send_platform_data Error - %x\n", errno);
                return true;
            }
            return true;
            break;

        case SOCKET_SPDM_COMMAND_NORMAL:
            /* unknown message*/
            return true;
            break;
        default:
            printf("Unrecognized platform interface command %x\n", m_command);
            result = send_platform_data(
                socket, SOCKET_SPDM_COMMAND_UNKOWN, NULL, 0);
            if (!result)
            {
                printf("send_platform_data Error - %x\n", errno);
                return true;
            }
            return true;
        }
    }
}

bool platform_server_routine(uint16_t port_number)
{
    SOCKET responder_socket;
    struct sockaddr_in peer_address;
    bool result;
    uint32_t length;
    bool continue_serving;

    result = create_socket(port_number, &responder_socket);
    if (!result)
    {
        printf("Create platform service socket fail\n");
        return false;
    }

    do
    {
        printf("Platform server listening on port %d\n", port_number);

        length = sizeof(peer_address);
        m_server_socket = accept(responder_socket,
                                 (struct sockaddr *)&peer_address,
                                 (socklen_t *)&length);
        if (m_server_socket == INVALID_SOCKET)
        {
            closesocket(responder_socket);
            printf("Accept error.  Error is 0x%x\n", errno);
            return false;
        }

        continue_serving = platform_server(m_server_socket);
        closesocket(m_server_socket);

    } while (continue_serving);
    closesocket(responder_socket);
    return true;
}

int main(int argc, char* argv[])
{
    // libspdm_return_t status;
    bool result;

    srand((unsigned int)time(NULL));

    // process_args("spdm_responder_emu", argc, argv);

    m_spdm_context = spdm_server_init();
    if (m_spdm_context == NULL)
    {
        return 1;
    }
    result = platform_server_routine(DEFAULT_SPDM_PLATFORM_PORT);

    if (m_spdm_context != NULL)
    {
        libspdm_deinit_context(m_spdm_context);
        free(m_spdm_context);
        free(m_scratch_buffer);
    }

    printf("Server stopped\n");

    close_pcap_packet_file();
    return (!result);
}
