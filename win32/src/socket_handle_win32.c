// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#include <inttypes.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "azure_macro_utils/macro_utils.h"

#include "azure_c_logging/xlogging.h"
#include "azure_c_pal/gballoc_ll.h"
#include "azure_c_pal/gballoc_ll_redirect.h"

#include "azure_c_pal/socket_objects.h"
#include "azure_c_pal/socket_handle.h"
#include "azure_c_pal/tls_handle.h"
#include "azure_c_pal/gballoc_socket.h"

#define RECV_BYTES_MAX_VALUE            1024

typedef enum SOCKET_STATE_TAG
{
    IO_STATE_CLOSED,
    IO_STATE_CLOSING,
    IO_STATE_OPENING,
    IO_STATE_OPEN,
    IO_STATE_LISTENING,
    IO_STATE_ERROR
} SOCKET_STATE;

typedef struct PENDING_SEND_ITEM_TAG
{
    const char* send_data;
    size_t data_len;
    ON_SEND_COMPLETE on_send_complete;
    void* send_ctx;
    void* cache_data;
} PENDING_SEND_ITEM;

typedef struct SOCKET_INSTANCE_TAG
{
    SOCKET socket;
    char* hostname;
    uint16_t port;
    NET_ADDRESS_TYPE address_type;
    SOCKET_STATE current_state;
    TLS_HANDLE tls_conn;

    // Callbacks
    ON_ERROR on_error;
    void* on_error_ctx;

    ON_INCOMING_CONNECT on_incoming_conn;
    void* on_incoming_ctx;
} SOCKET_INSTANCE;

static int clone_string(char** target, const char* source)
{
    int result;
    size_t length = strlen(source);
    if ((*target = malloc(length + 1)) == NULL)
    {
        result = __LINE__;
    }
    else
    {
        memset(*target, 0, length + 1);
        memcpy(*target, source, length);
        result = 0;
    }
    return result;
}

static void indicate_error(SOCKET_INSTANCE* comm_impl, SOCKET_ERROR_RESULT err_result)
{
    comm_impl->current_state = IO_STATE_ERROR;
    if (comm_impl->on_error != NULL)
    {
        comm_impl->on_error(comm_impl->on_error_ctx, err_result);
    }
}

static int construct_socket_object(SOCKET_INSTANCE* comm_impl)
{
    int result;
    if (comm_impl->address_type == ADDRESS_TYPE_UDP)
    {
        comm_impl->socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    }
    else
    {
        comm_impl->socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    }

    if (comm_impl->socket == INVALID_SOCKET)
    {
        LogLastError("Failure on socket call error: %d", WSAGetLastError());
        result = __LINE__;
    }
    else
    {
        result = 0;
    }
    return result;
}

static int recv_socket_data(SOCKET_INSTANCE* comm_impl, ON_BYTES_RECEIVED on_bytes_recv, void* bytes_recv_ctx)
{
    int result;
    unsigned char recv_bytes[RECV_BYTES_MAX_VALUE];

    int recv_res = recv(comm_impl->socket, (char*)recv_bytes, RECV_BYTES_MAX_VALUE, 0);
    if (recv_res > 0)
    {
        on_bytes_recv(bytes_recv_ctx, recv_bytes, recv_res);
        result = 0;
    }
    else if (recv_res == 0)
    {
        indicate_error(comm_impl, SOCKET_ERROR_ENDPOINT_DISCONN);
        result = __LINE__;
    }
    else
    {
        int last_sock_error = WSAGetLastError();
        if (WSAEWOULDBLOCK != last_sock_error)
        {
            LogLastError("Failure receiving data on the socket, last error: %d (%s)", last_sock_error, "Failure");
            indicate_error(comm_impl, SOCKET_ERROR_GENERAL);
        }
        result = __LINE__;
    }
    return result;
}

static int send_socket_data(SOCKET_INSTANCE* comm_impl, PENDING_SEND_ITEM* pending_item)
{
    int result;

    // Send the current item.  If the current item is NULL
    // then the cached item needs to be sent
    int send_res = send(comm_impl->socket, pending_item->send_data, (int)pending_item->data_len, 0);
    if (send_res != (int)pending_item->data_len)
    {
        if (send_res == SOCKET_ERROR)
        {
            int last_sock_error = WSAGetLastError();
            if (last_sock_error == WSAEWOULDBLOCK)
            {
                if (pending_item->on_send_complete != NULL)
                {
                    pending_item->on_send_complete(pending_item->send_ctx, SOCKET_SEND_WOULD_BLOCK, 0);
                }
                LogError("Failure moving data to storage");
                result = 0;
            }
            else
            {
                // Failure happened
                if (pending_item->on_send_complete != NULL)
                {
                    pending_item->on_send_complete(pending_item->send_ctx, SOCKET_SEND_ERROR, 0);
                }
                LogLastError("Failure sending data on the socket");
                result = MU_FAILURE;
            }
        }
        else
        {
            if (pending_item->on_send_complete != NULL)
            {
                pending_item->on_send_complete(pending_item->send_ctx, SOCKET_SEND_PARTIAL_SEND, send_res);
            }
            result = 0;
        }
    }
    else
    {
        // Send success free the memory
        if (pending_item->on_send_complete != NULL)
        {
            pending_item->on_send_complete(pending_item->send_ctx, SOCKET_SEND_OK, send_res);
        }
        result = 0;
    }
    return result;
}

static void close_socket(SOCKET_INSTANCE* comm_impl, ON_CLOSE_COMPLETE on_close_complete, void* close_complete_ctx)
{
    (void)shutdown(comm_impl->socket, SD_BOTH);
    closesocket(comm_impl->socket);
    comm_impl->socket = INVALID_SOCKET;

    if (on_close_complete != NULL)
    {
        on_close_complete(close_complete_ctx);
    }
}

static int open_socket(SOCKET_INSTANCE* comm_impl, ON_OPEN_COMPLETE on_open_complete, void* open_complete_ctx)
{
    int result;
    int error_value;
    struct addrinfo addr_info_hint = { 0 };
    struct addrinfo* addr_info_ip = NULL;
    struct sockaddr* connect_addr = NULL;
    socklen_t connect_addr_len = 0;

    char port_value[16];
    addr_info_hint.ai_family = AF_INET;
    addr_info_hint.ai_socktype = SOCK_STREAM;

    sprintf(port_value, "%u", comm_impl->port);
    if ((error_value = getaddrinfo(comm_impl->hostname, port_value, &addr_info_hint, &addr_info_ip)) != 0)
    {
        LogError("Failure getting host address info %s", comm_impl->hostname);
        if (on_open_complete != NULL)
        {
            on_open_complete(open_complete_ctx, SOCKET_OPEN_ERROR);
        }
        comm_impl->current_state = IO_STATE_ERROR;
        result = __LINE__;
    }
    else
    {
        connect_addr = addr_info_ip->ai_addr;
        connect_addr_len = sizeof(*addr_info_ip->ai_addr);
        u_long mode = 1;

        error_value = connect(comm_impl->socket, connect_addr, connect_addr_len);
        if ((error_value != 0) && (errno != EINPROGRESS))
        {
            LogError("Failure connectint on socket %d.", errno);
            if (on_open_complete != NULL)
            {
                on_open_complete(open_complete_ctx, SOCKET_OPEN_ERROR);
            }
            result = __LINE__;
        }
        else if (ioctlsocket(comm_impl->socket, FIONBIO, &mode) != 0)
        {
            LogError("Failure ioctlsocket on socket %d.", errno);
            if (on_open_complete != NULL)
            {
                on_open_complete(open_complete_ctx, SOCKET_OPEN_ERROR);
            }
            result = __LINE__;
        }
        else
        {
            if (on_open_complete != NULL)
            {
                on_open_complete(open_complete_ctx, SOCKET_OPEN_OK);
            }
            comm_impl->current_state = IO_STATE_OPEN;
            result = 0;
        }
        freeaddrinfo(addr_info_ip);
    }
    return result;
}

static SOCKET_INSTANCE* create_socket_info(const SOCKET_CONFIG* config)
{
    SOCKET_INSTANCE* result;
    if ((result = malloc(sizeof(SOCKET_INSTANCE))) == NULL)
    {
        LogError("Failure allocating socket instance");
    }
    else
    {
        memset(result, 0, sizeof(SOCKET_INSTANCE));
        result->port = config->port;
        result->address_type = config->address_type;

        // Copy the host name
        if (config->hostname != NULL && clone_string(&result->hostname, config->hostname) != 0)
        {
            LogError("Failure cloning hostname value");
            free(result);
            result = NULL;
        }
        else
        {
            if (config->accepted_socket != INVALID_SOCKET && config->accepted_socket != 0)
            {
                // [ If the Accepted socket is supplied the current state will be set to Open. ]
                result->socket = config->accepted_socket;
                result->current_state = IO_STATE_OPEN;
            }
            else
            {
                result->socket = INVALID_SOCKET;
            }

            if (config->tls_connection != NULL)
            {
                result->tls_conn = config->tls_connection;
            }
        }
    }
    return result;
}

SOCKET_HANDLE socket_create(const SOCKET_CONFIG* parameters, ON_ERROR on_error, void* on_error_ctx)
{
    SOCKET_INSTANCE* result;
    if (parameters == NULL)
    {
        LogError("Invalid parameter specified");
        result = NULL;
    }
    else if ((result = create_socket_info(parameters)) == NULL)
    {
        LogError("Failure creating socket info");
    }
    else
    {
        result->on_error = on_error;
        result->on_error_ctx = on_error_ctx;
    }
    return result;
}

void socket_destroy(SOCKET_HANDLE handle)
{
    if (handle)
    {
        SOCKET_INSTANCE* comm_impl = (SOCKET_INSTANCE*)handle;
        if (comm_impl->hostname != NULL)
        {
            free(comm_impl->hostname);
        }
        free(comm_impl);
    }
}

int socket_open(SOCKET_HANDLE handle, ON_OPEN_COMPLETE on_open_complete, void* user_ctx)
{
    int result;
    if (handle == NULL)
    {
        LogError("Invalid arguments: handle: %p", handle);
        result = MU_FAILURE;
    }
    else
    {
        if (handle->current_state == IO_STATE_OPENING || handle->current_state == IO_STATE_OPEN)
        {
            LogError("Invalid state for open %d", handle->current_state);
            result = MU_FAILURE;
        }
        else if (construct_socket_object(handle) != 0)
        {
            LogError("Failure constructing socket");
            result = __LINE__;
        }
        else if (open_socket(handle, on_open_complete, user_ctx) != 0)
        {
            LogError("Failure opening socket");
            result = MU_FAILURE;
        }
        else if (handle->tls_conn != NULL && tls_init_client_handshake(handle->tls_conn, handle, NULL, NULL) != 0)
        {
            close_socket(handle, NULL, NULL);
            LogError("Failure initializing tls handshake");
            result = MU_FAILURE;
        }
        else
        {
            result = 0;
        }
    }
    return result;
}

int socket_close(SOCKET_HANDLE handle, ON_CLOSE_COMPLETE on_close_complete, void* user_ctx)
{
    int result;
    if (handle == NULL)
    {
        LogError("Invalid arguments: handle: %p", handle);
        result = MU_FAILURE;
    }
    else
    {
        close_socket(handle, on_close_complete, user_ctx);
        result = 0;
    }
    return result;
}

int socket_send(SOCKET_HANDLE handle, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* user_ctx)
{
    int result;
    if (handle == NULL || buffer == NULL || size == 0)
    {
        LogError("Invalid arguments: handle: %p, buffer: %p, size: %zu", handle, buffer, size);
        result = MU_FAILURE;
    }
    else
    {
        if (handle->current_state != IO_STATE_OPEN)
        {
            LogError("Failure sending in incorrect state");
            result = MU_FAILURE;
        }
        else
        {
            PENDING_SEND_ITEM send_item;
            send_item.on_send_complete = on_send_complete;
            send_item.send_ctx = user_ctx;
            send_item.send_data = buffer;
            send_item.data_len = size;

            if (send_socket_data(handle, &send_item) != 0)
            {
                LogError("Failure attempting to send socket data");
                result = MU_FAILURE;
            }
            else
            {
                result = 0;
            }
        }
    }
    return result;
}

int socket_send_notify(SOCKET_HANDLE handle, const void* buffer, uint32_t size, uint32_t flags, void* notify_info)
{
    int result;
    if (handle == NULL)
    {
        LogError("Invalid arguments: handle: %p", handle);
        result = MU_FAILURE;
    }
    else
    {
        if (handle->current_state != IO_STATE_OPEN)
        {
            LogError("Failure sending in incorrect state");
            result = MU_FAILURE;
        }
        else
        {
            WSABUF* wsa_buffers = (WSABUF*)buffer;
            int last_error;
            int send_result = WSASend(handle->socket, wsa_buffers, size, NULL, flags, notify_info, NULL);
            if (send_result != 0 && send_result != SOCKET_ERROR)
            {
                LogLastError("WSASend failed with %d", send_result);
                result = MU_FAILURE;
            }
            else if (send_result == SOCKET_ERROR && (last_error = WSAGetLastError()) != WSA_IO_PENDING)
            {
                LogLastError("WSASend failed with %d, WSAGetLastError returned %lu", send_result, (unsigned long)last_error);
                result = MU_FAILURE;
            }
            else
            {
                result = 0;
            }
        }
    }
    return result;
}

int socket_recv(SOCKET_HANDLE handle, ON_BYTES_RECEIVED on_bytes_recv, void* user_ctx)
{
    int result;
    if (handle == NULL || on_bytes_recv == NULL)
    {
        LogError("Invalid arguments: handle: %p", handle);
        result = MU_FAILURE;
    }
    else
    {
        result = recv_socket_data(handle, on_bytes_recv, user_ctx);
    }
    return result;
}

int socket_recv_notify(SOCKET_HANDLE handle, void* buffer, uint32_t size, uint32_t* flags, void* overlapped_info)
{
    int result;
    if (handle == NULL)
    {
        LogError("Invalid arguments: handle: %p", handle);
        result = MU_FAILURE;
    }
    else
    {
        if (handle->current_state != IO_STATE_OPEN)
        {
            LogError("Failure sending in incorrect state");
            result = MU_FAILURE;
        }
        else
        {
            WSABUF* wsa_buffers = (WSABUF*)buffer;
            int receive_result;
            int last_error;

            receive_result = WSARecv(handle->socket, wsa_buffers, size, NULL, (LPDWORD)flags, (LPWSAOVERLAPPED)overlapped_info, NULL);
            if (receive_result != 0 && receive_result != SOCKET_ERROR)
            {
                // : [ If WSARecv fails with any other error, socket_handle_recv_notify shall return a non-zero value. ]
                LogLastError("WSARecv failed with %d", receive_result);
                result = MU_FAILURE;
            }
            // : [ If WSARecv fails with SOCKET_ERROR, socket_handle_recv_notify shall call WSAGetLastError. ]
            // : [ If WSAGetLastError returns IO_PENDING, it shall be not treated as an error. ]
            else if (receive_result == SOCKET_ERROR && (last_error = WSAGetLastError()) != WSA_IO_PENDING)
            {
                // : [ If any error occurs, socket_handle_recv_notify shall fail and return a non-zero value. ]
                LogLastError("WSARecv failed with %d, WSAGetLastError returned %lu", receive_result, last_error);
                result = MU_FAILURE;
            }
            else
            {
                result = 0;
            }
        }
    }
    return result;
}

int socket_listen(SOCKET_HANDLE handle)
{
    int result;
    if (handle == NULL)
    {
        LogError("Failure invalid parameter specified handle: %p", handle);
        result = MU_FAILURE;
    }
    else
    {
        u_long mode = 1;
        if (handle->current_state == IO_STATE_OPENING || handle->current_state == IO_STATE_OPEN)
        {
            LogError("Socket is in invalid state to open");
            result = __LINE__;
        }
        else if (handle->address_type != ADDRESS_TYPE_IP)
        {
            LogError("Socket is in an invalid state");
            result = __LINE__;
        }
        else if (construct_socket_object(handle) != 0)
        {
            LogError("Failure constructing socket");
            result = __LINE__;
        }
        else if (ioctlsocket(handle->socket, FIONBIO, &mode) != 0)
        {
            LogError("Failure Setting unblocking socket");
            close_socket(handle, NULL, NULL);
            result = __LINE__;
        }
        else
        {
            struct sockaddr_in serv_addr = { 0 };
            serv_addr.sin_family = AF_INET;
            serv_addr.sin_addr.s_addr = INADDR_ANY;
            serv_addr.sin_port = htons(handle->port);

            // bind the host address using bind() call
            if (bind(handle->socket, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
            {
                LogError("Failure binding to socket address error: %lu", WSAGetLastError() );
                close_socket(handle, NULL, NULL);
                result = __LINE__;
            }
            else if (listen(handle->socket, SOMAXCONN) < 0)
            {
                LogError("Failure listening to incoming connection");
                close_socket(handle, NULL, NULL);
                result = __LINE__;
            }
            else
            {
                handle->current_state = IO_STATE_LISTENING;
                result = 0;
            }
        }
    }
    return result;
}

SOCKET_HANDLE socket_accept(SOCKET_HANDLE handle)
{
    SOCKET_INSTANCE* result;
    if (handle == NULL)
    {
        LogError("Invalid arguments: handle: %p", handle);
        result = NULL;
    }
    else
    {
        SOCKET_CONFIG config = { 0 };
        struct sockaddr_in cli_addr;
        socklen_t client_len = sizeof(cli_addr);

        config.accepted_socket = (SYSTEM_SOCKET)accept(handle->socket, (struct sockaddr*)&cli_addr, &client_len);
        if (config.accepted_socket != INVALID_SOCKET)
        {
            u_long mode = 1;
            if (ioctlsocket(handle->socket, FIONBIO, &mode) != 0)
            {
                LogLastError("Failure setting accepted socket to non blocking");
                (void)shutdown(config.accepted_socket, SD_BOTH);
                closesocket(config.accepted_socket);
                result = NULL;
            }
            else
            {
                char incoming_host[128];
                config.port = cli_addr.sin_port;
                config.hostname = inet_ntop(AF_INET, &cli_addr.sin_addr.s_addr, incoming_host, sizeof(incoming_host));
                result = create_socket_info(&config);
            }
        }
        else
        {
            LogLastError("Failure setting accepted socket");
            result = NULL;
        }
    }
    return result;
}

SYSTEM_SOCKET socket_get_underlying_handle(SOCKET_HANDLE handle)
{
    SOCKET result;
    if (handle == NULL)
    {
        LogError("Invalid arguments: handle: %p", handle);
        result = INVALID_SOCKET;
    }
    else
    {
        result = handle->socket;
    }
    return (SYSTEM_SOCKET)result;
}
