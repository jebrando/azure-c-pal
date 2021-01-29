// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#include <stddef.h>
#include <inttypes.h>

#include "winsock2.h"
#include "ws2tcpip.h"

#include "macro_utils/macro_utils.h"

#include "c_logging/xlogging.h"

#include "c_pal/socket_handle.h"

typedef struct SOCKET_INFO_TAG
{
    int socket;
} SOCKET_INFO;

SOCKET_HANDLE socket_create(int domain, int type, int protocol)
{
    SOCKET_INFO* result;
    if ((result = malloc(sizeof(SOCKET_INFO))) == NULL)
    {
        LogError("Failure allocating SOCKET_INFO");
    }
    else
    {
        result->socket = socket(domain, type, protocol);
    }
    return NULL;
}

void socket_destroy(SOCKET_HANDLE handle)
{
    if (handle == NULL)
    {
        LogError("Invalid handle specified for destroy");
    }
    else
    {
        (void)shutdown(handle->socket, SHUT_RDWR);
        close(handle->socket);
        handle->socket = -1;

        free(handle);
    }
}

int socket_connect(SOCKET_HANDLE handle, const char* hostname, uint16_t port, SOCKET_ADDRESS_TYPE address_type)
{
    int result;
    if (handle == NULL)
    {
        result = MU_FAILURE;
    }
    else
    {
        result = 0;
    }
    return result;
}

int socket_bind(SOCKET_HANDLE handle, const SOCKET_ADDR_INFO* addr)
{
    int result;
    if (handle == NULL)
    {
        result = MU_FAILURE;
    }
    else
    {
        result = 0;
    }
    return result;
}

SOCKET_HANDLE socket_accept(SOCKET_HANDLE handle, SOCKET_ADDR_INFO* addr)
{
    SOCKET_HANDLE result;
    if (handle == NULL)
    {
        result = NULL;
    }
    else
    {
        result = NULL;
    }
    return result;
}

int socket_listen(SOCKET_HANDLE handle, int backlog)
{
    int result;
    if (handle == NULL)
    {
        result = MU_FAILURE;
    }
    else
    {
        result = 0;
    }
    return result;
}

int socket_ioctlsocket(SOCKET_HANDLE handle, long cmd, u_long* argp)
{
    int result;
    if (handle == NULL)
    {
        result = MU_FAILURE;
    }
    else
    {
        result = 0;
    }
    return result;
}

int socket_select(SOCKET_HANDLE handle, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timeval* timeout)
{
    (void)readfds;
    (void)writefds;
    (void)exceptfds;
    (void)timeout;
    int result;
    if (handle == NULL)
    {
        result = MU_FAILURE;
    }
    else
    {
        result = 0;
    }
    return result;
}
