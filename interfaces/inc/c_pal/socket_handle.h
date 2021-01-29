// Copyright (C) Microsoft Corporation. All rights reserved.

#ifndef SOCKET_HANDLE_H
#define SOCKET_HANDLE_H

#ifdef __cplusplus
#include <cstdint>
#else
#include <stdint.h>
#endif

#include "macro_utils/macro_utils.h"

#include "umock_c/umock_c_prod.h"

#ifdef __cplusplus
extern "C" {
#endif

    /* this type should abstract a socket for different platforms. I.e. for Windows it should simply wrap SOCKET */
    typedef struct SOCKET_INFO_TAG* SOCKET_HANDLE;

    #define SOCKET_ADDRESS_TYPE_VALUE   \
        ADDRESS_TYPE_IP,                \
        ADDRESS_TYPE_DOMAIN_SOCKET,     \
        ADDRESS_TYPE_UDP

    MU_DEFINE_ENUM(SOCKET_ADDRESS_TYPE, SOCKET_ADDRESS_TYPE_VALUE)

    typedef struct SOCKET_ADDR_INFO_TAG
    {
        uint16_t addr_family;
        unsigned long interface_addr;
        uint16_t port;
    } SOCKET_ADDR_INFO;

    MOCKABLE_FUNCTION(, SOCKET_HANDLE, socket_create, int, domain, int, type, int, protocol);
    MOCKABLE_FUNCTION(, void, socket_destroy, SOCKET_HANDLE, handle);

    MOCKABLE_FUNCTION(, int, socket_attach, SOCKET_HANDLE, handle, SOCKET_HANDLE, attach);

    MOCKABLE_FUNCTION(, int, socket_connect, SOCKET_HANDLE, handle, const char*, hostname, uint16_t, port, SOCKET_ADDRESS_TYPE, address_type);

    // listening
    MOCKABLE_FUNCTION(, int, socket_bind, SOCKET_HANDLE, handle, const SOCKET_ADDR_INFO*, addr);
    MOCKABLE_FUNCTION(, SOCKET_HANDLE, socket_accept, SOCKET_HANDLE, handle, SOCKET_ADDR_INFO*, addr);

    MOCKABLE_FUNCTION(, int, socket_listen, SOCKET_HANDLE, handle, int, backlog);
    MOCKABLE_FUNCTION(, int, socket_ioctlsocket, SOCKET_HANDLE, handle, long, cmd, u_long*, argp);
    MOCKABLE_FUNCTION(, int, socket_select, SOCKET_HANDLE, handle, fd_set*, readfds, fd_set*, writefds, fd_set*, exceptfds, const struct timeval*, timeout);


#ifdef __cplusplus
}
#endif

#endif // SOCKET_HANDLE_H
