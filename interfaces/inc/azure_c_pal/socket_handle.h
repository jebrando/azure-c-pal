// Copyright (C) Microsoft Corporation. All rights reserved.

#ifndef SOCKET_HANDLE_H
#define SOCKET_HANDLE_H

#include "azure_macro_utils/macro_utils.h"
#include "umock_c/umock_c_prod.h"
#include "azure_c_pal/socket_objects.h"

#ifdef __cplusplus
#include <cstdint>
extern "C" {
#else
#include <stdint.h>
#endif /* __cplusplus */

#define SOCKET_SEND_RESULT_VALUES \
    SOCKET_SEND_OK, \
    SOCKET_SEND_PARTIAL_SEND, \
    SOCKET_SEND_ERROR,  \
    SOCKET_SEND_WOULD_BLOCK,  \
    SOCKET_SEND_CANCELLED
MU_DEFINE_ENUM_WITHOUT_INVALID(SOCKET_SEND_RESULT, SOCKET_SEND_RESULT_VALUES)

#define SOCKET_OPEN_RESULT_VALUES \
    SOCKET_OPEN_OK, \
    SOCKET_OPEN_ERROR, \
    SOCKET_OPEN_CANCELLED
MU_DEFINE_ENUM_WITHOUT_INVALID(SOCKET_OPEN_RESULT, SOCKET_OPEN_RESULT_VALUES)

#define SOCKET_ERROR_RESULT_VALUES \
    SOCKET_ERROR_OK, \
    SOCKET_ERROR_GENERAL, \
    SOCKET_ERROR_MEMORY, \
    SOCKET_ERROR_ENDPOINT_DISCONN
MU_DEFINE_ENUM_WITHOUT_INVALID(SOCKET_ERROR_RESULT, SOCKET_ERROR_RESULT_VALUES)

#define NET_ADDRESS_TYPE_VALUES \
    ADDRESS_TYPE_IP, \
    ADDRESS_TYPE_UDP
MU_DEFINE_ENUM_WITHOUT_INVALID(NET_ADDRESS_TYPE, NET_ADDRESS_TYPE_VALUES)

typedef void(*ON_BYTES_RECEIVED)(void* user_ctx, const unsigned char* buffer, size_t size);
typedef void(*ON_SEND_COMPLETE)(void* user_ctx, SOCKET_SEND_RESULT send_result, size_t bytes_sent);
typedef void(*ON_OPEN_COMPLETE)(void* user_ctx, SOCKET_OPEN_RESULT open_result);
typedef void(*ON_CLOSE_COMPLETE)(void* user_ctx);
typedef void(*ON_ERROR)(void* user_ctx, SOCKET_ERROR_RESULT error_result);
typedef void(*ON_INCOMING_CONNECT)(void* user_ctx, const void* config);

typedef struct SOCKET_CONFIG_TAG
{
    const char* hostname;
    uint16_t port;
    NET_ADDRESS_TYPE address_type;
    SYSTEM_SOCKET accepted_socket;
    TLS_HANDLE tls_connection;
} SOCKET_CONFIG;

MOCKABLE_FUNCTION(, SOCKET_HANDLE, socket_create, const SOCKET_CONFIG*, parameters, ON_ERROR, on_error, void*, on_error_ctx);
MOCKABLE_FUNCTION(, void, socket_destroy, SOCKET_HANDLE, handle);
MOCKABLE_FUNCTION(, int, socket_open, SOCKET_HANDLE, handle, ON_OPEN_COMPLETE, on_open_complete, void*, user_ctx);
MOCKABLE_FUNCTION(, int, socket_close, SOCKET_HANDLE, handle, ON_CLOSE_COMPLETE, on_close_complete, void*, user_ctx);
MOCKABLE_FUNCTION(, int, socket_send, SOCKET_HANDLE, handle, const void*, buffer, size_t, size, ON_SEND_COMPLETE, on_send_complete, void*, user_ctx);
MOCKABLE_FUNCTION(, int, socket_recv, SOCKET_HANDLE, handle, ON_BYTES_RECEIVED, on_bytes_recv, void*, user_ctx);
MOCKABLE_FUNCTION(, int, socket_send_notify, SOCKET_HANDLE, handle, const void*, buffer, uint32_t, size, uint32_t, flags, void*, notify_info);
MOCKABLE_FUNCTION(, int, socket_recv_notify, SOCKET_HANDLE, handle, void*, buffer, uint32_t, size, uint32_t*, flags, void*, notify_info);
MOCKABLE_FUNCTION(, int, socket_listen, SOCKET_HANDLE, handle);
MOCKABLE_FUNCTION(, SOCKET_HANDLE, socket_accept, SOCKET_HANDLE, handle);

MOCKABLE_FUNCTION(, SYSTEM_SOCKET, socket_get_underlying_handle, SOCKET_HANDLE, handle);

#ifdef __cplusplus
}
#endif

#endif // SOCKET_HANDLE_H
