// Copyright (C) Microsoft Corporation. All rights reserved.

#pragma once

#include "azure_macro_utils/macro_utils.h"
#include "umock_c/umock_c_prod.h"
#include "azure_c_pal/socket_handle.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TLS_INSTANCE_TAG* TLS_HANDLE;

#define TLS_RESULT_VALUES \
    TLS_OK, \
    TLS_ERROR, \
    TLS_CANCELLED
MU_DEFINE_ENUM_WITHOUT_INVALID(TLS_RESULT, TLS_RESULT_VALUES)

typedef void(*ON_BYTES_ENCRYPTED)(void* user_ctx, TLS_RESULT result, const unsigned char* buffer, size_t size);
typedef void(*ON_BYTES_DECRYPTED)(void* user_ctx, TLS_RESULT result, const unsigned char* buffer, size_t size);
typedef void(*ON_HANDSHAKE_COMPLETE)(void* user_ctx, TLS_RESULT result);

MOCKABLE_FUNCTION(, TLS_HANDLE, tls_create);
MOCKABLE_FUNCTION(, void, tls_destroy, TLS_HANDLE, handle);

MOCKABLE_FUNCTION(, int, tls_init_client_handshake, TLS_HANDLE, handle, ON_HANDSHAKE_COMPLETE, handshake_cb, void*, user_ctx);
MOCKABLE_FUNCTION(, int, tls_send_server_handshake, TLS_HANDLE, handle, ON_HANDSHAKE_COMPLETE, handshake_cb, void*, user_ctx);

MOCKABLE_FUNCTION(, int, tls_encrypt_send_bytes, TLS_HANDLE, handle, const unsigned char*, buffer, size_t, size, ON_BYTES_ENCRYPTED, bytes_encrypted_cb, void*, user_ctx);
MOCKABLE_FUNCTION(, int, tls_decrypt_recv_bytes, TLS_HANDLE, handle, const unsigned char*, buffer, size_t, size, ON_BYTES_DECRYPTED, bytes_decrypted_cb, void*, user_ctx);

#ifdef __cplusplus
}
#endif

