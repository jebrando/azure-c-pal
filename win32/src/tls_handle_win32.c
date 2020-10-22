// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#define SECURITY_WIN32

#include <windows.h>
#include <sspi.h>
#include <schannel.h>

#include "azure_macro_utils/macro_utils.h"
#include "azure_c_logging/xlogging.h"

#include "azure_c_pal/tls_handle.h"
#include "azure_c_pal/socket_objects.h"

typedef enum TLS_CONTEXT_TAG
{
    CONTEXT_CLIENT,
    CONTEXT_SERVER
} TLS_CONTEXT;

typedef struct TLS_INSTANCE_TAG
{
    CredHandle cred_handle;
    CtxtHandle security_ctx;
    char* hostname;
} TLS_INSTANCE;

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
        memcpy(*target, source, length+1);
        //*target[length] = '\0';
        result = 0;
    }
    return result;
}

static int load_credential_info(TLS_INSTANCE* tls_instance, TLS_CONTEXT curr_context)
{
    int result;
    (void)curr_context;
    SECURITY_STATUS status;
    SCHANNEL_CRED auth_data = { 0 };
    auth_data.dwVersion = SCHANNEL_CRED_VERSION;
    auth_data.dwFlags = SCH_USE_STRONG_CRYPTO | SCH_CRED_NO_DEFAULT_CREDS;
    status = AcquireCredentialsHandle(NULL, UNISP_NAME, SECPKG_CRED_BOTH, NULL, &auth_data, NULL, NULL, &tls_instance->cred_handle, NULL);
    if (status != SEC_E_OK)
    {
        LogLastError("Failed aquiring credentials error: %d", status);
        result = MU_FAILURE;
    }
    else
    {
        result = 0;
    }
    return result;
}

static int send_client_handshake(TLS_INSTANCE* tls_instance, SOCKET_HANDLE socket, ON_HANDSHAKE_COMPLETE handshake_cb, void* handshake_ctx)
{
    int result = 0;
    (void)socket;
    SECURITY_STATUS status;
    TLS_RESULT tls_result = TLS_OK;
    DWORD ctx_flags = ISC_REQ_EXTENDED_ERROR | ISC_REQ_STREAM | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_USE_SUPPLIED_CREDS;
    SecBufferDesc sec_buffer_desc;
    SecBuffer sec_buffers[2];
    ULONG context_attributes;

    sec_buffers[0].cbBuffer = 0;
    sec_buffers[0].BufferType = SECBUFFER_TOKEN;
    sec_buffers[0].pvBuffer = NULL;
    sec_buffers[1].cbBuffer = 0;
    sec_buffers[1].BufferType = SECBUFFER_EMPTY;
    sec_buffers[1].pvBuffer = 0;

    sec_buffer_desc.cBuffers = 2;
    sec_buffer_desc.pBuffers = sec_buffers;
    sec_buffer_desc.ulVersion = SECBUFFER_VERSION;


    status = InitializeSecurityContext(&tls_instance->cred_handle, NULL, tls_instance->hostname, ctx_flags,
        0, 0, NULL, 0, &tls_instance->security_ctx, &sec_buffer_desc, &context_attributes, NULL);
    if (status == SEC_I_COMPLETE_NEEDED || status == SEC_I_CONTINUE_NEEDED || status == SEC_I_COMPLETE_AND_CONTINUE)
    {
        // Continue sending hello to client
    }
    else
    {
        // Fail here
    }

    if (handshake_cb != NULL)
    {
        handshake_cb(handshake_ctx, tls_result);
    }
    return result;
}

static int send_server_handshake(TLS_INSTANCE* tls_instance, SOCKET_HANDLE socket, ON_HANDSHAKE_COMPLETE handshake_cb, void* handshake_ctx)
{
    int result = 0;
    (void)tls_instance;
    (void)socket;
    TLS_RESULT tls_result = TLS_OK;

    if (handshake_cb != NULL)
    {
        handshake_cb(handshake_ctx, tls_result);
    }
    return result;
}

static int process_incoming_bytes(TLS_INSTANCE* tls_instance, const unsigned char* buffer, size_t size, ON_BYTES_ENCRYPTED bytes_encrypted_cb, void* user_ctx)
{
    int result = 0;
    (void)tls_instance;
    TLS_RESULT tls_result = TLS_OK;

    if (bytes_encrypted_cb != NULL)
    {
        bytes_encrypted_cb(user_ctx, tls_result, buffer, size);
    }
    return result;
}

static int process_outgoing_bytes(TLS_INSTANCE* tls_instance, const unsigned char* buffer, size_t size, ON_BYTES_DECRYPTED bytes_decrypted_cb, void* user_ctx)
{
    int result = 0;
    (void)tls_instance;
    TLS_RESULT tls_result = TLS_OK;

    if (bytes_decrypted_cb != NULL)
    {
        bytes_decrypted_cb(user_ctx, tls_result, buffer, size);
    }
    return result;
}

TLS_HANDLE tls_create(const char* hostname)
{
    TLS_INSTANCE* result;
    if ((result = malloc(sizeof(TLS_INSTANCE))) == NULL)
    {
        LogError("Failed allocating TLS instance");
    }
    else if (clone_string(&result->hostname, hostname) != 0)
    {
        LogError("Failed allocating hostname");
    }
    else if (load_credential_info(result, CONTEXT_CLIENT) != 0)
    {
        LogError("Failed loading credential information");
        free(result->hostname);
        free(result);
        result = NULL;
    }
    return result;
}

void tls_destroy(TLS_HANDLE handle)
{
    if (handle != NULL)
    {
        (void)FreeCredentialHandle(&handle->cred_handle);
        free(handle->hostname);
        free(handle);
    }
}

int tls_init_client_handshake(TLS_HANDLE handle, SOCKET_HANDLE socket, ON_HANDSHAKE_COMPLETE handshake_cb, void* user_ctx)
{
    int result;
    if (handle == NULL)
    {
        LogError("Invalid parameter specified handle: %p", handle);
        result = MU_FAILURE;
    }
    else
    {
        if (send_client_handshake(handle, socket, handshake_cb, user_ctx) != 0)
        {
            LogError("Failure sending client handshake");
            result = MU_FAILURE;
        }
        else
        {
            result = 0;
        }
    }
    return result;
}

int tls_send_server_handshake(TLS_HANDLE handle, SOCKET_HANDLE socket, ON_HANDSHAKE_COMPLETE handshake_cb, void* user_ctx)
{
    int result;
    if (handle == NULL)
    {
        LogError("Invalid parameter specified handle: %p", handle);
        result = MU_FAILURE;
    }
    else if (send_server_handshake(handle, socket, handshake_cb, user_ctx) != 0)
    {
        LogError("Failure sending client handshake");
        result = MU_FAILURE;
    }
    else
    {
        result = 0;
    }
    return result;
}

int tls_encrypt_send_bytes(TLS_HANDLE handle, const unsigned char* buffer, size_t size, ON_BYTES_ENCRYPTED bytes_encrypted_cb, void* user_ctx)
{
    int result;
    if (handle == NULL)
    {
        LogError("Invalid parameter specified handle: %p", handle);
        result = MU_FAILURE;
    }
    else if (process_outgoing_bytes(handle, buffer, size, bytes_encrypted_cb, user_ctx) != 0)
    {
        LogError("Failure processing outgoing bytes");
        result = MU_FAILURE;
    }
    else
    {
        result = 0;
    }
    return result;
}

int tls_decrypt_recv_bytes(TLS_HANDLE handle, const unsigned char* buffer, size_t size, ON_BYTES_DECRYPTED bytes_decrypted_cb, void* user_ctx)
{
    int result;
    if (handle == NULL)
    {
        LogError("Invalid parameter specified handle: %p", handle);
        result = MU_FAILURE;
    }
    else if (process_incoming_bytes(handle, buffer, size, bytes_decrypted_cb, user_ctx) != 0)
    {
        LogError("Failure processing outgoing bytes");
        result = MU_FAILURE;
    }
    else
    {
        result = 0;
    }
    return result;
}
