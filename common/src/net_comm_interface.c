// Copyright (C) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdint.h>

#include "azure_c_logging/xlogging.h"
#include "azure_c_pal/gballoc_ll.h"
#include "azure_c_pal/gballoc_ll_redirect.h"
#include "azure_macro_utils/macro_utils.h"

#include "azure_c_pal/net_comm_interface.h"

typedef struct NET_COMM_INSTANCE_TAG
{
    const COMM_INTERFACE_DESCRIPTION* comm_description;
    COMM_HANDLE comm_handle;
} NET_COMM_INSTANCE;

NET_COMM_INSTANCE_HANDLE net_comm_create(const COMM_INTERFACE_DESCRIPTION* comm_description, const void* parameters, const COMM_CALLBACK_INFO* client_cb)
{
    NET_COMM_INSTANCE* result;
    if ((comm_description == NULL) ||
        (comm_description->interface_impl_create == NULL) ||
        (comm_description->interface_impl_destroy == NULL) ||
        (comm_description->interface_impl_open == NULL) ||
        (comm_description->interface_impl_close == NULL) ||
        (comm_description->interface_impl_send == NULL) ||
        (comm_description->interface_impl_send_notify == NULL) ||
        (comm_description->interface_impl_recv == NULL) ||
        (comm_description->interface_impl_recv_notify == NULL) ||
        (comm_description->interface_impl_underlying == NULL)
       )
    {
        LogError("Invalid interface description specified");
        result = NULL;
    }
    else if (client_cb == NULL)
    {
        LogError("client callback parameter is NULL");
        result = NULL;
    }
    else
    {
        if ((result = (NET_COMM_INSTANCE*)malloc(sizeof(NET_COMM_INSTANCE))) != NULL)
        {
            result->comm_description = comm_description;
            if ((result->comm_handle = result->comm_description->interface_impl_create(parameters, client_cb)) == NULL)
            {
                LogError("Failure calling interface create");
                free(result);
                result = NULL;
            }
        }
        else
        {
            LogError("Failure allocating io instance");
        }
    }
    return (NET_COMM_INSTANCE_HANDLE)result;
}

void net_comm_destroy(NET_COMM_INSTANCE_HANDLE handle)
{
    if (handle != NULL)
    {
        handle->comm_description->interface_impl_destroy(handle->comm_handle);
        free(handle);
    }
}

int net_comm_open(NET_COMM_INSTANCE_HANDLE handle, ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_ctx)
{
    int result;
    if (handle == NULL)
    {
        LogError("Invalid parameter specified handle: NULL");
        result = __LINE__;
    }
    else
    {
        result = handle->comm_description->interface_impl_open(handle->comm_handle, on_io_open_complete, on_io_open_complete_ctx);
    }
    return result;
}

int net_comm_close(NET_COMM_INSTANCE_HANDLE handle)
{
    int result;
    if (handle == NULL)
    {
        LogError("Invalid parameter specified handle: NULL");
        result = __LINE__;
    }
    else
    {
        result = handle->comm_description->interface_impl_close(handle->comm_handle);
    }
    return result;
}

int net_comm_send(NET_COMM_INSTANCE_HANDLE handle, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
{
    int result;
    if (handle == NULL)
    {
        LogError("Invalid parameter specified");
        result = __LINE__;
    }
    else
    {
        result = handle->comm_description->interface_impl_send(handle->comm_handle, buffer, size, on_send_complete, callback_context);
    }
    return result;
}

int net_comm_send_notify(NET_COMM_INSTANCE_HANDLE handle, const void* buffer, uint32_t size, uint32_t flags, void* overlapped_info)
{
    int result;
    if (handle == NULL)
    {
        LogError("Invalid parameter specified");
        result = __LINE__;
    }
    else
    {
        result = handle->comm_description->interface_impl_send_notify(handle->comm_handle, buffer, size, flags, overlapped_info);
    }
    return result;
}

int net_comm_recv(NET_COMM_INSTANCE_HANDLE handle)
{
    int result;
    if (handle == NULL)
    {
        LogError("Invalid parameter specified");
        result = __LINE__;
    }
    else
    {
        result = handle->comm_description->interface_impl_recv(handle->comm_handle);
    }
    return result;
}

int net_comm_recv_notify(NET_COMM_INSTANCE_HANDLE handle, void* buffer, uint32_t size, uint32_t* flags, void* overlapped_info)
{
    int result;
    if (handle == NULL)
    {
        LogError("Invalid parameter specified");
        result = __LINE__;
    }
    else
    {
        result = handle->comm_description->interface_impl_recv_notify(handle->comm_handle, buffer, size, flags, overlapped_info);
    }
    return result;
}

SOCKET_HANDLE net_comm_underlying_handle(NET_COMM_INSTANCE_HANDLE handle)
{
    SOCKET_HANDLE result;
    if (handle == NULL)
    {
        LogError("Invalid parameter specified");
        result = NULL;
    }
    else
    {
        result = handle->comm_description->interface_impl_underlying(handle->comm_handle);
    }
    return result;
}

int net_comm_listen(NET_COMM_INSTANCE_HANDLE handle)
{
    int result;
    if (handle == NULL)
    {
        LogError("Invalid parameter specified");
        result = __LINE__;
    }
    else
    {
        if (handle->comm_description->interface_impl_listen == NULL)
        {
            LogError("Failure listening function not implemented");
            result = __LINE__;
        }
        else
        {
            result = handle->comm_description->interface_impl_listen(handle->comm_handle);
        }
    }
    return result;
}

int net_comm_accept_conn(NET_COMM_INSTANCE_HANDLE handle)
{
    int result;
    if (handle == NULL)
    {
        LogError("Invalid parameter specified");
        result = __LINE__;
    }
    else
    {
        if (handle->comm_description->interface_impl_accept_conn == NULL)
        {
            LogError("Failure accept connection function not implemented");
            result = __LINE__;
        }
        else
        {
            result = handle->comm_description->interface_impl_accept_conn(handle->comm_handle);
        }
    }
    return result;
}

NET_COMM_INSTANCE_HANDLE net_comm_accept_notify(NET_COMM_INSTANCE_HANDLE handle, const COMM_CALLBACK_INFO* client_cb)
{
    NET_COMM_INSTANCE_HANDLE result;
    if (handle == NULL)
    {
        LogError("Invalid parameter specified");
        result = NULL;
    }
    else
    {
        if (handle->comm_description->interface_impl_accept_notify == NULL)
        {
            LogError("Failure accept function not implemented");
            result = NULL;
        }
        else if ((result = (NET_COMM_INSTANCE*)malloc(sizeof(NET_COMM_INSTANCE))) == NULL)
        {
            LogError("Failure allocating instance in accepting connection");
        }
        else
        {
            result->comm_description = handle->comm_description;
            if ((result->comm_handle = handle->comm_description->interface_impl_accept_notify(handle->comm_handle, client_cb)) == NULL)
            {
                LogError("Failure accepting connection");
                free(result);
                result = NULL;
            }
        }
    }
    return (NET_COMM_INSTANCE_HANDLE)result;
}
