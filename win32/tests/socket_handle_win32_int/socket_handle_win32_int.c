// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifdef __cplus
#include <cstdint>
#else
#include <stdint.h>
#endif

#undef DECLSPEC_IMPORT

#pragma warning(disable: 4273)

#include <winsock2.h>

#include "testrunnerswitcher.h"
#include "azure_macro_utils/macro_utils.h"
#include "azure_c_pal/gballoc_ll.h"
#include "azure_c_pal/gballoc_ll_redirect.h"
#include "azure_c_logging/xlogging.h"

#include "azure_c_pal/socket_handle.h"
#include "azure_c_pal/platform.h"

typedef struct CLIENT_INFO_TAG
{
    int j;
} CLIENT_INFO;

#define SEND_BYTE_SIZE_256          256

static const char* TEST_HOSTNAME = "bishop";//"10.0.0.66";
static uint16_t TEST_PORT_VALUE = 4848;
static uint32_t TEST_256_BYTES_SEND[SEND_BYTE_SIZE_256];

static TEST_MUTEX_HANDLE g_testByTest;

static void on_socket_open(void* user_ctx, SOCKET_OPEN_RESULT open_result)
{
    CLIENT_INFO* client_info = (CLIENT_INFO*)user_ctx;
    (void)client_info;
    if (open_result != SOCKET_OPEN_OK)
    {
        LogError("Open failed %d", (int)open_result);
    }
    else
    {
        LogInfo("Socket successfully open");
    }
}

static void on_socket_error(void* user_ctx, SOCKET_ERROR_RESULT error_result)
{
    CLIENT_INFO* client_info = (CLIENT_INFO*)user_ctx;
    (void)client_info;
    LogError("Error detected %d", (int)error_result);
}

static void on_socket_send_complete(void* user_ctx, SOCKET_SEND_RESULT send_result, size_t bytes_sent)
{
    (void)user_ctx;
    if (send_result != SOCKET_SEND_OK)
    {
        LogError("Send failed %d", (int)send_result);
    }
    else
    {
        LogInfo("Socket successfully sent %zu bytes", bytes_sent);
    }
}

//MU_DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)
//static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
//{
//    ASSERT_FAIL("umock_c reported error :%" PRI_MU_ENUM "", MU_ENUM_VALUE(UMOCK_C_ERROR_CODE, error_code));
//}

static void create_listener(void)
{
    // Create listening socket
    CLIENT_INFO client_info = { 0 };
    SOCKET_CONFIG config = { 0 };
    config.port = TEST_PORT_VALUE;
    config.accepted_socket = ADDRESS_TYPE_IP;
    SOCKET_HANDLE listener = socket_create(&config, on_socket_error, &client_info);
    ASSERT_IS_NOT_NULL(listener);


}

BEGIN_TEST_SUITE(socket_handle_win32_inttests)

TEST_SUITE_INITIALIZE(suite_init)
{
    //ASSERT_ARE_EQUAL(int, 0, gballoc_hl_init(NULL, NULL));

    platform_init();

    //xlogging_set_log_function(NULL);
    g_testByTest = TEST_MUTEX_CREATE();
    ASSERT_IS_NOT_NULL(g_testByTest);

    uint32_t data_bytes = 0x10;
    for (size_t index = 0; index < SEND_BYTE_SIZE_256; index++)
    {
        TEST_256_BYTES_SEND[index] = data_bytes;
    }
}

TEST_SUITE_CLEANUP(suite_cleanup)
{
    platform_deinit();
    TEST_MUTEX_DESTROY(g_testByTest);
    //gballoc_hl_deinit();
}

TEST_FUNCTION_INITIALIZE(TestMethodInitialize)
{
    if (TEST_MUTEX_ACQUIRE(g_testByTest))
    {
        ASSERT_FAIL("our mutex is ABANDONED. Failure in test framework");
    }
}

TEST_FUNCTION_CLEANUP(TestMethodCleanup)
{
    TEST_MUTEX_RELEASE(g_testByTest);
}

TEST_FUNCTION(socket_handle_send_256_bytes_success)
{
    // TODO: Start the Server
    int result;


    CLIENT_INFO client_info = {0};
    SOCKET_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.accepted_socket = ADDRESS_TYPE_IP;

    SOCKET_HANDLE socket_handle = socket_create(&config, on_socket_error, &client_info);
    ASSERT_IS_NOT_NULL(socket_handle);

    result = socket_open(socket_handle, on_socket_open, &client_info);
    ASSERT_ARE_EQUAL(int, 0, result);

    SOCKET underlying_socket = socket_get_underlying_handle(socket_handle);
    ASSERT_IS_TRUE(INVALID_SOCKET != underlying_socket);

    result = socket_send(socket_handle, TEST_256_BYTES_SEND, SEND_BYTE_SIZE_256, on_socket_send_complete, &client_info);
    ASSERT_ARE_EQUAL(int, 0, result);

    result = socket_close(socket_handle, NULL, NULL);
    ASSERT_ARE_EQUAL(int, 0, result);

    socket_destroy(socket_handle);
}

END_TEST_SUITE(socket_handle_win32_inttests)
