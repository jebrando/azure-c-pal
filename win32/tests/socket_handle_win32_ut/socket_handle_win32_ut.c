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

static void* my_gballoc_malloc(size_t size)
{
    return malloc(size);
}

static void my_gballoc_free(void* ptr)
{
    free(ptr);
}

#include "testrunnerswitcher.h"
#include "umock_c/umock_c.h"
#include "umock_c/umocktypes_charptr.h"
#include "umock_c/umocktypes_stdint.h"
#include "umock_c/umock_c_negative_tests.h"
#include "azure_macro_utils/macro_utils.h"

#define ENABLE_MOCKS
#include "azure_c_pal/gballoc_ll.h"
#include "azure_c_pal/gballoc_ll_redirect.h"
#include "umock_c/umock_c_prod.h"
#include "azure_c_pal/gballoc_socket.h"

#undef ENABLE_MOCKS

#include "azure_c_pal/socket_handle.h"

#define ENABLE_MOCKS

MOCK_FUNCTION_WITH_CODE(, void, test_on_bytes_recv, void*, context, const unsigned char*, buffer, size_t, size)
MOCK_FUNCTION_END()

MOCK_FUNCTION_WITH_CODE(, void, test_on_open_complete, void*, context, SOCKET_OPEN_RESULT, open_result);
MOCK_FUNCTION_END()

//MOCKABLE_FUNCTION(, void, test_on_send_complete, void*, context, IO_SEND_RESULT, send_result);
MOCK_FUNCTION_WITH_CODE(, void, test_on_close_complete, void*, context);
MOCK_FUNCTION_END()
MOCK_FUNCTION_WITH_CODE(, void, test_on_error, void*, context, SOCKET_ERROR_RESULT, error_result);
MOCK_FUNCTION_END()

static const char* TEST_HOSTNAME = "test.hostname.com";
static const char* TEST_PORT_STRING = "8543";
static uint16_t TEST_PORT_VALUE = 8543;
static void* TEST_USER_CONTEXT = (void*)0x234587;
static struct addrinfo g_addr_info = { 0 };
static struct sockaddr g_connect_addr = { 0 };
static ADDRINFO TEST_ADDR_INFO = { 0 };

#define FAKE_GOOD_IP_ADDR 444

static TEST_MUTEX_HANDLE g_testByTest;

#ifdef __cplusplus
extern "C" {
#endif

char* umocktypes_stringify_const_ADDRINFOA_ptr(const ADDRINFOA** value)
{
    char* result = NULL;
    char temp_buffer[256];
    int length;

    length = sprintf(temp_buffer, "{ ai_flags = %d, ai_family = %d, ai_socktype = %d, ai_protocol = %d, ai_addrlen = %u, ai_canonname = %s", (*value)->ai_flags, (*value)->ai_family, (*value)->ai_socktype, (*value)->ai_protocol, (unsigned int)((*value)->ai_addrlen), (*value)->ai_canonname);
    if (length > 0)
    {
        result = (char*)my_gballoc_malloc(strlen(temp_buffer) + 1);
        if (result != NULL)
        {
            (void)memcpy(result, temp_buffer, strlen(temp_buffer) + 1);
        }
    }

    return result;
}

int umocktypes_are_equal_const_ADDRINFOA_ptr(const ADDRINFOA** left, const ADDRINFOA** right)
{
    int result = 1;
    if (((*left)->ai_flags != (*right)->ai_flags) ||
        ((*left)->ai_family != (*right)->ai_family) ||
        ((*left)->ai_socktype != (*right)->ai_socktype) ||
        ((*left)->ai_protocol != (*right)->ai_protocol) ||
        ((((*left)->ai_canonname == NULL) || ((*right)->ai_canonname == NULL)) && ((*left)->ai_canonname != (*right)->ai_canonname)) ||
        (((*left)->ai_canonname != NULL && (*right)->ai_canonname != NULL) && (strcmp((*left)->ai_canonname, (*right)->ai_canonname) != 0)))
    {
        result = 0;
    }
    return result;
}

int umocktypes_copy_const_ADDRINFOA_ptr(ADDRINFOA** destination, const ADDRINFOA** source)
{
    int result;
    *destination = (ADDRINFOA*)my_gballoc_malloc(sizeof(ADDRINFOA));
    if (*destination == NULL)
    {
        result = __LINE__;
    }
    else
    {
        if (*source != NULL)
        {
            (*destination)->ai_flags = (*source)->ai_flags;
            (*destination)->ai_family = (*source)->ai_family;
            (*destination)->ai_socktype = (*source)->ai_socktype;
            (*destination)->ai_protocol = (*source)->ai_protocol;
            (*destination)->ai_canonname = (*source)->ai_canonname;
        }
        else
        {
            memset(*destination, 0, sizeof(ADDRINFOA));
        }
        result = 0;
    }

    return result;
}

void umocktypes_free_const_ADDRINFOA_ptr(ADDRINFOA** value)
{
    my_gballoc_free(*value);
}

char* umocktypes_stringify_const_struct_sockaddr_ptr(const struct sockaddr** value)
{
    char* result = NULL;
    char temp_buffer[256];
    int length;

    length = sprintf(temp_buffer, "{ sa_family = %u, sa_data = ... }", (unsigned int)((*value)->sa_family));
    if (length > 0)
    {
        result = (char*)my_gballoc_malloc(strlen(temp_buffer) + 1);
        if (result != NULL)
        {
            (void)memcpy(result, temp_buffer, strlen(temp_buffer) + 1);
        }
    }

    return result;
}

int umocktypes_are_equal_const_struct_sockaddr_ptr(const struct sockaddr** left, const struct sockaddr** right)
{
    int result = 1;
    if (((*left)->sa_family != (*left)->sa_family) ||
        (memcmp((*left)->sa_data, (*right)->sa_data, sizeof((*left)->sa_data) != 0)))
    {
        result = 0;
    }

    return result;
}

int umocktypes_copy_const_struct_sockaddr_ptr(struct sockaddr** destination, const struct sockaddr** source)
{
    int result;

    *destination = (struct sockaddr*)my_gballoc_malloc(sizeof(struct sockaddr));
    if (*destination == NULL)
    {
        result = MU_FAILURE;
    }
    else
    {
        (*destination)->sa_family = (*source)->sa_family;
        (void)memcpy((*destination)->sa_data, (*source)->sa_data, sizeof((*source)->sa_data));

        result = 0;
    }

    return result;
}

static void umocktypes_free_const_struct_sockaddr_ptr(struct sockaddr** value)
{
    my_gballoc_free(*value);
}

#ifdef __cplusplus
}
#endif

static int my_gballoc_socket_getaddrinfo(const char* node, const char* svc_name, const struct addrinfo* hints, struct addrinfo** res)
{
    (void)node;
    (void)svc_name;
    (void)hints;
    //g_addr_info.ai_addr = &g_connect_addr;
    *res = (PADDRINFOA)my_gballoc_malloc(sizeof(ADDRINFOA));
    memcpy(*res, &TEST_ADDR_INFO, sizeof(ADDRINFOA));
    return 0;
}

static void my_gballoc_socket_freeaddrinfo(PADDRINFOA result)
{
    my_gballoc_free(result);
}

MU_DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)
static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    ASSERT_FAIL("umock_c reported error :%" PRI_MU_ENUM "", MU_ENUM_VALUE(UMOCK_C_ERROR_CODE, error_code));
}

BEGIN_TEST_SUITE(socket_handle_win32_ut)

TEST_SUITE_INITIALIZE(suite_init)
{
    g_testByTest = TEST_MUTEX_CREATE();
    ASSERT_IS_NOT_NULL(g_testByTest);

    umock_c_init(on_umock_c_error);

    ASSERT_ARE_EQUAL(int, 0, umocktypes_charptr_register_types());
    ASSERT_ARE_EQUAL(int, 0, umocktypes_stdint_register_types());

    REGISTER_UMOCK_ALIAS_TYPE(DWORD, unsigned long);
    REGISTER_UMOCK_ALIAS_TYPE(LPVOID, void*);
    REGISTER_UMOCK_ALIAS_TYPE(LPDWORD, void*);
    REGISTER_UMOCK_ALIAS_TYPE(WORD, unsigned short);
    REGISTER_UMOCK_ALIAS_TYPE(SOCKET, void*);
    REGISTER_UMOCK_ALIAS_TYPE(PCSTR, char*);
    REGISTER_UMOCK_ALIAS_TYPE(socklen_t, int);
    REGISTER_TYPE(const ADDRINFOA*, const_ADDRINFOA_ptr);
    REGISTER_UMOCK_ALIAS_TYPE(PADDRINFOA, const ADDRINFOA*);

    REGISTER_UMOCK_ALIAS_TYPE(SOCKET_OPEN_RESULT, int);
    REGISTER_UMOCK_ALIAS_TYPE(SOCKET_SEND_RESULT, int);
    REGISTER_UMOCK_ALIAS_TYPE(SOCKET_ERROR_RESULT, int);


    // REGISTER_UMOCK_ALIAS_TYPE(WORD, short);
    // REGISTER_UMOCK_ALIAS_TYPE(LPWSADATA, void *);

    REGISTER_GLOBAL_MOCK_HOOK(gballoc_ll_malloc, my_gballoc_malloc);
    REGISTER_GLOBAL_MOCK_HOOK(gballoc_ll_free, my_gballoc_free);
    REGISTER_GLOBAL_MOCK_HOOK(gballoc_socket_getaddrinfo, my_gballoc_socket_getaddrinfo);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(gballoc_socket_getaddrinfo, __LINE__);
    REGISTER_GLOBAL_MOCK_HOOK(gballoc_socket_freeaddrinfo, my_gballoc_socket_freeaddrinfo);

    REGISTER_GLOBAL_MOCK_RETURNS(gballoc_socket_connect, 0, __LINE__);
    REGISTER_GLOBAL_MOCK_RETURNS(gballoc_socket_ioctlsocket, 0, __LINE__);

    TEST_ADDR_INFO.ai_next = NULL;
    TEST_ADDR_INFO.ai_family = AF_INET;
    TEST_ADDR_INFO.ai_socktype = SOCK_STREAM;
    TEST_ADDR_INFO.ai_addr = (struct sockaddr*)(&g_connect_addr);
    ((struct sockaddr_in*)TEST_ADDR_INFO.ai_addr)->sin_addr.s_addr = FAKE_GOOD_IP_ADDR;
}

TEST_SUITE_CLEANUP(suite_cleanup)
{
    umock_c_deinit();

    TEST_MUTEX_DESTROY(g_testByTest);
}

TEST_FUNCTION_INITIALIZE(TestMethodInitialize)
{
    if (TEST_MUTEX_ACQUIRE(g_testByTest))
    {
        ASSERT_FAIL("our mutex is ABANDONED. Failure in test framework");
    }
    umock_c_reset_all_calls();
}

TEST_FUNCTION_CLEANUP(TestMethodCleanup)
{
    TEST_MUTEX_RELEASE(g_testByTest);
}

static void setup_socket_open_mocks(void)
{
    STRICT_EXPECTED_CALL(getaddrinfo(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG, IGNORED_ARG));
    STRICT_EXPECTED_CALL(connect(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG));
    STRICT_EXPECTED_CALL(ioctlsocket(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG));
    STRICT_EXPECTED_CALL(test_on_open_complete(TEST_USER_CONTEXT, SOCKET_OPEN_OK));
    STRICT_EXPECTED_CALL(freeaddrinfo(IGNORED_ARG));
}

/*TEST_FUNCTION(comm_impl_get_socket_interface_success)
{
    //arrange

    //act
    const COMM_INTERFACE_DESCRIPTION* interface_desc = comm_impl_get_socket_interface();

    //assert
    ASSERT_IS_NOT_NULL(interface_desc);
    ASSERT_IS_NOT_NULL(interface_desc->interface_impl_create);
    ASSERT_IS_NOT_NULL(interface_desc->interface_impl_destroy);
    ASSERT_IS_NOT_NULL(interface_desc->interface_impl_open);
    ASSERT_IS_NOT_NULL(interface_desc->interface_impl_close);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

TEST_FUNCTION(socket_handle_create_success)
{
    //arrange
    const COMM_INTERFACE_DESCRIPTION* interface_desc = comm_impl_get_socket_interface();
    SOCKET_COMM_CONFIG config = { 0 };
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;

    COMM_CALLBACK_INFO callback_info = { test_on_bytes_recv, TEST_USER_CONTEXT, test_on_error, TEST_USER_CONTEXT, };

    STRICT_EXPECTED_CALL(malloc(IGNORED_ARG));
    STRICT_EXPECTED_CALL(malloc(IGNORED_ARG));

    //act
    COMM_HANDLE handle = interface_desc->interface_impl_create(&config, &callback_info);

    //assert
    ASSERT_IS_NOT_NULL(handle);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    interface_desc->interface_impl_destroy(handle);
}

TEST_FUNCTION(socket_handle_create_fail)
{
    //arrange
    const COMM_INTERFACE_DESCRIPTION* interface_desc = comm_impl_get_socket_interface();
    SOCKET_COMM_CONFIG config = { 0 };
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;

    COMM_CALLBACK_INFO callback_info = { test_on_bytes_recv, TEST_USER_CONTEXT, test_on_error, TEST_USER_CONTEXT, };

    int negativeTestsInitResult = umock_c_negative_tests_init();
    ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    STRICT_EXPECTED_CALL(malloc(IGNORED_ARG));
    STRICT_EXPECTED_CALL(malloc(IGNORED_ARG));

    umock_c_negative_tests_snapshot();

    size_t count = umock_c_negative_tests_call_count();
    for (size_t index = 0; index < count; index++)
    {
        if (umock_c_negative_tests_can_call_fail(index))
        {
            umock_c_negative_tests_reset();
            umock_c_negative_tests_fail_call(index);

            //act
            COMM_HANDLE handle = interface_desc->interface_impl_create(&config, &callback_info);

            //assert
            ASSERT_IS_NULL(handle);
        }
    }
    // cleanup
    umock_c_negative_tests_deinit();
}

TEST_FUNCTION(socket_handle_destroy_success)
{
    //arrange
    const COMM_INTERFACE_DESCRIPTION* interface_desc = comm_impl_get_socket_interface();
    SOCKET_COMM_CONFIG config = { 0 };
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;

    COMM_CALLBACK_INFO callback_info = { test_on_bytes_recv, TEST_USER_CONTEXT, test_on_error, TEST_USER_CONTEXT, };
    COMM_HANDLE handle = interface_desc->interface_impl_create(&config, &callback_info);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(free(IGNORED_ARG));
    STRICT_EXPECTED_CALL(free(IGNORED_ARG));

    //act
    interface_desc->interface_impl_destroy(handle);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

TEST_FUNCTION(socket_handle_destroy_handle_NULL_success)
{
    //arrange
    const COMM_INTERFACE_DESCRIPTION* interface_desc = comm_impl_get_socket_interface();

    //act
    interface_desc->interface_impl_destroy(NULL);

    //assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

TEST_FUNCTION(socket_handle_open_success)
{
    //arrange
    const COMM_INTERFACE_DESCRIPTION* interface_desc = comm_impl_get_socket_interface();
    SOCKET_COMM_CONFIG config = { 0 };
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;

    COMM_CALLBACK_INFO callback_info = { test_on_bytes_recv, TEST_USER_CONTEXT, test_on_error, TEST_USER_CONTEXT, };
    COMM_HANDLE handle = interface_desc->interface_impl_create(&config, &callback_info);
    umock_c_reset_all_calls();

    setup_socket_open_mocks();

    //act
    int result = interface_desc->interface_impl_open(handle, test_on_open_complete, TEST_USER_CONTEXT);

    //assert
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    interface_desc->interface_impl_close(handle, NULL, NULL);
    interface_desc->interface_impl_destroy(handle);
}

TEST_FUNCTION(socket_handle_open_invalid_state_fail)
{
    //arrange
    const COMM_INTERFACE_DESCRIPTION* interface_desc = comm_impl_get_socket_interface();
    SOCKET_COMM_CONFIG config = { 0 };
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;

    COMM_CALLBACK_INFO callback_info = { test_on_bytes_recv, TEST_USER_CONTEXT, test_on_error, TEST_USER_CONTEXT, };
    COMM_HANDLE handle = interface_desc->interface_impl_create(&config, &callback_info);
    (void)interface_desc->interface_impl_open(handle, test_on_open_complete, TEST_USER_CONTEXT);
    umock_c_reset_all_calls();

    //act
    int result = interface_desc->interface_impl_open(handle, test_on_open_complete, TEST_USER_CONTEXT);

    //assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    interface_desc->interface_impl_close(handle, NULL, NULL);
    interface_desc->interface_impl_destroy(handle);
}

TEST_FUNCTION(socket_handle_open_fail)
{
    //arrange
    const COMM_INTERFACE_DESCRIPTION* interface_desc = comm_impl_get_socket_interface();
    SOCKET_COMM_CONFIG config = { 0 };
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;

    COMM_CALLBACK_INFO callback_info = { test_on_bytes_recv, TEST_USER_CONTEXT, test_on_error, TEST_USER_CONTEXT, };
    COMM_HANDLE handle = interface_desc->interface_impl_create(&config, &callback_info);
    umock_c_reset_all_calls();

    int negativeTestsInitResult = umock_c_negative_tests_init();
    ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    setup_socket_open_mocks();

    umock_c_negative_tests_snapshot();

    size_t count = umock_c_negative_tests_call_count();
    for (size_t index = 0; index < count; index++)
    {
        if (umock_c_negative_tests_can_call_fail(index))
        {
            umock_c_negative_tests_reset();
            umock_c_negative_tests_fail_call(index);

            //act
            int result = interface_desc->interface_impl_open(handle, test_on_open_complete, TEST_USER_CONTEXT);

            //assert
            ASSERT_ARE_NOT_EQUAL(int, 0, result, "Failure in test iteration %zu of %zu", index, count);
        }
    }

    // cleanup
    interface_desc->interface_impl_close(handle, NULL, NULL);
    interface_desc->interface_impl_destroy(handle);
    umock_c_negative_tests_deinit();
}

TEST_FUNCTION(socket_handle_close_success)
{
    //arrange
    const COMM_INTERFACE_DESCRIPTION* interface_desc = comm_impl_get_socket_interface();
    SOCKET_COMM_CONFIG config = { 0 };
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;

    COMM_CALLBACK_INFO callback_info = { test_on_bytes_recv, TEST_USER_CONTEXT, test_on_error, TEST_USER_CONTEXT, };
    COMM_HANDLE handle = interface_desc->interface_impl_create(&config, &callback_info);
    (void)interface_desc->interface_impl_open(handle, test_on_open_complete, TEST_USER_CONTEXT);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(shutdown(IGNORED_ARG, IGNORED_ARG));
    STRICT_EXPECTED_CALL(closesocket(IGNORED_ARG));
    STRICT_EXPECTED_CALL(test_on_close_complete(TEST_USER_CONTEXT));

    //act
    int result = interface_desc->interface_impl_close(handle, test_on_close_complete, TEST_USER_CONTEXT);

    //assert
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    interface_desc->interface_impl_destroy(handle);
}

TEST_FUNCTION(socket_handle_close_handle_NULL_fail)
{
    //arrange
    const COMM_INTERFACE_DESCRIPTION* interface_desc = comm_impl_get_socket_interface();

    //act
    int result = interface_desc->interface_impl_close(NULL, test_on_close_complete, TEST_USER_CONTEXT);

    //assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}*/

END_TEST_SUITE(socket_handle_win32_ut)
