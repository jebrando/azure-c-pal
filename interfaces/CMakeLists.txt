#Copyright (C) Microsoft Corporation. All rights reserved.

set(pal_interfaces_h_files
    ${PROJECT_SOURCE_DIR}/interfaces/inc/azure_c_pal/async_socket.h
    ${PROJECT_SOURCE_DIR}/interfaces/inc/azure_c_pal/execution_engine.h
    ${PROJECT_SOURCE_DIR}/interfaces/inc/azure_c_pal/file.h
    ${PROJECT_SOURCE_DIR}/interfaces/inc/azure_c_pal/gballoc_hl_redirect.h
    ${PROJECT_SOURCE_DIR}/interfaces/inc/azure_c_pal/gballoc_hl.h
    ${PROJECT_SOURCE_DIR}/interfaces/inc/azure_c_pal/gballoc_ll_redirect.h
    ${PROJECT_SOURCE_DIR}/interfaces/inc/azure_c_pal/gballoc_ll.h
    ${PROJECT_SOURCE_DIR}/interfaces/inc/azure_c_pal/gballoc_socket.h
    ${PROJECT_SOURCE_DIR}/interfaces/inc/azure_c_pal/gballoc_socket_redirect.h
    ${PROJECT_SOURCE_DIR}/interfaces/inc/azure_c_pal/interlocked.h
    ${PROJECT_SOURCE_DIR}/interfaces/inc/azure_c_pal/platform.h
    ${PROJECT_SOURCE_DIR}/interfaces/inc/azure_c_pal/socket_handle.h
    ${PROJECT_SOURCE_DIR}/interfaces/inc/azure_c_pal/socket_objects.h
    ${PROJECT_SOURCE_DIR}/interfaces/inc/azure_c_pal/srw_lock.h
    ${PROJECT_SOURCE_DIR}/interfaces/inc/azure_c_pal/sync.h
    ${PROJECT_SOURCE_DIR}/interfaces/inc/azure_c_pal/threadpool.h
    ${PROJECT_SOURCE_DIR}/interfaces/inc/azure_c_pal/threadapi.h
    ${PROJECT_SOURCE_DIR}/interfaces/inc/azure_c_pal/timer.h
    ${PROJECT_SOURCE_DIR}/interfaces/inc/azure_c_pal/tls_handle.h
    ${PROJECT_SOURCE_DIR}/interfaces/inc/azure_c_pal/uniqueid.h
)

FILE(GLOB pal_interfaces_md_files "devdoc/*.md")
SOURCE_GROUP(devdoc FILES ${pal_interfaces_md_files})

set(PAL_INTERFACES_INC_FOLDER ${CMAKE_CURRENT_LIST_DIR}/inc CACHE INTERNAL "this is what needs to be included if using the PAL interfaces" FORCE)

include_directories(${CMAKE_CURRENT_LIST_DIR}/inc)
include_directories(${MACRO_UTILS_INC_FOLDER})

add_library(pal_interfaces INTERFACE)
target_sources(pal_interfaces INTERFACE ${pal_interfaces_h_files})
target_include_directories(pal_interfaces INTERFACE ${CMAKE_CURRENT_LIST_DIR}/inc)

add_subdirectory(reals)

add_subdirectory(tests)
