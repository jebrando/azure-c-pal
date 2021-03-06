#Copyright (c) Microsoft. All rights reserved.
#Licensed under the MIT license. See LICENSE file in the project root for full license information.

cmake_minimum_required(VERSION 2.8.11)


set(reals_win32_c_files
    real_call_once.c
    real_lazy_init.c
    real_sync.c
    real_threadapi.c
    real_srw_lock_win32.c
    real_string_utils_win32.c
    real_timer_win32.c
    real_interlocked.c
    real_gballoc_ll_${gballoc_ll_type_lower}.c
    real_gballoc_hl_${gballoc_hl_type_lower}.c
)

set(reals_win32_h_files
    real_call_once.h
    real_call_once_renames.h
    real_interlocked.h
    real_interlocked_renames.h
    real_lazy_init.h
    real_lazy_init_renames.h
)

add_library(win32_reals ${reals_win32_c_files} ${reals_win32_h_files})
target_include_directories(win32_reals PUBLIC . ${CMAKE_CURRENT_LIST_DIR}/../src "$<TARGET_PROPERTY:pal_win32,INTERFACE_INCLUDE_DIRECTORIES>")
target_link_libraries(win32_reals pal_interfaces_reals synchronization)

if(${GBALLOC_LL_TYPE} STREQUAL "MIMALLOC")
    target_link_libraries(win32_reals mimalloc-obj)
endif()
if(${GBALLOC_LL_TYPE} STREQUAL "JEMALLOC")
    target_link_libraries(win32_reals jemalloc)
endif()
