#Copyright (c) Microsoft. All rights reserved.
#Licensed under the MIT license. See LICENSE file in the project root for full license information.

cmake_minimum_required(VERSION 2.8.11)

# canon way of using c-pal from another repo is below. It assumes the using repo has placed c-pal in "deps"

#if ((NOT TARGET c_pal) AND (EXISTS ${CMAKE_CURRENT_LIST_DIR}/deps/c-pal/CMakeLists.txt))
#    add_subdirectory(deps/c-pal)
#    include_directories(${C_PAL_INC_FOLDER})
#endif() 

if (TARGET c_pal)
    RETURN()
endif()

project(c_pal)

#the following variables are project-wide and can be used with cmake-gui
option(run_unittests "set run_unittests to ON to run unittests (default is OFF)" OFF)
option(run_e2e_tests "set run_e2e_tests to ON to run e2e tests (default is OFF). Chsare dutility does not have any e2e tests, but the option needs to exist to evaluate in IF statements" OFF)
option(run_int_tests "set run_int_tests to ON to integration tests (default is OFF)." OFF)
option(use_cppunittest "set use_cppunittest to ON to build CppUnitTest tests on Windows (default is ON)" ON)
option(run_traceability "run traceability tool (default is ON)" ON)

#canon way of limiting an option to a predefined set of values
set(GBALLOC_LL_TYPE_VALUES PASSTHROUGH WIN32HEAP MIMALLOC JEMALLOC) #the list of values which are allowed
set(GBALLOC_LL_TYPE PASSTHROUGH CACHE STRING "Value of GBALLOC_LL_TYPE") #setting the property's default value in case none is taken from the command line
set_property(CACHE GBALLOC_LL_TYPE PROPERTY STRINGS ${GBALLOC_LL_TYPE_VALUES}) #build a property that can have only the allowed values


list(FIND GBALLOC_LL_TYPE_VALUES ${GBALLOC_LL_TYPE} index) #check that the received value (either the default or the one from command line) matches one of the allowed values.
if(index EQUAL -1)
    message(FATAL_ERROR "GBALLOC_LL_TYPE must be one of '${GBALLOC_LL_TYPE_VALUES}'. It was actually '${GBALLOC_LL_TYPE}'")
endif()

#canon way of limiting an option to a predefined set of values
set(GBALLOC_HL_TYPE_VALUES PASSTHROUGH METRICS) #the list of values which are allowed
set(GBALLOC_HL_TYPE PASSTHROUGH CACHE STRING "Value of GBALLOC_HL_TYPE") #build a property that can have only the allowed values
set_property(CACHE GBALLOC_HL_TYPE PROPERTY STRINGS ${GBALLOC_HL_TYPE_VALUES}) #setting the property's default value in case none is taken from the command line

list(FIND GBALLOC_HL_TYPE_VALUES ${GBALLOC_HL_TYPE} index) #check that the received value (either the default or the one from command line) matches one of the allowed values.
if(index EQUAL -1)
    message(FATAL_ERROR "GBALLOC_HL_TYPE must be one of '${GBALLOC_HL_TYPE_VALUES}'. It was actually '${GBALLOC_HL_TYPE}'")
endif()

#bring in dependencies
#do not add or build any tests of the dependencies
set(original_run_e2e_tests ${run_e2e_tests})
set(original_run_unittests ${run_unittests})
set(original_run_int_tests ${run_int_tests})
set(original_run_traceability ${run_traceability})
set(original_run_perf_tests ${run_perf_tests})

set(run_e2e_tests OFF)
set(run_unittests OFF)
set(run_int_tests OFF)
set(run_traceability OFF)
set(run_perf_tests OFF)


if ((NOT TARGET c_build_tools) AND (EXISTS ${CMAKE_CURRENT_LIST_DIR}/deps/c-build-tools/CMakeLists.txt))
    add_subdirectory(deps/c-build-tools)
    set_default_build_options()
endif() 

if ((NOT TARGET macro_utils_c) AND (EXISTS ${CMAKE_CURRENT_LIST_DIR}/deps/macro-utils-c/CMakeLists.txt))
    add_subdirectory(deps/macro-utils-c)
    include_directories(${MACRO_UTILS_INC_FOLDER})
endif() 

if ((NOT TARGET c_logging) AND (EXISTS ${CMAKE_CURRENT_LIST_DIR}/deps/c-logging/CMakeLists.txt))
    add_subdirectory(deps/c-logging)
    include_directories(deps/c-logging/inc)
endif() 

if ((NOT TARGET ctest) AND (EXISTS ${CMAKE_CURRENT_LIST_DIR}/deps/ctest/CMakeLists.txt))
    add_subdirectory(deps/ctest)
    include_directories(${CTEST_INC_FOLDER})
endif() 

if ((NOT TARGET testrunnerswitcher) AND (EXISTS ${CMAKE_CURRENT_LIST_DIR}/deps/c-testrunnerswitcher/CMakeLists.txt))
    add_subdirectory(deps/c-testrunnerswitcher)
    include_directories(${TESTRUNNERSWITCHER_INC_FOLDER})
endif() 

if ((NOT TARGET umock_c) AND (EXISTS ${CMAKE_CURRENT_LIST_DIR}/deps/umock-c/CMakeLists.txt))
    add_subdirectory(deps/umock-c)
    include_directories(${UMOCK_C_INC_FOLDER})
endif() 

if (
    (NOT TARGET mimalloc-obj) AND 
    (EXISTS ${CMAKE_CURRENT_LIST_DIR}/deps/mimalloc/CMakeLists.txt)
    )
        set(MI_BUILD_SHARED OFF CACHE BOOL "Build shared library" FORCE) #not building a dll allows building on 32 bit, otherwise there's some errors on init.c about not finding a imported symbol
        set(MI_BUILD_TESTS OFF CACHE BOOL "Build test executables" FORCE) 
        #for mimalloc disable this warning: Warning C4459: declaration of 'os_page_size' hides global declaration
        #for mimalloc disable this warning: Warning C4100: 'try_alignment': unreferenced formal parameter
        #for mimalloc disable this warning: warning C4505: 'mi_os_get_aligned_hint': unreferenced local function has been removed

        set(PREV_CMAKE_C_FLAGS ${CMAKE_C_FLAGS})
        set(PREV_CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS})
        if(WIN32)
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4459 /wd4100 /wd4505")
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd4459 /wd4100 /wd4505")
        endif()

        add_subdirectory(deps/mimalloc)
        include_directories(deps/mimalloc/include)
        
        set(CMAKE_C_FLAGS ${PREV_CMAKE_C_FLAGS})
        set(CMAKE_CXX_FLAGS ${PREV_CMAKE_CXX_FLAGS})
endif()

if (
    (WIN32) AND
    (NOT TARGET jemalloc) AND 
    (EXISTS ${CMAKE_CURRENT_LIST_DIR}/deps/jemalloc/README)
    )
    set(PREV_CMAKE_C_FLAGS ${CMAKE_C_FLAGS})
    set(PREV_CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS})
    set(PREV_CMAKE_STATIC_LINKER_FLAGS ${CMAKE_STATIC_LINKER_FLAGS})

    if(WIN32)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4100 /wd4127 /wd4459 /wd4201 /wd4456 /wd4457 /wd4702 /wd4244 /wd4701 /wd4706 /wd4703 /wd4189 /wd4267 /wd4204 /wd4565 /wd4310 /wd4334 /wd4028 /DJEMALLOC_NO_PRIVATE_NAMESPACE /D_REENTRANT /DJEMALLOC_EXPORT= /D_LIB")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd4100 /wd4127 /wd4459 /wd4201 /wd4456 /wd4457 /wd4702 /wd4244 /wd4701 /wd4706 /wd4703 /wd4189 /wd4267 /wd4204 /wd4565 /wd4310 /wd4334 /wd4028 /DJEMALLOC_NO_PRIVATE_NAMESPACE /D_REENTRANT /DJEMALLOC_EXPORT= /D_LIB")
        set(CMAKE_STATIC_LINKER_FLAGS "${CMAKE_STATIC_LINKER_FLAGS} /IGNORE:4221")
    endif()

    add_subdirectory(jemalloc_build)

    set(CMAKE_C_FLAGS ${PREV_CMAKE_C_FLAGS})
    set(CMAKE_CXX_FLAGS ${PREV_CMAKE_CXX_FLAGS})
    set(CMAKE_STATIC_LINKER_FLAGS ${PREV_CMAKE_STATIC_LINKER_FLAGS})

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /DJEMALLOC_NO_PRIVATE_NAMESPACE /D_REENTRANT /DJEMALLOC_EXPORT= /D_LIB")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /DJEMALLOC_NO_PRIVATE_NAMESPACE /D_REENTRANT /DJEMALLOC_EXPORT= /D_LIB")

endif()

set(run_e2e_tests ${original_run_e2e_tests})
set(run_unittests ${original_run_unittests})
set(run_int_tests ${original_run_int_tests})
set(run_traceability ${original_run_traceability})
set(run_perf_tests ${original_run_perf_tests})


include(CTest)
enable_testing()

set(C_PAL_INC_FOLDER 
    ${CMAKE_CURRENT_LIST_DIR}/interfaces/inc
    ${CMAKE_CURRENT_LIST_DIR}/common/inc
    CACHE INTERNAL "this is what needs to be included if using c_pal" FORCE)

add_subdirectory(interfaces)
add_subdirectory(common)

if(WIN32)
    add_subdirectory(win32)
else()
    add_subdirectory(linux)
endif()

add_library(c_pal INTERFACE)

FILE(GLOB c_pal_md_files "doc/*.md")
SOURCE_GROUP(devdoc FILES ${c_pal_md_files})

if(MSVC)
    target_link_libraries(c_pal INTERFACE pal_win32)
else()
    target_link_libraries(c_pal INTERFACE pal_linux)
endif()


if((WIN32) AND (${run_traceability}))
    #add traceability custom target
    add_custom_target(c_pal_traceability ALL
        COMMAND traceabilitytool -buildcheck -e ${CMAKE_CURRENT_LIST_DIR}/deps -i ${CMAKE_CURRENT_LIST_DIR})
    add_dependencies(c_pal_traceability traceabilitytool)
endif()

add_library(c_pal_reals INTERFACE)
if(MSVC)
    target_link_libraries(c_pal_reals INTERFACE win32_reals)
else()
    target_link_libraries(c_pal_reals INTERFACE linux_reals)
endif()

include(CMakePackageConfigHelpers)

