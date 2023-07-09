cmake_minimum_required(VERSION 3.0.0)
project(bc-lib VERSION 1.0.0)

#
# Global config
#
set(CMAKE_CXX_STANDARD                                  17)
set(CMAKE_CXX_STANDARD_REQUIRED                         True)

#
# Options
#
option(BCLIB_KERNEL_MODE                                "Build bc-lib for kernel mode too (Windows only)."                      OFF)
option(BCLIB_GENERATE_DOCS                              "Generate documentation for bc-lib."                                    OFF)
option(BCLIB_DOCS_ONLY                                  "Generate documentation only (bc-lib binaries will not be built)."      OFF)
option(BCLIB_GITHUB_DOCS                                "Generate documentation for GitHub."                                    OFF)
option(BCLIB_PRETTY_DOCS                                "Use graphwiz for diagrams."                                            OFF)
option(BCLIB_ENABLE_TESTING                             "Enable testing of ciphers, modes of operation and other functions."    ON)

#
# Configuration
#
if (WIN32)
    set(BCLIB_WINDOWS_BUILD                             ON)
else (WIN32)
    set(BCLIB_WINDOWS_BUILD                             OFF)
endif (WIN32)

if (BCLIB_GENERATE_DOCS AND BCLIB_DOCS_ONLY)

    #
    # Building docs only
    #

    set(BCLIB_BUILD_LIB                                 OFF)
    set(BCLIB_BUILD_TESTS                               OFF)
    set(BCLIB_BUILD_DOCS                                ON)
    set(BCLIB_BUILD_GITHUB_DOCS                         ${BCLIB_GITHUB_DOCS})
    set(BCLIB_BUILD_PRETTY_DOCS                         ${BCLIB_PRETTY_DOCS})

    #
    # Just set this to OFF, because no binary is built
    #
    set(BCLIB_BUILD_KERNEL_LIB                          OFF)

else (BCLIB_GENERATE_DOCS AND BCLIB_DOCS_ONLY)

    #
    # Here I assume other flags, but library 
    # will be built always here.
    #

    set(BCLIB_BUILD_LIB                                 ON)
    set(BCLIB_BUILD_TESTS                               ${BCLIB_ENABLE_TESTING})
    set(BCLIB_BUILD_DOCS                                ${BCLIB_GENERATE_DOCS})
    set(BCLIB_BUILD_GITHUB_DOCS                         ${BCLIB_GITHUB_DOCS})
    set(BCLIB_BUILD_PRETTY_DOCS                         ${BCLIB_PRETTY_DOCS})

    #
    # Kernel mode library is supporten on Windows only
    #
    if (BCLIB_WINDOWS_BUILD)

        set(BCLIB_BUILD_KERNEL_LIB                      ${BCLIB_KERNEL_MODE})
        
    else (BCLIB_WINDOWS_BUILD)

        message(STATUS "[${PROJECT_NAME}]: Non-Windows version, BCLIB_BUILD_KERNEL_LIB will be set to OFF.")
        set(BCLIB_BUILD_KERNEL_LIB                      OFF)

    endif (BCLIB_WINDOWS_BUILD)

endif (BCLIB_GENERATE_DOCS AND BCLIB_DOCS_ONLY)

message("[${PROJECT_NAME}]: BCLIB_WINDOWS_BUILD     = ${BCLIB_WINDOWS_BUILD}")
message("[${PROJECT_NAME}]: BCLIB_BUILD_LIB         = ${BCLIB_BUILD_LIB}")
message("[${PROJECT_NAME}]: BCLIB_BUILD_KERNEL_LIB  = ${BCLIB_BUILD_KERNEL_LIB}")
message("[${PROJECT_NAME}]: BCLIB_BUILD_TESTS       = ${BCLIB_BUILD_TESTS}")
message("[${PROJECT_NAME}]: BCLIB_BUILD_DOCS        = ${BCLIB_BUILD_DOCS}")
message("[${PROJECT_NAME}]: BCLIB_BUILD_GITHUB_DOCS = ${BCLIB_BUILD_GITHUB_DOCS}")
message("[${PROJECT_NAME}]: BCLIB_BUILD_PRETTY_DOCS = ${BCLIB_BUILD_PRETTY_DOCS}")

#
# Just sanity check if we are going well
#
if (NOT BCLIB_BUILD_LIB AND BCLIB_BUILD_TESTS)
    message(FATAL_ERROR "[${PROJECT_NAME}]: cannot build tests without building bc-lib itself")
endif (NOT BCLIB_BUILD_LIB AND BCLIB_BUILD_TESTS)

#
# Configure dependencies:
# - propagate kernel lib building flag
# - disable documentation generation
#
include(FetchContent)

FetchContent_Declare(
    galois-lib
    GIT_REPOSITORY https://github.com/GeorgyFirsov/galois-lib.git
    GIT_TAG        v1.0.3
    CMAKE_ARGS     -DGALOISLIB_GENERATE_DOCS=OFF
                   -DGALOISLIB_KERNEL_MODE=${BCLIB_BUILD_KERNEL_LIB}
)

FetchContent_MakeAvailable(galois-lib)

#
# Set global directories
#
set(BCLIB_ROOT		                                    ${CMAKE_CURRENT_LIST_DIR})
set(BCLIB_SOURCES_ROOT				                    ${BCLIB_ROOT}/src)
set(BCLIB_INCLUDE_ROOT				                    ${BCLIB_ROOT}/include)
set(BCLIB_INCLUDE_DIRECTORIES		                    ${BCLIB_INCLUDE_ROOT})

#
# Set output directories for all targets
#
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY                      ${CMAKE_BINARY_DIR}/out)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY                      ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY                      ${CMAKE_BINARY_DIR}/lib)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE              ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE              ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE              ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY})

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG                ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_DEBUG                ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_DEBUG                ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY})

#
# Now let's build targets according to the flags set before
#
if (BCLIB_BUILD_LIB)
    
    #
    # FindWDK module
    #
    list(APPEND CMAKE_MODULE_PATH	                    ${CMAKE_SOURCE_DIR}/third-party/FindWDK/cmake)
    
    #
    # Preprocessor definitions
    #
    add_compile_definitions(UNICODE)

    #
    # Implementation directories
    #
    set(BCLIB_CIPHERS_SOURCES_DIR                       ${BCLIB_SOURCES_ROOT}/ciphers)
    set(BCLIB_CIPHERS_INCLUDE_DIR                       ${BCLIB_INCLUDE_ROOT}/ciphers)
    set(BCLIB_COMMON_INCLUDE_DIR                        ${BCLIB_INCLUDE_ROOT}/common)

    set(BCLIB_INTERNAL_INCLUDE_DIRECTORIES              ${BCLIB_INCLUDE_DIRECTORIES}
                                                        ${galois-lib_SOURCE_DIR}/include)

    set(BCLIB_KUZNYECHIK_SOURCES_DIR                    ${BCLIB_CIPHERS_SOURCES_DIR}/kuznyechik)
    set(BCLIB_KUZNYECHIK_INCLUDE_DIR                    ${BCLIB_CIPHERS_INCLUDE_DIR}/kuznyechik)

    #
    # Source files
    #
    set(BCLIB_SOURCE_FILES			                    ${BCLIB_KUZNYECHIK_SOURCES_DIR}/kuznyechik.c)

    set(BCLIB_HEADER_FILES			                    ${BCLIB_COMMON_INCLUDE_DIR}/interface.h
                                                        ${BCLIB_COMMON_INCLUDE_DIR}/utils.h
                                                        ${BCLIB_KUZNYECHIK_INCLUDE_DIR}/kuznyechik.h)

    set(BCLIB_SOURCES				                    ${BCLIB_SOURCE_FILES}
                                                        ${BCLIB_HEADER_FILES})

    #
    # Library itself (may be built for user mode as 
    # well as for kernel mode)
    #
    add_library(bc-lib					                ${BCLIB_SOURCES})

    if (BCLIB_BUILD_KERNEL_LIB)
        message("[${PROJECT_NAME}]: Building additional target for kernel mode")

        find_package(WDK REQUIRED)
        wdk_add_library(bc-lib-km		                ${BCLIB_SOURCES})
    endif (BCLIB_BUILD_KERNEL_LIB)


    #
    # Include directories
    #
    target_include_directories(bc-lib PRIVATE           ${BCLIB_INTERNAL_INCLUDE_DIRECTORIES})

    if (BCLIB_BUILD_KERNEL_LIB)
        target_include_directories(bc-lib-km PRIVATE    ${BCLIB_INTERNAL_INCLUDE_DIRECTORIES})
    endif (BCLIB_BUILD_KERNEL_LIB)


    #
    # Link with dependencies
    #
    target_link_libraries(bc-lib PRIVATE                galois-lib) 

    if (BCLIB_BUILD_KERNEL_LIB)
        target_link_libraries(bc-lib-km PRIVATE         galois-lib-km)
    endif (BCLIB_BUILD_KERNEL_LIB)

endif (BCLIB_BUILD_LIB)

if (BCLIB_BUILD_TESTS)

    include(CTest)

    #
    # Tests target
    #
    add_subdirectory(tests)

endif (BCLIB_BUILD_TESTS)

if (BCLIB_BUILD_DOCS)

    #
    # Docs target
    #
    add_subdirectory(docs)

endif (BCLIB_BUILD_DOCS)
