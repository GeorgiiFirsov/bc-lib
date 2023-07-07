cmake_minimum_required(VERSION 3.0.0)
project(bc-lib VERSION 1.0.0)

#
# Global config
#
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

#
# Options
#
option(BCLIB_KERNEL_MODE                    "Build bc-lib for kernel mode too (Windows only)."                      OFF)
option(BCLIB_GENERATE_DOCS                  "Generate documentation for bc-lib."                                    OFF)
option(BCLIB_DOCS_ONLY                      "Generate documentation only (bc-lib binaries will not be built)."      OFF)
option(BCLIB_GITHUB_DOCS                    "Generate documentation for GitHub."                                    OFF)
option(BCLIB_PRETTY_DOCS                    "Use graphwiz for diagrams."                                            OFF)
option(BCLIB_ENABLE_TESTING                 "Enable testing of ciphers, modes of operation and other functions."    ON)

#
# Configuration
#
if (WIN32)
    set(BCLIB_WINDOWS_BUILD                 ON)
else (WIN32)
    set(BCLIB_WINDOWS_BUILD                 OFF)
endif (WIN32)

if (BCLIB_GENERATE_DOCS AND BCLIB_DOCS_ONLY)

    #
    # Building docs only
    #

    set(BCLIB_BUILD_LIB                     OFF)
    set(BCLIB_BUILD_TESTS                   OFF)
    set(BCLIB_BUILD_DOCS                    ON)
    set(BCLIB_BUILD_GITHUB_DOCS             ${BCLIB_GITHUB_DOCS})
    set(BCLIB_BUILD_PRETTY_DOCS             ${BCLIB_PRETTY_DOCS})

    #
    # Just set this to OFF, because no binary is built
    #
    set(BCLIB_BUILD_KERNEL_LIB              OFF)

else (BCLIB_GENERATE_DOCS AND BCLIB_DOCS_ONLY)

    #
    # Here I assume other flags, but library 
    # will be built always here.
    #

    set(BCLIB_BUILD_LIB                     ON)
    set(BCLIB_BUILD_TESTS                   ${BCLIB_ENABLE_TESTING})
    set(BCLIB_BUILD_DOCS                    ${BCLIB_GENERATE_DOCS})
    set(BCLIB_BUILD_GITHUB_DOCS             ${BCLIB_GITHUB_DOCS})
    set(BCLIB_BUILD_PRETTY_DOCS             ${BCLIB_PRETTY_DOCS})

    #
    # Kernel mode library is supporten on Windows only
    #
    if (BCLIB_WINDOWS_BUILD)

        set(BCLIB_BUILD_KERNEL_LIB          ${BCLIB_KERNEL_MODE})
        
    else (BCLIB_WINDOWS_BUILD)

        message(STATUS "[${PROJECT_NAME}]: Non-Windows version, BCLIB_BUILD_KERNEL_LIB will be set to OFF.")
        set(BCLIB_BUILD_KERNEL_LIB          OFF)

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
option(GALOISLIB_KERNEL_MODE ""             ${BCLIB_BUILD_KERNEL_LIB})
option(GALOISLIB_GENERATE_DOCS ""           OFF)

#
# Set global directories
#
set(BCLIB_ROOT		                        ${CMAKE_CURRENT_LIST_DIR})
set(BCLIB_LIB_ROOT	                        ${BCLIB_ROOT}/bc-lib)

if (PROJECT_IS_TOP_LEVEL)

    #
    # Suppress warning -- not writing PARENT_SCOPE
    #

    set(BCLIB_INCLUDE                       ${BCLIB_LIB_ROOT}/include)

else (PROJECT_IS_TOP_LEVEL)

    #
    # Share public variables with parent projects
    #

    set(BCLIB_INCLUDE                       ${BCLIB_LIB_ROOT}/include PARENT_SCOPE)

endif (PROJECT_IS_TOP_LEVEL)

#
# Set output directories for all targets
#
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY          ${CMAKE_BINARY_DIR}/out)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY          ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY          ${CMAKE_BINARY_DIR}/lib)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE  ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE  ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE  ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY})

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG    ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_DEBUG    ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_DEBUG    ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY})

#
# Now let's build targets according to the flags set before
#
if (BCLIB_BUILD_LIB)
    
    #
    # FindWDK module
    #
    list(APPEND CMAKE_MODULE_PATH	        ${CMAKE_SOURCE_DIR}/third-party/FindWDK/cmake)
    
    #
    # Preprocessor definitions
    #
    add_compile_definitions(UNICODE)
    
    #
    # Dependencies
    #
    add_subdirectory(galois-lib)

    #
    # Main library target
    #
    add_subdirectory(bc-lib)

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
