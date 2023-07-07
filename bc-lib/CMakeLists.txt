#
# Directories
#
set(BCLIB_SOURCES_ROOT				                ${BCLIB_LIB_ROOT}/src)
set(BCLIB_INCLUDE_ROOT				                ${BCLIB_LIB_ROOT}/include)

set(BCLIB_INCLUDE_DIRECTORIES		                ${BCLIB_INCLUDE_ROOT}
													${GALOISLIB_INCLUDE})
													
#
# Implementation directories
#
set(BCLIB_CIPHERS_SOURCES_DIR                       ${BCLIB_SOURCES_ROOT}/ciphers)
set(BCLIB_CIPHERS_INCLUDE_DIR                       ${BCLIB_INCLUDE_ROOT}/ciphers)
set(BCLIB_COMMON_INCLUDE_DIR                        ${BCLIB_INCLUDE_ROOT}/common)

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
target_include_directories(bc-lib PRIVATE           ${BCLIB_INCLUDE_DIRECTORIES})

if (BCLIB_BUILD_KERNEL_LIB)
	target_include_directories(bc-lib-km PRIVATE    ${BCLIB_INCLUDE_DIRECTORIES})
endif (BCLIB_BUILD_KERNEL_LIB)


#
# Link with dependencies
#
target_link_libraries(bc-lib PRIVATE                galois-lib) 

if (BCLIB_BUILD_KERNEL_LIB)
    target_link_libraries(bc-lib-km PRIVATE         galois-lib-km)
endif (BCLIB_BUILD_KERNEL_LIB)
