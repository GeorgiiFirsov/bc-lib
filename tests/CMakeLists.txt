#
# Find googletest library
#
find_package(GTest CONFIG REQUIRED)

#
# Directories
#
set(BCLIB_TESTS_ROOT				            ${BCLIB_ROOT}/tests)
set(BCLIB_TESTS_INCLUDE                         ${BCLIB_TESTS_ROOT}/include)
set(BCLIB_TESTS_CASES                           ${BCLIB_TESTS_ROOT}/cases)
set(BCLIB_TESTS_COVERAGE                        ${BCLIB_TESTS_ROOT}/coverage)

set(BCLIB_TESTS_INCLUDE_DIRECTORIES	            ${BCLIB_INCLUDE_DIRECTORIES}
                                                ${BCLIB_TESTS_INCLUDE}
                                                ${gtest_SOURCE_DIR}/include 
                                                ${gtest_SOURCE_DIR})

#
# Sources and headers
#
set(BCLIB_SOURCE_FILES                          ${BCLIB_TESTS_CASES}/kuznyechik.cpp)

set(BCLIB_HEADER_FILES                          ${BCLIB_TESTS_INCLUDE}/tests_common.hpp
                                                ${BCLIB_TESTS_INCLUDE}/tests_utils.hpp)

set(BCLIB_SOURCES                               ${BCLIB_SOURCE_FILES}
                                                ${BCLIB_HEADER_FILES})

#
# Test executable
#
add_executable(bc-lib-test                      ${BCLIB_SOURCES})

#
# Include directories
#
target_include_directories(bc-lib-test PRIVATE  ${BCLIB_TESTS_INCLUDE_DIRECTORIES})

#
# Link with bc-lib and Google tests
#
target_link_libraries(bc-lib-test PRIVATE       bc-lib)
target_link_libraries(bc-lib-test PRIVATE       GTest::gtest)
target_link_libraries(bc-lib-test PRIVATE       GTest::gtest_main)

#
# Add target as test
#
add_test(NAME bc-lib-test 
         COMMAND bc-lib-test)

#
# Create code coverage reporting script (Windows build only)
#
if (BCLIB_WINDOWS_BUILD)

    string(REPLACE "/" "\\" BCLIB_COV_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

    configure_file(${BCLIB_TESTS_COVERAGE}/coverage.cmd.in
                   ${CMAKE_BINARY_DIR}/coverage.cmd
                   @ONLY)

endif (BCLIB_WINDOWS_BUILD)