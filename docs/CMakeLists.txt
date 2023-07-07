#
# Configuration flags
#
if (BCLIB_BUILD_PRETTY_DOCS)
    set(BCLIB_DOXYGEN_HAVE_DOT              YES)
else (BCLIB_BUILD_PRETTY_DOCS)
    set(BCLIB_DOXYGEN_HAVE_DOT              NO)
endif (BCLIB_BUILD_PRETTY_DOCS)

#
# Setup paths
#
set(BCLIB_DOCS_VERSION                      ${CMAKE_PROJECT_VERSION})
set(BCLIB_DOCS_ROOT                         ${BCLIB_ROOT}/docs)
set(BCLIB_DOCS_DOXYGEN_AWESOME_ROOT         ${BCLIB_DOCS_ROOT}/doxygen-awesome-css)
set(BCLIB_DOCS_DOXYGEN_IN                   ${BCLIB_DOCS_ROOT}/Doxyfile.in)
set(BCLIB_DOCS_DOXYGEN_OUT                  ${BCLIB_DOCS_ROOT}/Doxyfile)

#
# And here we go...
#
message("[${PROJECT_NAME}]: Configuring doxygen...")
configure_file(${BCLIB_DOCS_DOXYGEN_IN}     ${BCLIB_DOCS_DOXYGEN_OUT} @ONLY)

#
# In case of GitHub docs we only need a configuration file to be 
# generated, so we quit here in this case
#
if (BCLIB_BUILD_GITHUB_DOCS)
    message(NOTICE "[${PROJECT_NAME}]: Doxyfile is generated, but BCLIB_BUILD_GITHUB_DOCS is set, nothing else will be performed")
    message(NOTICE "[${PROJECT_NAME}]: Doxyfile is located here: '${BCLIB_DOCS_DOXYGEN_OUT}'")
    return()
endif (BCLIB_BUILD_GITHUB_DOCS)

#
# Otherwise we need to find Doxygen
#
find_package(Doxygen)

#
# Check if we have Doxygen installed
#
if (NOT DOXYGEN_FOUND )
    message(WARNING "[${PROJECT_NAME}]: Doxygen need to be installed to generate the doxygen documentation")
    return()
endif() 

#
# Custom target for building documentation
#
add_custom_target(bc-lib-docs ALL
    COMMAND ${DOXYGEN_EXECUTABLE} ${BCLIB_DOCS_DOXYGEN_OUT}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Generating documentation with Doxygen"
    VERBATIM)
    