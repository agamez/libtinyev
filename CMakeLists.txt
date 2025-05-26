cmake_minimum_required(VERSION 3.0)

project("Tiny events library" C)
set_property(GLOBAL PROPERTY CMAKE_C_STANDARD 11)
set(VERSION, "1.0.0")
add_compile_options(-fms-extensions)

set(INSTALL_BIN_DIR "${CMAKE_INSTALL_PREFIX}/bin" CACHE PATH "Installation directory for executables")
set(INSTALL_LIB_DIR "${CMAKE_INSTALL_PREFIX}/lib" CACHE PATH "Installation directory for libraries")
set(INSTALL_INC_DIR "${CMAKE_INSTALL_PREFIX}/include" CACHE PATH "Installation directory for headers")
set(INSTALL_MAN_DIR "${CMAKE_INSTALL_PREFIX}/share/man" CACHE PATH "Installation directory for manual pages")
set(INSTALL_PKGCONFIG_DIR "${CMAKE_INSTALL_PREFIX}/share/pkgconfig" CACHE PATH "Installation directory for pkgconfig (.pc) files")

set(libtinyev_PC ${CMAKE_CURRENT_BINARY_DIR}/libtinyev.pc)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/libtinyev.pc.in ${libtinyev_PC} @ONLY)

include_directories(
	${CMAKE_CURRENT_BINARY_DIR}
	${CMAKE_SOURCE_DIR}
)

set(libtinyev_SRCS libtinyev.c)
set(libtinyev_PUBLIC_HDRS libtinyev.h)

OPTION(BUF "Build buffer module" ON)
if(BUF)
	set(libtinyev_SRCS ${libtinyev_SRCS} libtinybuf.c)
	set(libtinyev_PUBLIC_HDRS ${libtinyev_PUBLIC_HDRS} libtinybuf.h)
endif()

OPTION(RPC "Build RPC module" ON)
if(RPC)
	set(BUF 1)
	set(libtinyev_SRCS ${libtinyev_SRCS} libtinyrpc.c)
	set(libtinyev_PUBLIC_HDRS ${libtinyev_PUBLIC_HDRS} libtinyrpc.h)
endif()

OPTION(HELPERS "Build helpers module" ON)
if(HELPERS)
	set(BUF 1)
	set(RPC 1)
	set(libtinyev_SRCS ${libtinyev_SRCS} libtinyhelpers.c)
	set(libtinyev_PUBLIC_HDRS ${libtinyev_PUBLIC_HDRS} libtinyhelpers.h)
endif()

option(BUILD_DOC "Build documentation" ON)
find_package(Doxygen)
if (DOXYGEN_FOUND AND BUILD_DOC)
	add_custom_target(doc ALL COMMAND ${DOXYGEN_EXECUTABLE} WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR} COMMENT "Generating API documentation with Doxygen" VERBATIM)
endif()

# Build library
add_library(tinyev SHARED ${libtinyev_SRCS} ${libtinyev_MODULES_SRCS} ${libtinyev_PUBLIC_HDRS})
set_target_properties(tinyev PROPERTIES SOVERSION 1)

if(NOT SKIP_INSTALL_LIBRARIES AND NOT SKIP_INSTALL_ALL )
    install(TARGETS
	tinyev

        RUNTIME DESTINATION "${INSTALL_BIN_DIR}"
        ARCHIVE DESTINATION "${INSTALL_LIB_DIR}"
        LIBRARY DESTINATION "${INSTALL_LIB_DIR}" )
endif()
if(NOT SKIP_INSTALL_HEADERS AND NOT SKIP_INSTALL_ALL )
    install(FILES ${libtinyev_PUBLIC_HDRS} DESTINATION "${INSTALL_INC_DIR}/")
endif()
if(NOT SKIP_INSTALL_FILES AND NOT SKIP_INSTALL_ALL )
    install(FILES ${libtinyev_PC} DESTINATION "${INSTALL_PKGCONFIG_DIR}")
endif()
