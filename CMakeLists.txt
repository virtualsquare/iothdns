cmake_minimum_required(VERSION 3.13)
project("libiothdns"
		DESCRIPTION "dns"
		HOMEPAGE_URL "https://github.com/rd235/libiothdns"
    VERSION 0.1.2
    LANGUAGES C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_FORTIFY_SOURCE=2 -O2 -pedantic -Wall -Wextra")

include(GNUInstallDirs)
include(CheckIncludeFile)
include(CheckSymbolExists)

set(LIBS_REQUIRED ioth volatilestream)
set(HEADERS_REQUIRED volatilestream.h pthread.h)

foreach(THISLIB IN LISTS LIBS_REQUIRED)
  find_library(LIB${THISLIB}_OK ${THISLIB})
  if(NOT LIB${THISLIB}_OK)
    message(FATAL_ERROR "library lib${THISLIB} not found")
  endif()
endforeach(THISLIB)

foreach(HEADER IN LISTS HEADERS_REQUIRED)
  check_include_file(${HEADER} ${HEADER}_OK)
  if(NOT ${HEADER}_OK)
    message(FATAL_ERROR "header file ${HEADER} not found")
  endif()
endforeach(HEADER)

add_definitions(-D_GNU_SOURCE)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
add_library(iothdns SHARED iothdns.c iothdns_pkt.c name2dns.c
		iothdns_gai.c iothdns_getserv.c iothdns_gethost.c)
target_link_libraries(iothdns volatilestream ioth pthread)

set_target_properties(iothdns PROPERTIES VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR})

# configure_file(iothdns.pc.in iothdns.pc @ONLY)
# configure_file(config.h.in config.h)

install(TARGETS iothdns DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES iothdns.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
# install(FILES ${CMAKE_CURRENT_BINARY_DIR}/iothdns.pc
# DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

# add_subdirectory(man)

add_custom_target(uninstall
  "${CMAKE_COMMAND}" -P "${PROJECT_SOURCE_DIR}/Uninstall.cmake")
