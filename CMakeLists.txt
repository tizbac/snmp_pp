cmake_minimum_required(VERSION 3.14...3.21)

project(
  snmp_pp
  VERSION 3.4.7.5
  LANGUAGES CXX C
)

include(CheckIncludeFiles)
include(CheckFunctionExists)
include(CheckSymbolExists)
include(CheckLibraryExists)
include(CheckStructHasMember)
include(CheckTypeSize)

set(CMAKE_CXX_STANDARD 17)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules)

option(SNMP_PP_EXAMPLES "Enable to build examples" OFF)
option(SNMP_PP_SNMPv3 "Enable support for SNMPv3" ON)
option(SNMP_PP_IPv6 "Enable support for IPv6" ON)
option(SNMP_PP_THREADS "Enable support for threads" ON)
option(SNMP_PP_NAMESPACE "Enable using of namespace" ON)
option(SNMP_PP_LOGGING "Enable logging" OFF)
option(SNMP_PP_MACADDR "Enable MacAddress class" OFF)
option(SNMP_PP_IPXADDR "Enable IpxAddress class" OFF)
option(SNMP_PP_OPENSSL "Search for OpenSSL library" ON)
option(SNMP_PP_LIBDES "Search for DES library" ON)
option(SNMP_PP_LIBTOMCRYPT "Search for Tomcrypt library" OFF)
option(SNMP_PP_EXTENDED_DEBUG "Enable additional debug messages" OFF)

if(SNMP_PP_LOGGING)
  set(LogProfile
      "original"
      CACHE STRING "Log Profile"
  )

  set(LogProfileValues
      "original;off;quiet;std;events;verbose;full;debug;schwafel"
      CACHE STRING "List of possible values for the Log Profile variable"
  )

  set_property(CACHE LogProfile PROPERTY STRINGS ${LogProfileValues})

  message(STATUS "LogProfile='${LogProfile}'")
endif()

set(VERSION ${PROJECT_VERSION})
set(SNMP_PP_MAJOR_VERSION ${PROJECT_VERSION_MAJOR})
set(SNMP_PP_MINOR_VERSION ${PROJECT_VERSION_MINOR})
set(SNMP_PP_MICRO_VERSION ${PROJECT_VERSION_PATCH})

message(STATUS "snmp++ Version ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}")

check_include_files(sys/types.h CNF_HAVE_SYS_TYPES_H)
check_include_files(sys/stat.h CNF_HAVE_SYS_STAT_H)
check_include_files("cctype;cerrno;climits;csignal;cstddef;cstdio;cstdlib;cstring;ctime" CNF_STDCXX_98_HEADERS)

if(NOT CNF_STDCXX_98_HEADERS)
  check_include_files("stdlib.h;stddef.h" CNF_STDC_HEADERS)
  check_include_files(stdlib.h CNF_HAVE_STDLIB_H)
  check_include_files(string.h CNF_HAVE_STRING_H)
  check_include_files(memory.h CNF_HAVE_MEMORY_H)
  check_include_files(strings.h CNF_HAVE_STRINGS_H)
  check_include_files(inttypes.h CNF_HAVE_INTTYPES_H)
  check_include_files(ctype.h CNF_HAVE_CTYPE_H)
  check_include_files(signal.h CNF_HAVE_SIGNAL_H)
  check_include_files(errno.h CNF_HAVE_ERRNO_H)
  check_include_files(time.h CNF_HAVE_TIME_H)
endif()

check_include_files(unistd.h CNF_HAVE_UNISTD_H)
check_include_files(sys/unistd.h CNF_HAVE_SYS_UNISTD_H)
check_include_files(stdint.h CNF_HAVE_STDINT_H)
check_include_files(sys/time.h CNF_HAVE_SYS_TIME_H)
check_include_files(sys/param.h CNF_HAVE_SYS_PARAM_H)
check_include_files(sys/timeb.h CNF_HAVE_SYS_TIMEB_H)

if(MSVC)
  check_include_files(winsock2.h CNF_HAVE_WINSOCK2_H)
  check_include_files(ws2tcpip.h CNF_HAVE_WS2TCPIP_H)
  check_include_files(wspiapi.h CNF_HAVE_WSPIAPI_H)
  check_function_exists("_getpid" CNF_HAVE__GETPID)
endif()

check_include_files(netdb.h CNF_HAVE_NETDB_H)
check_include_files(sys/socket.h CNF_HAVE_SYS_SOCKET_H)
check_include_files(arpa/inet.h CNF_HAVE_ARPA_INET_H)
check_include_files(netinet/in.h CNF_HAVE_NETINET_IN_H)
check_include_files(poll.h CNF_HAVE_POLL_H)
check_include_files(sys/select.h CNF_HAVE_SYS_SELECT_H)
check_include_files(io.h CNF_HAVE_IO_H)
check_include_files(process.h CNF_HAVE_PROCESS_H)
check_include_files(pthread.h CNF_HAVE_PTHREAD_H)
check_function_exists("strcasecmp" CNF_HAVE_STRCASECMP)
check_function_exists("stricmp" CNF_HAVE_STRICMP)
check_function_exists("getpid" CNF_HAVE_GETPID)

check_function_exists("clock_gettime" HAVE_CLOCK_GETTIME)
check_function_exists("getaddrinfo" HAVE_GETADDRINFO)
check_function_exists("gethostbyaddr" HAVE_GETHOSTBYADDR)
check_function_exists("gethostbyaddr_r" HAVE_GETHOSTBYADDR_R)
check_function_exists("gethostbyname" HAVE_GETHOSTBYNAME)
check_function_exists("gethostbyname2" HAVE_GETHOSTBYNAME2)
check_function_exists("gethostbyname_r" HAVE_GETHOSTBYNAME_R)
check_function_exists("gethostname" HAVE_GETHOSTNAME)
check_function_exists("getpid" HAVE_GETPID)
check_function_exists("gettimeofday" HAVE_GETTIMEOFDAY)
check_function_exists("htonl" HAVE_HTONL)
check_function_exists("inet_aton" HAVE_INET_ATON)
check_function_exists("inet_ntoa" HAVE_INET_NTOA)
check_function_exists("inet_ntop" HAVE_INET_NTOP)
check_function_exists("inet_pton" HAVE_INET_PTON)
check_function_exists("isdigit" HAVE_ISDIGIT)
check_function_exists("localtime_r" HAVE_LOCALTIME_R)
check_function_exists("malloc" HAVE_MALLOC)
check_function_exists("memset" HAVE_MEMSET)
check_function_exists("poll" HAVE_POLL)
check_function_exists("realloc" HAVE_REALLOC)
check_function_exists("select" HAVE_SELECT)
check_function_exists("socket" HAVE_SOCKET)
check_function_exists("strcasecmp" HAVE_STRCASECMP)
check_function_exists("strchr" HAVE_STRCHR)
check_function_exists("strerror" HAVE_STRERROR)
check_function_exists("stricmp" HAVE_STRICMP)
check_function_exists("strstr" HAVE_STRSTR)
check_include_files(inttypes.h HAVE_INTTYPES_H) # again?
check_include_files(io.h HAVE_IO_H) # again?
check_include_files(limits.h HAVE_LIMITS_H)
check_include_files(memory.h HAVE_MEMORY_H) # again?
check_include_files(netdb.h HAVE_NETDB_H) # again?
check_include_files(netinet/in.h HAVE_NETINET_IN_H) # again?
check_include_files(poll.h HAVE_POLL_H) # again?
check_include_files(process.h HAVE_PROCESS_H) # again?
check_include_files(pthread.h HAVE_PTHREAD) # again?
check_include_files(signal.h HAVE_SIGNAL_H) # again?
check_include_files(stdint.h HAVE_STDINT_H) # again?
check_include_files(stdio.h HAVE_STDIO_H)
check_include_files(stdlib.h HAVE_STDLIB_H) # again?
check_include_files(string.h HAVE_STRING_H) # again?
check_include_files(strings.h HAVE_STRINGS_H) # again?
check_include_files(sys/param.h HAVE_SYS_PARAM_H) # again?
check_include_files(sys/select.h HAVE_SYS_SELECT_H) # again?
check_include_files(sys/socket.h HAVE_SYS_SOCKET_H) # again?
check_include_files(sys/stat.h HAVE_SYS_STAT_H) # again?
check_include_files(sys/time.h HAVE_SYS_TIME_H) # again?
check_include_files(sys/timeb.h HAVE_SYS_TIMEB_H) # again?
check_include_files(sys/types.h HAVE_SYS_TYPES_H) # again?
check_include_files(sys/unistd.h HAVE_SYS_UNISTD_H) # again?
check_include_files(time.h HAVE_TIME_H) # again?
check_include_files(unistd.h HAVE_UNISTD_H) # again?

if(MSVC)
  check_include_files(winsock2.h HAVE_WINSOCK2_H) # again?
  check_include_files(ws2tcpip.h HAVE_WS2TCPIP_H) # again?
  check_include_files(wspiapi.h HAVE_WSPIAPI_H) # again?
  check_function_exists("_getpid" HAVE__GETPID) # again?
endif()

check_type_size("int64_t" SIZEOF_INT64_T LANGUAGE CXX)
check_type_size("long long" SIZEOF_LONG_LONG LANGUAGE CXX)
check_type_size("long" SIZEOF_LONG LANGUAGE CXX)
check_type_size("uint64_t" SIZEOF_UINT64_T LANGUAGE CXX)
check_type_size("unsigned long long" SIZEOF_ULONG_LONG LANGUAGE CXX)
check_type_size("unsigned long" SIZEOF_ULONG LANGUAGE CXX)

if(SIZEOF_INT64_T EQUAL "8")
  set(TYPE_INT64_T "int64_t")
elseif(SIZEOF_LONG EQUAL "8")
  set(TYPE_INT64_T "long")
elseif(SIZEOF_LONG_LONG EQUAL "8")
  set(TYPE_INT64_T "long long")
else()
  message(FATAL_ERROR "Can't find suitable int64_t")
endif()
message(STATUS "Found int64_t: ${TYPE_INT64_T}")

if(SIZEOF_UINT64_T EQUAL "8")
  set(TYPE_UINT64_T "uint64_t")
elseif(SIZEOF_ULONG EQUAL "8")
  set(TYPE_INT64_T "unsigned long")
elseif(SIZEOF_ULONG_LONG EQUAL "8")
  set(TYPE_INT64_T "unsigned long long")
else()
  message(FATAL_ERROR "Can't find suitable uint64_t")
endif()
message(STATUS "Found uint64_t: ${TYPE_UINT64_T}")

set(SOCKADDR_HEADERS)
if(CNF_HAVE_WINSOCK2_H)
  set(SOCKADDR_HEADERS ${SOCKADDR_HEADERS} winsock2.h)
endif()
if(CNF_HAVE_WS2TCPIP_H)
  set(SOCKADDR_HEADERS ${SOCKADDR_HEADERS} ws2tcpip.h)
endif()
if(CNF_HAVE_NETDB_H)
  set(SOCKADDR_HEADERS ${SOCKADDR_HEADERS} netdb.h)
endif()
if(CNF_HAVE_SYS_SOCKET_H)
  set(SOCKADDR_HEADERS ${SOCKADDR_HEADERS} sys/socket.h)
endif()
if(CNF_HAVE_ARPA_INET_H)
  set(SOCKADDR_HEADERS ${SOCKADDR_HEADERS} arpa/inet.h)
endif()
if(CNF_HAVE_NETINET_IN_H)
  set(SOCKADDR_HEADERS ${SOCKADDR_HEADERS} netinet/in.h)
endif()

check_struct_has_member(
  "struct sockaddr_storage" ss_family "${SOCKADDR_HEADERS}" CNF_HAVE_STRUCT_SOCKADDR_STORAGE_SS_FAMILY LANGUAGE CXX
)

check_struct_has_member(
  "struct sockaddr_storage" __ss_family "${SOCKADDR_HEADERS}" CNF_HAVE_STRUCT_SOCKADDR_STORAGE___SS_FAMILY LANGUAGE CXX
)

if(SNMP_PP_SNMPv3)
  set(_SNMPv3 1)
  set(_NO_SNMPv3 0)
else()
  set(_SNMPv3 0)
  set(_NO_SNMPv3 1)
endif()

if(SNMP_PP_IPv6)
  set(WITH_SNMP_PP_IPv6 1)
  set(SNMP_PP_IPv6 1)
else()
  set(WITH_SNMP_PP_IPv6 0)
  set(SNMP_PP_IPv6 0)
endif()

if(SNMP_PP_THREADS)
  set(CMAKE_THREAD_PREFER_PTHREAD 1)
  find_package(Threads REQUIRED)

  set(WITH_THREADS 1)
  if(CNF_HAVE_PTHREAD_H)
    set(WITH_PTHREAD 1)
  else()
    set(WITH_PTHREAD 0)
  endif()
else()
  set(CMAKE_DISABLE_FIND_PACKAGE_Threads ON)
  set(WITH_THREADS 0)
  set(WITH_PTHREAD 0)
endif()

if(SNMP_PP_NAMESPACE)
  set(WITH_NAMESPACE 1)
else()
  message(WARNING "NO NAMESPACE?")
  set(WITH_NAMESPACE 0)
endif()

if(SNMP_PP_LOGGING)
  set(WITH_LOGGING 1)
else()
  set(WITH_LOGGING 0)
endif()

if(SNMP_PP_MACADDR)
  set(WITH_MACADDRESS 1)
else()
  set(WITH_MACADDRESS 0)
endif()

if(SNMP_PP_IPXADDR)
  set(WITH_IPXADDRESS 1)
else()
  set(WITH_IPXADDRESS 0)
endif()

if(SNMP_PP_EXTENDED_DEBUG)
  set(_DEBUG 1)
else()
  set(_DEBUG 0)
endif()

# ---- Add dependencies via CPM ----
# see https://github.com/cpm-cmake/CPM.cmake for more info

include(CPM)

if(SNMP_PP_OPENSSL)
  if(APPLE)
    # NOTE: may needed on OSX! CK
    set(OPENSSL_ROOT_DIR
        /usr/local/opt/openssl
        CACHE FILEPATH ""
    )
  endif()

  find_package(OpenSSL)

  if(OPENSSL_FOUND)
    message(STATUS "Found OpenSSL (include: ${OPENSSL_INCLUDE_DIR}, library: ${OPENSSL_LIBRARIES})")
    set(CRYPTO_INCLUDE_DIRS ${OPENSSL_INCLUDE_DIR})
    set(CRYPTO_LINKLIBS ${OPENSSL_LIBRARIES})
    set(CRYPTO_LIB OpenSSL)
    set(WITH_LIBSSL 1)
  else()
    # message(FATAL_ERROR "LibOpenSSL NOT found!")
    set(WITH_LIBSSL 0)
  endif()
else()
  set(WITH_LIBSSL 0)
endif()

if(NOT CRYPTO_LIB AND SNMP_PP_LIBTOMCRYPT)
  find_package(TOMCRYPT)

  if(TOMCRYPT_FOUND)
    set(WITH_LIBSSL 0)

    message(STATUS "Found TOMCRYPT (include: ${TOMCRYPT_INCLUDE_DIR}, library: ${TOMCRYPT_LIBRARIES})")
    set(CRYPTO_INCLUDE_DIRS ${TOMCRYPT_INCLUDE_DIR})
    set(CRYPTO_LINKLIBS ${TOMCRYPT_LIBRARIES})
    set(CRYPTO_LIB TOMCRYPT)
    set(WITH_LIBTOMCRYPT 1)
  else()
    # message(FATAL_ERROR "Libtomcrypt NOT found!")
    set(WITH_LIBTOMCRYPT 0)
  endif()

else()
  set(WITH_LIBTOMCRYPT 0)
endif()

if(NOT CRYPTO_LIB AND SNMP_PP_LIBDES)
  # see https://github.com/ClausKlein/libdes/releases/tag/v4.1.1.2
  CPMAddPackage(
    NAME libdes
    GIT_TAG v4.1.1.2
    GITHUB_REPOSITORY ClausKlein/libdes
  )
  # FIXME: install(TARGETS des EXPORT ${PROJECT_NAME} LIBRARY DESTINATION lib)
  # CMake Error: install(EXPORT "snmp_ppTargets" ...) includes target "snmp_pp" which requires target "des" that is not in any export set.

  # message(STATUS "Searching for libdes...")
  # XXX find_package(DES)
  # if(DES_FOUND)
    set(WITH_LIBSSL 0)
    set(WITH_LIBTOMCRYPT 0)

    # message(STATUS "Libdes found / ${DES_INCLUDE_DIR} / ${DES_LIBRARIES} / ")
    set(CRYPTO_INCLUDE_DIRS ${des_SOURCE_DIR})
    set(CRYPTO_LINKLIBS des::des)

    set(CRYPTO_LIB des) # NOTE: dummy only! CK
    set(WITH_LIBDES 1)
  # else()
  #   message(FATAL_ERROR "Libdes NOT found!")
  # endif()

else()
  set(WITH_LIBDES 0)
endif()

if(SNMP_PP_LOGGING)
  if(${LogProfile} STREQUAL "off")
    set(WITH_LOG_PROFILES 0)
  else()
    set(WITH_LOG_PROFILES 1)
    set(DEFAULT_LOG_PROFILE "${LogProfile}")
  endif()
else()
  set(WITH_LOG_PROFILES 0)
endif()

if(CNF_STDC_HEADERS)
  set(STDC_HEADERS 1)
else()
  set(STDC_HEADERS 0)
endif()

if(CNF_STDCXX_98_HEADERS)
  set(STDCXX_98_HEADERS 1)
  set(STDC_HEADERS 0)
else()
  set(STDCXX_98_HEADERS 0)
endif()

check_type_size(size_t SIZE_T LANGUAGE CXX)
if(NOT HAVE_SIZE_T)
  if("${CMAKE_SIZEOF_VOID_P}" EQUAL 8)
    set(size_t "uint64_t")
  else()
    set(size_t "uint32_t")
  endif("${CMAKE_SIZEOF_VOID_P}" EQUAL 8)
endif()

check_include_files(malloc.h HAVE_MALLOC_H)
check_include_files("sys/param.h;sys/mount.h" HAVE_SYS_MOUNT_H)
check_function_exists("strcasecmp" HAVE_STRCASECMP)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake_config.h.in config.h)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake_libsnmp.h.in libsnmp.h)
configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/include/snmp_pp/config_snmp_pp.h.in
  ${CMAKE_CURRENT_SOURCE_DIR}/include/snmp_pp/config_snmp_pp.h
)

set(MY_HEADER_FILES
    include/snmp_pp/address.h
    include/snmp_pp/asn1.h
    include/snmp_pp/auth_priv.h
    include/snmp_pp/collect.h
    include/snmp_pp/config_snmp_pp.h
    include/snmp_pp/counter.h
    include/snmp_pp/ctr64.h
    include/snmp_pp/eventlist.h
    include/snmp_pp/eventlistholder.h
    include/snmp_pp/gauge.h
    include/snmp_pp/idea.h
    include/snmp_pp/integer.h
    include/snmp_pp/IPv6Utility.h
    include/snmp_pp/log.h
    include/snmp_pp/md5.h
    include/snmp_pp/mp_v3.h
    include/snmp_pp/msec.h
    include/snmp_pp/msgqueue.h
    include/snmp_pp/notifyqueue.h
    include/snmp_pp/octet.h
    include/snmp_pp/oid.h
    include/snmp_pp/oid_def.h
    include/snmp_pp/pdu.h
    include/snmp_pp/reentrant.h
    include/snmp_pp/sha.h
    include/snmp_pp/smi.h
    include/snmp_pp/smival.h
    include/snmp_pp/snmp_pp.h
    include/snmp_pp/snmperrs.h
    include/snmp_pp/snmpmsg.h
    include/snmp_pp/target.h
    include/snmp_pp/timetick.h
    include/snmp_pp/userdefined.h
    include/snmp_pp/usertimeout.h
    include/snmp_pp/usm_v3.h
    include/snmp_pp/uxsnmp.h
    include/snmp_pp/v3.h
    include/snmp_pp/vb.h
)

set(MY_HEADER_LIB_FILES ${CMAKE_CURRENT_BINARY_DIR}/libsnmp.h)

set(MY_SRC_FILES
    src/address.cpp
    src/asn1.cpp
    src/auth_priv.cpp
    src/counter.cpp
    src/ctr64.cpp
    src/eventlist.cpp
    src/eventlistholder.cpp
    src/gauge.cpp
    src/idea.cpp
    src/integer.cpp
    src/IPv6Utility.cpp
    src/log.cpp
    src/md5c.cpp
    src/mp_v3.cpp
    src/msec.cpp
    src/msgqueue.cpp
    src/notifyqueue.cpp
    src/octet.cpp
    src/oid.cpp
    src/pdu.cpp
    src/reentrant.cpp
    src/sha.cpp
    src/snmpmsg.cpp
    src/target.cpp
    src/timetick.cpp
    src/userdefined.cpp
    src/usertimeout.cpp
    src/usm_v3.cpp
    src/uxsnmp.cpp
    src/v3.cpp
    src/vb.cpp
)

option(BUILD_SHARED_LIBS "Global flag to cause add_library() to create shared libraries if on." ON)
add_library(
  ${PROJECT_NAME} ${MY_HEADER_FILES} ${MY_HEADER_LIB_FILES} ${CMAKE_CURRENT_BINARY_DIR}/config.h ${MY_SRC_FILES}
)

if(MSVC)
  # warning level 4 (all warnings as errors: /WX)
  # FIXME target_compile_options(${PROJECT_NAME} PRIVATE /W4 /WX)
else()
  target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Wno-unused-parameter)
  # TODO: lots of warnings (more: -Wpedantic)
endif()

set_property(TARGET ${PROJECT_NAME} PROPERTY POSITION_INDEPENDENT_CODE 1)
# Set .so version as autoconf does: snmp++ version 1.2.3 will go to .so.12.0.3!
set_target_properties(
  ${PROJECT_NAME} PROPERTIES VERSION ${PROJECT_VERSION_MAJOR}${PROJECT_VERSION_MINOR}.0.${PROJECT_VERSION_PATCH}
                             SOVERSION ${PROJECT_VERSION_MAJOR}${PROJECT_VERSION_MINOR}
)
set_target_properties(${PROJECT_NAME} PROPERTIES CXX_STANDARD ${CMAKE_CXX_STANDARD})
target_link_libraries(${PROJECT_NAME} PUBLIC ${CRYPTO_LINKLIBS} Threads::Threads)
#
# NOTE: we have to prevent the use of older installed project headers
#
target_include_directories(
  ${PROJECT_NAME} SYSTEM BEFORE PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_include_directories(
  ${PROJECT_NAME}
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}> $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
         $<BUILD_INTERFACE:${CRYPTO_INCLUDE_DIRS}> $<INSTALL_INTERFACE:include>
)

if(SNMP_PP_EXAMPLES)
  set(EXAMPLE_SOURCE_FILES
      consoleExamples/receive_trap.cpp
      consoleExamples/snmpBulk.cpp
      consoleExamples/snmpDiscover.cpp
      consoleExamples/snmpGet.cpp
      consoleExamples/snmpInform.cpp
      consoleExamples/snmpNext.cpp
      consoleExamples/snmpNextAsync.cpp
      consoleExamples/snmpPasswd.cpp
      consoleExamples/snmpSet.cpp
      consoleExamples/snmpTraps.cpp
      consoleExamples/snmpWalk.cpp
      consoleExamples/snmpWalkThreads.cpp
      consoleExamples/test_app.cpp
  )

  foreach(examplesourcefile ${EXAMPLE_SOURCE_FILES})
    string(REPLACE ".cpp" "" examplename ${examplesourcefile})
    string(REPLACE "consoleExamples/" "" examplename ${examplename})
    add_executable(${examplename} ${examplesourcefile})
    target_link_libraries(${examplename} ${PROJECT_NAME})
    target_include_directories(
      ${examplename} SYSTEM BEFORE PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
  endforeach()
endif()

install(FILES ${MY_HEADER_LIB_FILES} DESTINATION include)

# XXX include(PackageProject)
CPMAddPackage("gh:TheLartians/PackageProject.cmake@1.8.0")

packageProject(
  # the name of the target to export
  NAME ${PROJECT_NAME}
  # the version of the target to export
  VERSION ${PROJECT_VERSION}
  # a temporary directory to create the config files
  BINARY_DIR ${PROJECT_BINARY_DIR}
  # location of the target's public headers
  INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include
  # should match the target's INSTALL_INTERFACE include directory
  INCLUDE_DESTINATION include
  # semicolon separated list of the project's dependencies
  DEPENDENCIES "${CRYPTO_LIB}; Threads"
  # (optional) create a header containing the version info
  # Note: that the path to headers should be lowercase
  VERSION_HEADER "${PROJECT_NAME}/version.h"
  # (optional) create a export header using GenerateExportHeader module
  EXPORT_HEADER "${PROJECT_NAME}/export.h"
  # (optional) install your library with a namespace (Note: do NOT add extra '::')
  NAMESPACE ${PROJECT_NAME}
  # (optional) define the project's version compatibility, defaults to `AnyNewerVersion`
  # supported values: `AnyNewerVersion|SameMajorVersion|SameMinorVersion|ExactVersion`
  COMPATIBILITY SameMajorVersion
  # (optional) option to disable the versioning of install destinations
  DISABLE_VERSION_SUFFIX YES
  # (optional) option to ignore target architecture for package resolution
  # defaults to YES for header only (i.e. INTERFACE) libraries
  ## ARCH_INDEPENDENT YES
)
