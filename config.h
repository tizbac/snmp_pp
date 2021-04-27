/*_############################################################################
  _## 
  _##  cmake_config.h.in  
  _##
  _##  SNMP++ v3.4
  _##  -----------------------------------------------
  _##  Copyright (c) 2001-2021 Jochen Katz, Frank Fock
  _##
  _##  This software is based on SNMP++2.6 from Hewlett Packard:
  _##  
  _##    Copyright (c) 1996
  _##    Hewlett-Packard Company
  _##  
  _##  ATTENTION: USE OF THIS SOFTWARE IS SUBJECT TO THE FOLLOWING TERMS.
  _##  Permission to use, copy, modify, distribute and/or sell this software 
  _##  and/or its documentation is hereby granted without fee. User agrees 
  _##  to display the above copyright notice and this license notice in all 
  _##  copies of the software and any documentation of the software. User 
  _##  agrees to assume all liability for the use of the software; 
  _##  Hewlett-Packard, Frank Fock, and Jochen Katz make no representations 
  _##  about the suitability of this software for any purpose. It is provided 
  _##  "AS-IS" without warranty of any kind, either express or implied. User 
  _##  hereby grants a royalty-free license to any and all derivatives based
  _##  upon this software code base. 
  _##  
  _##########################################################################*/
/* Define if you want the debug output support compiled in. */
/* #undef DEBUG */

/* Defines default log profile to use */
#define DEFAULT_LOG_PROFILE "original"

/* Define to 1 if you have the `clock_gettime' function. */
#define HAVE_CLOCK_GETTIME

/* Define if getaddrinfo is there */
#define HAVE_GETADDRINFO

/* Define to 1 if you have the `gethostbyaddr' function. */
#define HAVE_GETHOSTBYADDR

/* Define to 1 if you have the `gethostbyaddr_r' function. */
/* #undef HAVE_GETHOSTBYADDR_R */

/* Define to 1 if you have the `gethostbyname' function. */
#define HAVE_GETHOSTBYNAME

/* Define to 1 if you have the `gethostbyname2' function. */
#define HAVE_GETHOSTBYNAME2

/* Define to 1 if you have the `gethostbyname_r' function. */
/* #undef HAVE_GETHOSTBYNAME_R */

/* Define to 1 if you have the `gethostname' function. */
#define HAVE_GETHOSTNAME

/* Define to 1 if you have the `getpid' function. */
#define HAVE_GETPID

/* Define to 1 if you have the `gettimeofday' function. */
#define HAVE_GETTIMEOFDAY

/* Define to 1 if you have the `htonl' function. */
#define HAVE_HTONL

/* Define to 1 if you have the `inet_aton' function. */
#define HAVE_INET_ATON

/* Define to 1 if you have the `inet_ntoa' function. */
#define HAVE_INET_NTOA

/* Define to 1 if you have the `inet_ntop' function. */
#define HAVE_INET_NTOP

/* Define to 1 if you have the `inet_pton' function. */
#define HAVE_INET_PTON

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H

/* Define to 1 if you have the <io.h> header file. */
/* #undef HAVE_IO_H */

/* Define to 1 if you have the `isdigit' function. */
#define HAVE_ISDIGIT

/* Define when libdes.h shall be favored over des.h */
/* #undef HAVE_LIBDES_H */

/* Define to 1 if you have the <limits.h> header file. */
#define HAVE_LIMITS_H

/* Define to 1 if you have the `localtime_r' function. */
#define HAVE_LOCALTIME_R

/* Define to 1 if you have the `malloc' function. */
#define HAVE_MALLOC

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H

/* Define to 1 if you have the `memset' function. */
#define HAVE_MEMSET

/* Define to 1 if you have the <netdb.h> header file. */
#define HAVE_NETDB_H

/* Define to 1 if you have the <netinet/in.h> header file. */
#define HAVE_NETINET_IN_H

/* Define to 1 if you have the `poll' function. */
#define HAVE_POLL

/* Define to 1 if you have the <poll.h> header file. */
#define HAVE_POLL_H

/* Define to 1 if you have the <process.h> header file. */
/* #undef HAVE_PROCESS_H */

/* Define if you have POSIX threads libraries and header files. */
#define HAVE_PTHREAD 1

/* Define to 1 if you have the `realloc' function. */
#define HAVE_REALLOC

/* Define to 1 if you have the `select' function. */
#define HAVE_SELECT

/* Define to 1 if you have the <signal.h> header file. */
#define HAVE_SIGNAL_H

/* Define to 1 if you have the `socket' function. */
#define HAVE_SOCKET

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H

/* Define to 1 if you have the `strcasecmp' function. */
#define HAVE_STRCASECMP

/* Define to 1 if you have the `strchr' function. */
#define HAVE_STRCHR

/* Define to 1 if you have the `strerror' function. */
#define HAVE_STRERROR

/* Define to 1 if you have the `stricmp' function. */
/* #undef HAVE_STRICMP */

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H

/* Define to 1 if you have the `strstr' function. */
#define HAVE_STRSTR

/* Define to 1 if you have the <sys/param.h> header file. */
#define HAVE_SYS_PARAM_H

/* Define to 1 if you have the <sys/select.h> header file. */
#define HAVE_SYS_SELECT_H

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H

/* Define to 1 if you have the <sys/timeb.h> header file. */
#define HAVE_SYS_TIMEB_H

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H

/* Define to 1 if you have the <sys/unistd.h> header file. */
#define HAVE_SYS_UNISTD_H

/* Define to 1 if you have the <time.h> header file. */
#define HAVE_TIME_H

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H

/* Define to 1 if you have the <winsock2.h> header file. */
/* #undef HAVE_WINSOCK2_H */

/* Define to 1 if you have the <winsock.h> header file. */
/* #undef HAVE_WINSOCK_H */

/* Define to 1 if you have the <ws2tcpip.h> header file. */
/* #undef HAVE_WS2TCPIP_H */

/* Define to 1 if you have the <wspiapi.h> header file. */
/* #undef HAVE_WSPIAPI_H */

/* Define to 1 if you have the `_getpid' function. */
/* #undef HAVE__GETPID */

/* define SNMP_PP_IPv6 if you want to use IPv6 */
#define SNMP_PP_IPv6 1

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS

/* Define if ISO C++ 1998 header files are present. */
#define STDCXX_98_HEADERS

/* Version number of package */
#define VERSION "3.4.6"

/* define _NO_SNMPv3 if you do not want to use SNMPv3 */
/* #undef _NO_SNMPv3 */

/* define _SNMPv3 if you want to use SNMPv3 */
#define _SNMPv3 1

/* Define to necessary symbol if this constant uses a non-standard name on
   your system. */
/* #undef PTHREAD_CREATE_JOINABLE */

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
/* #undef inline */
#define inline 
#endif

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef size_t */

/* _XOPEN_SOURCE $HAVE_XOPEN_SOURCE */
/* #undef HAVE_XOPEN_SOURCE */

