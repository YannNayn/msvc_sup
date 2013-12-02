#ifndef __msvc_sup_h__
#define __msvc_sup_h__
#ifdef _MSC_VER
#include "hsregex.h"
#include <windows.h>
#	include <iphlpapi.h>
#include <time.h>
#if !defined(IF_NAMESIZE) || (1==1)
#       ifdef IFNAMSIZ
#               define IF_NAMESIZE      IFNAMSIZ
#       elif defined(MAX_INTERFACE_NAME_LEN)
#               define IF_NAMESIZE      MAX_INTERFACE_NAME_LEN
#       elif defined(_WIN32)
/* 40 for UUID, 256 for device path */
#               define IF_NAMESIZE      256
#       else
#               define IF_NAMESIZE      16
#       endif
#endif
#ifdef __cplusplus
extern "C"
{
#endif
struct pgm_ifaddrs_t
{
        struct pgm_ifaddrs_t*   ifa_next;       /* Pointer to the next structure.  */

        char*                   ifa_name;       /* Name of this network interface.  */
        unsigned int            ifa_flags;      /* Flags as from SIOCGIFFLAGS ioctl.  */

#ifdef ifa_addr
#       undef ifa_addr
#endif
        struct sockaddr*        ifa_addr;       /* Network address of this interface.  */
        struct sockaddr*        ifa_netmask;    /* Netmask of this interface.  */
};

int getifaddrs (struct pgm_ifaddrs_t**);
void freeifaddrs (struct pgm_ifaddrs_t*);
struct timezone
{
int tz_minuteswest; /* minutes W of Greenwich */
int tz_dsttime; /* type of dst correction */
};
int gettimeofday(struct timeval *tv, struct timezone *tz);
typedef long off_t;
int posix_fallocate(int fd, off_t offset, off_t len);
int ftruncate (int fd, off_t size);
int mkstemp(char *_template);
struct tm * gmtime_r(const time_t *clock, struct tm *result);
struct tm * localtime_r(const time_t *clock, struct tm *result);
struct tm * localtime_rl(const long *clock, struct tm *result);

#define PROT_NONE       0
#define PROT_READ       1
#define PROT_WRITE      2
#define PROT_EXEC       4

#define MAP_FILE        0
#define MAP_SHARED      1
#define MAP_PRIVATE     2
#define MAP_TYPE        0xf
#define MAP_FIXED       0x10
#define MAP_ANONYMOUS   0x20
#define MAP_ANON        MAP_ANONYMOUS

#define MAP_FAILED      ((void *)-1)

/* Flags for msync. */
#define MS_ASYNC        1
#define MS_SYNC         2
#define MS_INVALIDATE   4

#ifndef MAP_NORESERVE
#  ifdef MAP_AUTORESRV
#    if (defined(__sgi) && defined(_COMPILER_VERSION))
#      define MAP_NORESERVE MAP_AUTORESRV
#    endif
#  else
#    define MAP_NORESERVE 0
#  endif
#endif

void* mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off);

int munmap(void *addr, size_t len);
int mprotect(void *addr, size_t len, int prot);
int msync(void *addr, size_t len, int flags);
int mlock(const void *addr, size_t len);
int munlock(const void *addr, size_t len);

#define _SC_PAGESIZE 1
#define _SC_PHYS_PAGES 2
#define _SC_OPEN_MAX 3
#define _SC_AVPHYS_PAGES 4
#define _SC_PAGE_SIZE _SC_PAGESIZE
size_t sysconf(int type);

unsigned int pgm_if_nametoindex (	const char* ifname);
long long rand_rl(unsigned long long* seed);
int rand_r(unsigned int* seed);


#ifndef _TIMESPEC_DEFINED
#define _TIMESPEC_DEFINED
typedef struct timespec {               /* definition per POSIX.4 */
         time_t          tv_sec;         /* seconds */
         long            tv_nsec;        /* and nanoseconds */
 } timespec_t;
#endif /* _TIMESPEC_DEFINED */


int nanosleep (const struct timespec *requested_delay,struct timespec *remaining_delay);
 
 /* POSIX emulation layer for Windows.
*
* Copyright (C) 2008-2013 Anope Team <team@anope.org>
*
* Please read COPYING and README for further details.
*
* Based on the original code of Epona by Lara.
* Based on the original code of Services by Andy Church.
*/

#ifndef SIGHUP
# define SIGHUP -1
#endif
#ifndef SIGPIPE
# define SIGPIPE -1
#endif

#ifndef _SIGACTION_DEFINED
#define _SIGACTION_DEFINED
struct sigaction
{
    void (*sa_handler)(int);
    int sa_flags;
    int sa_mask;
};
#endif //_SIGACTION_DEFINED

#ifndef _SSIZE_T_DEFINED
#ifdef  _WIN64
typedef __int64    ssize_t;
#else
typedef _W64 int   ssize_t;
#endif
#define _SIZE_T_DEFINED
#endif

int sigaction(int sig, struct sigaction *action, struct sigaction *old);

char *strndup( const char *s,int len);

#ifdef __cplusplus
}
#endif
#define SSIZET_PRINTF_SPEC "%ld"
#define SIZET_PRINTF_SPEC "%lu"
#define DIR_SEP_S "\\"
#define DIR_SEP_C '\\'
#else
#define SSIZET_PRINTF_SPEC "%zd"
#define SIZET_PRINTF_SPEC "%zu"
#define DIR_SEP_S "/"
#define DIR_SEP_C '/'
#endif



#endif // __msvc_sup_h__
