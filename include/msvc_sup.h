#ifndef __win32_galera_h__
#define __win32_galera_h__
#include "hsregex.h"
#include <windows.h>
#	include <iphlpapi.h>
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
#ifdef __cplusplus
}
#endif
#endif
