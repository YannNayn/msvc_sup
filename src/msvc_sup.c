#include <fcntl.h>
#include "msvc_sup.h"
#include <io.h>
#include <errno.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#include <signal.h>
//#pragma message("compiling msvc_sup.c ...")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"iphlpapi.lib")

#ifndef TRUE
#   define TRUE 1
#endif
#ifndef FALSE
#   define FALSE 0
#endif

int posix_fallocate(int fd, off_t offset, off_t len)
{
    __int64 pos = _telli64(fd);
    __int64 flen = _lseeki64(fd,0,SEEK_END);
    
    __int64  wlen = offset+len-flen;
    if (wlen<0)
        return 0;
    else
    {
        static const char buf[65536] = "";
        while (wlen > 0) {
            unsigned int now = 65536;
            if (wlen < now)
                now = wlen;
            _write(fd,buf, now); // allowed to fail; this function is advisory anyway
            wlen -= now;
        }
        _lseeki64(fd,pos,SEEK_SET);
        _commit(fd);
    }
    return 0;
}
int
ftruncate (int fd, off_t size)
{
HANDLE hfile;
unsigned int curpos;
if (fd < 0)
return -1;
hfile = (HANDLE) _get_osfhandle (fd);
curpos = SetFilePointer (hfile, 0, NULL, FILE_CURRENT);
if (curpos == 0xFFFFFFFF
|| SetFilePointer (hfile, size, NULL, FILE_BEGIN) == 0xFFFFFFFF
|| !SetEndOfFile (hfile))
{
int error = GetLastError ();
switch (error)
{
case ERROR_INVALID_HANDLE:
errno = EBADF;
break;
default:
errno = EIO;
break;
}
return -1;
}
return 0;
}

int mkstemp(char *_template)
{
DWORD pathSize;
char pathBuffer[1000];
char tempFilename[MAX_PATH];
UINT uniqueNum;
pathSize = GetTempPath( 1000, pathBuffer);
if (pathSize < 1000)
pathBuffer[pathSize] = 0;
else
pathBuffer[0] = 0;
uniqueNum = GetTempFileName(pathBuffer, "tmp", FILE_FLAG_DELETE_ON_CLOSE , tempFilename);
strcpy(_template, tempFilename);
return _open(tempFilename, _O_RDWR|_O_BINARY);
}



#if defined(_MSC_VER) || defined(_MSC_EXTENSIONS)
#define DELTA_EPOCH_IN_MICROSECS 11644473600000000Ui64
#else
#define DELTA_EPOCH_IN_MICROSECS 11644473600000000ULL
#endif
int gettimeofday(struct timeval *tv, struct timezone *tz)
{
FILETIME ft;
unsigned __int64 tmpres = 0;
static int tzflag;
if (NULL != tv)
{
GetSystemTimeAsFileTime(&ft);
tmpres |= ft.dwHighDateTime;
tmpres <<= 32;
tmpres |= ft.dwLowDateTime;
/*converting file time to unix epoch*/
tmpres -= DELTA_EPOCH_IN_MICROSECS;
tmpres /= 10; /*convert into microseconds*/
tv->tv_sec = (long)(tmpres / 1000000UL);
tv->tv_usec = (long)(tmpres % 1000000UL);
}
if (NULL != tz)
{
if (!tzflag)
{
_tzset();
tzflag++;
}
tz->tz_minuteswest = _timezone / 60;
tz->tz_dsttime = _daylight;
}
return 0;
}
struct tm * gmtime_r(const time_t *clock, struct tm *result)
{
memcpy( result, gmtime(clock), sizeof(struct tm) );
return result;
}
struct tm * localtime_r(const time_t *clock, struct tm *result)
{
memcpy( result, localtime(clock), sizeof(struct tm) );
return result;
}
struct tm * localtime_rl(const long *clock, struct tm *result)
{
    time_t cl=(time_t)*clock;
memcpy( result, localtime(&cl), sizeof(struct tm) );
return result;
}

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


#ifndef FILE_MAP_EXECUTE
#define FILE_MAP_EXECUTE    0x0020
#endif /* FILE_MAP_EXECUTE */

static int __map_mman_error(const DWORD err, const int deferr)
{
    if (err == 0)
        return 0;
    //TODO: implement
    return err;
}

static DWORD __map_mmap_prot_page(const int prot)
{
    DWORD protect = 0;
   
    if (prot == PROT_NONE)
        return protect;
       
    if ((prot & PROT_EXEC) != 0)
    {
        protect = ((prot & PROT_WRITE) != 0) ?
                    PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
    }
    else
    {
        protect = ((prot & PROT_WRITE) != 0) ?
                    PAGE_READWRITE : PAGE_READONLY;
    }
   
    return protect;
}

static DWORD __map_mmap_prot_file(const int prot)
{
    DWORD desiredAccess = 0;
   
    if (prot == PROT_NONE)
        return desiredAccess;
       
    if ((prot & PROT_READ) != 0)
        desiredAccess |= FILE_MAP_READ;
    if ((prot & PROT_WRITE) != 0)
        desiredAccess |= FILE_MAP_WRITE;
    if ((prot & PROT_EXEC) != 0)
        desiredAccess |= FILE_MAP_EXECUTE;
   
    return desiredAccess;
}

void* mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off)
{
    HANDLE fm, h;
   
    void * map = MAP_FAILED;
   
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4293)
#endif

    const DWORD dwFileOffsetLow = (sizeof(off_t) <= sizeof(DWORD)) ?
                    (DWORD)off : (DWORD)(off & 0xFFFFFFFFL);
    const DWORD dwFileOffsetHigh = (sizeof(off_t) <= sizeof(DWORD)) ?
                    (DWORD)0 : (DWORD)((off >> 32) & 0xFFFFFFFFL);
    const DWORD protect = __map_mmap_prot_page(prot);
    const DWORD desiredAccess = __map_mmap_prot_file(prot);

    const off_t maxSize = off + (off_t)len;

    const DWORD dwMaxSizeLow = (sizeof(off_t) <= sizeof(DWORD)) ?
                    (DWORD)maxSize : (DWORD)(maxSize & 0xFFFFFFFFL);
    const DWORD dwMaxSizeHigh = (sizeof(off_t) <= sizeof(DWORD)) ?
                    (DWORD)0 : (DWORD)((maxSize >> 32) & 0xFFFFFFFFL);

#ifdef _MSC_VER
#pragma warning(pop)
#endif

    errno = 0;
   
    if (len == 0
        /* Unsupported flag combinations */
        || (flags & MAP_FIXED) != 0
        /* Usupported protection combinations */
        || prot == PROT_EXEC)
    {
        errno = EINVAL;
        return MAP_FAILED;
    }
   
    h = ((flags & MAP_ANONYMOUS) == 0) ?
                    (HANDLE)_get_osfhandle(fildes) : INVALID_HANDLE_VALUE;

    if ((flags & MAP_ANONYMOUS) == 0 && h == INVALID_HANDLE_VALUE)
    {
        errno = EBADF;
        return MAP_FAILED;
    }

    fm = CreateFileMapping(h, NULL, protect, dwMaxSizeHigh, dwMaxSizeLow, NULL);

    if (fm == NULL)
    {
        errno = __map_mman_error(GetLastError(), EPERM);
        return MAP_FAILED;
    }
 
    map = MapViewOfFile(fm, desiredAccess, dwFileOffsetHigh, dwFileOffsetLow, len);

    CloseHandle(fm);
 
    if (map == NULL)
    {
        errno = __map_mman_error(GetLastError(), EPERM);
        return MAP_FAILED;
    }

    return map;
}

int munmap(void *addr, size_t len)
{
    if (UnmapViewOfFile(addr))
        return 0;
       
    errno =  __map_mman_error(GetLastError(), EPERM);
   
    return -1;
}

int mprotect(void *addr, size_t len, int prot)
{
    DWORD newProtect = __map_mmap_prot_page(prot);
    DWORD oldProtect = 0;
   
    if (VirtualProtect(addr, len, newProtect, &oldProtect))
        return 0;
   
    errno =  __map_mman_error(GetLastError(), EPERM);
   
    return -1;
}

int msync(void *addr, size_t len, int flags)
{
    if (FlushViewOfFile(addr, len))
        return 0;
   
    errno =  __map_mman_error(GetLastError(), EPERM);
   
    return -1;
}

int mlock(const void *addr, size_t len)
{
    if (VirtualLock((LPVOID)addr, len))
        return 0;
       
    errno =  __map_mman_error(GetLastError(), EPERM);
   
    return -1;
}

int munlock(const void *addr, size_t len)
{
    if (VirtualUnlock((LPVOID)addr, len))
        return 0;
       
    errno =  __map_mman_error(GetLastError(), EPERM);
   
    return -1;
}

#define _SC_PAGESIZE 1
#define _SC_PHYS_PAGES 2
#define _SC_OPEN_MAX 3
#define _SC_AVPHYS_PAGES 4
#define _SC_PAGE_SIZE _SC_PAGESIZE
size_t szPageSize=0;
__inline size_t getpagesize()
{
	if (szPageSize == 0)
    {
        SYSTEM_INFO SystemInfo;
        GetSystemInfo( &SystemInfo );
        szPageSize = (size_t)SystemInfo.dwPageSize;
    }
	return szPageSize;
}
size_t sysconf(int type)
{
    switch (type) 
    
    {
        case _SC_PAGESIZE:
        {
            return getpagesize();
        }
        case _SC_PHYS_PAGES:
        {
            MEMORYSTATUSEX statex;
            statex.dwLength = sizeof (statex);
            GlobalMemoryStatusEx (&statex);
            return statex.ullTotalPhys/getpagesize();
        }
        case _SC_AVPHYS_PAGES:
        {
            MEMORYSTATUSEX statex;
            statex.dwLength = sizeof (statex);
            GlobalMemoryStatusEx (&statex);
            return statex.ullAvailPhys/getpagesize();
        }
        default:
            return (size_t)0;
    }
    return (size_t)0;
}

/* strndup.c
 *
 */

/* Written by Niels M�ller <nisse@lysator.liu.se>
 *
 * This file is hereby placed in the public domain.
 */


char *
strndup (const char *s, size_t size)
{
  char *r;
  const char *end = (const char *)memchr(s, 0, size);
  
  if (end)
    /* Length + 1 */
    size = end - s + 1;
  
  r = (char *)malloc(size);

  if (size)
    {
      memcpy(r, s, size-1);
      r[size-1] = '\0';
    }
  return r;
}





int
pgm_sockaddr_pton (
	const char* src,
	struct sockaddr* dst		/* will error on wrong size */
	)
{
    int status;
	struct addrinfo hints = {0}, *result = NULL;
    hints.ai_family	= AF_UNSPEC;
    hints.ai_socktype	= SOCK_STREAM;		/* not really */
    hints.ai_protocol	= IPPROTO_TCP;		/* not really */
    hints.ai_flags	= AI_NUMERICHOST;
	
	status = getaddrinfo (src, NULL, &hints, &result);
	if (0 == status) {
		memcpy (dst, result->ai_addr, result->ai_addrlen);
		freeaddrinfo (result);
		return 1;
	}
	return 0;
}

/* MSDN(GetAdaptersAddresses Function) recommends pre-allocating a 15KB
 * working buffer to reduce chances of a buffer overflow.
 * NB: The article actually recommends 15,000 and not 15,360 bytes.
 */
#	define DEFAULT_BUFFER_SIZE	15000
#define MAX_TRIES		3
struct _pgm_ifaddrs_t
{
	struct pgm_ifaddrs_t		_ifa;
	char				_name[IF_NAMESIZE];
	struct sockaddr_storage		_addr;
	struct sockaddr_storage		_netmask;
};

static __inline
void*
_pgm_heap_alloc (
        const size_t    n_bytes
        )
{
#       ifdef CONFIG_USE_HEAPALLOC
/* Does not appear very safe with re-entrant calls on XP */
        return HeapAlloc (GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, n_bytes);
#       else
        return malloc (n_bytes);
#       endif
}

static __inline
void
_pgm_heap_free (
        void*           mem
        )
{
#       ifdef CONFIG_USE_HEAPALLOC
        HeapFree (GetProcessHeap(), 0, mem);
#       else
        free (mem);
#       endif
}

/* NB: IP_ADAPTER_INFO size varies size due to sizeof (time_t), the API assumes
 * 4-byte datatype whilst compiler uses an 8-byte datatype.  Size can be forced
 * with -D_USE_32BIT_TIME_T with side effects to everything else.
 */

static
int
_pgm_getadaptersinfo (
        struct pgm_ifaddrs_t**  ifap
        )
{
        int n, k;
        struct _pgm_ifaddrs_t* ifa;
        struct _pgm_ifaddrs_t* ift;
        unsigned i;
        DWORD dwRet;
        ULONG ulOutBufLen = DEFAULT_BUFFER_SIZE;
        PIP_ADAPTER_INFO pAdapterInfo = NULL;
        PIP_ADAPTER_INFO pAdapter = NULL;

/* loop to handle interfaces coming online causing a buffer overflow
 * between first call to list buffer length and second call to enumerate.
 */
        for (i = MAX_TRIES; i; i--)
        {
                //pgm_debug ("IP_ADAPTER_INFO buffer length %lu bytes.", ulOutBufLen);
                pAdapterInfo = (IP_ADAPTER_INFO*)_pgm_heap_alloc (ulOutBufLen);
                dwRet = GetAdaptersInfo (pAdapterInfo, &ulOutBufLen);
                if (ERROR_BUFFER_OVERFLOW == dwRet) {
                        _pgm_heap_free (pAdapterInfo);
                        pAdapterInfo = NULL;
                } else {
                        break;
                }
        }

        switch (dwRet) {
        case ERROR_SUCCESS:     /* NO_ERROR */
                break;
        case ERROR_BUFFER_OVERFLOW:
                /*
                pgm_set_error (error,
                                PGM_ERROR_DOMAIN_IF,
                                PGM_ERROR_NOBUFS,
                                _("GetAdaptersInfo repeatedly failed with ERROR_BUFFER_OVERFLOW."));
                                */
                if (pAdapterInfo)
                        _pgm_heap_free (pAdapterInfo);
                return FALSE;
        default:
                /*
                pgm_set_error (error,
                                PGM_ERROR_DOMAIN_IF,
                                pgm_error_from_win_errno (dwRet),
                                _("GetAdaptersInfo failed: %s"),
                                pgm_adapter_strerror (dwRet));
                                */
                if (pAdapterInfo)
                        _pgm_heap_free (pAdapterInfo);
                return FALSE;
        }

/* count valid adapters */
        n = 0, k = 0;
        for (pAdapter = pAdapterInfo;
                 pAdapter;
                 pAdapter = pAdapter->Next)
        {
                IP_ADDR_STRING *pIPAddr;
                for (pIPAddr = &pAdapter->IpAddressList;
                         pIPAddr;
                         pIPAddr = pIPAddr->Next)
                {
/* skip null adapters */
                        if (strlen (pIPAddr->IpAddress.String) == 0)
                                continue;
                        ++n;
                }
        }

        //pgm_debug ("GetAdaptersInfo() discovered %d interfaces.", n);

/* contiguous block for adapter list */
        ifa = (struct _pgm_ifaddrs_t*) malloc(sizeof(struct _pgm_ifaddrs_t) * n);
        ift = ifa;

/* now populate list */
        for (pAdapter = pAdapterInfo;
                 pAdapter;
                 pAdapter = pAdapter->Next)
        {
                IP_ADDR_STRING *pIPAddr;
                for (pIPAddr = &pAdapter->IpAddressList;
                         pIPAddr;
                         pIPAddr = pIPAddr->Next)
                {
/* skip null adapters */
                        if (strlen (pIPAddr->IpAddress.String) == 0)
                                continue;

/* address */
                        ift->_ifa.ifa_addr = (struct sockaddr*)&ift->_addr;
                        assert(1 == pgm_sockaddr_pton (pIPAddr->IpAddress.String, ift->_ifa.ifa_addr));

/* name */
                        //pgm_debug ("name:%s IPv4 index:%lu",
                        //        pAdapter->AdapterName, pAdapter->Index);
                        ift->_ifa.ifa_name = ift->_name;
                        strncpy_s (ift->_ifa.ifa_name, IF_NAMESIZE, pAdapter->AdapterName, _TRUNCATE);

/* flags: assume up, broadcast and multicast */
                        ift->_ifa.ifa_flags = IFF_UP | IFF_BROADCAST | IFF_MULTICAST;
                        if (pAdapter->Type == MIB_IF_TYPE_LOOPBACK)
                                ift->_ifa.ifa_flags |= IFF_LOOPBACK;

/* netmask */
                        ift->_ifa.ifa_netmask = (struct sockaddr*)&ift->_netmask;
                        assert(1 == pgm_sockaddr_pton (pIPAddr->IpMask.String, ift->_ifa.ifa_netmask));

/* next */
                        if (k++ < (n - 1)) {
                                ift->_ifa.ifa_next = (struct pgm_ifaddrs_t*)(ift + 1);
                                ift = (struct _pgm_ifaddrs_t*)(ift->_ifa.ifa_next);
                        }
                }
        }

        if (pAdapterInfo)
                _pgm_heap_free (pAdapterInfo);
        *ifap = (struct pgm_ifaddrs_t*)ifa;
        return TRUE;
}

static
int
_pgm_getadaptersaddresses (
        struct pgm_ifaddrs_t**  ifap
        )
{
        struct _pgm_ifaddrs_t* ifa;
        struct _pgm_ifaddrs_t* ift;
        unsigned i;
        int n, k;
        DWORD dwSize = DEFAULT_BUFFER_SIZE, dwRet;
        IP_ADAPTER_ADDRESSES *pAdapterAddresses = NULL, *adapter;

/* loop to handle interfaces coming online causing a buffer overflow
 * between first call to list buffer length and second call to enumerate.
 */
        for (i = MAX_TRIES; i; i--)
        {
                //pgm_debug ("IP_ADAPTER_ADDRESSES buffer length %lu bytes.", dwSize);
                pAdapterAddresses = (IP_ADAPTER_ADDRESSES*)_pgm_heap_alloc (dwSize);
                dwRet = GetAdaptersAddresses (AF_UNSPEC,
                                                GAA_FLAG_INCLUDE_PREFIX |
                                                GAA_FLAG_SKIP_ANYCAST |
                                                GAA_FLAG_SKIP_DNS_SERVER |
                                                GAA_FLAG_SKIP_FRIENDLY_NAME |
                                                GAA_FLAG_SKIP_MULTICAST,
                                                NULL,
                                                pAdapterAddresses,
                                                &dwSize);
                if (ERROR_BUFFER_OVERFLOW == dwRet) {
                        _pgm_heap_free (pAdapterAddresses);
                        pAdapterAddresses = NULL;
                } else {
                        break;
                }
        }

        switch (dwRet) {
        case ERROR_SUCCESS:
                break;
        case ERROR_BUFFER_OVERFLOW:
                /*
                    pgm_set_error (error,
                                PGM_ERROR_DOMAIN_IF,
                                PGM_ERROR_NOBUFS,
                                _("GetAdaptersAddresses repeatedly failed with ERROR_BUFFER_OVERFLOW."));
                                */
                if (pAdapterAddresses)
                        _pgm_heap_free (pAdapterAddresses);
                return FALSE;
        default:
                /*
                pgm_set_error (error,
                                PGM_ERROR_DOMAIN_IF,
                                pgm_error_from_win_errno (dwRet),
                                _("GetAdaptersAddresses failed: %s"),
                                pgm_adapter_strerror (dwRet));
                                */
                if (pAdapterAddresses)
                        _pgm_heap_free (pAdapterAddresses);
                return FALSE;
        }

/* count valid adapters */
        n = 0, k = 0;
        for (adapter = pAdapterAddresses;
                 adapter;
                 adapter = adapter->Next)
        {
                IP_ADAPTER_UNICAST_ADDRESS *unicast;
                for (unicast = adapter->FirstUnicastAddress;
                         unicast;
                         unicast = unicast->Next)
                {
/* ensure IP adapter */
                        if (AF_INET != unicast->Address.lpSockaddr->sa_family &&
                            AF_INET6 != unicast->Address.lpSockaddr->sa_family)
                        {
                                continue;
                        }

                        ++n;
                }
        }

/* contiguous block for adapter list */
        ifa = (struct _pgm_ifaddrs_t*) malloc(sizeof(struct _pgm_ifaddrs_t) * n);
        ift = ifa;

/* now populate list */
        for (adapter = pAdapterAddresses;
                 adapter;
                 adapter = adapter->Next)
        {
                int unicastIndex = 0;
                IP_ADAPTER_UNICAST_ADDRESS *unicast;
                for (unicast = adapter->FirstUnicastAddress;
                         unicast;
                         unicast = unicast->Next, ++unicastIndex)
                {
                        IP_ADAPTER_PREFIX *prefix;
                        int prefixIndex;
                        ULONG prefixLength;
                        ULONG i,j;
/* ensure IP adapter */
                        if (AF_INET != unicast->Address.lpSockaddr->sa_family &&
                            AF_INET6 != unicast->Address.lpSockaddr->sa_family)
                        {
                                continue;
                        }

/* address */
                        ift->_ifa.ifa_addr = (struct sockaddr*)&ift->_addr;
                        memcpy (ift->_ifa.ifa_addr, unicast->Address.lpSockaddr, unicast->Address.iSockaddrLength);

/* name */
                        //pgm_debug ("name:%s IPv4 index:%lu IPv6 index:%lu",
                        //        adapter->AdapterName, adapter->IfIndex, adapter->Ipv6IfIndex);
                        ift->_ifa.ifa_name = ift->_name;
                        strncpy_s (ift->_ifa.ifa_name, IF_NAMESIZE, adapter->AdapterName, _TRUNCATE);

/* flags */
                        ift->_ifa.ifa_flags = 0;
                        if (IfOperStatusUp == adapter->OperStatus)
                                ift->_ifa.ifa_flags |= IFF_UP;
                        if (IF_TYPE_SOFTWARE_LOOPBACK == adapter->IfType)
                                ift->_ifa.ifa_flags |= IFF_LOOPBACK;
                        if (!(adapter->Flags & IP_ADAPTER_NO_MULTICAST))
                                ift->_ifa.ifa_flags |= IFF_MULTICAST;

/* netmask */
                        ift->_ifa.ifa_netmask = (struct sockaddr*)&ift->_netmask;

/* pre-Vista must hunt for matching prefix in linked list, otherwise use OnLinkPrefixLength */
                        prefixIndex = 0;
                        prefixLength = 0;
                        for (prefix = adapter->FirstPrefix;
                                prefix;
                                prefix = prefix->Next, ++prefixIndex)
                        {
                                if (prefixIndex == unicastIndex) {
                                        prefixLength = prefix->PrefixLength;
                                        break;
                                }
                        }

/* map prefix to netmask */
                        ift->_ifa.ifa_netmask->sa_family = unicast->Address.lpSockaddr->sa_family;
                        switch (unicast->Address.lpSockaddr->sa_family) {
                        case AF_INET:
                                if (0 == prefixLength) {
                                        //pgm_trace (PGM_LOG_ROLE_NETWORK,_("IPv4 adapter %s prefix length is 0, overriding to 32."), adapter->AdapterName);
                                        prefixLength = 32;
                                }
                                ((struct sockaddr_in*)ift->_ifa.ifa_netmask)->sin_addr.s_addr = htonl( 0xffffffffU << ( 32 - prefixLength ) );
                                break;

                        case AF_INET6:
                                if (0 == prefixLength) {
                                        //pgm_trace (PGM_LOG_ROLE_NETWORK,_("IPv6 adapter %s prefix length is 0, overriding to 128."), adapter->AdapterName);
                                        prefixLength = 128;
                                }
                                for (i = prefixLength, j = 0; i > 0; i -= 8, ++j)
                                {
                                        ((struct sockaddr_in6*)ift->_ifa.ifa_netmask)->sin6_addr.s6_addr[ j ] = i >= 8 ? 0xff : (ULONG)(( 0xffU << ( 8 - i ) ) & 0xffU );
                                }
                                break;
                        }

/* next */
                        if (k++ < (n - 1)) {
                                ift->_ifa.ifa_next = (struct pgm_ifaddrs_t*)(ift + 1);
                                ift = (struct _pgm_ifaddrs_t*)(ift->_ifa.ifa_next);
                        }
                }
        }

        if (pAdapterAddresses)
                _pgm_heap_free (pAdapterAddresses);
        *ifap = (struct pgm_ifaddrs_t*)ifa;
        return TRUE;
}


/* returns TRUE on success setting ifap to a linked list of system interfaces,
 * returns FALSE on failure and sets error appropriately.
 */

int
getifaddrs (struct pgm_ifaddrs_t**  ifap)
{
        assert(NULL != ifap);

        //pgm_debug ("pgm_getifaddrs (ifap:%p error:%p)",
        //        (void*)ifap, (void*)error);

#ifdef CONFIG_HAVE_GETIFADDRS
        const int e = getifaddrs ((struct ifaddrs**)ifap);
        if (-1 == e) {
                char errbuf[1024];
                pgm_set_error (error,
                                PGM_ERROR_DOMAIN_IF,
                                pgm_error_from_errno (errno),
                                _("getifaddrs failed: %s"),
                                pgm_strerror_s (errbuf, sizeof (errbuf), errno));
                return FALSE;
        }
        return TRUE;
#elif defined(CONFIG_TARGET_WINE)
        return _pgm_getadaptersinfo (ifap, error);
#elif defined(_WIN32)
        return _pgm_getadaptersaddresses (ifap);
#elif defined(SIOCGLIFCONF)
        return _pgm_getlifaddrs (ifap, error);
#elif defined(SIOCGIFCONF)
        return _pgm_getifaddrs (ifap, error);
#else
#       error "Unsupported interface enumeration on this platform."
#endif /* !CONFIG_HAVE_GETIFADDRS */
}
void
freeifaddrs (
        struct pgm_ifaddrs_t*   ifa
        )
{
        //pgm_return_if_fail (NULL != ifa);

#ifdef CONFIG_HAVE_GETIFADDRS
        freeifaddrs ((struct ifaddrs*)ifa);
#else
        free (ifa);
#endif
}

#define MAX_TRIES		3
#define DEFAULT_BUFFER_SIZE	4096

/* Retrieve adapter index via name.
 * Wine edition:  First try GetAdapterIndex() then fallback to enumerating
 * adapters via GetAdaptersInfo().
 *
 * On error returns zero, no errors are defined.
 *
 * Requires Windows 2000 or Wine 1.0.
 */
typedef int sa_family_t;
static
unsigned					/* type matching if_nametoindex() */
_pgm_getadaptersinfo_nametoindex (
	const sa_family_t	iffamily,
	const char*		ifname
        )
{
    unsigned i;
    DWORD dwRet, ifIndex;
	ULONG ulOutBufLen = DEFAULT_BUFFER_SIZE;
	PIP_ADAPTER_INFO pAdapterInfo = NULL;
	PIP_ADAPTER_INFO pAdapter = NULL;
	if(ifname != NULL) return 0;

	assert (AF_INET6 != iffamily);

	

/* loop to handle interfaces coming online causing a buffer overflow
 * between first call to list buffer length and second call to enumerate.
 */
	for (i = MAX_TRIES; i; i--)
	{
		//pgm_debug ("IP_ADAPTER_INFO buffer length %lu bytes.", ulOutBufLen);
		pAdapterInfo = (IP_ADAPTER_INFO*)_pgm_heap_alloc (ulOutBufLen);
		dwRet = GetAdaptersInfo (pAdapterInfo, &ulOutBufLen);
		if (ERROR_BUFFER_OVERFLOW == dwRet) {
			_pgm_heap_free (pAdapterInfo);
			pAdapterInfo = NULL;
		} else {
			break;
		}
	}

	switch (dwRet) {
	case ERROR_SUCCESS:	/* NO_ERROR */
		break;
	case ERROR_BUFFER_OVERFLOW:
		//pgm_warn (_("GetAdaptersInfo repeatedly failed with ERROR_BUFFER_OVERFLOW."));
		if (pAdapterInfo)
			_pgm_heap_free (pAdapterInfo);
		return 0;
	default:
		//pgm_warn (_("GetAdaptersInfo failed"));
		if (pAdapterInfo)
			_pgm_heap_free (pAdapterInfo);
		return 0;
	}

	for (pAdapter = pAdapterInfo;
		 pAdapter;
		 pAdapter = pAdapter->Next)
	{
        IP_ADDR_STRING *pIPAddr;
		for (pIPAddr = &pAdapter->IpAddressList;
			 pIPAddr;
			 pIPAddr = pIPAddr->Next)
		{
/* skip null adapters */
			if (strlen (pIPAddr->IpAddress.String) == 0)
				continue;

			if (0 == strncmp (ifname, pAdapter->AdapterName, IF_NAMESIZE)) {
				ifIndex = pAdapter->Index;
				_pgm_heap_free (pAdapterInfo);
				return ifIndex;
			}
		}
	}

	if (pAdapterInfo)
		_pgm_heap_free (pAdapterInfo);
	return 0;
}

/* Retrieve adapter index via name.
 * Windows edition:  First try GetAdapterIndex() then fallback to enumerating
 * adapters via GetAdaptersAddresses().
 *
 * On error returns zero, no errors are defined.
 *
 * Requires Windows XP or Wine 1.3.
 */

static
unsigned					/* type matching if_nametoindex() */
_pgm_getadaptersaddresses_nametoindex (
	const sa_family_t	iffamily,
	const char*		ifname
        )
{
    unsigned i;
    ULONG ifIndex;
	DWORD dwSize = DEFAULT_BUFFER_SIZE, dwRet;
	IP_ADAPTER_ADDRESSES *pAdapterAddresses = NULL, *adapter;
	char szAdapterName[IF_NAMESIZE];
    
	if(ifname != NULL) return 0;

	

/* first see if GetAdapterIndex is working,
 */
	strncpy_s (szAdapterName, sizeof (szAdapterName), ifname, _TRUNCATE);
	dwRet = GetAdapterIndex ((LPWSTR)szAdapterName, &ifIndex);
	if (NO_ERROR == dwRet)
		return ifIndex;

/* fallback to finding index via iterating adapter list */

/* loop to handle interfaces coming online causing a buffer overflow
 * between first call to list buffer length and second call to enumerate.
 */
	for (i = MAX_TRIES; i; i--)
	{
		pAdapterAddresses = (IP_ADAPTER_ADDRESSES*)_pgm_heap_alloc (dwSize);
		dwRet = GetAdaptersAddresses (AF_UNSPEC,
						GAA_FLAG_SKIP_ANYCAST |
						GAA_FLAG_SKIP_DNS_SERVER |
						GAA_FLAG_SKIP_FRIENDLY_NAME |
						GAA_FLAG_SKIP_MULTICAST,
						NULL,
						pAdapterAddresses,
						&dwSize);
		if (ERROR_BUFFER_OVERFLOW == dwRet) {
			_pgm_heap_free (pAdapterAddresses);
			pAdapterAddresses = NULL;
		} else {
			break;
		}
	}

	switch (dwRet) {
	case ERROR_SUCCESS:
		break;
	case ERROR_BUFFER_OVERFLOW:
		//pgm_warn (_("GetAdaptersAddresses repeatedly failed with ERROR_BUFFER_OVERFLOW"));
		if (pAdapterAddresses)
			_pgm_heap_free (pAdapterAddresses);
		return 0;
	default:
		//pgm_warn (_("GetAdaptersAddresses failed"));
		if (pAdapterAddresses)
			_pgm_heap_free (pAdapterAddresses);
		return 0;
	}

	for (adapter = pAdapterAddresses;
		adapter;
		adapter = adapter->Next)
	{
		if (0 == strcmp (szAdapterName, adapter->AdapterName)) {
			ifIndex = AF_INET6 == iffamily ? adapter->Ipv6IfIndex : adapter->IfIndex;
			_pgm_heap_free (pAdapterAddresses);
			return ifIndex;
		}
	}

	if (pAdapterAddresses)
		_pgm_heap_free (pAdapterAddresses);
	return 0;
}


/* Retrieve interface index for a specified adapter name.
 * On error returns zero, no errors are defined.
 */

unsigned int					/* type matching if_nametoindex() */
pgm_if_nametoindex (
	const char*		ifname
        )
{
#if _WIN32_WINNT   < 0x0600    
    unsigned int index;
#endif    
	if(ifname != NULL) return 0;
    
#if _WIN32_WINNT  >= 0x0600
/* Vista+ implements if_nametoindex for IPv6 */
	return if_nametoindex (ifname);
#else
#pragma message("pgm_if_nametoindex uses _pgm_getadaptersaddresses_nametoindex")    
	index = _pgm_getadaptersaddresses_nametoindex (AF_INET, ifname);
    if (index>0)
        return index;
    return _pgm_getadaptersaddresses_nametoindex (AF_INET6, ifname);
#endif
}






/*
   Copyright (C) 2002 Luc Van Oostenryck

   This is free software. You can redistribute and
   modify it under the terms of the GNU General Public
   Public License.
*/

//#include "target_winver.h"
//#include <stdlib.h>

/* Knuth's TAOCP section 3.6 */
#define M       ((1U<<31) -1)
#define A       48271
#define Q       44488           // M/A
#define R       3399            // M%A; R < Q !!!

// FIXME: ISO C/SuS want a longer period

long long rand_rl(unsigned long long* seed)
{
        long long X;

    X = *seed;
    X = A*(X%Q) - R * (long long) (X/Q);
    if (X < 0)
                X += M;

    *seed = X;
    return X;
}

int rand_r(unsigned int* seed)
{
        int X;

    X = *seed;
    X = A*(X%Q) - R * (int) (X/Q);
    if (X < 0)
                X += M;

    *seed = X;
    return X;
}

/* Windows platforms.  */


/* The Win32 function Sleep() has a resolution of about 15 ms and takes
   at least 5 ms to execute.  We use this function for longer time periods.
   Additionally, we use busy-looping over short time periods, to get a
   resolution of about 0.01 ms.  In order to measure such short timespans,
   we use the QueryPerformanceCounter() function.  */
#define BILLION 1000000000000.0
int
nanosleep (const struct timespec *requested_delay,
           struct timespec *remaining_delay)
{
  static int initialized =0;
  /* Number of performance counter increments per nanosecond,
     or zero if it could not be determined.  */
  static double ticks_per_nanosecond;

  if (requested_delay->tv_nsec < 0 || BILLION <= requested_delay->tv_nsec)
    {
      errno = EINVAL;
      return -1;
    }

  /* For requested delays of one second or more, 15ms resolution is
     sufficient.  */
  if (requested_delay->tv_sec == 0)
    {
      if (!initialized)
        {
          /* Initialize ticks_per_nanosecond.  */
          LARGE_INTEGER ticks_per_second;

          if (QueryPerformanceFrequency (&ticks_per_second))
            ticks_per_nanosecond =
              (double) ticks_per_second.QuadPart / 1000000000.0;

          initialized = 1;
        }
      if (ticks_per_nanosecond)
        {
          /* QueryPerformanceFrequency worked.  We can use
             QueryPerformanceCounter.  Use a combination of Sleep and
             busy-looping.  */
          /* Number of milliseconds to pass to the Sleep function.
             Since Sleep can take up to 8 ms less or 8 ms more than requested
             (or maybe more if the system is loaded), we subtract 10 ms.  */
          int sleep_millis = (int) requested_delay->tv_nsec / 1000000 - 10;
          /* Determine how many ticks to delay.  */
          LONGLONG wait_ticks = requested_delay->tv_nsec * 
ticks_per_nanosecond;
          /* Start.  */
          LARGE_INTEGER counter_before;
          if (QueryPerformanceCounter (&counter_before))
            {
              /* Wait until the performance counter has reached this value.
                 We don't need to worry about overflow, because the performance
                 counter is reset at reboot, and with a frequency of 3.6E6
                 ticks per second 63 bits suffice for over 80000 years.  */
              LONGLONG wait_until = counter_before.QuadPart + wait_ticks;
              /* Use Sleep for the longest part.  */
              if (sleep_millis > 0)
                Sleep (sleep_millis);
              /* Busy-loop for the rest.  */
              for (;;)
                {
                  LARGE_INTEGER counter_after;
                  if (!QueryPerformanceCounter (&counter_after))
                    /* QueryPerformanceCounter failed, but succeeded earlier.
                       Should not happen.  */
                    break;
                  if (counter_after.QuadPart >= wait_until)
                    /* The requested time has elapsed.  */
                    break;
                }
              goto done;
            }
        }
    }
  /* Implementation for long delays and as fallback.  */
  Sleep (requested_delay->tv_sec * 1000 + requested_delay->tv_nsec / 1000000);

 done:
  /* Sleep is not interruptible.  So there is no remaining delay.  */
  if (remaining_delay != NULL)
    {
      remaining_delay->tv_sec = 0;
      remaining_delay->tv_nsec = 0;
    }
  return 0;
}

int sigaction(int sig, struct sigaction *action, struct sigaction *old)
{
    if (sig == -1)
        return 0;
    if (old == NULL)
    {
        if (signal(sig, SIG_DFL) == SIG_ERR)
            return -1;
    }
    else
    {
        if (signal(sig, action->sa_handler) == SIG_ERR)
            return -1;
    }
    return 0;
}
