#ifndef __PKT_CONFIG__
#define __PKT_CONFIG__

#if (defined(WIN32) || defined(_WIN32) || defined(__WIN32)) && !defined(__CYGWIN__)
#define PKT_WIN_NATIVE
#endif

#if defined(__CYGWIN__)
#define PKT_CYGWIN
#endif

#if defined(PKT_WIN_NATIVE) || defined(PKT_CYGWIN)
#define PKT_WIN32
#endif

#if !defined(PS_WIN_NATIVE)
#define PKT_POSIX
#endif

#if defined(_MSC_VER)
#define PKT_MSVC
#if !defined(_DEBUG) && !defined(__PKT_INLINE__)
#define __PKT_INLINE__
#endif
#endif

#if defined(__GNUC__)
#define PKT_GCC
#if __GNUC__ < 4
#define PKT_GCC3
#endif
#if !defined (__PKT_INLINE__)
#define __PKT_INLINE__
#endif
#endif

#if defined(PKT_LACKS_INLINE_FUNCTIONS) && !defined(PKT_NO_INLINE)
#define PKT_NO_INLINE
#endif

#if defined(PKT_NO_INLINE)
#undef __PKT_INLINE__
#endif

#if defined(__PKT_INLINE__)
#define PKT_INLINE inline
#else
#define PKT_INLINE
#endif

#if defined(PKT_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#endif

#if defined(PKT_MSVC)
#define PACKED( __decl__ ) __pragma(pack(push, 1)) __decl__ __pragma(pack(pop))
#else
#define PACKED( __decl__ ) __decl__ __attribute__((__packed__))
#endif

#if !defined(IPPROTO_IPIP)
#define IPPROTO_IPIP 4
#endif

#if !defined(IPPROTO_GRE)
#define IPPROTO_GRE 47
#endif

#if !defined(IPPROTO_MH)
#define IPPROTO_MH 135
#endif

#if !defined(IPPROTO_HIP)
#define IPPROTO_HIP 139
#endif

#if !defined(IPPROTO_SHIM6)
#define IPPROTO_SHIM6 140
#endif

#endif
