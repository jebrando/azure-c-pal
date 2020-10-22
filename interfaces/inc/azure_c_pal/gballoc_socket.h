// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef GBALLOC_SOCKET_H
#define GBALLOC_SOCKET_H

#ifdef __cplusplus
#include <cstdlib>
#include <cstdint>
extern "C" {
#else
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#endif

#include "umock_c/umock_c_prod.h"
#ifdef WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netdb.h>
#endif

#if defined(USE_SOCKET_DEBUG_SHIM)
MOCKABLE_FUNCTION(, int, gballoc_socket_init);
MOCKABLE_FUNCTION(, void, gballoc_socket_deinit);

#ifdef WIN32
MOCKABLE_FUNCTION(, SOCKET, gballoc_socket_socket, int, af, int, type, int, protocol);
#else
MOCKABLE_FUNCTION(, int, gballoc_socket_socket, int, domain, int, type, int, protocol);
#endif

#ifdef WIN32
MOCKABLE_FUNCTION(, int, gballoc_socket_send, SOCKET, sock, const char*, buf, int, len, int, flags);
#else
MOCKABLE_FUNCTION(, ssize_t, gballoc_socket_send, int, sock, const void*, buf, size_t, len, int, flags);
#endif

#ifdef WIN32
MOCKABLE_FUNCTION(, int, gballoc_socket_recv, SOCKET, sock, char*, buf, int, len, int, flags);
#else
MOCKABLE_FUNCTION(, ssize_t, gballoc_socket_recv, int, sock, void*, buf, size_t, len, int, flags);
#endif

#ifdef WIN32
MOCKABLE_FUNCTION(, int, gballoc_socket_connect, SOCKET, sock, const struct sockaddr*, name, int, len);
#else
MOCKABLE_FUNCTION(, int, gballoc_socket_connect, int, sock, __CONST_SOCKADDR_ARG, addr, socklen_t, len);
#endif

#ifdef WIN32
MOCKABLE_FUNCTION(, int, gballoc_socket_getaddrinfo, PCSTR, node, PCSTR, svc_name, const ADDRINFOA*, hints, PADDRINFOA*, res);
#else
MOCKABLE_FUNCTION(, int, gballoc_socket_getaddrinfo, const char*, node, const char*, svc_name, const struct addrinfo*, hints, struct addrinfo**, res);
#endif

#ifdef WIN32
MOCKABLE_FUNCTION(, int, gballoc_socket_shutdown, SOCKET, node, int, how);
#else
MOCKABLE_FUNCTION(, int, gballoc_socket_shutdown, int, sockfd, int, how);
#endif

#ifdef WIN32
MOCKABLE_FUNCTION(, int, gballoc_socket_close, SOCKET, sock);
#else
MOCKABLE_FUNCTION(, int, gballoc_socket_close, int, sock);
#endif

#ifdef WIN32
MOCKABLE_FUNCTION(, void, gballoc_socket_freeaddrinfo, struct addrinfo*, res);
#else
MOCKABLE_FUNCTION(, void, gballoc_socket_freeaddrinfo, struct addrinfo*, res);
#endif

#ifdef WIN32
MOCKABLE_FUNCTION(, int, gballoc_socket_bind, SOCKET, __fd, const struct sockaddr FAR*, __addr, int, __len);
#else
MOCKABLE_FUNCTION(, int, gballoc_socket_bind, int, __fd, __CONST_SOCKADDR_ARG, __addr, socklen_t, __len);
#endif

#ifdef WIN32
MOCKABLE_FUNCTION(, int, gballoc_socket_listen, SOCKET, __fd, int, __n);
#else
MOCKABLE_FUNCTION(, int, gballoc_socket_listen, int, __fd, int, __n);
#endif

#ifdef WIN32
MOCKABLE_FUNCTION(, int, gballoc_socket_accept, SOCKET, __fd, struct sockaddr FAR*, __addr, int FAR*, __addr_len);
#else
MOCKABLE_FUNCTION(, int, gballoc_socket_accept, int, __fd, __SOCKADDR_ARG, __addr, socklen_t*, __addr_len);
#endif

#ifdef WIN32
MOCKABLE_FUNCTION(, int, gballoc_socket_ioctlsocket, SOCKET, s, long, cmd, u_long*, argp);
MOCKABLE_FUNCTION(, int, gballoc_socket_wsastartup, WORD, wVersionRequested, LPWSADATA, lpWSAData);
MOCKABLE_FUNCTION(, int, gballoc_socket_wsacleanup);
MOCKABLE_FUNCTION(, int, gballoc_socket_wsagetlasterror);
MOCKABLE_FUNCTION(, u_short, gballoc_socket_htons, u_short, hostshort);
MOCKABLE_FUNCTION(, int, gballoc_socket_wsarecv, SOCKET, s, LPWSABUF, lpBuffers, DWORD, dwBufferCount, LPDWORD, lpNumberOfBytesRecvd,
    LPDWORD, lpFlags, LPWSAOVERLAPPED, lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE, lpCompletionRoutine);
MOCKABLE_FUNCTION(, int, gballoc_socket_wsasend, SOCKET, s, LPWSABUF, lpBuffers, DWORD, dwBufferCount, LPDWORD, lpNumberOfBytesSent, DWORD, dwFlags,
    LPWSAOVERLAPPED, lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE, lpCompletionRoutine);
#endif

extern int gballoc_socket_fcntl(int __fd, int __cmd, ...);

MOCKABLE_FUNCTION(, uint64_t, gballoc_socket_get_bytes_sent);
MOCKABLE_FUNCTION(, uint64_t, gballoc_socket_get_num_sends);
MOCKABLE_FUNCTION(, uint64_t, gballoc_socket_get_bytes_recv);
MOCKABLE_FUNCTION(, uint64_t, gballoc_socket_get_num_recv);
MOCKABLE_FUNCTION(, void, gballoc_socket_reset);

#else // USE_SOCKET_DEBUG_SHIM

#define gballoc_socket_init() 0
#define gballoc_socket_deinit() ((void)0)

#define gballoc_socket_get_bytes_sent     0
#define gballoc_socket_get_num_sends      0
#define gballoc_socket_get_bytes_recv     0
#define gballoc_socket_get_num_recv       0
#define gballoc_socket_reset()            0

#endif  // USE_SOCKET_DEBUG_SHIM

#ifdef __cplusplus
}
#endif

#endif // GBALLOC_SOCKET_H
