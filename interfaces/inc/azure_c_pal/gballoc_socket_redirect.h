// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef SOCKET_REDIRECT_H
#define SOCKET_REDIRECT_H

/*this file provides a convenient way of having all the socket preprocessor tokens in a source file replaced by their gballoc_socket counterparts*/

#define socket gballoc_socket_socket
#define send gballoc_socket_send
#define recv gballoc_socket_recv
#define connect gballoc_socket_connect
#define fcntl gballoc_socket_fcntl
#define shutdown gballoc_socket_shutdown
#define getaddrinfo gballoc_socket_getaddrinfo
#define freeaddrinfo gballoc_socket_freeaddrinfo
#define bind gballoc_socket_bind
#define listen gballoc_socket_listen
#define accept gballoc_socket_accept

#ifdef WIN32
#define closesocket gballoc_socket_close
#define ioctlsocket gballoc_socket_ioctlsocket
#define WSAStartup gballoc_socket_wsastartup
#define WSACleanup gballoc_socket_wsacleanup
#define WSAGetLastError gballoc_socket_wsagetlasterror
#define htons gballoc_socket_htons
#define WSASend gballoc_socket_wsasend
#define WSARecv gballoc_socket_wsarecv
#else
#define close gballoc_socket_close
//#define shutdown gballoc_socket_shutdown
#endif

#endif // SOCKET_REDIRECT_H
