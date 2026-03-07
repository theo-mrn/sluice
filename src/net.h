#ifndef SLUICE_NET_H
#define SLUICE_NET_H

/* Plain sockets: no protocol knowledge here. */

#include <stddef.h>
#include <sys/socket.h>

/* send() flag that turns a write to a closed peer into EPIPE instead of SIGPIPE, where it exists.
 */
#ifdef MSG_NOSIGNAL
#define SL_SEND_FLAGS MSG_NOSIGNAL
#else
#define SL_SEND_FLAGS 0
#endif

int sl_net_set_nonblocking(int fd);

/* TCP_NODELAY (queries and answers are small and latency matters), close-on-exec, no SIGPIPE, and
 * TCP keepalive: a peer that vanished without closing (a machine switched off, a cable cut, a NAT
 * that forgot the connection) is noticed after about two minutes instead of never, and its slot is
 * given back. */
void sl_net_tune(int fd);

/* True for "localhost" and for an address that never leaves the machine: 127.0.0.0/8 and ::1 (as an
 * IPv4 address, an IPv6 one, or an IPv4-mapped one). A name that merely looks like one
 * ("127.example.com") is not. */
int sl_net_host_is_local(const char *host);

/* Non-blocking listening socket. Returns the fd, or -1 with a message in err. */
int sl_net_listen(const char *host, const char *port, char *err, size_t errcap);

/* Connecting to a name that has several addresses ("localhost" is ::1 and 127.0.0.1; a service can
 * have an IPv6 and an IPv4 address). The addresses are tried one after the other, each by a
 * non-blocking connect: when one is refused or unreachable, the next one is tried, so that a
 * database listening on IPv4 only is reached through "localhost" too. An address that does not
 * answer at all is waited for until the connection timeout of the caller; the others are not tried
 * before that. */
typedef struct sl_net_target sl_net_target;

/* Resolves host:port. Resolving the name blocks. Returns NULL with a message in err. */
sl_net_target *sl_net_target_resolve(const char *host, const char *port, char *err, size_t errcap);

/* Starts a non-blocking connect to the next address that can be tried. Returns the fd (completion
 * is signalled by the socket becoming writable, then check sl_net_connect_result), or -1 with a
 * message in err when no address is left. `failed` is the errno of the attempt that has just failed
 * (from sl_net_connect_result), or 0 for the first call; it is what the message reports if this is
 * the last one. */
int sl_net_target_next(sl_net_target *t, int failed, char *err, size_t errcap);
void sl_net_target_free(sl_net_target *t);

/* After a non-blocking connect became writable: 0 if connected, else the errno value. */
int sl_net_connect_result(int fd);

/* The port a bound socket is really using (useful when 0 was requested), or -1. */
int sl_net_local_port(int fd);

/* "ip:port" of the peer, or "unknown". */
void sl_net_peer_str(int fd, char *out, size_t cap);

#endif
