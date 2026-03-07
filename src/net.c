#include "net.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

int sl_net_set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* A silent peer is probed after KEEPALIVE_IDLE seconds, then every KEEPALIVE_INTERVAL, and given up
 * on after KEEPALIVE_COUNT unanswered probes: about two minutes in all. The system default is two
 * hours. */
#define KEEPALIVE_IDLE 60
#define KEEPALIVE_INTERVAL 10
#define KEEPALIVE_COUNT 6

static void set_int_option(int fd, int level, int name, int value)
{
    (void)setsockopt(fd, level, name, &value, sizeof value);
}

void sl_net_tune(int fd)
{
    set_int_option(fd, IPPROTO_TCP, TCP_NODELAY, 1);
#ifdef SO_NOSIGPIPE
    set_int_option(fd, SOL_SOCKET, SO_NOSIGPIPE, 1);
#endif
    set_int_option(fd, SOL_SOCKET, SO_KEEPALIVE, 1);
#if defined(TCP_KEEPIDLE)
    set_int_option(fd, IPPROTO_TCP, TCP_KEEPIDLE, KEEPALIVE_IDLE); /* Linux */
#elif defined(TCP_KEEPALIVE)
    set_int_option(fd, IPPROTO_TCP, TCP_KEEPALIVE, KEEPALIVE_IDLE); /* macOS: the idle time */
#endif
#ifdef TCP_KEEPINTVL
    set_int_option(fd, IPPROTO_TCP, TCP_KEEPINTVL, KEEPALIVE_INTERVAL);
#endif
#ifdef TCP_KEEPCNT
    set_int_option(fd, IPPROTO_TCP, TCP_KEEPCNT, KEEPALIVE_COUNT);
#endif
    (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
}

int sl_net_host_is_local(const char *host)
{
    struct in_addr a4;
    struct in6_addr a6;

    if (strcasecmp(host, "localhost") == 0) {
        return 1;
    }
    if (inet_pton(AF_INET, host, &a4) == 1) {
        return (ntohl(a4.s_addr) >> 24) == 127;
    }
    if (inet_pton(AF_INET6, host, &a6) == 1) {
        if (IN6_IS_ADDR_LOOPBACK(&a6)) {
            return 1;
        }
        return IN6_IS_ADDR_V4MAPPED(&a6) && a6.s6_addr[12] == 127;
    }
    return 0;
}

int sl_net_listen(const char *host, const char *port, char *err, size_t errcap)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    int fd = -1;
    int last_errno = 0;
    int rc;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        snprintf(err, errcap, "cannot resolve listen address %s: %s", host, gai_strerror(rc));
        return -1;
    }

    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        int one = 1;

        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            last_errno = errno;
            continue;
        }
        (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0 && listen(fd, 128) == 0 &&
            sl_net_set_nonblocking(fd) == 0) {
            break;
        }
        last_errno = errno;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) {
        snprintf(err, errcap, "cannot listen on %s:%s: %s", host, port, strerror(last_errno));
        return -1;
    }
    (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
    return fd;
}

struct sl_net_target {
    struct addrinfo *list;
    const struct addrinfo *next; /* the next address to try */
    int last_errno;
    char host[256];
    char port[8];
};

sl_net_target *sl_net_target_resolve(const char *host, const char *port, char *err, size_t errcap)
{
    struct addrinfo hints;
    sl_net_target *t;
    int rc;

    if (strlen(host) >= sizeof t->host || strlen(port) >= sizeof t->port) {
        snprintf(err, errcap, "cannot resolve %s: name too long", host);
        return NULL;
    }
    t = calloc(1, sizeof *t);
    if (t == NULL) {
        snprintf(err, errcap, "out of memory");
        return NULL;
    }
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    rc = getaddrinfo(host, port, &hints, &t->list);
    if (rc != 0) {
        snprintf(err, errcap, "cannot resolve %s: %s", host, gai_strerror(rc));
        free(t);
        return NULL;
    }
    t->next = t->list;
    snprintf(t->host, sizeof t->host, "%s", host);
    snprintf(t->port, sizeof t->port, "%s", port);
    return t;
}

int sl_net_target_next(sl_net_target *t, int failed, char *err, size_t errcap)
{
    if (failed != 0) {
        t->last_errno = failed;
    }
    while (t->next != NULL) {
        const struct addrinfo *ai = t->next;
        int fd;

        t->next = ai->ai_next;
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            t->last_errno = errno;
            continue;
        }
        if (sl_net_set_nonblocking(fd) == 0 &&
            (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0 || errno == EINPROGRESS)) {
            sl_net_tune(fd);
            return fd;
        }
        t->last_errno = errno;
        close(fd);
    }
    snprintf(err, errcap, "cannot connect to %s:%s: %s", t->host, t->port,
             t->last_errno != 0 ? strerror(t->last_errno) : "no address");
    return -1;
}

void sl_net_target_free(sl_net_target *t)
{
    if (t != NULL) {
        freeaddrinfo(t->list);
        free(t);
    }
}

int sl_net_connect_result(int fd)
{
    int e = 0;
    socklen_t l = sizeof e;

    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &e, &l) != 0) {
        return errno;
    }
    return e;
}

int sl_net_local_port(int fd)
{
    struct sockaddr_storage ss;
    socklen_t l = sizeof ss;

    if (getsockname(fd, (struct sockaddr *)&ss, &l) != 0) {
        return -1;
    }
    if (ss.ss_family == AF_INET) {
        return ntohs(((struct sockaddr_in *)&ss)->sin_port);
    }
    if (ss.ss_family == AF_INET6) {
        return ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
    }
    return -1;
}

void sl_net_peer_str(int fd, char *out, size_t cap)
{
    struct sockaddr_storage ss;
    socklen_t l = sizeof ss;
    char host[128];
    char serv[16];

    if (getpeername(fd, (struct sockaddr *)&ss, &l) != 0 ||
        getnameinfo((struct sockaddr *)&ss, l, host, sizeof host, serv, sizeof serv,
                    NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
        snprintf(out, cap, "unknown");
        return;
    }
    snprintf(out, cap, "%s:%s", host, serv);
}
