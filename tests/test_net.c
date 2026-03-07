#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "check.h"
#include "net.h"

static void test_host_is_local(void)
{
    /* the machine itself */
    CHECK(sl_net_host_is_local("localhost"));
    CHECK(sl_net_host_is_local("LocalHost"));
    CHECK(sl_net_host_is_local("127.0.0.1"));
    CHECK(sl_net_host_is_local("127.255.255.254"));
    CHECK(sl_net_host_is_local("::1"));
    CHECK(sl_net_host_is_local("::ffff:127.0.0.1"));

    /* anything else, including names that only look like it */
    CHECK(!sl_net_host_is_local("127.example.com"));
    CHECK(!sl_net_host_is_local("127.0.0.1.example.com"));
    CHECK(!sl_net_host_is_local("localhost.example.com"));
    CHECK(!sl_net_host_is_local("db.internal"));
    CHECK(!sl_net_host_is_local("10.0.0.5"));
    CHECK(!sl_net_host_is_local("128.0.0.1"));
    CHECK(!sl_net_host_is_local("126.255.255.255"));
    CHECK(!sl_net_host_is_local("::2"));
    CHECK(!sl_net_host_is_local("::ffff:10.0.0.1"));
    CHECK(!sl_net_host_is_local("2001:db8::1"));
    CHECK(!sl_net_host_is_local("0.0.0.0"));
    CHECK(!sl_net_host_is_local(""));
}

static int option(int fd, int level, int name)
{
    int v = -1;
    socklen_t l = sizeof v;

    if (getsockopt(fd, level, name, &v, &l) != 0) {
        return -1;
    }
    return v;
}

static void test_tune(void)
{
    char err[200];
    int srv = sl_net_listen("127.0.0.1", "0", err, sizeof err);
    int port;
    int client;
    int accepted;
    struct sockaddr_in to;

    CHECK(srv >= 0);
    if (srv < 0) {
        return;
    }
    port = sl_net_local_port(srv);
    to.sin_family = AF_INET;
    to.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, "127.0.0.1", &to.sin_addr);
    client = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(client >= 0 && connect(client, (struct sockaddr *)&to, sizeof to) == 0);
    {
        /* the listening socket does not block: wait until the connection is there */
        struct pollfd pfd = {srv, POLLIN, 0};

        CHECK(poll(&pfd, 1, 5000) == 1);
    }
    accepted = accept(srv, NULL, NULL);
    CHECK(accepted >= 0);

    CHECK(option(client, SOL_SOCKET, SO_KEEPALIVE) ==
          0); /* not by default: that is what the call changes */
    sl_net_tune(client);
    sl_net_tune(accepted);
    for (int i = 0; i < 2; i++) {
        int fd = i == 0 ? client : accepted;

        CHECK(option(fd, SOL_SOCKET, SO_KEEPALIVE) != 0);
        CHECK(option(fd, IPPROTO_TCP, TCP_NODELAY) != 0);
#if defined(TCP_KEEPIDLE)
        CHECK(option(fd, IPPROTO_TCP, TCP_KEEPIDLE) == 60);
#elif defined(TCP_KEEPALIVE)
        CHECK(option(fd, IPPROTO_TCP, TCP_KEEPALIVE) == 60);
#endif
#ifdef TCP_KEEPINTVL
        CHECK(option(fd, IPPROTO_TCP, TCP_KEEPINTVL) == 10);
#endif
#ifdef TCP_KEEPCNT
        CHECK(option(fd, IPPROTO_TCP, TCP_KEEPCNT) == 6);
#endif
    }
    close(accepted);
    close(client);
    close(srv);
}

int main(void)
{
    test_host_is_local();
    test_tune();
    return TEST_RESULT();
}
