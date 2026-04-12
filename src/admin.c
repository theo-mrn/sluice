#include "admin.h"

#include <errno.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#include "clock.h"
#include "log.h"
#include "net.h"

#define MAX_CONNS 8
#define REQ_MAX 4096
#define REQ_TIMEOUT_MS 5000

typedef struct {
    int fd;
    char req[REQ_MAX + 1];
    size_t len;
    int writing;
    sl_buf out;
    size_t off;
    int64_t deadline;
} aconn;

struct sl_admin {
    int listen_fd;
    char *token;
    size_t token_len;
    sl_admin_ops ops;
    aconn conns[MAX_CONNS];
};

sl_admin *sl_admin_new(const char *host, const char *port, const char *token, size_t token_len,
                       const sl_admin_ops *ops, char *err, size_t errcap)
{
    sl_admin *a = calloc(1, sizeof *a);

    if (a == NULL) {
        snprintf(err, errcap, "out of memory");
        return NULL;
    }
    a->ops = *ops;
    for (int i = 0; i < MAX_CONNS; i++) {
        a->conns[i].fd = -1;
    }
    if (token != NULL && token_len > 0) {
        a->token = malloc(token_len);
        if (a->token == NULL) {
            free(a);
            snprintf(err, errcap, "out of memory");
            return NULL;
        }
        memcpy(a->token, token, token_len);
        a->token_len = token_len;
    }
    a->listen_fd = sl_net_listen(host, port, err, errcap);
    if (a->listen_fd < 0) {
        free(a->token);
        free(a);
        return NULL;
    }
    return a;
}

static void drop(aconn *c)
{
    if (c->fd >= 0) {
        close(c->fd);
    }
    c->fd = -1;
    sl_buf_free(&c->out);
    c->len = 0;
    c->off = 0;
    c->writing = 0;
}

void sl_admin_free(sl_admin *a)
{
    if (a == NULL) {
        return;
    }
    for (int i = 0; i < MAX_CONNS; i++) {
        drop(&a->conns[i]);
    }
    if (a->listen_fd >= 0) {
        close(a->listen_fd);
    }
    if (a->token != NULL) {
        OPENSSL_cleanse(a->token, a->token_len);
        free(a->token);
    }
    free(a);
}

int sl_admin_port(const sl_admin *a)
{
    return sl_net_local_port(a->listen_fd);
}

size_t sl_admin_pollfds(const sl_admin *a, struct pollfd *out)
{
    size_t n = 0;

    out[n].fd = a->listen_fd;
    out[n].events = POLLIN;
    out[n].revents = 0;
    n++;
    for (int i = 0; i < MAX_CONNS; i++) {
        if (a->conns[i].fd >= 0) {
            out[n].fd = a->conns[i].fd;
            out[n].events = a->conns[i].writing ? POLLOUT : POLLIN;
            out[n].revents = 0;
            n++;
        }
    }
    return n;
}

int64_t sl_admin_deadline(const sl_admin *a)
{
    int64_t d = -1;

    for (int i = 0; i < MAX_CONNS; i++) {
        if (a->conns[i].fd >= 0 && (d < 0 || a->conns[i].deadline < d)) {
            d = a->conns[i].deadline;
        }
    }
    return d;
}

void sl_admin_tick(sl_admin *a, int64_t now_ms)
{
    for (int i = 0; i < MAX_CONNS; i++) {
        if (a->conns[i].fd >= 0 && now_ms >= a->conns[i].deadline) {
            drop(&a->conns[i]);
        }
    }
}

/* ---- the responses ---- */

static const char *reason_of(int status)
{
    switch (status) {
    case 200:
        return "OK";
    case 400:
        return "Bad Request";
    case 401:
        return "Unauthorized";
    case 404:
        return "Not Found";
    case 405:
        return "Method Not Allowed";
    case 414:
        return "URI Too Long";
    default:
        return "Error";
    }
}

static int respond(sl_buf *out, int status, const char *type, const char *body, size_t body_len)
{
    char head[256];
    int n = snprintf(head, sizeof head,
                     "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\nCache-Control: "
                     "no-store\r\nConnection: close\r\n%s\r\n",
                     status, reason_of(status), type, body_len,
                     status == 401 ? "WWW-Authenticate: Bearer\r\n" : "");

    if (n < 0 || (size_t)n >= sizeof head || sl_buf_append(out, head, (size_t)n) != 0 ||
        (body_len > 0 && sl_buf_append(out, body, body_len) != 0)) {
        return -1;
    }
    return status;
}

static int respond_text(sl_buf *out, int status, const char *text)
{
    return respond(out, status, "text/plain; charset=utf-8", text, strlen(text));
}

static int authorized(const sl_admin *a, const char *authorization)
{
    const char *p;
    size_t n;

    if (a->token == NULL) {
        return 1;
    }
    if (authorization == NULL || strncasecmp(authorization, "Bearer ", 7) != 0) {
        return 0;
    }
    p = authorization + 7;
    while (*p == ' ') {
        p++;
    }
    n = strlen(p);
    while (n > 0 && (p[n - 1] == ' ' || p[n - 1] == '\r')) {
        n--;
    }
    return n == a->token_len && CRYPTO_memcmp(p, a->token, n) == 0;
}

static int valid_id(const char *s, size_t n)
{
    if (n != 16) {
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

/* The route a request is for, as a fixed word (the label of the counter: never what the client
 * wrote) */
static const char *route_of(const char *path, size_t plen)
{
    if (plen == 8 && memcmp(path, "/healthz", 8) == 0) {
        return "/healthz";
    }
    if (plen == 8 && memcmp(path, "/metrics", 8) == 0) {
        return "/metrics";
    }
    if (plen == 8 && memcmp(path, "/pending", 8) == 0) {
        return "/pending";
    }
    if (plen > 9 && memcmp(path, "/pending/", 9) == 0) {
        return "/pending/ID";
    }
    if (plen > 9 && memcmp(path, "/confirm/", 9) == 0) {
        return "/confirm/ID";
    }
    return "other";
}

int sl_admin_respond(sl_admin *a, const char *method, const char *path, const char *authorization,
                     sl_buf *out)
{
    int get = strcmp(method, "GET") == 0;
    int post = strcmp(method, "POST") == 0;
    size_t plen = strlen(path);
    const char *q = strchr(path, '?');
    const char *label = "other";
    int status;

    if (q != NULL) {
        plen = (size_t)(q - path); /* a query string is not used */
    }
    label = route_of(path, plen);
    if (!get && !post) {
        status = respond_text(out, 405, "method not allowed\n");
        goto done;
    }
    if (plen == 8 && memcmp(path, "/healthz", 8) == 0 && get) {
        status = respond_text(out, 200, "ok\n");
        goto done;
    }
    if (!authorized(a, authorization)) {
        status = respond_text(out, 401, "a Bearer token is needed\n");
        goto done;
    }
    if (plen == 8 && memcmp(path, "/metrics", 8) == 0 && get) {
        sl_metrics_gauges g;
        sl_buf body;

        memset(&g, 0, sizeof g);
        a->ops.gauges(a->ops.ctx, &g);
        sl_buf_init(&body);
        if (sl_metrics_render(&body, &g) != 0) {
            sl_buf_free(&body);
            status = respond_text(out, 400, "out of memory\n");
            goto done;
        }
        status = respond(out, 200, "text/plain; version=0.0.4; charset=utf-8",
                         (const char *)sl_buf_data(&body), sl_buf_len(&body));
        sl_buf_free(&body);
        goto done;
    }
    if (plen == 8 && memcmp(path, "/pending", 8) == 0 && get) {
        sl_buf body;

        sl_buf_init(&body);
        if (a->ops.pending_json(a->ops.ctx, &body) != 0) {
            sl_buf_free(&body);
            status = respond_text(out, 400, "out of memory\n");
            goto done;
        }
        status = respond(out, 200, "application/json", (const char *)sl_buf_data(&body),
                         sl_buf_len(&body));
        sl_buf_free(&body);
        goto done;
    }
    if (plen == 25 && memcmp(path, "/pending/", 9) == 0 && get && valid_id(path + 9, 16)) {
        char id[17];
        sl_buf body;

        memcpy(id, path + 9, 16);
        id[16] = '\0';
        sl_buf_init(&body);
        if (a->ops.pending_text(a->ops.ctx, id, &body) != 0) {
            sl_buf_free(&body);
            status = respond_text(out, 404, "nothing is waiting under that id\n");
            goto done;
        }
        status = respond(out, 200, "text/plain; charset=utf-8", (const char *)sl_buf_data(&body),
                         sl_buf_len(&body));
        sl_buf_free(&body);
        goto done;
    }
    if (post && (plen == 9 + 16 + 4 || plen == 9 + 16 + 3) && memcmp(path, "/confirm/", 9) == 0 &&
        valid_id(path + 9, 16) && path[25] == '/') {
        int yes = plen == 29 && memcmp(path + 26, "yes", 3) == 0;
        int no = plen == 28 && memcmp(path + 26, "no", 2) == 0;
        char id[17];

        if (!yes && !no) {
            status = respond_text(out, 404, "not found\n");
            goto done;
        }
        memcpy(id, path + 9, 16);
        id[16] = '\0';
        if (a->ops.answer(a->ops.ctx, id, yes) != 0) {
            status = respond_text(out, 404,
                                  "nothing is waiting under that id (answered, timed out, or "
                                  "the client left)\n");
            goto done;
        }
        status =
            respond(out, 200, "application/json",
                    yes ? "{\"answered\":\"yes\"}\n" : "{\"answered\":\"no\"}\n", yes ? 19 : 18);
        goto done;
    }
    status = respond_text(out, 404, "not found\n");
done:
    {
        char code[8];

        snprintf(code, sizeof code, "%d", status);
        sl_metric_inc(SL_M_ADMIN, label, code);
        if (status == 401) {
            sl_log_ev ev;

            sl_log_begin(&ev, "admin_denied");
            sl_log_str(&ev, "path", path, plen < 64 ? plen : 64);
            sl_log_cstr(&ev, "method", method);
            sl_log_end(&ev);
        }
    }
    return status;
}

/* ---- the sockets ---- */

static void accept_one(sl_admin *a, int64_t now_ms)
{
    int fd = accept(a->listen_fd, NULL, NULL);

    if (fd < 0) {
        return;
    }
    sl_net_set_nonblocking(fd);
    for (int i = 0; i < MAX_CONNS; i++) {
        if (a->conns[i].fd < 0) {
            memset(&a->conns[i], 0, sizeof a->conns[i]);
            a->conns[i].fd = fd;
            a->conns[i].deadline = now_ms + REQ_TIMEOUT_MS;
            return;
        }
    }
    close(fd); /* all busy: the client tries again */
}

/* The request is complete (its headers end): answer it. */
static void answer_request(sl_admin *a, aconn *c)
{
    char *line_end = strstr(c->req, "\r\n");
    char method[8] = "", path[512] = "";
    const char *auth = NULL;
    char authv[300];
    char *p;

    if (line_end == NULL || sscanf(c->req, "%7s %511s", method, path) != 2) {
        respond_text(&c->out, 400, "bad request\n");
    } else {
        for (p = line_end + 2; *p != '\0' && !(p[0] == '\r' && p[1] == '\n');) {
            char *e = strstr(p, "\r\n");

            if (e == NULL) {
                break;
            }
            if (strncasecmp(p, "Authorization:", 14) == 0) {
                size_t n = (size_t)(e - (p + 14));

                if (n >= sizeof authv) {
                    n = sizeof authv - 1;
                }
                memcpy(authv, p + 14, n);
                authv[n] = '\0';
                for (auth = authv; *auth == ' ' || *auth == '\t'; auth++) {
                }
            }
            p = e + 2;
        }
        (void)sl_admin_respond(a, method, path, auth, &c->out);
    }
    c->writing = 1;
    c->off = 0;
}

void sl_admin_ready(sl_admin *a, int fd, short revents, int64_t now_ms)
{
    if (fd == a->listen_fd) {
        if (revents & POLLIN) {
            accept_one(a, now_ms);
        }
        return;
    }
    for (int i = 0; i < MAX_CONNS; i++) {
        aconn *c = &a->conns[i];

        if (c->fd != fd) {
            continue;
        }
        if (revents & (POLLERR | POLLNVAL)) {
            drop(c);
            return;
        }
        if (!c->writing && (revents & (POLLIN | POLLHUP))) {
            ssize_t n = recv(c->fd, c->req + c->len, REQ_MAX - c->len, 0);

            if (n <= 0) {
                if (n < 0 && (errno == EAGAIN || errno == EINTR)) {
                    return;
                }
                drop(c);
                return;
            }
            c->len += (size_t)n;
            c->req[c->len] = '\0';
            if (strstr(c->req, "\r\n\r\n") != NULL) {
                answer_request(a, c);
            } else if (c->len >= REQ_MAX) {
                respond_text(&c->out, 414, "the request is too long\n");
                c->writing = 1;
            }
        }
        if (c->writing && (revents & POLLOUT || sl_buf_len(&c->out) > 0)) {
            while (c->off < sl_buf_len(&c->out)) {
                ssize_t w = send(c->fd, sl_buf_data(&c->out) + c->off, sl_buf_len(&c->out) - c->off,
                                 SL_SEND_FLAGS);

                if (w < 0 && errno == EINTR) {
                    continue;
                }
                if (w <= 0) {
                    if (w < 0 && errno == EAGAIN) {
                        return; /* the rest when it is writable */
                    }
                    drop(c);
                    return;
                }
                c->off += (size_t)w;
            }
            drop(c); /* one request per connection */
        }
        return;
    }
}
