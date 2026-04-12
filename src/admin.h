#ifndef SLUICE_ADMIN_H
#define SLUICE_ADMIN_H

/* A small HTTP listener for the people who run sluice, in the same poll loop as everything else
 * (--admin HOST:PORT). It answers:
 *
 *   GET  /healthz              ok (no token needed: for a load balancer)
 *   GET  /metrics              the counters, in the Prometheus text format (metrics.h)
 *   GET  /pending              the confirmations waiting for an answer, as JSON
 *   GET  /pending/ID           the question of one, as text (what a person is shown)
 *   POST /confirm/ID/yes       answer one (and /no). Only POST: a GET is something a chat client
 *                              or a browser fetches by itself to show a preview, and must never
 * decide
 *
 * With a token (--admin-token-file) every route but /healthz needs `Authorization: Bearer TOKEN`.
 * The token is required when the address is not a loopback one, and whenever confirmations are
 * answered here (--confirm-admin): the questions hold rows. It speaks plain HTTP, one request per
 * connection, and has no TLS: put it behind a reverse proxy that has, or keep it on a loopback
 * address or a private network.
 *
 * It is written for few and small requests: at most 8 connections, 4 KiB of request, 5 seconds to
 * send it. It never blocks the proxy: all its sockets are non-blocking. */

#include <poll.h>
#include <stddef.h>
#include <stdint.h>

#include "buf.h"
#include "metrics.h"

typedef struct sl_admin sl_admin;

typedef struct {
    void *ctx;
    void (*gauges)(void *ctx, sl_metrics_gauges *g);
    /* appends a JSON array of what is waiting */
    int (*pending_json)(void *ctx, sl_buf *out);
    /* appends the text of one question; 0, or -1 when there is none with that id */
    int (*pending_text)(void *ctx, const char *id, sl_buf *out);
    /* answers it; 0, or -1 when there is none with that id */
    int (*answer)(void *ctx, const char *id, int yes);
} sl_admin_ops;

/* Listens on host:port (not NUL terminated token of `token_len` bytes, or NULL for none). NULL with
 * a message in err on failure. */
sl_admin *sl_admin_new(const char *host, const char *port, const char *token, size_t token_len,
                       const sl_admin_ops *ops, char *err, size_t errcap);
void sl_admin_free(sl_admin *a);

int sl_admin_port(const sl_admin *a);

/* The descriptors to poll (at most SL_ADMIN_MAX_FDS): fills out[], returns how many. */
#define SL_ADMIN_MAX_FDS 10
size_t sl_admin_pollfds(const sl_admin *a, struct pollfd *out);
/* One of them is ready. */
void sl_admin_ready(sl_admin *a, int fd, short revents, int64_t now_ms);
/* The time (ms) of the next thing to do, or -1. */
int64_t sl_admin_deadline(const sl_admin *a);
void sl_admin_tick(sl_admin *a, int64_t now_ms);

/* Builds the response to one request, without sockets: method, path, the value of the
 * Authorization header (or NULL). Returns the status code; the whole response (status line,
 * headers, body) is in out. For the tests. */
int sl_admin_respond(sl_admin *a, const char *method, const char *path, const char *authorization,
                     sl_buf *out);

#endif
