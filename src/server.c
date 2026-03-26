#include "server.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "buf.h"
#include "clock.h"
#include "conn.h"
#include "log.h"
#include "net.h"
#include "pg_proto.h"

#define MAX_CONNS_DEFAULT 1024
#define POLL_MAX_WAIT_MS 1000
/* How long the listening socket is left alone after accept() failed for a reason that does not go
 * away by itself (no descriptors left, no memory). */
#define ACCEPT_PAUSE_MS 500

static volatile sig_atomic_t g_stop;
static volatile sig_atomic_t g_reload;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static void on_hup(int sig)
{
    (void)sig;
    g_reload = 1;
}

/* Which connection and which of its two sockets a pollfd entry stands for. */
typedef struct {
    sl_conn *conn;
    int is_upstream; /* 0: the client's socket, 1: the upstream's, 2: the terminal of the prompt */
} slot;

typedef struct {
    const sl_config *cfg;
    /* The policy in force is one of two slots: a reload reads the file into the other slot and,
     * only if it is valid, switches to it and frees the old one. `current` is what connections look
     * at. */
    sl_policy pols[2];
    int active;
    const sl_policy *current; /* NULL when there is no policy file */
    sl_conn_env env;          /* what each connection is given */
    int listen_fd;
    sl_prompt *prompt;
    size_t max_conns;
    uint64_t next_id;
    int64_t
        accept_resume_ms; /* accept() failed: the listening socket is not polled before this time */

    sl_conn **conns;
    size_t nconns;
    size_t cap_conns;

    struct pollfd *pfds;
    slot *slots;
    size_t cap_poll;
} server;

/* Each connection uses two descriptors. Raise the soft limit (macOS defaults to 256) and size the
 * connection limit so that accept() cannot run out of descriptors. */
static size_t compute_max_conns(void)
{
    struct rlimit rl;
    size_t max = MAX_CONNS_DEFAULT;
    size_t fit;

    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
        return 64;
    }
    if (rl.rlim_cur != RLIM_INFINITY && rl.rlim_cur < 4096) {
        rlim_t want = 4096;

        if (rl.rlim_max != RLIM_INFINITY && rl.rlim_max < want) {
            want = rl.rlim_max;
        }
        rl.rlim_cur = want;
        if (setrlimit(RLIMIT_NOFILE, &rl) != 0 && getrlimit(RLIMIT_NOFILE, &rl) != 0) {
            return 64;
        }
    }
    if (rl.rlim_cur != RLIM_INFINITY) {
        if (rl.rlim_cur < 32) {
            return 4;
        }
        fit = (size_t)((rl.rlim_cur - 16) / 2);
        if (fit < max) {
            max = fit;
        }
    }
    return max;
}

static int push_conn(server *s, sl_conn *c)
{
    if (s->nconns == s->cap_conns) {
        size_t cap = s->cap_conns ? s->cap_conns * 2 : 16;
        sl_conn **p = realloc(s->conns, cap * sizeof *p);

        if (p == NULL) {
            return -1;
        }
        s->conns = p;
        s->cap_conns = cap;
    }
    s->conns[s->nconns++] = c;
    return 0;
}

static int ensure_poll_capacity(server *s)
{
    size_t need = 2 + 2 * s->nconns; /* the listening socket, the terminal, two per connection */

    if (need > s->cap_poll) {
        size_t cap = need * 2;
        struct pollfd *p = realloc(s->pfds, cap * sizeof *p);
        slot *q;

        if (p == NULL) {
            return -1;
        }
        s->pfds = p;
        q = realloc(s->slots, cap * sizeof *q);
        if (q == NULL) {
            return -1;
        }
        s->slots = q;
        s->cap_poll = cap;
    }
    return 0;
}

/* Tells a client we are full, in a form PostgreSQL clients understand, then drops it. */
static void reject(int fd)
{
    sl_buf b;
    sl_log_ev ev;

    sl_buf_init(&b);
    if (sl_pg_append_error(&b, "FATAL", "53300", "sluice: too many connections") == 0) {
        (void)send(fd, sl_buf_data(&b), sl_buf_len(&b), SL_SEND_FLAGS);
    }
    sl_buf_free(&b);
    close(fd);

    sl_log_begin(&ev, "connection_rejected");
    sl_log_cstr(&ev, "reason", "too_many_connections");
    sl_log_end(&ev);
}

static void accept_clients(server *s)
{
    for (;;) {
        int fd = accept(s->listen_fd, NULL, NULL);
        sl_conn *c;

        if (fd < 0) {
            if (errno == EINTR || errno == ECONNABORTED) {
                continue;
            }
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                sl_log_ev ev;

                sl_log_begin(&ev, "accept_error");
                sl_log_cstr(&ev, "error", strerror(errno));
                sl_log_end(&ev);
                /* Out of descriptors, for instance: on Linux the connection then stays in the
                 * queue, so the socket stays readable and polling it again at once would loop at
                 * full speed, and log. */
                s->accept_resume_ms = sl_now_ms() + ACCEPT_PAUSE_MS;
            }
            return;
        }
        if (s->nconns >= s->max_conns) {
            reject(fd);
            continue;
        }
        if (sl_net_set_nonblocking(fd) != 0) {
            close(fd);
            continue;
        }
        sl_net_tune(fd);

        c = sl_conn_new(&s->env, fd, s->next_id++);
        if (c == NULL) {
            close(fd);
            continue;
        }
        if (push_conn(s, c) != 0) {
            sl_conn_abort(c, "out_of_memory");
            sl_conn_free(c);
        }
    }
}

static void reap(server *s)
{
    for (size_t i = s->nconns; i-- > 0;) {
        if (sl_conn_is_done(s->conns[i])) {
            sl_conn_free(s->conns[i]);
            s->conns[i] = s->conns[--s->nconns];
            s->accept_resume_ms = 0; /* descriptors were given back: accepting can resume at once */
        }
    }
}

/* A table entry with upper-case letters only ever matches a table written with quotes ("Ledger"):
 * the SQL parser makes unquoted names lower case. Someone who writes "Ledger" in a deny rule almost
 * certainly means ledger, and a rule that never applies protects nothing, so say so instead of
 * staying silent. */
static void warn_policy(const sl_policy *p)
{
    unsigned shown = 0;

    for (size_t i = 0; i < p->nrules; i++) {
        const sl_rule *r = &p->rules[i];

        for (int pass = 0; pass < 2; pass++) {
            char *const *list = pass == 0 ? r->tables : r->outside_tables;
            size_t n = pass == 0 ? r->ntables : r->noutside;

            for (size_t k = 0; k < n; k++) {
                int upper = 0;
                sl_log_ev ev;

                for (const char *c = list[k]; *c; c++) {
                    upper |= *c >= 'A' && *c <= 'Z';
                }
                if (!upper) {
                    continue;
                }
                if (++shown > 10) {
                    return; /* enough to notice; the file is the place to look at the rest */
                }
                sl_log_begin(&ev, "warning");
                sl_log_cstr(&ev, "rule", r->name);
                sl_log_cstr(&ev, "entry", list[k]);
                sl_log_cstr(
                    &ev, "detail",
                    "this table name has upper-case letters: SQL names are lower case unless "
                    "quoted, so it only matches a table written with double quotes");
                sl_log_end(&ev);
            }
        }
    }
}

/* SIGHUP: read the policy file again. The new policy replaces the old one only if it is valid; a
 * file that cannot be read or understood is reported and the policy in force stays in force, since
 * the alternative (running without rules, or stopping) is worse than running on the last good ones.
 * It takes effect at once, connections that are open included. Called between two events, never
 * during one. */
static void reload_policy(server *s)
{
    sl_log_ev ev;
    char err[256];
    int next = 1 - s->active;

    if (s->current == NULL) {
        sl_log_begin(&ev, "policy_reload_ignored");
        sl_log_cstr(&ev, "detail",
                    "sluice was started without --policy: there is nothing to reload");
        sl_log_end(&ev);
        return;
    }
    if (sl_policy_load(&s->pols[next], s->cfg->policy_path, err, sizeof err) != 0) {
        sl_log_begin(&ev, "policy_reload_failed");
        sl_log_cstr(&ev, "error", err);
        sl_log_cstr(&ev, "detail", "the previous policy stays in force");
        sl_log_end(&ev);
        return;
    }
    sl_policy_free(&s->pols[s->active]);
    s->active = next;
    s->current = &s->pols[next];

    sl_log_begin(&ev, "policy_reloaded");
    sl_log_cstr(&ev, "policy", s->cfg->policy_path);
    sl_log_cstr(&ev, "mode", s->current->mode == SL_MODE_ENFORCE ? "enforce" : "audit");
    sl_log_int(&ev, "rules", (long long)s->current->nrules);
    sl_log_cstr(&ev, "on_uninspectable", s->current->deny_uninspectable ? "deny" : "allow");
    sl_log_end(&ev);
    warn_policy(s->current);
}

/* A private key readable by other users is a secret that is not kept: say so. Only a warning, since
 * a key mounted by an orchestrator often comes with group access that the operator chose. */
static void warn_key_permissions(const char *path, const char *option)
{
    struct stat st;
    char detail[200];
    sl_log_ev ev;

    if (path[0] == '\0' || stat(path, &st) != 0 || (st.st_mode & (S_IRWXG | S_IRWXO)) == 0) {
        return;
    }
    snprintf(detail, sizeof detail,
             "the private key given to %s is readable by other users: restrict it (chmod 600)",
             option);
    sl_log_begin(&ev, "warning");
    sl_log_cstr(&ev, "detail", detail);
    sl_log_end(&ev);
}

int sl_server_run(const sl_config *cfg)
{
    server s;
    sl_tls_ctx *tls = NULL;
    sl_tls_ctx *client_tls = NULL;
    int listen_tls;
    struct sigaction sa;
    sl_log_ev ev;
    char err[256];
    char upstream[sizeof cfg->upstream_host + sizeof cfg->upstream_port + 2]; /* "host:port" */

    memset(&s, 0, sizeof s);
    s.cfg = cfg;
    s.next_id = 1;
    s.max_conns = compute_max_conns();

    /* The rules are read before anything is opened: a bad policy file must stop sluice, never be
     * skipped. */
    if (cfg->policy_path[0] != '\0') {
        if (sl_policy_load(&s.pols[0], cfg->policy_path, err, sizeof err) != 0) {
            fprintf(stderr, "sluice: %s\n", err);
            return 1;
        }
        s.current = &s.pols[0];
    }

    /* Same for TLS: asked for and impossible means sluice does not start, it never falls back to
     * plain text. */
    if (cfg->upstream_tls != SL_TLS_OFF) {
        tls = sl_tls_ctx_new(cfg->upstream_tls, cfg->upstream_ca, cfg->upstream_cert,
                             cfg->upstream_key, err, sizeof err);
        if (tls == NULL) {
            fprintf(stderr, "sluice: %s\n", err);
            if (s.current) {
                sl_policy_free(&s.pols[s.active]);
            }
            return 1;
        }
    }
    listen_tls = cfg->listen_tls_self_signed || cfg->listen_tls_cert[0] != '\0';
    if (listen_tls) {
        client_tls = sl_tls_server_ctx_new(cfg->listen_tls_cert, cfg->listen_tls_key,
                                           cfg->listen_tls_self_signed, err, sizeof err);
        if (client_tls == NULL) {
            fprintf(stderr, "sluice: %s\n", err);
            if (s.current) {
                sl_policy_free(&s.pols[s.active]);
            }
            sl_tls_ctx_free(tls);
            return 1;
        }
    }
    s.env.cfg = cfg;
    s.env.policy = cfg->policy_path[0] != '\0' ? &s.current : NULL;
    s.env.tls = tls;
    s.env.client_tls = client_tls;
    s.prompt = sl_prompt_new(cfg->confirm_tty);
    s.env.prompt = s.prompt;

    s.listen_fd = sl_net_listen(cfg->listen_host, cfg->listen_port, err, sizeof err);
    if (s.listen_fd < 0) {
        fprintf(stderr, "sluice: %s\n", err);
        if (s.current) {
            sl_policy_free(&s.pols[s.active]);
        }
        sl_prompt_free(s.prompt);
        sl_tls_ctx_free(tls);
        sl_tls_ctx_free(client_tls);
        return 1;
    }

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal; /* no SA_RESTART: poll() must return so the loop sees the flag */
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sa.sa_handler = on_hup;
    sigaction(SIGHUP, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    sl_log_begin(&ev, "listening");
    sl_log_cstr(&ev, "host", cfg->listen_host);
    sl_log_int(&ev, "port", sl_net_local_port(s.listen_fd));
    snprintf(upstream, sizeof upstream, "%s:%s", cfg->upstream_host, cfg->upstream_port);
    sl_log_cstr(&ev, "upstream", upstream);
    sl_log_int(&ev, "max_connections", (long long)s.max_conns);
    sl_log_cstr(&ev, "log_sql",
                cfg->log_sql == SL_LOGSQL_NORMALIZED ? "normalized"
                : cfg->log_sql == SL_LOGSQL_NONE     ? "none"
                                                     : "full");
    sl_log_cstr(&ev, "listen_tls",
                !listen_tls                   ? "off"
                : cfg->listen_tls_self_signed ? "self-signed"
                                              : "certificate");
    sl_log_bool(&ev, "upstream_client_cert", cfg->upstream_cert[0] != '\0');
    sl_log_cstr(&ev, "upstream_tls",
                cfg->upstream_tls == SL_TLS_VERIFY_FULL ? "verify-full"
                : cfg->upstream_tls == SL_TLS_REQUIRE   ? "require"
                                                        : "off");
    if (s.current != NULL) {
        sl_log_cstr(&ev, "policy", cfg->policy_path);
        sl_log_cstr(&ev, "mode", s.current->mode == SL_MODE_ENFORCE ? "enforce" : "audit");
        sl_log_int(&ev, "rules", (long long)s.current->nrules);
        sl_log_cstr(&ev, "on_uninspectable", s.current->deny_uninspectable ? "deny" : "allow");
    }
    sl_log_end(&ev);

    if (s.current != NULL) {
        warn_policy(s.current);
    }
    if (cfg->listen_tls_self_signed) {
        sl_log_begin(&ev, "warning");
        sl_log_cstr(&ev, "detail",
                    "the certificate offered to clients is made at startup and signed by nobody: "
                    "it encrypts (sslmode=require) but a client cannot check who it talks to. Give "
                    "--listen-tls-cert and --listen-tls-key for sslmode=verify-full");
        sl_log_end(&ev);
    }
    if (!listen_tls && !sl_net_host_is_local(cfg->listen_host)) {
        sl_log_begin(&ev, "warning");
        sl_log_cstr(
            &ev, "detail",
            "sluice listens on an address that is not only this machine, and the connection "
            "between the clients and sluice is not encrypted: queries, and the SQL in the "
            "log, cross the network in clear. Listen on 127.0.0.1 or a pod-local address, or "
            "use --listen-tls");
        sl_log_end(&ev);
    }

    /* The private key of the client certificate is a secret: say so when other users can read it.
     * It only warns, since a key mounted by an orchestrator often comes with group access that the
     * operator chose. */
    warn_key_permissions(cfg->upstream_key, "--upstream-key");
    warn_key_permissions(cfg->listen_tls_key, "--listen-tls-key");
    if (cfg->upstream_tls == SL_TLS_OFF && !sl_net_host_is_local(cfg->upstream_host)) {
        sl_log_begin(&ev, "warning");
        sl_log_cstr(&ev, "detail",
                    "the connection to the upstream is not encrypted and the upstream is not "
                    "on this machine: use --upstream-tls verify-full");
        sl_log_end(&ev);
    } else if (cfg->upstream_tls == SL_TLS_REQUIRE) {
        sl_log_begin(&ev, "warning");
        sl_log_cstr(&ev, "detail",
                    "--upstream-tls require encrypts but does not check who the server is: "
                    "use verify-full against an untrusted network");
        sl_log_end(&ev);
    }

    while (!g_stop) {
        size_t np = 1;

        if (g_reload) {
            g_reload = 0;
            reload_policy(&s);
        }
        int64_t now = sl_now_ms();
        int timeout = POLL_MAX_WAIT_MS;
        int rc;

        if (ensure_poll_capacity(&s) != 0) {
            fprintf(stderr, "sluice: out of memory\n");
            break;
        }
        if (now < s.accept_resume_ms) {
            s.pfds[0].fd = -1; /* poll() ignores it */
            if (s.accept_resume_ms - now < timeout) {
                timeout = (int)(s.accept_resume_ms - now);
            }
        } else {
            s.pfds[0].fd = s.listen_fd;
        }
        s.pfds[0].events = POLLIN;
        s.pfds[0].revents = 0;
        s.slots[0].conn = NULL;
        s.slots[0].is_upstream = 0;
        if (s.prompt != NULL && sl_prompt_fd(s.prompt) >= 0) {
            s.pfds[np].fd = sl_prompt_fd(s.prompt);
            s.pfds[np].events = POLLIN;
            s.pfds[np].revents = 0;
            s.slots[np].conn = NULL;
            s.slots[np].is_upstream = 2;
            np++;
        }

        for (size_t i = 0; i < s.nconns; i++) {
            sl_conn *c = s.conns[i];
            short cev = sl_conn_client_events(c);
            short uev = sl_conn_upstream_events(c);
            int64_t dl = sl_conn_deadline(c);

            if (cev) {
                s.pfds[np].fd = sl_conn_client_fd(c);
                s.pfds[np].events = cev;
                s.pfds[np].revents = 0;
                s.slots[np].conn = c;
                s.slots[np].is_upstream = 0;
                np++;
            }
            if (uev && sl_conn_upstream_fd(c) >= 0) {
                s.pfds[np].fd = sl_conn_upstream_fd(c);
                s.pfds[np].events = uev;
                s.pfds[np].revents = 0;
                s.slots[np].conn = c;
                s.slots[np].is_upstream = 1;
                np++;
            }
            if (sl_conn_has_pending(c)) {
                timeout =
                    0; /* bytes are waiting inside the TLS library: do not sleep on the socket */
            }
            if (dl >= 0) {
                int64_t wait = dl - now;

                if (wait < 0) {
                    wait = 0;
                }
                if (wait < timeout) {
                    timeout = (int)wait;
                }
            }
        }

        rc = poll(s.pfds, (nfds_t)np, timeout);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr, "sluice: poll: %s\n", strerror(errno));
            break;
        }

        if (rc > 0) {
            if (s.pfds[0].revents & POLLIN) {
                accept_clients(&s);
            }
            for (size_t k = 1; k < np; k++) {
                sl_conn *c = s.slots[k].conn;

                if (s.slots[k].is_upstream == 2) {
                    if (s.pfds[k].revents != 0 && s.prompt != NULL) {
                        sl_prompt_readable(s.prompt);
                    }
                    continue;
                }
                if (s.pfds[k].revents == 0 || sl_conn_is_done(c)) {
                    continue;
                }
                if (s.slots[k].is_upstream) {
                    sl_conn_on_upstream(c, s.pfds[k].revents);
                } else {
                    sl_conn_on_client(c, s.pfds[k].revents);
                }
            }
        }

        now = sl_now_ms();
        for (size_t i = 0; i < s.nconns; i++) {
            sl_conn_service_pending(s.conns[i]);
            sl_conn_check_deadline(s.conns[i], now);
        }
        reap(&s);
    }

    sl_log_begin(&ev, "shutdown");
    sl_log_int(&ev, "open_connections", (long long)s.nconns);
    sl_log_end(&ev);

    for (size_t i = 0; i < s.nconns; i++) {
        sl_conn_abort(s.conns[i], "shutdown");
        sl_conn_free(s.conns[i]);
    }
    close(s.listen_fd);
    free(s.conns);
    free(s.pfds);
    free(s.slots);
    if (s.current != NULL) {
        sl_policy_free(&s.pols[s.active]);
    }
    sl_prompt_free(s.prompt);
    sl_tls_ctx_free(tls);
    sl_tls_ctx_free(client_tls);
    return 0;
}
