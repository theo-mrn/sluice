#include "conn.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#include "buf.h"
#include "clock.h"
#include "confirm.h"
#include "json.h"
#include "log.h"
#include "net.h"
#include "pg_proto.h"
#include "policy.h"
#include "prompt.h"
#include "scanner.h"
#include "sql_check.h"
#include "srvscan.h"
#include "tls.h"

#define READ_CHUNK 16384
#define HIGH_WATER (256 * 1024)
#define HANDSHAKE_TIMEOUT_MS 10000

/* Longest SQL text copied into one log line. The full length is logged next to it. */
#define LOG_SQL_MAX 8192
/* Longest user / database name kept for the log lines of a connection. */
#define IDENT_MAX 127

/* ST_TLS: the TCP connection to the upstream is up, and the TLS negotiation is under way. */
typedef enum { ST_STARTUP, ST_CONNECTING, ST_TLS, ST_RELAY, ST_DONE } conn_state;

/* The steps of the negotiation (ST_TLS). */
typedef enum { TLS_SEND_REQUEST, TLS_READ_REPLY, TLS_HANDSHAKE } tls_phase;

struct sl_conn {
    const sl_config *cfg;
    const sl_policy *const *policy_ref; /* NULL: relay and log only; else the policy in force */
    sl_tls_ctx *tls_ctx;                /* NULL: plain text to the upstream */
    uint64_t id;
    int client_fd;
    int upstream_fd;
    sl_net_target *target; /* the addresses of the upstream, while the connection is being made */
    conn_state state;

    /* TLS towards the client, when sluice is configured as a TLS server for its clients */
    sl_tls_ctx *client_tls_ctx;
    sl_tls *ctls;
    int cl_tls_ready; /* the handshake with the client is done: its reads and writes go through TLS
                       */
    int cl_hs_want;   /* what the handshake waits for: SL_TLS_WANT_READ or _WRITE */
    int cl_rd_wants_write; /* a read waits for the client's socket to become writable (TLS) */
    int cl_wr_wants_read;  /* a write waits for it to become readable (TLS) */

    /* TLS towards the upstream */
    sl_tls *tls;
    tls_phase phase;
    uint8_t sslreq[8]; /* the SSLRequest packet */
    size_t sslreq_sent;
    int hs_want;           /* what the handshake waits for: SL_TLS_WANT_READ or _WRITE */
    int tls_ready;         /* the handshake is done: upstream reads and writes go through TLS */
    int up_rd_wants_write; /* a read waits for the socket to become writable (TLS) */
    int up_wr_wants_read;  /* a write waits for the socket to become readable (TLS) */

    /* Bytes read from the client. The first `released` of them may be written to the upstream; the
     * rest is received but not yet cleared by the scanner (an incomplete Query or Parse,
     * typically). */
    sl_buf c2u;
    sl_scan scan;       /* what the scanner has cleared to be sent, and where it is in the stream */
    size_t startup_len; /* size of the startup packet at the head of c2u */

    sl_buf u2c; /* read from the upstream, not yet written to the client */
    /* With TLS towards the upstream, the server's first authentication message is read and, if need
     * be, rewritten (see scan_u2c): until then only the first `u_released` bytes of u2c may be
     * sent. */
    int u_scan;
    size_t u_released;

    /* The server's stream, followed once in relay when there is a policy (see srvscan.h): where the
     * server is in its conversation, and, for a confirmation, the answers kept from the client. */
    sl_srv srv;
    int srv_on;
    int first_z;       /* the ReadyForQuery that ends the login has been seen */
    uint8_t tx_status; /* the status of the last ReadyForQuery: 'I', 'T' or 'E' */
    uint64_t z_seen;   /* ReadyForQuery seen after that one */
    int scan_waiting;  /* a statement waits until the server has answered what came before it */

    /* A DELETE or UPDATE that is being run in a transaction that is not committed yet (confirm.h).
     */
    sl_prompt *prompt;
    sl_confirm *guard;
    sl_buf g_server; /* messages the confirmation wants sent to the server */
    sl_buf g_client; /* what it wants to give the client when it is over */
    int g_ask;       /* the last message made it ask */
    int g_done;      /* ... or end */
    int g_nomem;
    int g_asked; /* the question is on the terminal */
    int64_t g_started_ms;
    int64_t g_deadline_ms;
    unsigned g_timeout_s;
    char g_rule[72];

    int client_eof;
    int upstream_eof;
    int closing;              /* an error reply is queued: flush u2c, then finish */
    const char *close_reason; /* a literal, logged on close */

    char user[IDENT_MAX];
    size_t user_len;
    char database[IDENT_MAX];
    size_t database_len;

    int64_t opened_ms;
    int64_t deadline_ms; /* -1 once the connection reached RELAY */
    uint64_t bytes_from_client;
    uint64_t bytes_from_upstream;
    uint64_t statements;
    uint64_t blocked;
};

/* How many bytes of u2c may be written to the client now. */
static size_t u2c_sendable(const sl_conn *c)
{
    if (c->u_scan) {
        return c->u_released;
    }
    return c->state == ST_RELAY && c->srv_on ? c->srv.released : sl_buf_len(&c->u2c);
}

/* The policy in force right now. It can be replaced between two events (SIGHUP), never during one,
 * so a handler may keep the pointer for as long as it runs. NULL without a policy file. */
static const sl_policy *policy_now(const sl_conn *c)
{
    return c->policy_ref != NULL ? *c->policy_ref : NULL;
}

/* True when rules are loaded and in enforce mode: only then does sluice change what the server
 * receives. */
static int enforcing(const sl_conn *c)
{
    const sl_policy *p = policy_now(c);

    return p != NULL && p->mode == SL_MODE_ENFORCE;
}

/* ---- life cycle ---- */

static void finish(sl_conn *c, const char *reason)
{
    if (c->state == ST_DONE) {
        return;
    }
    c->state = ST_DONE;
    c->close_reason = reason;
}

/* Decides, after any event, whether the connection is over. */
static void check_done(sl_conn *c)
{
    if (c->state == ST_DONE) {
        return;
    }
    if (c->closing) {
        if (sl_buf_len(&c->u2c) == 0) {
            finish(c, c->close_reason);
        }
        return;
    }
    if (c->upstream_eof && sl_buf_len(&c->u2c) == 0) {
        finish(c, "upstream_closed");
        return;
    }
    /* What a paused scanner holds has not been judged: it is never let through for the client
     * having gone, the connection just ends (and a transaction that was not committed with it). */
    if (c->client_eof &&
        (c->state != ST_RELAY || sl_buf_len(&c->c2u) == 0 || c->scan.paused || c->guard != NULL)) {
        finish(c, "client_closed");
    }
}

sl_conn *sl_conn_new(const sl_conn_env *env, int client_fd, uint64_t id)
{
    sl_conn *c = calloc(1, sizeof *c);
    sl_log_ev ev;
    char peer[96];

    if (c == NULL) {
        return NULL;
    }
    c->cfg = env->cfg;
    c->policy_ref = env->policy;
    c->tls_ctx = env->tls;
    c->client_tls_ctx = env->client_tls;
    c->id = id;
    c->client_fd = client_fd;
    c->upstream_fd = -1;
    c->state = ST_STARTUP;
    sl_scan_init(&c->scan, c->policy_ref != NULL,
                 SL_SCAN_INSPECT_MAX); /* a policy, once there, stays */
    sl_buf_init(&c->c2u);
    sl_buf_init(&c->u2c);
    sl_buf_init(&c->g_server);
    sl_buf_init(&c->g_client);
    c->prompt = env->prompt;
    c->tx_status = 'I';
    c->close_reason = "unknown";
    c->opened_ms = sl_now_ms();
    c->deadline_ms = c->opened_ms + HANDSHAKE_TIMEOUT_MS;

    sl_net_peer_str(client_fd, peer, sizeof peer);
    sl_log_begin(&ev, "connection_open");
    sl_log_int(&ev, "id", (long long)id);
    sl_log_cstr(&ev, "client", peer);
    sl_log_end(&ev);
    return c;
}

void sl_conn_free(sl_conn *c)
{
    sl_log_ev ev;

    if (c == NULL) {
        return;
    }
    sl_log_begin(&ev, "connection_close");
    sl_log_int(&ev, "id", (long long)c->id);
    sl_log_cstr(&ev, "reason", c->close_reason);
    sl_log_int(&ev, "statements", (long long)c->statements);
    sl_log_int(&ev, "blocked", (long long)c->blocked);
    sl_log_int(&ev, "bytes_from_client", (long long)c->bytes_from_client);
    sl_log_int(&ev, "bytes_from_upstream", (long long)c->bytes_from_upstream);
    sl_log_int(&ev, "duration_ms", (long long)(sl_now_ms() - c->opened_ms));
    sl_log_end(&ev);

    if (c->guard != NULL && c->g_asked && c->prompt != NULL) {
        sl_prompt_cancel(c->prompt, c);
    }
    sl_confirm_free(c->guard);
    sl_buf_free(&c->g_server);
    sl_buf_free(&c->g_client);
    sl_tls_free(c->ctls);
    sl_tls_free(c->tls); /* before the socket it uses is closed */
    sl_net_target_free(c->target);
    if (c->client_fd >= 0) {
        close(c->client_fd);
    }
    if (c->upstream_fd >= 0) {
        close(c->upstream_fd);
    }
    sl_buf_free(&c->c2u);
    sl_buf_free(&c->u2c);
    free(c);
}

int sl_conn_client_fd(const sl_conn *c)
{
    return c->client_fd;
}

int sl_conn_upstream_fd(const sl_conn *c)
{
    return c->upstream_fd;
}

int sl_conn_is_done(const sl_conn *c)
{
    return c->state == ST_DONE;
}

void sl_conn_abort(sl_conn *c, const char *reason)
{
    finish(c, reason);
}

static void answer_guard(sl_conn *c, int yes, const char *outcome);

int64_t sl_conn_deadline(const sl_conn *c)
{
    if (c->state == ST_DONE) {
        return -1;
    }
    if (c->guard != NULL && c->g_asked) {
        return c->g_deadline_ms; /* the person has this long to answer */
    }
    return c->deadline_ms;
}

void sl_conn_check_deadline(sl_conn *c, int64_t now_ms)
{
    if (c->state != ST_DONE && c->guard != NULL && c->g_asked && now_ms >= c->g_deadline_ms) {
        if (c->prompt != NULL) {
            sl_prompt_cancel(c->prompt, c);
        }
        answer_guard(c, 0, "timeout");
        return;
    }
    if (c->state == ST_DONE || c->deadline_ms < 0 || now_ms < c->deadline_ms) {
        return;
    }
    finish(c, (c->state == ST_CONNECTING || c->state == ST_TLS) ? "upstream_timeout"
                                                                : "startup_timeout");
}

/* ---- the upstream socket: plain, or through TLS once the handshake is done ---- */

/* Like send(2) and recv(2): bytes, 0 at the end of the stream (reads), or -1 with errno set
 * (EAGAIN: try again when poll() says so; for TLS, up_rd_wants_write / up_wr_wants_read say which
 * readiness). */
static ssize_t up_write(sl_conn *c, const void *buf, size_t n)
{
    int want;
    ssize_t r;

    if (!c->tls_ready) {
        return send(c->upstream_fd, buf, n, SL_SEND_FLAGS);
    }
    r = sl_tls_write(c->tls, buf, n, &want);
    c->up_wr_wants_read = (r == -1 && want == SL_TLS_WANT_READ);
    if (r == -1) {
        errno = EAGAIN;
    } else if (r < 0) {
        errno = EIO;
        r = -1;
    }
    return r;
}

static ssize_t up_read(sl_conn *c, void *buf, size_t n)
{
    int want;
    ssize_t r;

    if (!c->tls_ready) {
        return recv(c->upstream_fd, buf, n, 0);
    }
    r = sl_tls_read(c->tls, buf, n, &want);
    c->up_rd_wants_write = (r == -1 && want == SL_TLS_WANT_WRITE);
    if (r == -1) {
        errno = EAGAIN;
    } else if (r < 0) {
        errno = EIO;
        r = -1;
    }
    return r;
}

/* The client's socket: plain, or through TLS once the handshake with it is done. Same conventions
 * as up_read and up_write. */
static ssize_t cl_read(sl_conn *c, void *buf, size_t n)
{
    int want;
    ssize_t r;

    if (!c->cl_tls_ready) {
        return recv(c->client_fd, buf, n, 0);
    }
    r = sl_tls_read(c->ctls, buf, n, &want);
    c->cl_rd_wants_write = (r == -1 && want == SL_TLS_WANT_WRITE);
    if (r == -1) {
        errno = EAGAIN;
    } else if (r < 0) {
        errno = EIO;
        r = -1;
    }
    return r;
}

static ssize_t cl_write(sl_conn *c, const void *buf, size_t n)
{
    int want;
    ssize_t r;

    if (!c->cl_tls_ready) {
        return send(c->client_fd, buf, n, SL_SEND_FLAGS);
    }
    r = sl_tls_write(c->ctls, buf, n, &want);
    c->cl_wr_wants_read = (r == -1 && want == SL_TLS_WANT_READ);
    if (r == -1) {
        errno = EAGAIN;
    } else if (r < 0) {
        errno = EIO;
        r = -1;
    }
    return r;
}

/* The upstream socket failed after the connection was set up: say why in the log, then end. */
static void log_upstream_error(const sl_conn *c, const char *code, const char *error, int alert);

static void upstream_failed(sl_conn *c)
{
    if (c->state == ST_DONE) {
        return; /* already over, and already explained */
    }
    if (c->tls_ready) {
        log_upstream_error(c, sl_tls_last_code(c->tls), sl_tls_last_error(c->tls),
                           sl_tls_last_alert(c->tls));
    } else {
        log_upstream_error(c, "io_error", errno != 0 ? strerror(errno) : "connection error", -1);
    }
    finish(c, "upstream_error");
}

/* ---- writing ---- */

static void flush_u2c(sl_conn *c)
{
    while (c->state != ST_DONE && u2c_sendable(c) > 0) {
        ssize_t n = cl_write(c, sl_buf_data(&c->u2c), u2c_sendable(c));

        if (n > 0) {
            sl_buf_consume(&c->u2c, (size_t)n);
            if (c->u_scan) {
                c->u_released -= (size_t)n;
            } else if (c->state == ST_RELAY && c->srv_on) {
                c->srv.released -= (size_t)n;
            }
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return;
        } else {
            finish(c, "client_error");
        }
    }
}

/* Writes the released part of c2u to the upstream. Held bytes stay where they are. */
static void flush_c2u(sl_conn *c)
{
    while (c->state != ST_DONE && c->upstream_fd >= 0 && c->scan.released > 0) {
        ssize_t n = up_write(c, sl_buf_data(&c->c2u), c->scan.released);

        if (n > 0) {
            sl_buf_consume(&c->c2u, (size_t)n);
            c->scan.released -= (size_t)n;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return;
        } else {
            upstream_failed(c);
        }
    }
}

/* Queues a PostgreSQL FATAL error for the client and ends the connection once it is sent. Only
 * valid before RELAY: later, writing into the stream could land in the middle of a message. */
static void fatal(sl_conn *c, const char *sqlstate, const char *msg, const char *reason)
{
    if (c->state == ST_DONE) {
        return;
    }
    sl_tls_free(c->tls);
    c->tls = NULL;
    c->tls_ready = 0;
    sl_net_target_free(c->target);
    c->target = NULL;
    if (c->upstream_fd >= 0) {
        close(c->upstream_fd);
        c->upstream_fd = -1;
    }
    sl_buf_free(&c->c2u);
    c->scan.released = 0;
    c->closing = 1;
    c->close_reason = reason;

    if (sl_pg_append_error(&c->u2c, "FATAL", sqlstate, msg) != 0) {
        finish(c, reason);
        return;
    }
    flush_u2c(c);
    check_done(c);
}

/* ---- judging the client's messages ---- */

typedef enum { STMT_OK, STMT_MALFORMED, STMT_OVERSIZED, STMT_FASTPATH } stmt_status;

/* What the policy thinks of a message, and what sluice does about it. */
typedef struct {
    const char *verdict; /* "allow", "deny", "uninspectable"; NULL when there is no policy */
    const char *rule;    /* the rule that decided, when one did */
    char detail[256];    /* why it could not be inspected */
    char reason[320];    /* the text the client will see in its error, when blocked */
    int has_detail;
    int blocked;
    int held;      /* a confirmation has started: the statement is being run */
    int confirm;   /* the policy wants a person to confirm this statement */
    int guardable; /* it is exactly one DELETE or UPDATE: it can be run, then looked at */
    uint8_t kind;  /* 'D' or 'U' */
    int returning; /* it has a RETURNING of its own */
    unsigned long long over_rows;
    const sl_rule *crule;
    /* the tables of the message, for the log: only filled when a rule needs them */
    char table_text[1024];
    const char *tables[32];
    size_t ntables;
    int tables_cut;
} judgement;

/* Remembers "schema.name" of every table of the message, once each, for as long as there is room.
 */
static void note_tables(judgement *j, const sl_sql_info *info)
{
    size_t used = 0;

    for (size_t g = 0; g < info->top_level; g++) {
        for (size_t i = 0; i < info->tables[g].count; i++) {
            const sl_sql_table *t = &info->tables[g].items[i];
            char full[256];
            size_t len;
            size_t k;

            len = (size_t)snprintf(full, sizeof full, "%s%s%s", t->schema, t->schema[0] ? "." : "",
                                   t->name);
            if (len >= sizeof full) {
                len = sizeof full - 1;
            }
            for (k = 0; k < j->ntables && strcmp(j->tables[k], full) != 0; k++) {
            }
            if (k < j->ntables) {
                continue; /* already noted */
            }
            if (j->ntables == sizeof j->tables / sizeof j->tables[0] ||
                used + len + 1 > sizeof j->table_text) {
                j->tables_cut = 1;
                return;
            }
            memcpy(j->table_text + used, full, len + 1);
            j->tables[j->ntables++] = j->table_text + used;
            used += len + 1;
        }
    }
}

static void judgement_uninspectable(const sl_conn *c, judgement *j, const char *why)
{
    j->verdict = "uninspectable";
    snprintf(j->detail, sizeof j->detail, "%s", why);
    j->has_detail = 1;
    j->blocked = enforcing(c) && policy_now(c)->deny_uninspectable;
    snprintf(j->reason, sizeof j->reason, "sluice: cannot inspect this statement (%s)", j->detail);
}

/* st is NULL when the message could not even be read (malformed, too big, fast-path call): why says
 * so. */
static void judge(const sl_conn *c, const sl_pg_statement *st, const char *why, judgement *j)
{
    const sl_policy *pol = policy_now(c);
    sl_sql_info info;
    char err[256];
    sl_verdict v;
    char pr[200];

    memset(j, 0, sizeof *j);
    if (pol == NULL) {
        return;
    }
    if (st == NULL) {
        judgement_uninspectable(c, j, why);
        return;
    }
    /* The tables cost a second parse of each statement: only worked out when a rule is about them.
     */
    if ((sl_policy_needs_tables(pol)
             ? sl_sql_classify_with_tables(st->sql, st->sql_len, &info, err, sizeof err)
             : sl_sql_classify(st->sql, st->sql_len, &info, err, sizeof err)) != 0) {
        judgement_uninspectable(c, j, err);
        return;
    }
    v = sl_policy_evaluate(pol, &info, c->user, c->user_len, c->database, c->database_len);
    if (info.tables != NULL) {
        note_tables(j, &info);
    }
    if (v.confirm) {
        size_t dml = 0;

        for (size_t i = 0; i < info.count; i++) {
            dml += (info.flags[i] & SL_SQL_NOT_READ_ONLY) != 0;
        }
        j->kind = info.top_kind;
        j->returning = info.top_returning;
        j->guardable = info.top_kind != 0 && info.top_level == 1 && dml == 1;
    }
    sl_sql_info_free(&info);

    if (!v.deny) {
        j->verdict = v.confirm ? "confirm" : "allow";
        if (v.confirm) {
            j->confirm = 1;
            j->rule = v.rule->name;
            j->crule = v.rule;
            j->over_rows = v.rule->over_rows;
        }
        return;
    }
    j->verdict = "deny";
    j->rule = v.rule->name;
    j->blocked = enforcing(c);
    sl_policy_reason(v.rule, pr, sizeof pr);
    snprintf(j->reason, sizeof j->reason, "sluice: %s", pr);
}

static const char *kind_name(uint8_t type)
{
    return type == 'Q' ? "query" : type == 'P' ? "parse" : "function";
}

static void log_statement(sl_conn *c, uint8_t type, const sl_pg_statement *st, stmt_status status,
                          size_t message_len, const judgement *j)
{
    sl_log_ev ev;

    c->statements++;
    sl_log_begin(&ev, "statement");
    sl_log_int(&ev, "id", (long long)c->id);
    sl_log_str(&ev, "user", c->user, c->user_len);
    sl_log_str(&ev, "database", c->database, c->database_len);
    sl_log_cstr(&ev, "kind", kind_name(type));

    if (status == STMT_OK && c->cfg->log_sql == SL_LOGSQL_FULL) {
        size_t shown = sl_json_utf8_prefix(st->sql, st->sql_len, LOG_SQL_MAX);

        if (type == 'P') {
            sl_log_str(&ev, "name", st->name, st->name_len);
        }
        sl_log_str(&ev, "sql", st->sql, shown);
        sl_log_int(&ev, "sql_len", (long long)st->sql_len);
        if (shown < st->sql_len) {
            sl_log_bool(&ev, "truncated", 1);
        }
    } else if (status == STMT_OK) {
        /* The values of the statement stay out of the log: its shape (normalized text, when it can
         * be shown safely) and a fingerprint of it go in. A statement that does not parse has
         * neither. */
        sl_sql_redacted rd;
        char perr[200];
        int parsed = sl_sql_redact(st->sql, st->sql_len, &rd, perr, sizeof perr) == 0;

        if (type == 'P') {
            sl_log_str(&ev, "name", st->name, st->name_len);
        }
        if (parsed && rd.text != NULL && c->cfg->log_sql == SL_LOGSQL_NORMALIZED) {
            size_t len = strlen(rd.text);
            size_t shown = sl_json_utf8_prefix(rd.text, len, LOG_SQL_MAX);

            sl_log_str(&ev, "sql", rd.text, shown);
            if (shown < len) {
                sl_log_bool(&ev, "truncated", 1);
            }
        } else {
            sl_log_bool(&ev, "sql_redacted", 1);
        }
        if (parsed) {
            sl_log_cstr(&ev, "fingerprint", rd.fingerprint);
            sl_sql_redacted_free(&rd);
        }
        sl_log_int(&ev, "sql_len", (long long)st->sql_len);
    } else if (status == STMT_MALFORMED) {
        sl_log_bool(&ev, "malformed", 1);
        sl_log_int(&ev, "message_len", (long long)message_len);
    } else if (status == STMT_OVERSIZED) {
        sl_log_bool(&ev, "oversized", 1);
        sl_log_int(&ev, "message_len", (long long)message_len);
    } else {
        sl_log_int(&ev, "message_len", (long long)message_len);
    }

    if (j->verdict != NULL) {
        sl_log_cstr(&ev, "verdict", j->verdict);
        if (j->rule != NULL) {
            sl_log_cstr(&ev, "rule", j->rule);
        }
        if (j->ntables > 0) {
            sl_log_list(&ev, "tables", j->tables, j->ntables);
            if (j->tables_cut) {
                sl_log_bool(&ev, "tables_truncated", 1);
            }
        }
        if (j->has_detail) {
            char shown[sizeof j->detail];

            /* a parser message quotes the SQL ("at or near ..."): not in a log that keeps values
             * out */
            snprintf(shown, sizeof shown, "%s", j->detail);
            if (c->cfg->log_sql != SL_LOGSQL_FULL) {
                sl_sql_scrub_error(shown);
            }
            sl_log_cstr(&ev, "detail", shown);
        }
        sl_log_cstr(&ev, "action", j->blocked ? "blocked" : (j->held ? "held" : "relayed"));
    }
    sl_log_end(&ev);
}

/* Builds the message that takes the place of a blocked one: same kind, guaranteed to fail on the
 * server. */
static int build_replacement(sl_buf *out, uint8_t type, const char *name, size_t name_len,
                             const char *reason)
{
    if (type == 'P') {
        return sl_pg_append_failing_parse(out, name, name_len, reason);
    }
    return sl_pg_append_failing_query(out,
                                      reason); /* 'Q', and the fast-path 'F' (it too is answered by
                                                  an ErrorResponse and a ReadyForQuery) */
}

static void log_frame_error(const sl_conn *c)
{
    sl_log_ev ev;

    sl_log_begin(&ev, "frame_error");
    sl_log_int(&ev, "id", (long long)c->id);
    sl_log_cstr(&ev, "detail", "invalid message header from the client");
    sl_log_cstr(&ev, "action",
                enforcing(c) ? "the connection is closed"
                             : "the rest of the stream is relayed without inspection");
    sl_log_end(&ev);
}

/* What the scanner (scanner.c) asks of the connection: judge a message, and say what replaces it
 * when it is blocked. The walk through the stream itself is the scanner's. */

/* A Query or Parse message, complete and small enough to be read. Judged and logged; blocked means
 * that `replacement` holds the message that fails in its place. */
/* ---- a DELETE or UPDATE that a person confirms (see confirm.h and docs/design.md, section 20)
 * ---- */

static void scan_c2u(sl_conn *c);

/* The server has answered everything that was sent before: nothing is in flight. */
static int server_idle(const sl_conn *c)
{
    return c->first_z && c->scan.owed <= c->z_seen;
}

/* The stream of the server is followed, so that what the server owes can be known. */
static int session_followed(const sl_conn *c)
{
    return c->srv_on && !c->srv.lost && !c->scan.owed_unknown;
}

typedef enum { PLAN_NORMAL, PLAN_BLOCK, PLAN_WAIT, PLAN_GUARD } plan;

/* What to do with a statement that a rule wants confirmed. */
static plan confirm_plan(const sl_conn *c, uint8_t type, judgement *j)
{
    const char *why = NULL;

    if (!j->confirm || !enforcing(c)) {
        return PLAN_NORMAL; /* in audit mode the verdict is logged and the statement goes through */
    }
    if (type != 'Q') {
        why = "it can be confirmed only with the simple query protocol for now (psql, not a "
              "prepared statement)";
    } else if (!j->guardable) {
        why = "it can be confirmed only when the message holds one DELETE or UPDATE, and nothing "
              "else that changes data";
    } else if (!session_followed(c)) {
        why = "sluice cannot follow this session closely enough to confirm";
    }
    if (why != NULL) {
        j->blocked = 1;
        snprintf(j->reason, sizeof j->reason, "sluice: rule %s asks for a confirmation, but %s",
                 j->rule, why);
        return PLAN_BLOCK;
    }
    if (c->tx_status == 'E' && c->first_z) {
        return PLAN_NORMAL; /* the transaction is aborted: the server refuses it anyway */
    }
    return server_idle(c) ? PLAN_GUARD : PLAN_WAIT;
}

static unsigned count_queries(const sl_buf *b)
{
    const uint8_t *d = sl_buf_data(b);
    size_t pos = 0;
    unsigned n = 0;

    while (d != NULL && pos + 5 <= sl_buf_len(b)) {
        size_t len = sl_pg_get_be32(d + pos + 1);

        n += d[pos] == 'Q';
        pos += 1 + len;
    }
    return n;
}

/* Sends what the confirmation asked to send to the server, ahead of whatever the client sent
 * after its statement. */
static void guard_send(sl_conn *c)
{
    size_t len = sl_buf_len(&c->g_server);

    if (len == 0) {
        return;
    }
    if (sl_scan_inject(&c->scan, &c->c2u, sl_buf_data(&c->g_server), len,
                       count_queries(&c->g_server)) != 0) {
        finish(c, "out_of_memory");
        return;
    }
    sl_buf_free(&c->g_server);
    flush_c2u(c);
}

static void answer_guard(sl_conn *c, int yes, const char *outcome)
{
    c->g_asked = 0;
    if (sl_confirm_answer(c->guard, yes, outcome, &c->g_server) != 0) {
        finish(c, "out_of_memory");
        return;
    }
    guard_send(c);
}

/* Called by the prompt when the person has answered. */
static void confirm_reply(void *ctx, int yes)
{
    sl_conn *c = ctx;

    if (c->guard != NULL && c->g_asked && c->state != ST_DONE) {
        answer_guard(c, yes, "no");
    }
}

static void guard_ask(sl_conn *c)
{
    char text[4096];
    int rc;

    (void)sl_confirm_render(c->guard, text, sizeof text);
    rc = c->prompt != NULL ? sl_prompt_ask(c->prompt, c, text, confirm_reply) : -1;
    if (rc != 0) {
        answer_guard(c, 0, rc == -2 ? "error" : "no_terminal");
        return;
    }
    c->g_asked = 1;
    c->g_deadline_ms = sl_now_ms() + (int64_t)c->g_timeout_s * 1000;
}

static void log_confirm(const sl_conn *c)
{
    sl_log_ev ev;

    sl_log_begin(&ev, "confirm");
    sl_log_int(&ev, "id", (long long)c->id);
    sl_log_str(&ev, "user", c->user, c->user_len);
    sl_log_str(&ev, "database", c->database, c->database_len);
    sl_log_cstr(&ev, "rule", c->g_rule);
    sl_log_int(&ev, "rows", (long long)sl_confirm_rows(c->guard));
    sl_log_cstr(&ev, "outcome", sl_confirm_outcome(c->guard));
    sl_log_bool(&ev, "detail", sl_confirm_has_detail(c->guard));
    sl_log_int(&ev, "wait_ms", (long long)(sl_now_ms() - c->g_started_ms));
    sl_log_end(&ev);
}

/* The confirmation is over: the client gets its answer, and the stream goes on. */
static void guard_finish(sl_conn *c)
{
    size_t at = c->srv.released;

    log_confirm(c);
    if (c->g_asked && c->prompt != NULL) {
        sl_prompt_cancel(c->prompt, c);
    }
    c->g_asked = 0;
    if (sl_buf_len(&c->g_client) > 0) {
        if (sl_buf_replace(&c->u2c, at, 0, sl_buf_data(&c->g_client), sl_buf_len(&c->g_client)) !=
            0) {
            finish(c, "out_of_memory");
            return;
        }
        c->srv.released += sl_buf_len(&c->g_client);
    }
    sl_buf_free(&c->g_client);
    sl_confirm_free(c->guard);
    c->guard = NULL;
    c->g_done = 0;
    c->g_ask = 0;
    sl_srv_resume(&c->srv);
    sl_scan_resume(&c->scan);
    /* what the client sent behind the statement has been waiting: it goes on now */
    scan_c2u(c);
    flush_c2u(c);
}

static int begin_guard(sl_conn *c, const sl_pg_statement *st, const judgement *j,
                       sl_buf *replacement)
{
    sl_confirm_args a;
    size_t end = sl_sql_statement_end(st->sql, st->sql_len);
    char *returning = NULL;
    const sl_policy *pol = policy_now(c);
    int rc;

    if (end == 0) {
        return -2; /* the lexer cannot say where the statement ends */
    }
    memset(&a, 0, sizeof a);
    a.sql = st->sql;
    a.sql_len = end;
    if (!j->returning) {
        returning = malloc(end + 13);
        if (returning == NULL) {
            return -1;
        }
        memcpy(returning, st->sql, end);
        memcpy(returning + end, " RETURNING *", 12);
        a.sql_returning = returning;
        a.sql_returning_len = end + 12;
    }
    a.client_returning = j->returning;
    a.tx_status = c->tx_status == 'T' ? 'T' : 'I';
    a.over_rows = j->over_rows;
    a.user = c->user;
    a.user_len = c->user_len;
    a.database = c->database;
    a.database_len = c->database_len;
    a.rule = j->rule;
    a.message = j->crule != NULL ? j->crule->message : NULL;
    c->guard = sl_confirm_new();
    rc = c->guard == NULL ? -1 : sl_confirm_start(c->guard, &a, replacement);
    free(returning);
    if (rc != 0) {
        sl_confirm_free(c->guard);
        c->guard = NULL;
        return -1;
    }
    c->g_started_ms = sl_now_ms();
    c->g_timeout_s = pol != NULL ? pol->confirm_timeout_s : 120;
    snprintf(c->g_rule, sizeof c->g_rule, "%s", j->rule);
    return 0;
}

static int on_statement(void *ctx, uint8_t type, const uint8_t *payload, size_t len,
                        sl_buf *replacement)
{
    sl_conn *c = ctx;
    sl_pg_statement st;
    judgement j;
    int ok = (type == 'Q' ? sl_pg_statement_from_query(payload, len, &st)
                          : sl_pg_statement_from_parse(payload, len, &st)) == SL_PG_OK;
    plan how;

    judge(c, ok ? &st : NULL, "malformed message", &j);
    how = ok ? confirm_plan(c, type, &j) : PLAN_NORMAL;
    if (how == PLAN_WAIT) {
        /* the server still owes answers to what came before: look at it again when they are in. It
         * is logged then, once. */
        c->scan_waiting = 1;
        return SL_SCAN_WAIT;
    }
    if (how == PLAN_GUARD) {
        int rc = begin_guard(c, &st, &j, replacement);

        if (rc == -1) {
            return SL_SCAN_FAIL;
        }
        if (rc == -2) {
            j.blocked = 1;
            how = PLAN_BLOCK;
            snprintf(j.reason, sizeof j.reason,
                     "sluice: rule %s asks for a confirmation, but the statement cannot be read "
                     "well enough to run it first",
                     j.rule);
        } else {
            j.held = 1;
        }
    }
    log_statement(c, type, &st, ok ? STMT_OK : STMT_MALFORMED, len, &j);
    if (how == PLAN_GUARD) {
        return SL_SCAN_GUARD;
    }
    if (!j.blocked) {
        return SL_SCAN_RELAY;
    }
    if (build_replacement(replacement, type, ok ? st.name : "", ok ? st.name_len : 0, j.reason) !=
        0) {
        return SL_SCAN_FAIL;
    }
    c->blocked++;
    return SL_SCAN_BLOCK;
}

/* A message that will not be read: over the size limit, or a fast-path call. Only its header is
 * known. */
static int on_unreadable(void *ctx, uint8_t type, size_t payload_len, int too_big,
                         sl_buf *replacement)
{
    sl_conn *c = ctx;
    judgement j;

    judge(c, NULL, too_big ? "message over 1 MiB" : "fast-path function calls cannot be inspected",
          &j);
    log_statement(c, type, NULL, too_big ? STMT_OVERSIZED : STMT_FASTPATH, payload_len, &j);
    if (!j.blocked) {
        return SL_SCAN_RELAY;
    }
    if (build_replacement(replacement, type, "", 0, j.reason) != 0) {
        return SL_SCAN_FAIL;
    }
    c->blocked++;
    return SL_SCAN_BLOCK;
}

/* Audit mode stays transparent and stops inspecting; enforce mode cannot know what the bytes mean
 * and closes the connection. */
static int on_frame_error(void *ctx)
{
    sl_conn *c = ctx;

    log_frame_error(c);
    return enforcing(c);
}

static const sl_scan_ops scan_ops = {on_statement, on_unreadable, on_frame_error};

static void scan_c2u(sl_conn *c)
{
    int rc = sl_scan_run(&c->scan, &c->c2u, &scan_ops, c);

    if (rc == SL_SCAN_CLOSE) {
        finish(c, "frame_error");
    } else if (rc == SL_SCAN_NOMEM) {
        finish(c, "out_of_memory");
    }
}

/* ---- startup ---- */

/* code: a stable word to filter and alert on; error: the explanation for a person, which changes
 * with the libraries and the system. alert is the TLS alert number the server sent, or -1. */
static void log_upstream_error(const sl_conn *c, const char *code, const char *error, int alert)
{
    sl_log_ev ev;

    sl_log_begin(&ev, "upstream_error");
    sl_log_int(&ev, "id", (long long)c->id);
    sl_log_cstr(&ev, "code", code);
    if (alert >= 0) {
        sl_log_int(&ev, "tls_alert", alert);
    }
    sl_log_cstr(&ev, "error", error);
    sl_log_end(&ev);
}

static void keep_param(const sl_pg_startup_packet *pkt, const char *key, char *dst, size_t *dst_len)
{
    const char *val;
    size_t vlen;

    *dst_len = 0;
    if (sl_pg_startup_param(pkt, key, &val, &vlen) == 1) {
        *dst_len = sl_json_utf8_prefix(val, vlen, IDENT_MAX);
        memcpy(dst, val, *dst_len);
    }
}

static void record_startup(sl_conn *c, const sl_pg_startup_packet *pkt)
{
    static const char *const keys[] = {"user", "database", "application_name"};
    sl_log_ev ev;
    char proto[16];

    keep_param(pkt, "user", c->user, &c->user_len);
    keep_param(pkt, "database", c->database, &c->database_len);

    sl_log_begin(&ev, "startup");
    sl_log_int(&ev, "id", (long long)c->id);
    for (size_t i = 0; i < sizeof keys / sizeof keys[0]; i++) {
        const char *val;
        size_t vlen;

        if (sl_pg_startup_param(pkt, keys[i], &val, &vlen) == 1) {
            sl_log_str(&ev, keys[i], val, vlen);
        }
    }
    snprintf(proto, sizeof proto, "%u.%u", (unsigned)(pkt->code >> 16),
             (unsigned)(pkt->code & 0xffff));
    sl_log_cstr(&ev, "protocol", proto);
    sl_log_end(&ev);
}

static void read_client(sl_conn *c);
static void cltls_step(sl_conn *c);

/* The client asked for TLS and sluice does it: say yes, in the clear (one byte, as PostgreSQL
 * does), then the handshake. */
static void begin_client_tls(sl_conn *c)
{
    char err[200];
    ssize_t w;

    do {
        w = send(c->client_fd, "S", 1, SL_SEND_FLAGS);
    } while (w < 0 && errno == EINTR);
    if (w != 1) {
        finish(c, "client_error");
        return;
    }
    c->ctls = sl_tls_start_server(c->client_tls_ctx, c->client_fd, err, sizeof err);
    if (c->ctls == NULL) {
        sl_log_ev ev;

        sl_log_begin(&ev, "client_tls_error");
        sl_log_int(&ev, "id", (long long)c->id);
        sl_log_cstr(&ev, "error", err);
        sl_log_end(&ev);
        finish(c, "internal_error");
        return;
    }
    cltls_step(c);
}

/* A replication connection (replication=true, on, yes, 1 or database) speaks a protocol of its own,
 * and with replication=database it runs ordinary SQL: sluice would not see it the way it sees a
 * normal one. */
static int wants_replication(const sl_pg_startup_packet *pkt)
{
    static const char *const off[] = {"false", "off", "no", "0"};
    const char *val;
    size_t vlen;

    if (sl_pg_startup_param(pkt, "replication", &val, &vlen) != 1) {
        return 0;
    }
    for (size_t i = 0; i < sizeof off / sizeof off[0]; i++) {
        if (strlen(off[i]) == vlen && strncasecmp(val, off[i], vlen) == 0) {
            return 0;
        }
    }
    return 1;
}

static void begin_connect(sl_conn *c, size_t packet_len)
{
    char err[sizeof c->cfg->upstream_host + sizeof c->cfg->upstream_port + 256];
    int fd;

    c->target =
        sl_net_target_resolve(c->cfg->upstream_host, c->cfg->upstream_port, err, sizeof err);
    fd = c->target != NULL ? sl_net_target_next(c->target, 0, err, sizeof err) : -1;
    if (fd < 0) {
        log_upstream_error(c, "connect_failed", err, -1);
        fatal(c, "08001", "sluice: cannot connect to the upstream database",
              "upstream_unreachable");
        return;
    }
    c->upstream_fd = fd;
    c->startup_len = packet_len;
    c->state = ST_CONNECTING;
}

/* Consumes what the client sent while in STARTUP. The packet that ends the phase is left in c2u so
 * that it becomes the first thing written upstream. */
static void advance_startup(sl_conn *c)
{
    for (;;) {
        sl_pg_startup_packet pkt;
        int rc = sl_pg_parse_startup_packet(sl_buf_data(&c->c2u), sl_buf_len(&c->c2u), &pkt);

        if (rc == SL_PG_NEED_MORE) {
            return;
        }
        if (rc == SL_PG_ERROR) {
            fatal(c, "08P01", "sluice: invalid startup packet", "protocol_error");
            return;
        }

        if (pkt.kind == SL_PG_SSL_REQUEST && c->client_tls_ctx != NULL) {
            if (c->ctls != NULL || sl_buf_len(&c->c2u) != pkt.total_len) {
                /* A second request, or bytes sent behind this one before the handshake: once the
                 * session is encrypted they would be taken for something the client sent under it.
                 */
                fatal(c, "08P01", "sluice: unexpected data before the TLS handshake",
                      "protocol_error");
                return;
            }
            sl_buf_consume(&c->c2u, pkt.total_len);
            begin_client_tls(c);
            return;
        }

        switch (pkt.kind) {
        case SL_PG_SSL_REQUEST:
        case SL_PG_GSSENC_REQUEST:
            /* No encryption towards the proxy: say so, the client then sends its real startup
             * packet (or fails if it insists on TLS). */
            if (sl_buf_append(&c->u2c, "N", 1) != 0) {
                finish(c, "out_of_memory");
                return;
            }
            sl_buf_consume(&c->c2u, pkt.total_len);
            flush_u2c(c);
            if (c->state == ST_DONE) {
                return;
            }
            break;
        case SL_PG_CANCEL_REQUEST: {
            sl_log_ev ev;

            sl_log_begin(&ev, "cancel_request");
            sl_log_int(&ev, "id", (long long)c->id);
            sl_log_end(&ev);
            begin_connect(c, pkt.total_len);
            return;
        }
        case SL_PG_STARTUP_MESSAGE:
            if (c->client_tls_ctx != NULL && !c->cl_tls_ready) {
                fatal(c, "28000", "sluice: this server requires TLS (sslmode=require or stronger)",
                      "tls_required");
                return;
            }
            record_startup(c, &pkt);
            if (enforcing(c) && wants_replication(&pkt)) {
                fatal(c, "42501", "sluice: replication connections are not allowed through sluice",
                      "replication_denied");
                return;
            }
            begin_connect(c, pkt.total_len);
            return;
        }
    }
}

/* ---- reading ---- */

static void read_client(sl_conn *c)
{
    uint8_t *p = sl_buf_reserve(&c->c2u, READ_CHUNK);
    ssize_t n;

    if (p == NULL) {
        finish(c, "out_of_memory");
        return;
    }
    n = cl_read(c, p, READ_CHUNK);
    if (n > 0) {
        sl_buf_commit(&c->c2u, (size_t)n);
        c->bytes_from_client += (uint64_t)n;
        if (c->state == ST_STARTUP) {
            advance_startup(c);
        } else if (c->state == ST_RELAY) {
            scan_c2u(c);
            flush_c2u(c);
        }
        /* else the database is not reached yet: the bytes wait in c2u, enter_relay() scans them */
    } else if (n == 0) {
        c->client_eof = 1;
        if (c->state == ST_RELAY && !c->scan.paused) {
            /* Whatever is still held (a message cut short) goes through as it is: the upstream sees
             * the same truncated stream it would have seen without sluice, and drops it. */
            c->scan.released = sl_buf_len(&c->c2u);
            flush_c2u(c);
        }
    } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
        finish(c, "client_error");
    }
}

static void cltls_step(sl_conn *c)
{
    char err[256];

    switch (sl_tls_handshake(c->ctls, err, sizeof err)) {
    case SL_TLS_DONE:
        c->cl_tls_ready = 1;
        read_client(c); /* the startup packet may already be here */
        return;
    case SL_TLS_WANT_READ:
        c->cl_hs_want = SL_TLS_WANT_READ;
        return;
    case SL_TLS_WANT_WRITE:
        c->cl_hs_want = SL_TLS_WANT_WRITE;
        return;
    default: {
        sl_log_ev ev;

        sl_log_begin(&ev, "client_tls_error");
        sl_log_int(&ev, "id", (long long)c->id);
        sl_log_cstr(&ev, "error", err);
        sl_log_end(&ev);
        finish(c, "client_tls_failed");
    }
    }
}

/* True when the TLS library holds bytes that a read would return although the socket is quiet. */
static int tls_has_pending(const sl_conn *c)
{
    return c->tls_ready && !c->upstream_eof && sl_tls_pending(c->tls);
}

/* The server's first authentication message, when it offers SCRAM-SHA-256-PLUS, is sent on without
 * it.
 *
 * Channel binding ties the login to the TLS session between the client and the server. With sluice
 * in the middle there are two sessions, so it cannot hold; and a client that is not on TLS (it is
 * not: it talks to sluice in clear) refuses a server that offers it. Without PLUS in the list the
 * client picks plain SCRAM-SHA-256, which a server accepts on a TLS connection too. A client that
 * insists on channel binding (channel_binding=require) then fails to log in, which is the right
 * answer.
 *
 * Only that first message is looked at; every other byte of the server's stream is relayed
 * untouched. A NegotiateProtocolVersion message may come first. The whole message is held until it
 * is complete. */
#define AUTH_MSG_MAX 8192

static void scan_u2c(sl_conn *c)
{
    while (c->u_scan) {
        size_t avail = sl_buf_len(&c->u2c) - c->u_released;
        const uint8_t *p;
        uint32_t length;

        if (avail < 5) {
            return;
        }
        p = sl_buf_data(&c->u2c) + c->u_released;
        length = sl_pg_get_be32(p + 1);
        if (length < 4 || length > AUTH_MSG_MAX) {
            break; /* not the kind of message this is about */
        }
        if (avail < 1 + (size_t)length) {
            return;
        }
        if (p[0] == 'v') {
            c->u_released += 1 + (size_t)length;
            continue;
        }
        if (p[0] == 'R' && length >= 8 && sl_pg_get_be32(p + 5) == 10) {
            sl_buf repl;
            int rc;

            sl_buf_init(&repl);
            rc = sl_pg_sasl_drop_plus(p + 5, length - 4, &repl);
            if (rc == 1) {
                rc = sl_buf_replace(&c->u2c, c->u_released, 1 + (size_t)length, sl_buf_data(&repl),
                                    sl_buf_len(&repl)) == 0
                         ? 1
                         : -1;
            }
            if (rc < 0) {
                sl_buf_free(&repl);
                finish(c, "out_of_memory");
                return;
            }
            if (rc == 1) {
                sl_log_ev ev;

                sl_log_begin(&ev, "auth_adjusted");
                sl_log_int(&ev, "id", (long long)c->id);
                sl_log_cstr(&ev, "detail",
                            "SCRAM-SHA-256-PLUS removed from the server's offer: channel "
                            "binding cannot work through sluice");
                sl_log_end(&ev);
            }
            sl_buf_free(&repl);
        }
        break; /* the first authentication message is the only one of interest */
    }
    c->u_scan = 0;
    c->srv.released = c->u_released; /* what follows is for the server scanner */
}

/* ---- the server's stream ---- */

static int srv_classify(void *ctx, uint8_t type, size_t payload_len)
{
    sl_conn *c = ctx;

    (void)payload_len;
    if (c->guard != NULL) {
        return SL_SRV_READ; /* every answer to the statement is read, and kept or consumed */
    }
    return type == 'Z' ? SL_SRV_READ : SL_SRV_PASS;
}

static int srv_message(void *ctx, uint8_t type, const uint8_t *payload, size_t len)
{
    sl_conn *c = ctx;

    if (type == 'Z' && len >= 1) {
        c->tx_status = payload[0];
        if (c->first_z) {
            c->z_seen++;
        }
        c->first_z = 1;
    }
    if (c->guard != NULL) {
        sl_confirm_step step;
        int rc = sl_confirm_server(c->guard, type, payload, len, &c->g_server, &c->g_client, &step);

        if (rc < 0) {
            c->g_nomem = 1;
            return SL_SRV_KEEP;
        }
        c->g_ask |= step.ask;
        if (step.done) {
            c->g_done = 1;
            c->srv.paused = 1; /* what follows is not part of the confirmation */
        }
        return rc;
    }
    return SL_SRV_KEEP;
}

static const sl_srv_ops srv_ops = {srv_classify, srv_message};

/* A statement that waited for the server to be quiet can go on. */
static int resume_waiting_statement(sl_conn *c)
{
    if (!c->scan_waiting || c->guard != NULL || !server_idle(c)) {
        return 0;
    }
    c->scan_waiting = 0;
    sl_scan_resume(&c->scan);
    scan_c2u(c);
    flush_c2u(c);
    return 1;
}

static void scan_server(sl_conn *c)
{
    if (!c->srv_on) {
        return;
    }
    for (int again = 1; again && c->state != ST_DONE;) {
        unsigned oversized = 0;

        again = 0;
        c->g_ask = 0;
        (void)sl_srv_run(&c->srv, &c->u2c, &srv_ops, c, &oversized);
        if (c->g_nomem) {
            finish(c, "out_of_memory");
            return;
        }
        if (c->guard != NULL) {
            if (oversized > 0) {
                sl_confirm_overflow(c->guard);
            }
            guard_send(c);
            if (c->state == ST_DONE) {
                return;
            }
            if (c->g_done) {
                guard_finish(c);
                again =
                    1; /* what the server sent after the confirmation, and what the client sent */
            } else if (c->g_ask) {
                guard_ask(c);
            }
        }
        if (resume_waiting_statement(c)) {
            again = 1;
        }
    }
}

static void read_upstream(sl_conn *c)
{
    for (;;) {
        uint8_t *p = sl_buf_reserve(&c->u2c, READ_CHUNK);
        ssize_t n;

        if (p == NULL) {
            finish(c, "out_of_memory");
            return;
        }
        n = up_read(c, p, READ_CHUNK);
        if (n > 0) {
            sl_buf_commit(&c->u2c, (size_t)n);
            c->bytes_from_upstream += (uint64_t)n;
            if (c->u_scan) {
                scan_u2c(c);
            }
            if (!c->u_scan) {
                scan_server(c);
            }
            flush_u2c(c);
            if (c->state != ST_DONE && tls_has_pending(c) && sl_buf_len(&c->u2c) < HIGH_WATER) {
                continue; /* the library still holds bytes: the socket will not tell us */
            }
        } else if (n == 0) {
            c->upstream_eof = 1;
            c->u_scan = 0; /* whatever is held goes to the client as it is */
            if (c->srv_on) {
                c->srv.released = sl_buf_len(&c->u2c);
            }
            flush_u2c(c);
        } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            upstream_failed(c);
        }
        return;
    }
}

/* Bytes that TLS holds inside its library, where poll() cannot see them, for the client's side...
 */
static int client_has_pending(const sl_conn *c)
{
    return c->cl_tls_ready && !c->client_eof && !c->closing && c->state != ST_DONE &&
           sl_buf_len(&c->c2u) < HIGH_WATER && sl_tls_pending(c->ctls);
}

/* ...and for the upstream's. */
static int upstream_has_pending(const sl_conn *c)
{
    return c->state == ST_RELAY && !c->closing && tls_has_pending(c) &&
           sl_buf_len(&c->u2c) < HIGH_WATER;
}

int sl_conn_has_pending(const sl_conn *c)
{
    return client_has_pending(c) || upstream_has_pending(c);
}

void sl_conn_service_pending(sl_conn *c)
{
    if (client_has_pending(c)) {
        read_client(c);
    }
    if (upstream_has_pending(c)) {
        read_upstream(c);
    }
    check_done(c);
}

/* ---- events ---- */

short sl_conn_client_events(const sl_conn *c)
{
    short ev = 0;

    if (c->state == ST_DONE) {
        return 0;
    }
    if (c->ctls != NULL && !c->cl_tls_ready) {
        return c->cl_hs_want == SL_TLS_WANT_WRITE ? POLLOUT : POLLIN;
    }
    if (u2c_sendable(c) > 0 || c->cl_rd_wants_write) {
        ev |= POLLOUT;
    }
    if (c->cl_wr_wants_read) {
        ev |= POLLIN;
    }
    if (!c->closing && !c->client_eof) {
        if (c->state == ST_STARTUP) {
            ev |= POLLIN;
        } else if (c->state == ST_RELAY && c->scan.released < HIGH_WATER &&
                   (!c->scan.paused || sl_buf_len(&c->c2u) < HIGH_WATER)) {
            /* Backpressure counts what the upstream has not taken yet, not what the scanner holds:
             * a held message must be able to finish arriving. */
            ev |= POLLIN;
        } else if ((c->state == ST_CONNECTING || c->state == ST_TLS) &&
                   sl_buf_len(&c->c2u) < HIGH_WATER) {
            /* Listened to while the database is being reached too: a client that gives up (a reset,
             * a close) is seen at once, instead of when the connection attempt times out. What it
             * sends meanwhile is kept. */
            ev |= POLLIN;
        }
    }
    return ev;
}

static short tls_events(const sl_conn *c)
{
    switch (c->phase) {
    case TLS_SEND_REQUEST:
        return POLLOUT;
    case TLS_READ_REPLY:
        return POLLIN;
    default:
        return c->hs_want == SL_TLS_WANT_WRITE ? POLLOUT : POLLIN;
    }
}

short sl_conn_upstream_events(const sl_conn *c)
{
    short ev = 0;

    if (c->state == ST_DONE || c->upstream_fd < 0) {
        return 0;
    }
    if (c->state == ST_CONNECTING) {
        return POLLOUT;
    }
    if (c->state == ST_TLS) {
        return tls_events(c);
    }
    /* With TLS a write may need the socket to be readable, and a read may need it writable. */
    if (c->scan.released > 0 || c->up_rd_wants_write) {
        ev |= POLLOUT;
    }
    if ((!c->closing && !c->upstream_eof && sl_buf_len(&c->u2c) < HIGH_WATER) ||
        c->up_wr_wants_read) {
        ev |= POLLIN;
    }
    return ev;
}

void sl_conn_on_client(sl_conn *c, short revents)
{
    if (c->state == ST_DONE) {
        return;
    }
    if (revents & POLLNVAL) {
        finish(c, "internal_error");
        return;
    }
    if (c->ctls != NULL && !c->cl_tls_ready) {
        if (revents & (POLLIN | POLLOUT | POLLHUP | POLLERR)) {
            cltls_step(c);
        }
        check_done(c);
        return;
    }
    if ((revents & POLLOUT) || (c->cl_wr_wants_read && (revents & POLLIN))) {
        flush_u2c(c);
    }
    if (c->state != ST_DONE && ((revents & (POLLIN | POLLHUP | POLLERR)) ||
                                (c->cl_rd_wants_write && (revents & POLLOUT)))) {
        if (c->closing) {
            /* An error reply is on its way: the client is not read any more, only a dead socket
             * matters. */
            if (revents & (POLLHUP | POLLERR)) {
                finish(c, c->closing ? c->close_reason : "client_closed");
            }
        } else if (!c->client_eof) {
            read_client(c);
        }
    }
    check_done(c);
}

/* The upstream is ready for the client's bytes (after TCP, or after TCP and TLS). */
static void enter_relay(sl_conn *c)
{
    sl_log_ev ev;
    char msg[sizeof c->cfg->upstream_host + sizeof c->cfg->upstream_port + 2]; /* "host:port" */
    char tlsinfo[96];

    c->state = ST_RELAY;
    c->deadline_ms = -1;
    snprintf(msg, sizeof msg, "%s:%s", c->cfg->upstream_host, c->cfg->upstream_port);
    sl_log_begin(&ev, "upstream_connected");
    sl_log_int(&ev, "id", (long long)c->id);
    sl_log_cstr(&ev, "upstream", msg);
    if (c->tls_ready) {
        sl_tls_describe(c->tls, tlsinfo, sizeof tlsinfo);
        sl_log_cstr(&ev, "tls", tlsinfo);
    }
    sl_log_end(&ev);

    /* With TLS to the upstream, read the server's first authentication message (see scan_u2c). What
     * is already in u2c, such as the 'N' answer to an SSLRequest, was meant for the client: it may
     * go. */
    c->u_scan = c->tls_ready;
    c->u_released = sl_buf_len(&c->u2c);
    c->srv_on = c->policy_ref != NULL;
    sl_srv_init(&c->srv, c->tls_ready ? 0 : sl_buf_len(&c->u2c), SL_SRV_READ_MAX);

    /* The startup packet goes first; anything the client sent after it is scanned like the rest. */
    c->scan.released = c->startup_len;
    scan_c2u(c);
    flush_c2u(c);
}

static void tls_fail(sl_conn *c, const char *code, const char *why)
{
    log_upstream_error(c, code, why, -1);
    fatal(c, "08001", "sluice: cannot establish TLS with the upstream database",
          "upstream_tls_failed");
}

/* Moves the TLS negotiation as far as the socket allows: SSLRequest, the server's one byte answer,
 * then the handshake. Only the exact answer byte is read, so nothing the server sends in clear
 * after it can be mistaken for TLS data. */
static void tls_step(sl_conn *c)
{
    char err[256];

    for (;;) {
        if (c->phase == TLS_SEND_REQUEST) {
            ssize_t n = send(c->upstream_fd, c->sslreq + c->sslreq_sent,
                             sizeof c->sslreq - c->sslreq_sent, SL_SEND_FLAGS);

            if (n > 0) {
                c->sslreq_sent += (size_t)n;
                if (c->sslreq_sent == sizeof c->sslreq) {
                    c->phase = TLS_READ_REPLY;
                }
                continue;
            }
            if (n < 0 && errno == EINTR) {
                continue;
            }
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                return;
            }
            tls_fail(c, "tls_request_failed", "cannot send the TLS request to the upstream");
            return;
        }

        if (c->phase == TLS_READ_REPLY) {
            char answer;
            ssize_t n = recv(c->upstream_fd, &answer, 1, 0);

            if (n == 1) {
                if (answer != 'S') {
                    tls_fail(c, "tls_not_supported", "the upstream server does not support TLS");
                    return;
                }
                c->tls = sl_tls_start(c->tls_ctx, c->upstream_fd, c->cfg->upstream_host, err,
                                      sizeof err);
                if (c->tls == NULL) {
                    tls_fail(c, "tls_setup_failed", err);
                    return;
                }
                c->phase = TLS_HANDSHAKE;
                continue;
            }
            if (n < 0 && errno == EINTR) {
                continue;
            }
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                return;
            }
            tls_fail(c, "tls_request_failed",
                     "the upstream closed the connection during the TLS request");
            return;
        }

        switch (sl_tls_handshake(c->tls, err, sizeof err)) {
        case SL_TLS_DONE:
            c->tls_ready = 1;
            enter_relay(c);
            return;
        case SL_TLS_WANT_READ:
            c->hs_want = SL_TLS_WANT_READ;
            return;
        case SL_TLS_WANT_WRITE:
            c->hs_want = SL_TLS_WANT_WRITE;
            return;
        default:
            tls_fail(c, "tls_handshake_failed", err);
            return;
        }
    }
}

static void on_connect_ready(sl_conn *c)
{
    int e = sl_net_connect_result(c->upstream_fd);

    if (e != 0) {
        /* this address did not work: the next one, if the name has another */
        char msg[sizeof c->cfg->upstream_host + sizeof c->cfg->upstream_port + 256];
        int fd;

        close(c->upstream_fd);
        c->upstream_fd = -1;
        fd = sl_net_target_next(c->target, e, msg, sizeof msg);
        if (fd >= 0) {
            c->upstream_fd = fd;
            return;
        }
        log_upstream_error(c, "connect_failed", msg, -1);
        fatal(c, "08001", "sluice: cannot connect to the upstream database",
              "upstream_unreachable");
        return;
    }
    sl_net_target_free(c->target); /* connected: the other addresses are not needed */
    c->target = NULL;

    if (c->tls_ctx != NULL) {
        /* the SSLRequest packet: length 8, code 80877103 */
        sl_pg_put_be32(c->sslreq, 8);
        sl_pg_put_be32(c->sslreq + 4, SL_PG_SSL_REQUEST_CODE);
        c->state = ST_TLS;
        c->phase = TLS_SEND_REQUEST;
        tls_step(c);
        return;
    }
    enter_relay(c);
}

void sl_conn_on_upstream(sl_conn *c, short revents)
{
    if (c->state == ST_DONE || c->upstream_fd < 0) {
        return;
    }
    if (revents & POLLNVAL) {
        finish(c, "internal_error");
        return;
    }

    if (c->state == ST_CONNECTING) {
        if (revents & (POLLOUT | POLLERR | POLLHUP)) {
            on_connect_ready(c);
        }
        check_done(c);
        return;
    }

    if (c->state == ST_TLS) {
        if (revents & (POLLIN | POLLOUT | POLLHUP | POLLERR)) {
            tls_step(c);
        }
        check_done(c);
        return;
    }

    /* With TLS a write can be waiting for the socket to become readable, and a read for writable.
     */
    if ((revents & POLLOUT) || (c->up_wr_wants_read && (revents & POLLIN))) {
        flush_c2u(c);
    }
    if (c->state != ST_DONE && !c->upstream_eof &&
        ((revents & (POLLIN | POLLHUP | POLLERR)) ||
         (c->up_rd_wants_write && (revents & POLLOUT)))) {
        read_upstream(c);
    }
    check_done(c);
}
