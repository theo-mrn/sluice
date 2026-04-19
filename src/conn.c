#include "conn.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#include "budget.h"
#include "buf.h"
#include "clock.h"
#include "confirm.h"
#include "extstate.h"
#include "json.h"
#include "log.h"
#include "mask.h"
#include "metrics.h"
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
    int g_via; /* SL_VIA_*: where the guard being run is asked */

    /* The extended protocol (docs/design.md, section 21). */
    sl_ext *ext;  /* the guarded statements and portals, and the answers the server owes */
    int ext_bad;  /* that queue overflowed: it cannot be trusted any more on this connection */
    int g_ext;    /* the confirmation in progress is an extended one */
    int g_front;  /* ... and the server has started to answer it */
    int g_cancel; /* ... and an error came before it: it will not run */

    /* A statement that waits for the person who sent it to confirm it, in their own session: it has
     * run in a transaction that is still open on the server, and everything the client sends is
     * answered here until it says sluice_confirm() or sluice_cancel() (docs/design.md, section 23).
     */
    sl_confirm *pend;
    int pend_skip; /* after an error: ignore messages up to the next Sync */
    int64_t pend_deadline_ms;
    int swallow;   /* answers of a message of ours still to be thrown away (ReadyForQuery) */
    int probe;     /* the catalog query for qualified mask names: 0 not yet, 1 asked, 2 over */
    int probe_bad; /* its answer was an error, or not what was asked for */
    char tag_rewrite[64]; /* the next CommandComplete is that of the statement a yes was turned
                             into: the client gets the tag of the statement it had sent instead */

    /* Limits of the connection (policy.h, sl_limits): what a result and the whole connection may
     * carry out to the client, and how long a statement may run. */
    sl_limits lim;
    int lim_on;                  /* a limit on rows or bytes applies to the stream of the server */
    unsigned long long res_rows; /* DataRows passed in the current result */
    unsigned long long res_bytes;
    unsigned long long total_bytes; /* all that passed on this connection */
    int cut; /* rows of the current result were dropped: 1 rows, 2 bytes, 3 total, 4 a
                budget of rows, 5 a budget of bytes */
    /* Masking (mask.h): the "mask" rules that apply to the user, and what they need of the stream.
     */
    sl_mask *mask;
    int mask_on;
    int mask_overflow;  /* too much to follow: masking cannot be kept up, the connection ends */
    char mask_rule[72]; /* the first rule, for the log */
    unsigned long long masked_cells;
    const uint8_t *mask_key;
    size_t mask_key_len;
    sl_journal *journal;
    sl_budget *budget;
    sl_budget_entry *bud[SL_MAX_BUDGETS]; /* the counters of lim.budgets, held by this connection */
    int bud_stream;                       /* some budget counts rows or bytes sent */
    int bud_changed;                      /* some budget counts rows changed */
    int bud_stmts;                        /* some budget counts round trips */
    int64_t tx_since_ms;                  /* in an open transaction since then, else -1 */
    size_t cut_bud;                       /* the budget that cut the result */
    int close_after_z;    /* the volume of the connection is spent: it ends with this answer */
    const char *z_reason; /* why, for the log (NULL: volume_limit) */
    int killed;           /* a rule with action = "kill" matched: nothing more is let through */
    char kill_rule[72];
    uint8_t be_key[8]; /* the process id and secret of the server's session, to cancel it */
    int have_key;
    int64_t busy_since_ms;    /* the server has been working for the client since then, else -1 */
    int cancelled;            /* a cancel was sent for this busy period */
    int64_t idle_tx_since_ms; /* idle in an open transaction since then, else -1 */
    int64_t mark_ms; /* when the last result ended (or the server became busy): for the time of the
                        next */
    unsigned long long (*count_user)(void *ctx, const sl_conn *self, const char *user, size_t len);
    void *count_ctx;

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
    c->count_user = env->count_user;
    c->count_ctx = env->count_ctx;
    c->budget = env->budget;
    c->mask_key = env->mask_key;
    c->journal = env->journal;
    c->mask_key_len = env->mask_key_len;
    c->busy_since_ms = -1;
    c->idle_tx_since_ms = -1;
    c->tx_since_ms = -1;
    c->mark_ms = -1;
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
    sl_metric_inc(SL_M_CONNECTIONS, NULL, NULL);
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
    if (c->mask_on) {
        sl_log_int(&ev, "masked", (long long)c->masked_cells);
    }
    sl_log_end(&ev);
    sl_metric_inc(SL_M_CLOSED, c->close_reason, NULL);
    sl_metric_add(SL_M_BYTES, "client_to_upstream", NULL, c->bytes_from_client);
    sl_metric_add(SL_M_BYTES, "upstream_to_client", NULL, c->bytes_from_upstream);
    if (c->mask_on) {
        sl_metric_add(SL_M_MASKED, NULL, NULL, c->masked_cells);
    }

    if (c->guard != NULL && c->g_asked && c->prompt != NULL) {
        sl_prompt_cancel(c->prompt, c);
    }
    sl_confirm_free(c->guard);
    sl_buf_free(&c->g_server);
    sl_buf_free(&c->g_client);
    sl_ext_free(c->ext);
    sl_confirm_free(c->pend);
    sl_mask_free(c->mask);
    for (size_t i = 0; i < SL_MAX_BUDGETS; i++) {
        if (c->bud[i] != NULL) {
            sl_budget_release(c->budget, c->bud[i], sl_now_ms());
        }
    }
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

int sl_conn_is_user(const sl_conn *c, const char *user, size_t len)
{
    return c->state != ST_DONE && len > 0 && c->user_len == len && memcmp(c->user, user, len) == 0;
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
    if (c->pend != NULL) {
        return c->pend_deadline_ms;
    }
    {
        int64_t d = c->deadline_ms;

        if (c->lim.duration_s != 0 && c->busy_since_ms >= 0 && !c->cancelled) {
            int64_t at = c->busy_since_ms + (int64_t)c->lim.duration_s * 1000;

            d = d >= 0 && d < at ? d : at;
        }
        if (c->lim.idle_in_transaction_s != 0 && c->idle_tx_since_ms >= 0) {
            int64_t at = c->idle_tx_since_ms + (int64_t)c->lim.idle_in_transaction_s * 1000;

            d = d >= 0 && d < at ? d : at;
        }
        if (c->lim.transaction_s != 0 && c->tx_since_ms >= 0) {
            int64_t at = c->tx_since_ms + (int64_t)c->lim.transaction_s * 1000;

            d = d >= 0 && d < at ? d : at;
        }
        return d;
    }
}

static void pend_expire(sl_conn *c);
static void statement_too_long(sl_conn *c);
static void idle_too_long(sl_conn *c);
static void transaction_too_long(sl_conn *c);

void sl_conn_check_deadline(sl_conn *c, int64_t now_ms)
{
    if (c->state == ST_RELAY && c->lim.idle_in_transaction_s != 0 && c->idle_tx_since_ms >= 0 &&
        now_ms >= c->idle_tx_since_ms + (int64_t)c->lim.idle_in_transaction_s * 1000) {
        idle_too_long(c);
        return;
    }
    if (c->state == ST_RELAY && c->lim.transaction_s != 0 && c->tx_since_ms >= 0 &&
        c->busy_since_ms < 0 && c->swallow == 0 && c->scan.owed <= c->z_seen &&
        now_ms >= c->tx_since_ms + (int64_t)c->lim.transaction_s * 1000) {
        transaction_too_long(
            c); /* between two statements: the stream is not in the middle of one */
        return;
    }
    if (c->state == ST_RELAY && c->lim.duration_s != 0 && c->busy_since_ms >= 0 && !c->cancelled &&
        now_ms >= c->busy_since_ms + (int64_t)c->lim.duration_s * 1000) {
        statement_too_long(c);
    }
    if (c->state != ST_DONE && c->pend != NULL && now_ms >= c->pend_deadline_ms) {
        pend_expire(c);
        return;
    }
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
    /* in the relay the server's stream is followed, and only what it has released may be sent: the
     * error is ours, and goes out as it is */
    c->u_scan = 0;
    if (c->srv_on) {
        c->srv.released = sl_buf_len(&c->u2c);
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
    int kill;          /* ... and the connection is closed after the answer (action = "kill") */
    const char *alert; /* the name of an "alert" rule that matched, whatever was decided */
    const char *dry;   /* a rule that is being tried (dry_run) matched: it decided nothing */
    const char *dry_would;
    int held;        /* a confirmation has started: the statement is being run */
    int confirm;     /* the policy wants a person to confirm this statement */
    int limit;       /* the rule is a limit: nobody is asked, more rows than it says is undone */
    int guardable;   /* it is exactly one DELETE or UPDATE: it can be run, then looked at */
    uint8_t kind;    /* the kind of statement: D, U, I, M, T or R */
    int returning;   /* it has a RETURNING of its own */
    char schema[64]; /* a DELETE: what it deletes from, as written */
    char table[64];
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

/* "30m", "2h", "7d": a window, for what the client reads. */
static const char *window_text(unsigned s)
{
    static char t[24];

    if (s % 86400 == 0) {
        snprintf(t, sizeof t, "%ud", s / 86400);
    } else if (s % 3600 == 0) {
        snprintf(t, sizeof t, "%uh", s / 3600);
    } else {
        snprintf(t, sizeof t, "%um", (s + 59) / 60);
    }
    return t;
}

/* ---- masking (mask.h) ---- */

/* The mask of this user, made from the rules that apply to them. 0 on out of memory. */
static int setup_mask(sl_conn *c)
{
    sl_mask_rule_view v[SL_MASK_MAX_RULES];
    size_t n =
        sl_policy_masks(policy_now(c), c->user, c->user_len, c->database, c->database_len, v);

    if (n == 0) {
        return 1;
    }
    if (c->mask_key == NULL || c->mask_key_len == 0) {
        return 0;
    }
    c->mask = sl_mask_new(v, n, c->mask_key, c->mask_key_len);
    if (c->mask == NULL) {
        return 0;
    }
    snprintf(c->mask_rule, sizeof c->mask_rule, "%s", v[0].name);
    c->mask_on = 1;
    return 1;
}

/* Masks with qualified names (users.email) need to know which table a column comes from: the
 * RowDescription gives an OID. Once the login is over, and only if the client has not said anything
 * yet (what it was owed is all in, nothing of it is still on the way), sluice asks the server for
 * the tables it has, as a query of its own. The answers are read here and never reach the client; a
 * client that sends its first message before then simply gets the names hidden whatever the
 * table, which is the safe way to be wrong (mask.h). */
static void expect(sl_conn *c, int kind);

static void probe_catalog(sl_conn *c)
{
    sl_buf q;
    size_t n = strlen(SL_MASK_CATALOG_SQL);
    uint8_t head[5];

    if (c->probe != 0 || !c->mask_on || !c->first_z || c->state != ST_RELAY) {
        return;
    }
    c->probe = 2; /* one try */
    if (!sl_mask_qualified(c->mask) || c->scan.owed > c->z_seen || c->swallow != 0 ||
        c->pend != NULL || c->guard != NULL || c->srv.lost || c->scan.owed_unknown ||
        c->tx_status != 'I') {
        return;
    }
    head[0] = 'Q';
    sl_pg_put_be32(head + 1, (uint32_t)(4 + n + 1));
    sl_buf_init(&q);
    if (sl_buf_append(&q, head, 5) != 0 || sl_buf_append(&q, SL_MASK_CATALOG_SQL, n + 1) != 0 ||
        sl_scan_inject(&c->scan, &c->c2u, sl_buf_data(&q), sl_buf_len(&q), 1) != 0) {
        sl_buf_free(&q);
        return; /* out of memory: the names stay as they are, hidden whatever the table */
    }
    sl_buf_free(&q);
    expect(c, SL_EXT_SIMPLE);
    sl_mask_catalog_start(c->mask);
    c->swallow++;
    c->probe = 1;
    c->probe_bad = 0;
}

/* One answer to that query. */
static void probe_answer(sl_conn *c, uint8_t type, const uint8_t *payload, size_t len)
{
    if (type == 'D') {
        if (sl_mask_catalog_row(c->mask, payload, len) != 0) {
            c->probe_bad = 1;
        }
    } else if (type == 'E') {
        c->probe_bad = 1;
    } else if (type == 'Z') {
        sl_mask_catalog_end(c->mask, !c->probe_bad);
        c->probe = 2;
        if (c->probe_bad) {
            sl_log_ev ev;

            sl_log_begin(&ev, "mask_catalog");
            sl_log_int(&ev, "id", (long long)c->id);
            sl_log_cstr(&ev, "outcome", "failed");
            sl_log_cstr(&ev, "detail",
                        "the tables could not be listed: qualified names hide by column name "
                        "alone for this connection");
            sl_log_end(&ev);
        }
    }
}

/* Rows are only worth reading when the description says there is something to hide in them. A row
 * that cannot be read is not sent (SKIP): there is no way to know what is in it. */
static int mask_reads_rows(const sl_conn *c)
{
    return !sl_mask_described(c->mask) || sl_mask_has_work(c->mask);
}

/* Masking needs to follow the stream of both sides. When it cannot (a frame that cannot be read,
 * more messages in flight than the queue holds), what follows would go out unmasked: the connection
 * ends instead. */
static void mask_check(sl_conn *c)
{
    if (c->mask_on && c->state == ST_RELAY &&
        (c->mask_overflow || c->ext_bad || c->srv.lost || c->scan.owed_unknown)) {
        fatal(
            c, "54000",
            "sluice: this session can no longer be followed closely enough to hide values in what "
            "it reads; it is closed",
            "mask_lost_track");
    }
}

/* ---- budgets (budget.h): what a user may carry out or change in a window of time ---- */

/* Takes the counters of every budget rule that applies to this user. 0 when there is no room. */
static int hold_budgets(sl_conn *c)
{
    int64_t now = sl_now_ms();

    if (c->budget == NULL) {
        c->lim.nbudgets = 0;
        return 1;
    }
    for (size_t i = 0; i < c->lim.nbudgets; i++) {
        const sl_budget_spec *s = &c->lim.budgets[i];

        c->bud[i] = sl_budget_acquire(c->budget, s->rule, c->user, c->user_len, s->window_s, now);
        if (c->bud[i] == NULL) {
            return 0;
        }
        c->bud_stream |= s->rows != 0 || s->bytes != 0;
        c->bud_changed |= s->changed != 0;
        c->bud_stmts |= s->statements != 0;
    }
    return 1;
}

/* Would a row of this size go past a budget? 0, or the budget's index plus one (and what ran out).
 */
static size_t budget_row_hit(const sl_conn *c, size_t payload_len, int *kind)
{
    int64_t now = sl_now_ms();

    for (size_t i = 0; i < c->lim.nbudgets; i++) {
        const sl_budget_spec *s = &c->lim.budgets[i];

        if (c->bud[i] == NULL) {
            continue;
        }
        if (s->rows != 0 && sl_budget_used(c->bud[i], now, SL_BUDGET_ROWS) >= s->rows) {
            *kind = SL_BUDGET_ROWS;
            return i + 1;
        }
        if (s->bytes != 0 &&
            sl_budget_used(c->bud[i], now, SL_BUDGET_BYTES) + 5 + payload_len > s->bytes) {
            *kind = SL_BUDGET_BYTES;
            return i + 1;
        }
    }
    return 0;
}

/* Has a budget of rows changed run out? Fills why (what the client reads) and returns the rule. */
static const char *budget_changed_hit(const sl_conn *c, char *why, size_t cap)
{
    int64_t now = sl_now_ms();

    for (size_t i = 0; i < c->lim.nbudgets; i++) {
        const sl_budget_spec *s = &c->lim.budgets[i];

        if (c->bud[i] != NULL && s->changed != 0 &&
            sl_budget_used(c->bud[i], now, SL_BUDGET_CHANGED) >= s->changed) {
            snprintf(why, cap,
                     "sluice: budget of changed rows used up (rule %s: %llu rows in %s); writes "
                     "are possible again in about %us",
                     s->rule, s->changed, window_text(s->window_s),
                     sl_budget_wait_s(c->bud[i], now, SL_BUDGET_CHANGED, s->changed));
            return s->rule;
        }
    }
    return NULL;
}

/* Has a budget of round trips run out? Fills why (what the client reads) and returns the rule. */
static const char *budget_statements_hit(const sl_conn *c, char *why, size_t cap)
{
    int64_t now = sl_now_ms();

    for (size_t i = 0; i < c->lim.nbudgets; i++) {
        const sl_budget_spec *s = &c->lim.budgets[i];

        if (c->bud[i] != NULL && s->statements != 0 &&
            sl_budget_used(c->bud[i], now, SL_BUDGET_STATEMENTS) >= s->statements) {
            snprintf(why, cap,
                     "sluice: budget of round trips used up (rule %s: %llu in %s); statements "
                     "are possible again in about %us",
                     s->rule, s->statements, window_text(s->window_s),
                     sl_budget_wait_s(c->bud[i], now, SL_BUDGET_STATEMENTS, s->statements));
            return s->rule;
        }
    }
    return NULL;
}

/* One more round trip was answered. When that spends a budget the connection ends: a statement
 * that was prepared before can still be run again without a new Parse, so it cannot be refused one
 * statement at a time. Returns the rule that ran out, or NULL. */
static const char *budget_note_round_trip(sl_conn *c)
{
    int64_t now = sl_now_ms();
    const char *spent = NULL;

    for (size_t k = 0; k < c->lim.nbudgets; k++) {
        const sl_budget_spec *s = &c->lim.budgets[k];

        if (c->bud[k] != NULL && s->statements != 0) {
            sl_budget_add(c->bud[k], now, SL_BUDGET_STATEMENTS, 1);
            if (spent == NULL &&
                sl_budget_used(c->bud[k], now, SL_BUDGET_STATEMENTS) >= s->statements) {
                spent = s->rule;
            }
        }
    }
    return spent;
}

/* Rows changed, as a CommandComplete tag says: "INSERT 0 5", "UPDATE 3", "DELETE 3", "MERGE 3". */
static void budget_note_tag(sl_conn *c, const uint8_t *payload, size_t len)
{
    unsigned long long n = 0;
    size_t i;
    int64_t now;

    if (!((len >= 7 && memcmp(payload, "INSERT ", 7) == 0) ||
          (len >= 7 && memcmp(payload, "UPDATE ", 7) == 0) ||
          (len >= 7 && memcmp(payload, "DELETE ", 7) == 0) ||
          (len >= 6 && memcmp(payload, "MERGE ", 6) == 0))) {
        return;
    }
    i = len;
    while (i > 0 && payload[i - 1] == '\0') {
        i--;
    }
    while (i > 0 && payload[i - 1] >= '0' && payload[i - 1] <= '9') {
        i--;
    }
    for (; i < len && payload[i] >= '0' && payload[i] <= '9'; i++) {
        n = n * 10 + (unsigned long long)(payload[i] - '0');
        if (n > 1000000000000ULL) {
            break;
        }
    }
    now = sl_now_ms();
    for (size_t k = 0; k < c->lim.nbudgets; k++) {
        sl_budget_add(c->bud[k], now, SL_BUDGET_CHANGED, n);
    }
}

static void judgement_uninspectable(const sl_conn *c, judgement *j, const char *why)
{
    j->verdict = "uninspectable";
    snprintf(j->detail, sizeof j->detail, "%s", why);
    j->has_detail = 1;
    j->blocked = enforcing(c) && policy_now(c)->deny_uninspectable;
    snprintf(j->reason, sizeof j->reason, "sluice: cannot inspect this statement (%s)", j->detail);
    if (c->bud_changed && !j->blocked) {
        const char *rule = budget_changed_hit(c, j->reason, sizeof j->reason);

        if (rule != NULL) {
            j->blocked = 1; /* it may write, and the budget for writes is spent */
            j->rule = rule;
        }
    }
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
    if (c->killed) {
        j->verdict = "deny";
        j->rule = c->kill_rule;
        j->blocked = 1;
        snprintf(j->reason, sizeof j->reason,
                 "sluice: rule %s closed this connection; nothing more is run", c->kill_rule);
        return;
    }
    if (pol == NULL) {
        return;
    }
    if (c->bud_stmts) {
        const char *rule = budget_statements_hit(c, j->reason, sizeof j->reason);

        if (rule != NULL) {
            j->verdict = "deny";
            j->rule = rule;
            j->blocked = 1;
            return;
        }
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
    j->alert = v.alert != NULL ? v.alert->name : NULL;
    j->dry = v.dry != NULL ? v.dry->name : NULL;
    j->dry_would = v.dry != NULL ? sl_rule_would(v.dry) : NULL;
    if (info.tables != NULL) {
        note_tables(j, &info);
    }
    if (c->bud_changed) {
        int writes = 0;

        for (size_t i = 0; i < info.count; i++) {
            writes |= (info.flags[i] & SL_SQL_NOT_READ_ONLY) != 0;
        }
        if (writes) {
            const char *rule = budget_changed_hit(c, j->reason, sizeof j->reason);

            if (rule != NULL) {
                sl_sql_info_free(&info);
                j->verdict = "deny";
                j->rule = rule;
                j->blocked = 1;
                return;
            }
        }
    }
    if (v.confirm) {
        size_t dml = 0;

        for (size_t i = 0; i < info.count; i++) {
            dml += (info.flags[i] & SL_SQL_NOT_READ_ONLY) != 0;
        }
        j->kind = info.top_kind;
        j->returning = info.top_returning;
        memcpy(j->schema, info.top_schema, sizeof j->schema);
        memcpy(j->table, info.top_table, sizeof j->table);
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
            j->limit = v.rule->limit;
        }
        return;
    }
    j->verdict = "deny";
    j->rule = v.rule->name;
    j->blocked = enforcing(c);
    j->kill = v.kill && enforcing(c);
    sl_policy_reason(v.rule, pr, sizeof pr);
    snprintf(j->reason, sizeof j->reason, "sluice: %s%s", pr,
             j->kill ? " (this connection is closed)" : "");
}

/* A "kill" rule matched: this statement is refused, and so is everything after it; the connection
 * ends with the answer to this one. */
static void note_kill(sl_conn *c, const judgement *j)
{
    if (j->kill && !c->killed) {
        c->killed = 1;
        c->close_after_z = 1;
        c->z_reason = "killed";
        snprintf(c->kill_rule, sizeof c->kill_rule, "%s", j->rule != NULL ? j->rule : "");
        {
            sl_log_ev ev;

            /* a line of its own, so that it can be sent where somebody will read it */
            sl_log_begin(&ev, "kill");
            sl_log_int(&ev, "id", (long long)c->id);
            sl_log_str(&ev, "user", c->user, c->user_len);
            sl_log_str(&ev, "database", c->database, c->database_len);
            sl_log_cstr(&ev, "rule", c->kill_rule);
            sl_log_end(&ev);
        }
    }
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
    sl_metric_inc(SL_M_STATEMENTS, j->verdict != NULL ? j->verdict : "none",
                  j->blocked ? "blocked" : (j->held ? "held" : "relayed"));
    if (j->rule != NULL && j->verdict != NULL) {
        sl_metric_inc(SL_M_RULE_HITS, j->rule, j->verdict);
    }
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
        {
            /* the shape too, so that a log written with the text can be learned from as well */
            sl_sql_redacted rd;
            char perr[200];

            if (sl_sql_redact(st->sql, st->sql_len, &rd, perr, sizeof perr) == 0) {
                sl_log_cstr(&ev, "fingerprint", rd.fingerprint);
                sl_sql_redacted_free(&rd);
            }
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
        if (j->kill) {
            sl_log_bool(&ev, "kill", 1);
        }
        if (j->alert != NULL) {
            sl_log_cstr(&ev, "alert", j->alert);
        }
        if (j->dry != NULL) {
            sl_log_cstr(&ev, "dry_run", j->dry);
        }
    }
    sl_log_end(&ev);
    if (j->dry != NULL) {
        /* what a rule that is being tried would have done, in a line of its own */
        sl_log_begin(&ev, "dry_run");
        sl_log_int(&ev, "id", (long long)c->id);
        sl_log_str(&ev, "user", c->user, c->user_len);
        sl_log_str(&ev, "database", c->database, c->database_len);
        sl_log_cstr(&ev, "rule", j->dry);
        sl_log_cstr(&ev, "would", j->dry_would);
        sl_log_cstr(&ev, "kind", kind_name(type));
        sl_log_cstr(&ev, "action", j->blocked ? "blocked" : (j->held ? "held" : "relayed"));
        if (j->ntables > 0) {
            sl_log_list(&ev, "tables", j->tables, j->ntables);
        }
        sl_log_end(&ev);
    }
    if (j->alert != NULL) {
        /* a line of its own, to be found without reading every statement */
        sl_log_begin(&ev, "alert");
        sl_log_int(&ev, "id", (long long)c->id);
        sl_log_str(&ev, "user", c->user, c->user_len);
        sl_log_str(&ev, "database", c->database, c->database_len);
        sl_log_cstr(&ev, "rule", j->alert);
        sl_log_cstr(&ev, "kind", kind_name(type));
        sl_log_cstr(&ev, "action", j->blocked ? "blocked" : (j->held ? "held" : "relayed"));
        if (j->ntables > 0) {
            sl_log_list(&ev, "tables", j->tables, j->ntables);
        }
        sl_log_end(&ev);
    }
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
    return c->srv_on && !c->srv.lost && !c->scan.owed_unknown && !c->ext_bad && c->ext != NULL;
}

/* Notes what a message that goes to the server will be answered with (extstate.h). A full queue is
 * not an error to the client: sluice stops following the answers on this connection, and refuses
 * what would need them. */
static void expect(sl_conn *c, int kind)
{
    if (c->ext == NULL || c->ext_bad) {
        return;
    }
    if (sl_ext_expect(c->ext, kind) != SL_EXT_OK) {
        c->ext_bad = 1;
    }
}

typedef enum { PLAN_NORMAL, PLAN_BLOCK, PLAN_WAIT, PLAN_GUARD, PLAN_REWRITE } plan;

/* What to do with a statement that a rule wants confirmed. */
static plan confirm_plan(const sl_conn *c, uint8_t type, judgement *j)
{
    const char *why = NULL;

    if (!j->confirm || !enforcing(c)) {
        return PLAN_NORMAL; /* in audit mode the verdict is logged and the statement goes through */
    }
    if (j->limit && (j->kind == 'T' || j->kind == 'R')) {
        why = "a limit counts the rows of a DELETE or UPDATE: TRUNCATE and DROP have none (use "
              "confirm or deny)";
    } else if (!j->guardable) {
        why = "it can be confirmed only when the message holds one DELETE, UPDATE, TRUNCATE or "
              "DROP of tables, views or indexes, and nothing else that changes data";
    } else if (!session_followed(c)) {
        why = "sluice cannot follow this session closely enough to confirm";
    }
    if (why != NULL) {
        j->blocked = 1;
        snprintf(j->reason, sizeof j->reason, "sluice: rule %s asks for a confirmation, but %s",
                 j->rule, why);
        return PLAN_BLOCK;
    }
    if (type == 'P') {
        return PLAN_REWRITE; /* it is prepared now, and asked about when it is run */
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

static void guard_finish(sl_conn *c);

static void answer_guard(sl_conn *c, int yes, const char *outcome)
{
    c->g_asked = 0;
    if (c->g_ext) {
        sl_confirm_step step;

        if (sl_confirm_answer_ext(c->guard, yes, outcome, &c->g_server, &c->g_client, &step) != 0) {
            finish(c, "out_of_memory");
            return;
        }
        guard_send(c);
        if (step.done && c->state != ST_DONE) {
            /* a yes ends it here: no answer of the server is awaited */
            guard_finish(c);
            flush_u2c(c);
        }
        return;
    }
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

/* Who is asked. Nobody is usually at the proxy: unless the operator named a terminal or a command,
 * the person who sent the statement is asked, in their own session. */
static int session_channel(const sl_conn *c)
{
    if (c->g_via != SL_VIA_DEFAULT) {
        return c->g_via == SL_VIA_SESSION;
    }
    return c->cfg->confirm_tty[0] == '\0' && c->cfg->confirm_command[0] == '\0' &&
           !c->cfg->confirm_admin;
}

static void guard_pend(sl_conn *c);

static void guard_ask(sl_conn *c)
{
    char text[4096];
    int rc;

    if (session_channel(c)) {
        guard_pend(c);
        return;
    }
    (void)sl_confirm_render(c->guard, text, sizeof text);
    rc = c->prompt != NULL ? sl_prompt_ask(c->prompt, c, text, confirm_reply) : -1;
    if (rc != 0) {
        answer_guard(c, 0, rc == -2 ? "error" : "no_terminal");
        return;
    }
    c->g_asked = 1;
    c->g_deadline_ms = sl_now_ms() + (int64_t)c->g_timeout_s * 1000;
    if (c->cfg->confirm_admin) {
        const char *qid = sl_prompt_admin_id(c->prompt, c);

        if (qid != NULL && qid[0] != '\0') {
            sl_log_ev ev;
            sl_buf meta;

            /* somebody has to be told: the line is what an event command sends where a person
             * reads it, and /pending says the same to a program. The rows stay in the question,
             * which is fetched with the token, never in the log. */
            sl_buf_init(&meta);
            sl_buf_append(&meta, "\"user\":", 7);
            sl_json_append_string(&meta, c->user, c->user_len);
            sl_buf_append(&meta, ",\"database\":", 12);
            sl_json_append_string(&meta, c->database, c->database_len);
            sl_buf_append(&meta, ",\"rule\":", 8);
            sl_json_append_string(&meta, c->g_rule, strlen(c->g_rule));
            sl_buf_append(&meta, ",\"tag\":", 7);
            sl_json_append_string(&meta, sl_confirm_tag(c->guard),
                                  strlen(sl_confirm_tag(c->guard)));
            {
                char rows[48];

                snprintf(rows, sizeof rows, ",\"rows\":%llu,\"expires_in_s\":%u",
                         (unsigned long long)sl_confirm_rows(c->guard), c->g_timeout_s);
                sl_buf_append(&meta, rows, strlen(rows));
            }
            sl_buf_append(&meta, "", 1);
            sl_prompt_admin_meta(c->prompt, c, (const char *)sl_buf_data(&meta));
            sl_buf_free(&meta);

            sl_log_begin(&ev, "confirm_pending");
            sl_log_int(&ev, "id", (long long)c->id);
            sl_log_cstr(&ev, "question", qid);
            sl_log_str(&ev, "user", c->user, c->user_len);
            sl_log_str(&ev, "database", c->database, c->database_len);
            sl_log_cstr(&ev, "rule", c->g_rule);
            sl_log_cstr(&ev, "tag", sl_confirm_tag(c->guard));
            sl_log_int(&ev, "rows", (long long)sl_confirm_rows(c->guard));
            sl_log_int(&ev, "expires_in_s", (long long)c->g_timeout_s);
            sl_log_end(&ev);
        }
    }
}

/* ---- how long a statement may run ---- */

static void log_limit(const sl_conn *c, const char *kind, const char *rule);
static int answer_client(sl_conn *c, const sl_buf *b);

/* Is the server working for the client? A statement or a Sync has been sent and not answered, and
 * nobody is being asked a question (which is the person's time, not the statement's). */
static void note_busy(sl_conn *c)
{
    int busy = c->state == ST_RELAY && c->first_z && c->scan.owed > c->z_seen &&
               !(c->guard != NULL && c->g_asked) && c->pend == NULL;

    int idle_tx = c->state == ST_RELAY && c->first_z && !busy &&
                  (c->tx_status == 'T' || c->tx_status == 'E') && c->guard == NULL &&
                  c->pend == NULL && c->swallow == 0 && c->scan.owed <= c->z_seen;

    if (!busy) {
        c->busy_since_ms = -1;
        c->cancelled = 0;
    } else if (c->busy_since_ms < 0) {
        c->busy_since_ms = sl_now_ms();
        c->mark_ms = c->busy_since_ms;
    }
    if (c->state == ST_RELAY && c->first_z && (c->tx_status == 'T' || c->tx_status == 'E') &&
        c->guard == NULL && c->pend == NULL) {
        if (c->tx_since_ms < 0) {
            c->tx_since_ms = sl_now_ms();
        }
    } else {
        c->tx_since_ms = -1;
    }
    if (!idle_tx) {
        c->idle_tx_since_ms = -1;
    } else if (c->idle_tx_since_ms < 0) {
        c->idle_tx_since_ms = sl_now_ms();
    }
}

/* A cancel request on a connection of its own, as any client's cancel goes: the process and secret
 * of the session, in 16 bytes. The connection is made and used within a quarter of a second: this
 * is the one place where sluice waits, and only on a statement that has run too long. */
static void send_cancel(const sl_conn *c)
{
    char err[128];
    sl_net_target *t =
        sl_net_target_resolve(c->cfg->upstream_host, c->cfg->upstream_port, err, sizeof err);
    uint8_t pkt[16];
    int failed = 0;

    if (t == NULL) {
        return;
    }
    sl_pg_put_be32(pkt, 16);
    sl_pg_put_be32(pkt + 4, 80877102u);
    memcpy(pkt + 8, c->be_key, 8);
    for (;;) {
        int fd = sl_net_target_next(t, failed, err, sizeof err);
        struct pollfd pf;

        if (fd < 0) {
            break;
        }
        pf.fd = fd;
        pf.events = POLLOUT;
        pf.revents = 0;
        if (poll(&pf, 1, 250) > 0 && (failed = sl_net_connect_result(fd)) == 0) {
            (void)send(fd, pkt, sizeof pkt, SL_SEND_FLAGS);
            close(fd);
            break;
        }
        if (failed == 0) {
            failed = ETIMEDOUT;
        }
        close(fd);
    }
    sl_net_target_free(t);
}

/* The statement has run for as long as the policy allows: the server is asked to cancel it. It
 * answers with its own error (57014), after a warning of ours that says why. */
static void statement_too_long(sl_conn *c)
{
    char msg[200];
    sl_buf n;

    c->cancelled = 1;
    log_limit(c, "duration", c->lim.rule_duration);
    if (c->have_key) {
        send_cancel(c);
    }
    snprintf(msg, sizeof msg, "sluice: a statement ran for more than %us (rule %s): cancelling it",
             c->lim.duration_s, c->lim.rule_duration);
    sl_buf_init(&n);
    if (sl_pg_append_report(&n, 'N', "WARNING", "01000", msg, NULL, NULL) == 0 &&
        c->srv.pass_remaining == 0 && c->srv.skip_remaining == 0 && !c->srv.lost && !c->u_scan) {
        (void)answer_client(c, &n);
    }
    sl_buf_free(&n);
}

/* A transaction was left open, and nothing has been sent for as long as the policy allows: it holds
 * locks and a snapshot for nothing. The connection is ended (the server rolls the transaction
 * back); the session could lift a `idle_in_transaction_session_timeout` of its own, this it cannot.
 */
static void idle_too_long(sl_conn *c)
{
    char msg[200];

    log_limit(c, "idle_in_transaction", c->lim.rule_idle);
    snprintf(
        msg, sizeof msg,
        "sluice: idle in a transaction for more than %us (rule %s): the connection is closed and "
        "the transaction rolled back",
        c->lim.idle_in_transaction_s, c->lim.rule_idle);
    fatal(c, "25P03", msg, "idle_in_transaction");
}

/* A transaction has been open for longer than the policy allows, whatever it was doing in between:
 * it holds locks and keeps the vacuum from cleaning up. It is ended (the server rolls it back) the
 * next time the connection is between two statements. */
static void transaction_too_long(sl_conn *c)
{
    char msg[200];

    log_limit(c, "transaction", c->lim.rule_transaction);
    snprintf(msg, sizeof msg,
             "sluice: a transaction open for more than %us (rule %s): the connection is closed and "
             "the transaction rolled back",
             c->lim.transaction_s, c->lim.rule_transaction);
    fatal(c, "25P03", msg, "transaction_limit");
}

static void log_confirm_of(const sl_conn *c, const sl_confirm *conf, int ext, const char *channel)
{
    sl_log_ev ev;

    if (c->bud_changed && (strcmp(sl_confirm_outcome(conf), "yes") == 0 ||
                           strcmp(sl_confirm_outcome(conf), "auto") == 0)) {
        int64_t now = sl_now_ms(); /* the statement was committed: its rows count */

        for (size_t k = 0; k < c->lim.nbudgets; k++) {
            sl_budget_add(c->bud[k], now, SL_BUDGET_CHANGED, sl_confirm_rows(conf));
        }
    }

    sl_metric_inc(SL_M_CONFIRMATIONS, sl_confirm_outcome(conf), channel);
    sl_log_begin(&ev, "confirm");
    sl_log_int(&ev, "id", (long long)c->id);
    sl_log_str(&ev, "user", c->user, c->user_len);
    sl_log_str(&ev, "database", c->database, c->database_len);
    sl_log_cstr(&ev, "rule", c->g_rule);
    sl_log_cstr(&ev, "protocol", ext ? "extended" : "simple");
    sl_log_cstr(&ev, "channel", channel);
    sl_log_int(&ev, "rows", (long long)sl_confirm_rows(conf));
    sl_log_cstr(&ev, "outcome", sl_confirm_outcome(conf));
    sl_log_bool(&ev, "detail", sl_confirm_has_detail(conf));
    sl_log_int(&ev, "wait_ms", (long long)(sl_now_ms() - c->g_started_ms));
    sl_log_end(&ev);
}

static void log_confirm(const sl_conn *c);

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
    if (c->mask != NULL) {
        sl_mask_forget(c->mask);
    }
    c->g_done = 0;
    c->g_ask = 0;
    c->g_ext = 0;
    c->g_front = 0;
    c->g_cancel = 0;
    sl_srv_resume(&c->srv);
    sl_scan_resume(&c->scan);
    /* what the client sent behind the statement has been waiting: it goes on now */
    scan_c2u(c);
    flush_c2u(c);
}

/* ---- a statement that waits in the client's own session ---- */

static void log_confirm(const sl_conn *c)
{
    log_confirm_of(c, c->guard, c->g_ext,
                   session_channel(c)           ? "session"
                   : c->cfg->confirm_command[0] ? "command"
                   : c->cfg->confirm_admin      ? "admin"
                                                : "terminal");
}

/* Puts bytes for the client where the server's stream stands: it is quiet while the statement
 * waits, so this is a message boundary. */
static int answer_client(sl_conn *c, const sl_buf *b)
{
    if (sl_buf_len(b) == 0) {
        return 0;
    }
    if (sl_buf_replace(&c->u2c, c->srv.released, 0, sl_buf_data(b), sl_buf_len(b)) != 0) {
        finish(c, "out_of_memory");
        return -1;
    }
    c->srv.released += sl_buf_len(b);
    return 0;
}

static void add_ready(sl_buf *out, uint8_t status)
{
    uint8_t m[6];

    m[0] = 'Z';
    sl_pg_put_be32(m + 1, 5);
    m[5] = status;
    (void)sl_buf_append(out, m, 6);
}

/* The question, and what to do about it, are the error that answers the statement: psql shows the
 * message, then the rows as DETAIL, then how to answer as HINT. The statement itself has run in a
 * transaction that stays open on the server. */
/* The question, as the error that answers a statement: the message says what to type, the rows are
 * the DETAIL (`rows` of them), and the HINT says when it is undone, with the rule's own message. */
static int build_question(const sl_conn *c, const sl_confirm *conf, int rows, sl_buf *q)
{
    char detail[8192];
    char msg[384];
    char hint[640];
    const char *rule_msg = sl_confirm_message(conf);
    size_t dl = sl_confirm_render_brief(conf, detail, sizeof detail, rows);

    while (dl > 0 && detail[dl - 1] == '\n') { /* psql adds its own line break */
        detail[--dl] = '\0';
    }
    snprintf(msg, sizeof msg,
             "sluice: %s waiting for you (rule %s): type  yes;  to apply,  no;  to undo,  show;  "
             "for more",
             sl_confirm_tag(conf), sl_confirm_rule(conf));
    if (c->g_timeout_s % 60 == 0) {
        snprintf(hint, sizeof hint, "Not final until you answer; undone after %um.%s%s",
                 c->g_timeout_s / 60, rule_msg[0] != '\0' ? " " : "", rule_msg);
    } else {
        snprintf(hint, sizeof hint, "Not final until you answer; undone after %us.%s%s",
                 c->g_timeout_s, rule_msg[0] != '\0' ? " " : "", rule_msg);
    }
    return sl_pg_append_report(q, 'E', "ERROR", "42501", msg, detail, hint);
}

static void guard_pend(sl_conn *c)
{
    sl_buf q;
    int simple = !c->g_ext;

    sl_buf_init(&q);
    if (build_question(c, c->guard, 5, &q) != 0) {
        sl_buf_free(&q);
        finish(c, "internal_error");
        return;
    }
    if (simple) {
        add_ready(&q, 'T'); /* the transaction is open, which is what the client will see */
    }
    sl_buf_free(&c->g_client);
    (void)sl_buf_append(&c->g_client, sl_buf_data(&q), sl_buf_len(&q));
    sl_buf_free(&q);
    /* the exchange is over for the stream: what the client sent behind the statement is dealt with
     * now, by the filter; the confirmation itself waits, with the transaction */
    c->pend = c->guard;
    c->guard = NULL;
    c->pend_skip = 0;
    c->pend_deadline_ms = sl_now_ms() + (int64_t)c->g_timeout_s * 1000;
    if (answer_client(c, &c->g_client) != 0) {
        return;
    }
    sl_buf_free(&c->g_client);
    c->g_done = 0;
    c->g_ask = 0;
    c->g_ext = 0;
    c->g_front = 0;
    c->g_cancel = 0;
    sl_srv_resume(&c->srv);
    sl_scan_resume(&c->scan);
    scan_c2u(c);
    flush_c2u(c);
}

/* The answer to a waiting statement: yes (or y) and no (or n), whatever the case, the spacing, and
 * a trailing semicolon, or the calls select sluice_confirm() and select sluice_cancel() (for a
 * client that wants something that parses). None of these is SQL, and none is looked at unless a
 * statement is waiting. Returns 1 (yes), 2 (no), or 0 for anything else. */
static int confirm_call(const char *sql, size_t len)
{
    char norm[40];
    size_t n = 0;

    for (size_t i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)sql[i];

        if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == ';') {
            continue;
        }
        if (n + 1 >= sizeof norm) {
            return 0;
        }
        norm[n++] = (char)(ch >= 'A' && ch <= 'Z' ? ch + 32 : ch);
    }
    norm[n] = '\0';
    if (strcmp(norm, "yes") == 0 || strcmp(norm, "y") == 0 ||
        strcmp(norm, "selectsluice_confirm()") == 0) {
        return 1;
    }
    if (strcmp(norm, "show") == 0 || strcmp(norm, "more") == 0) {
        return 3;
    }
    if (strcmp(norm, "no") == 0 || strcmp(norm, "n") == 0 ||
        strcmp(norm, "selectsluice_cancel()") == 0) {
        return 2;
    }
    /* What a driver sends by itself: a rollback is a no (it is what the client wants anyway: after
     * an error an application rolls back), a commit would apply what was not confirmed. */
    if (strcmp(norm, "rollback") == 0 || strcmp(norm, "rollbackwork") == 0 ||
        strcmp(norm, "rollbacktransaction") == 0 || strcmp(norm, "abort") == 0 ||
        strcmp(norm, "abortwork") == 0 || strcmp(norm, "aborttransaction") == 0) {
        return 4;
    }
    if (strcmp(norm, "commit") == 0 || strcmp(norm, "commitwork") == 0 ||
        strcmp(norm, "committransaction") == 0 || strcmp(norm, "end") == 0 ||
        strcmp(norm, "endwork") == 0 || strcmp(norm, "endtransaction") == 0) {
        return 5;
    }
    return 0;
}

/* The pending statement is decided: a notice for the client (which sees the answer of the statement
 * that ends the transaction after it), and the record. */
static void pend_decided(sl_conn *c, const char *outcome)
{
    sl_confirm_set_outcome(c->pend, outcome);
    if (strcmp(outcome, "yes") == 0) {
        /* the answer is the statement's own tag, as if it had just run: DELETE 20 */
        snprintf(c->tag_rewrite, sizeof c->tag_rewrite, "%s", sl_confirm_tag(c->pend));
    }
    log_confirm_of(c, c->pend, sl_confirm_is_extended(c->pend), "session");
    sl_confirm_free(c->pend);
    c->pend = NULL;
    c->pend_skip = 0;
}

/* The message that fails, or the statement that ends the transaction, for a Query or a Parse. */
static int resolution_message(sl_conn *c, int yes, uint8_t type, const char *name, size_t name_len,
                              sl_buf *out)
{
    const char *sql = sl_confirm_resolution_sql(c->pend, yes);

    if (sql == NULL) {
        return build_replacement(out, type, name, name_len,
                                 "sluice: cancelled, nothing was changed");
    }
    if (type == 'Q') {
        uint8_t head[5];

        head[0] = 'Q';
        sl_pg_put_be32(head + 1, (uint32_t)(4 + strlen(sql) + 1));
        return sl_buf_append(out, head, 5) != 0 || sl_buf_append(out, sql, strlen(sql) + 1) != 0
                   ? -1
                   : 0;
    }
    {
        uint8_t head[5];
        static const uint8_t no_params[2] = {0, 0};

        head[0] = 'P';
        sl_pg_put_be32(head + 1, (uint32_t)(4 + name_len + 1 + strlen(sql) + 1 + 2));
        return sl_buf_append(out, head, 5) != 0 || sl_buf_append(out, name, name_len) != 0 ||
                       sl_buf_append(out, "", 1) != 0 ||
                       sl_buf_append(out, sql, strlen(sql) + 1) != 0 ||
                       sl_buf_append(out, no_params, 2) != 0
                   ? -1
                   : 0;
    }
}

/* Anything else the client sends while a statement waits is refused here, without the server
 * hearing of it (that would run it inside the open transaction). */
static int pend_refuse_with(sl_conn *c, uint8_t type, const char *why)
{
    char msg[384];
    sl_buf q;

    if (c->pend_skip) {
        return SL_SCAN_ANSWER; /* the error was given; the server would ignore the rest too */
    }
    snprintf(msg, sizeof msg,
             "sluice: waiting for your answer: type  yes;  to apply,  no;  to undo,  show;  for "
             "more%s%s",
             why[0] != '\0' ? ". " : "", why);
    sl_buf_init(&q);
    if (sl_pg_append_error(&q, "ERROR", "25000", msg) == 0) {
        if (type == 'Q' || type == 'F') {
            add_ready(&q, 'T');
        } else {
            c->pend_skip = 1; /* an extended message: ignored up to its Sync, as after any error */
        }
        (void)answer_client(c, &q);
    }
    sl_buf_free(&q);
    return SL_SCAN_ANSWER;
}

static int pend_refuse(sl_conn *c, uint8_t type)
{
    return pend_refuse_with(c, type, "");
}

/* The client rolls back (as a driver does when something raised): the waiting statement goes with
 * it. A transaction block that sluice started, or the client's own, ends by that rollback. A
 * prepared statement runs in the implicit transaction of its cycle, which a ROLLBACK does not end
 * (outside a block it only warns, and the next Sync would commit): a message that fails is sent
 * first, its answers thrown away, and the client's own rollback follows. */
static int pend_client_rollback(sl_conn *c, uint8_t type)
{
    if (sl_confirm_is_extended(c->pend)) {
        sl_buf q;

        sl_buf_init(&q);
        if (sl_pg_append_failing_query(&q, "sluice: undone") != 0 ||
            sl_scan_inject(&c->scan, &c->c2u, sl_buf_data(&q), sl_buf_len(&q), 1) != 0) {
            sl_buf_free(&q);
            return SL_SCAN_FAIL;
        }
        sl_buf_free(&q);
        c->swallow++;
    }
    pend_decided(c, "rolled_back");
    if (type == 'Q') {
        expect(c, SL_EXT_SIMPLE);
    }
    return SL_SCAN_RELAY;
}

/* A Query or Parse while a statement waits. */
static int pend_statement(sl_conn *c, uint8_t type, const uint8_t *payload, size_t len,
                          sl_buf *replacement)
{
    sl_pg_statement st;
    int ok = (type == 'Q' ? sl_pg_statement_from_query(payload, len, &st)
                          : sl_pg_statement_from_parse(payload, len, &st)) == SL_PG_OK;
    int kind = ok ? confirm_call(st.sql, st.sql_len) : 0;

    if (kind == 0) {
        return pend_refuse(c, type);
    }
    if (kind == 4) {
        return pend_client_rollback(c, type);
    }
    if (kind == 5) {
        return pend_refuse_with(c, type,
                                "A COMMIT now would apply a statement that was not confirmed");
    }
    if (kind == 3) { /* show: the same question again, with the rows that were kept */
        sl_buf q;

        sl_buf_init(&q);
        if (build_question(c, c->pend, SL_CONFIRM_SAMPLE_ROWS, &q) == 0) {
            if (type == 'Q') {
                add_ready(&q, 'T');
            } else {
                c->pend_skip = 1; /* an error to an extended message: ignored up to its Sync */
            }
            (void)answer_client(c, &q);
        }
        sl_buf_free(&q);
        return SL_SCAN_ANSWER;
    }
    if (kind == 1 && sl_confirm_journal_gate(c->pend) != 0) {
        /* the rows could not be recorded and the rule requires it: what the person said yes to is
         * undone, and they are told */
        char msg[320];
        sl_buf n;

        snprintf(msg, sizeof msg, "sluice: %s was NOT applied (rule %s): %s",
                 sl_confirm_tag(c->pend), sl_confirm_rule(c->pend), sl_confirm_why(c->pend));
        sl_buf_init(&n);
        if (sl_pg_append_report(&n, 'N', "WARNING", "01000", msg, NULL, NULL) == 0) {
            (void)answer_client(c, &n);
        }
        sl_buf_free(&n);
        kind = 6;
    }
    if (resolution_message(c, kind == 1, type, type == 'P' ? st.name : "",
                           type == 'P' ? st.name_len : 0, replacement) != 0) {
        return SL_SCAN_FAIL;
    }
    if (type == 'P' && c->ext != NULL) {
        /* the Parse that is sent is not the statement that had that name: whatever was guarded
         * under it must not be taken for it (the Execute that follows would be asked about again)
         */
        sl_ext_stmt_close(c->ext, st.name, st.name_len);
    }
    pend_decided(c, kind == 1 ? "yes" : kind == 6 ? "journal" : "no");
    if (type == 'Q') {
        expect(c, SL_EXT_SIMPLE);
    }
    return SL_SCAN_BLOCK;
}

/* The start of a Bind, Describe, Execute, Close or Sync while a statement waits. */
static int pend_extended(sl_conn *c, uint8_t type)
{
    sl_buf z;

    if (type == 'H') {
        return SL_SCAN_RELAY;
    }
    if (type == 'S') { /* the end of a cycle that was refused or that the statement was in */
        c->pend_skip = 0;
        sl_buf_init(&z);
        add_ready(&z, 'T');
        (void)answer_client(c, &z);
        sl_buf_free(&z);
        return SL_SCAN_ANSWER;
    }
    return pend_refuse(c, type);
}

/* The time is up: the statement is undone, with a message of ours whose answers are thrown away,
 * and the client is told. */
static void pend_expire(sl_conn *c)
{
    sl_buf q;
    sl_buf n;
    char msg[256];

    if (c->scan.pass_remaining > 0 || c->scan.skip_remaining > 0 || c->scan.paused) {
        c->pend_deadline_ms = sl_now_ms() + 100; /* in the middle of a message: a moment later */
        return;
    }
    sl_buf_init(&q);
    if (resolution_message(c, 0, 'Q', "", 0, &q) != 0 ||
        sl_scan_inject(&c->scan, &c->c2u, sl_buf_data(&q), sl_buf_len(&q), 1) != 0) {
        sl_buf_free(&q);
        finish(c, "out_of_memory");
        return;
    }
    sl_buf_free(&q);
    c->swallow++;
    sl_confirm_set_outcome(c->pend, "timeout");
    snprintf(msg, sizeof msg, "sluice: %s was not confirmed in time, and was undone",
             sl_confirm_tag(c->pend));
    sl_buf_init(&n);
    if (sl_pg_append_report(&n, 'N', "WARNING", "01000", msg, NULL, NULL) == 0) {
        (void)answer_client(c, &n);
    }
    sl_buf_free(&n);
    log_confirm_of(c, c->pend, sl_confirm_is_extended(c->pend), "session");
    sl_confirm_free(c->pend);
    c->pend = NULL;
    c->pend_skip = 0;
    flush_c2u(c);
    flush_u2c(c);
}

/* A DELETE is about to be committed and a rule keeps its rows for undo: they are written first. */
static int journal_record(void *ctx, sl_journal_entry *e)
{
    sl_conn *c = ctx;
    char id[SL_JOURNAL_ID_LEN + 1] = "";
    char err[200] = "no undo journal is open";
    int rc = c->journal != NULL ? sl_journal_append(c->journal, e, id, err, sizeof err) : -1;
    sl_log_ev ev;

    sl_log_begin(&ev, "journal");
    sl_log_int(&ev, "id", (long long)c->id);
    sl_log_cstr(&ev, "entry", rc == 0 ? id : NULL);
    sl_log_cstr(&ev, "rule", e->rule);
    sl_log_str(&ev, "user", e->user, e->user_len);
    sl_log_str(&ev, "database", e->database, e->database_len);
    sl_log_int(&ev, "rows", (long long)e->rows);
    sl_log_bool(&ev, "complete", e->incomplete == NULL);
    sl_log_cstr(&ev, "outcome", rc == 0 ? "written" : "failed");
    if (rc != 0) {
        sl_log_cstr(&ev, "error", err);
    }
    if (e->incomplete != NULL) {
        sl_log_cstr(&ev, "incomplete", e->incomplete);
    }
    sl_log_end(&ev);
    return rc;
}

/* The RETURNING that sluice adds to a statement it confirms: every column of the rows. A rule that
 * keeps the old values of an UPDATE for undo asks for both the old and the new row (PostgreSQL
 * 18); the confirmation shows the new one and the journal keeps both. */
static const char *added_returning(const judgement *j, size_t *len)
{
    static const char plain[] = " RETURNING *";
    static const char both[] = " RETURNING OLD.*, NEW.*";
    int old = j->kind == 'U' && j->crule != NULL && j->crule->journal != SL_JOURNAL_OFF;

    *len = old ? sizeof both - 1 : sizeof plain - 1;
    return old ? both : plain;
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
        size_t rl;
        const char *ret = added_returning(j, &rl);

        returning = malloc(end + rl + 1);
        if (returning == NULL) {
            return -1;
        }
        memcpy(returning, st->sql, end);
        memcpy(returning + end, ret, rl);
        a.sql_returning = returning;
        a.sql_returning_len = end + rl;
    }
    a.client_returning = j->returning;
    a.tx_status = c->tx_status == 'T' ? 'T' : 'I';
    a.over_rows = j->over_rows;
    a.limit = j->limit;
    a.kind = j->kind;
    a.user = c->user;
    a.user_len = c->user_len;
    a.database = c->database;
    a.database_len = c->database_len;
    a.rule = j->rule;
    a.message = j->crule != NULL ? j->crule->message : NULL;
    a.side_effects = j->crule == NULL || !j->crule->no_side_effects;
    a.mask = c->mask;
    a.journal = j->crule != NULL ? j->crule->journal : 0;
    a.schema = j->schema;
    a.table = j->table;
    a.journal_fn = journal_record;
    a.journal_ctx = c;
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
    c->g_via = j->crule != NULL ? j->crule->via : 0;
    return 0;
}

/* An error came before the Execute of a confirmation: the server will not run it, so there is
 * nothing to ask about. The client's stream goes on. */
static void guard_cancel(sl_conn *c)
{
    sl_log_ev ev;

    sl_log_begin(&ev, "confirm");
    sl_log_int(&ev, "id", (long long)c->id);
    sl_log_str(&ev, "user", c->user, c->user_len);
    sl_log_str(&ev, "database", c->database, c->database_len);
    sl_log_cstr(&ev, "rule", c->g_rule);
    sl_log_cstr(&ev, "protocol", "extended");
    sl_log_cstr(&ev, "outcome", "skipped");
    sl_log_end(&ev);
    sl_confirm_free(c->guard);
    c->guard = NULL;
    sl_buf_free(&c->g_server);
    sl_buf_free(&c->g_client);
    c->g_ext = 0;
    c->g_front = 0;
    c->g_cancel = 0;
    c->g_done = 0;
    c->g_ask = 0;
    sl_scan_resume(&c->scan);
    scan_c2u(c);
    flush_c2u(c);
}

/* A Parse of a DELETE or UPDATE that a rule wants confirmed: the statement is recorded, and sent
 * with a RETURNING added unless the client wrote one. Returns 0 (replacement holds the Parse to
 * send), 1 (relay it as it is), -1 (out of memory), -2 (the lexer cannot say where the statement
 * ends), -3 (too many guarded statements, or a name too long to follow). */
static int rewrite_parse(sl_conn *c, const sl_pg_statement *st, size_t payload_len,
                         const judgement *j, sl_buf *replacement)
{
    size_t retlen;
    const char *ret = added_returning(j, &retlen);
    size_t end = sl_sql_statement_end(st->sql, st->sql_len);
    sl_ext_guard g;
    size_t rest_at;
    uint8_t head[5];
    int rc;

    if (end == 0) {
        return -2;
    }
    memset(&g, 0, sizeof g);
    g.sql = st->sql;
    g.sql_len = end;
    g.rule = j->rule;
    g.message = j->crule != NULL ? j->crule->message : NULL;
    g.over_rows = j->over_rows;
    g.limit = j->limit;
    g.via = j->crule != NULL ? j->crule->via : 0;
    g.journal = j->crule != NULL ? j->crule->journal : 0;
    g.schema = j->schema;
    g.table = j->table;
    g.kind = j->kind;
    g.rewritten = !j->returning;
    g.side_effects = j->crule == NULL || !j->crule->no_side_effects;
    rc = sl_ext_parse_guarded(c->ext, st->name, st->name_len, &g);
    if (rc == SL_EXT_NOMEM) {
        return -1;
    }
    if (rc != SL_EXT_OK) {
        return -3;
    }
    if (j->returning) {
        return 1;
    }
    /* name NUL, the statement with RETURNING * where it ends, what followed it (; or comments) NUL,
     * then the parameter types as the client sent them */
    rest_at = st->name_len + 1 + st->sql_len + 1;
    head[0] = 'P';
    sl_pg_put_be32(head + 1, (uint32_t)(4 + st->name_len + 1 + st->sql_len + retlen + 1 +
                                        (payload_len - rest_at)));
    if (sl_buf_append(replacement, head, 5) != 0 ||
        sl_buf_append(replacement, st->name, st->name_len) != 0 ||
        sl_buf_append(replacement, "", 1) != 0 || sl_buf_append(replacement, st->sql, end) != 0 ||
        sl_buf_append(replacement, ret, retlen) != 0 ||
        sl_buf_append(replacement, st->sql + end, st->sql_len - end) != 0 ||
        sl_buf_append(replacement, "", 1) != 0) {
        return -1;
    }
    /* the parameter count and types: copied from the client's message, which follows the SQL's NUL.
     * st->sql points into that message, so they sit right after it. */
    if (payload_len > rest_at &&
        sl_buf_append(replacement, st->sql + st->sql_len + 1, payload_len - rest_at) != 0) {
        return -1;
    }
    return 0;
}

static int on_statement(void *ctx, uint8_t type, const uint8_t *payload, size_t len,
                        sl_buf *replacement)
{
    sl_conn *c = ctx;
    sl_pg_statement st;
    judgement j;
    int ok;
    plan how;

    if (c->pend != NULL) {
        return pend_statement(c, type, payload, len, replacement);
    }
    ok = (type == 'Q' ? sl_pg_statement_from_query(payload, len, &st)
                      : sl_pg_statement_from_parse(payload, len, &st)) == SL_PG_OK;

    judge(c, ok ? &st : NULL, "malformed message", &j);
    note_kill(c, &j);
    how = ok ? confirm_plan(c, type, &j) : PLAN_NORMAL;
    if (type == 'P' && ok && c->ext != NULL) {
        sl_ext_parse_plain(c->ext, st.name, st.name_len); /* the unnamed statement is replaced */
    }
    if (how == PLAN_WAIT) {
        /* the server still owes answers to what came before: look at it again when they are in. It
         * is logged then, once. */
        c->scan_waiting = 1;
        return SL_SCAN_WAIT;
    }
    if (how == PLAN_REWRITE) {
        int rc = rewrite_parse(c, &st, len, &j, replacement);

        if (rc == -1) {
            return SL_SCAN_FAIL;
        }
        if (rc < 0) {
            j.blocked = 1;
            how = PLAN_BLOCK;
            snprintf(j.reason, sizeof j.reason,
                     rc == -2 ? "sluice: rule %s asks for a confirmation, but the statement cannot "
                                "be read well enough to run it first"
                              : "sluice: rule %s asks for a confirmation, but this connection "
                                "already holds as many confirmable statements as can be followed "
                                "(or the statement name is too long)",
                     j.rule);
        } else {
            j.held = 1;
            log_statement(c, type, &st, STMT_OK, len, &j);
            /* 0: it goes with a RETURNING added; 1: as the client wrote it */
            return rc == 0 ? SL_SCAN_BLOCK : SL_SCAN_RELAY;
        }
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
    if (type == 'Q' && !j.blocked && c->ext != NULL && !c->ext_bad &&
        sl_ext_guard_pending(c->ext)) {
        /* the answers of a statement that waits for confirmation are still to come, and a Query in
         * between could not be told from them */
        j.blocked = 1;
        snprintf(j.reason, sizeof j.reason,
                 "sluice: a statement that has to be confirmed is still being answered: send "
                 "this after it");
    }
    if (type == 'Q') {
        expect(c, SL_EXT_SIMPLE); /* relayed or replaced, a Query ends with a ReadyForQuery */
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

    if (c->pend != NULL && (type == 'Q' || type == 'P' || type == 'F')) {
        return pend_refuse(c, type);
    }
    judge(c, NULL, too_big ? "message over 1 MiB" : "fast-path function calls cannot be inspected",
          &j);
    note_kill(c, &j);
    if (type == 'F' && c->mask_on && !j.blocked) {
        j.blocked = 1; /* its answer is a bare value: there is no description to hide it by */
        snprintf(j.reason, sizeof j.reason,
                 "sluice: fast-path function calls cannot be used where values are hidden");
    }
    log_statement(c, type, NULL, too_big ? STMT_OVERSIZED : STMT_FASTPATH, payload_len, &j);
    if (type == 'Q' || type == 'F') {
        expect(c, SL_EXT_SIMPLE); /* either way it is answered up to a ReadyForQuery */
    }
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

static int refuse_ext(sl_buf *replacement, const char *reason);

/* The Execute of a guarded portal: it goes to the server, preceded by a Describe of the portal (the
 * names of the columns, for the person) and followed by a Flush (so that the answers come now, not
 * at the Sync), and the rest of what the client sent waits. */
static int begin_guard_ext(sl_conn *c, const sl_ext_entry *g, const uint8_t *payload,
                           size_t name_len, sl_buf *replacement)
{
    sl_confirm_args a;
    uint32_t maxrows = sl_pg_get_be32(payload + name_len + 1);
    const sl_policy *pol = policy_now(c);

    if (!session_followed(c) || c->guard != NULL) {
        return refuse_ext(replacement, "sluice cannot follow this session closely enough to "
                                       "confirm");
    }
    if (maxrows != 0 && !g->rewritten && g->kind != 'T' && g->kind != 'R') {
        /* the client's own RETURNING, fetched a few rows at a time: it cannot be held and confirmed
         */
        return refuse_ext(replacement,
                          "sluice: a statement with a RETURNING that has to be confirmed cannot be "
                          "run a few rows at a time: execute it without a row limit");
    }
    if (!sl_ext_in_step(c->ext)) {
        expect(c, SL_EXT_EXEC); /* an error already ended this cycle: the server ignores it */
        return SL_SCAN_RELAY;
    }
    memset(&a, 0, sizeof a);
    a.sql = g->sql;
    a.sql_len = g->sql_len;
    a.client_returning = !g->rewritten;
    a.tx_status = c->tx_status == 'T' ? 'T' : 'I';
    a.over_rows = g->over_rows;
    a.limit = g->limit;
    a.kind = g->kind;
    a.side_effects = g->side_effects;
    a.mask = c->mask;
    a.journal = g->journal;
    a.schema = g->schema;
    a.table = g->table;
    a.journal_fn = journal_record;
    a.journal_ctx = c;
    a.user = c->user;
    a.user_len = c->user_len;
    a.database = c->database;
    a.database_len = c->database_len;
    a.rule = g->rule;
    a.message = g->message;
    a.extended = 1;
    c->guard = sl_confirm_new();
    if (c->guard == NULL || sl_confirm_start(c->guard, &a, NULL) != 0) {
        sl_confirm_free(c->guard);
        c->guard = NULL;
        return SL_SCAN_FAIL;
    }
    /* Describe(portal), the looks, Execute, Flush (confirm.c) */
    /* A statement that sluice gave a RETURNING returns rows the client does not know about, so the
     * row limit it sent (pgjdbc always sends 1 for a DELETE, to notice stray rows) means nothing to
     * it, and would suspend the portal after the first of them: it runs without one. */
    uint8_t exec_payload[SL_EXT_NAME_MAX + 6];

    memcpy(exec_payload, payload, name_len + 1);
    sl_pg_put_be32(exec_payload + name_len + 1,
                   g->rewritten || g->kind == 'T' || g->kind == 'R' ? 0 : maxrows);
    if (sl_confirm_ext_wrap(c->guard, payload, name_len, exec_payload, name_len + 5, replacement) !=
        0) {
        sl_confirm_free(c->guard);
        c->guard = NULL;
        return SL_SCAN_FAIL;
    }
    c->g_ext = 1;
    c->g_front = 0;
    c->g_cancel = 0;
    c->g_started_ms = sl_now_ms();
    c->g_timeout_s = pol != NULL ? pol->confirm_timeout_s : 120;
    snprintf(c->g_rule, sizeof c->g_rule, "%s", g->rule);
    c->g_via = g->via;
    expect(c, SL_EXT_EXEC_G);
    return SL_SCAN_GUARD;
}

/* The error that refuses a Bind, Describe, Execute or Close: a Parse that fails takes its place, so
 * the server answers with an error at the point the client expects its answer. */
static int refuse_ext(sl_buf *replacement, const char *reason)
{
    return sl_pg_append_failing_parse(replacement, "", 0, reason) == 0 ? SL_SCAN_BLOCK
                                                                       : SL_SCAN_FAIL;
}

/* The start of a message the client's extended protocol uses: Bind, Describe, Execute, Close, Sync.
 * What it needs here is which statements and portals are guarded, and what the server will answer
 * (extstate.h). */
/* While values are hidden, every Execute is preceded by a Describe of its portal: the answer says
 * which columns the rows have, whether or not the client asked. The client never sees that answer.
 */
static int mask_execute(sl_conn *c, const uint8_t *payload, size_t name_len, size_t total,
                        size_t peeked, sl_buf *replacement)
{
    uint8_t head[5];

    if (name_len + 5 != total || name_len + 5 > peeked) {
        return refuse_ext(replacement,
                          "sluice: this Execute cannot be read to hide values in its rows");
    }
    if (c->ext_bad) {
        c->mask_overflow = 1;
        return refuse_ext(replacement, "sluice: too many messages are waiting for an answer to "
                                       "follow the session closely enough to hide values");
    }
    head[0] = 'D';
    sl_pg_put_be32(head + 1, (uint32_t)(4 + 1 + name_len + 1));
    if (sl_buf_append(replacement, head, 5) != 0 || sl_buf_append(replacement, "P", 1) != 0 ||
        sl_buf_append(replacement, payload, name_len + 1) != 0) {
        return SL_SCAN_FAIL;
    }
    head[0] = 'E';
    sl_pg_put_be32(head + 1, (uint32_t)(4 + total));
    if (sl_buf_append(replacement, head, 5) != 0 ||
        sl_buf_append(replacement, payload, total) != 0) {
        return SL_SCAN_FAIL;
    }
    expect(c, SL_EXT_EXEC_M);
    if (c->ext_bad) {
        c->mask_overflow = 1;
    }
    return SL_SCAN_BLOCK;
}

static int on_extended(void *ctx, uint8_t type, const uint8_t *payload, size_t len, size_t total,
                       sl_buf *replacement)
{
    sl_conn *c = ctx;
    const char *name;
    const char *name2;
    int n;
    int n2;
    const sl_ext_entry *g;

    if (c->pend != NULL) {
        return pend_extended(c, type);
    }
    if (c->ext == NULL) {
        return SL_SCAN_RELAY;
    }
    if (type == 'S' || type == 'F') {
        expect(c, type == 'S' ? SL_EXT_SYNC : SL_EXT_SIMPLE);
        return SL_SCAN_RELAY;
    }
    /* Once the queue of answers has overflowed it is not kept any more (`ext_bad`): what needs it,
     * a guarded statement, is refused below; the rest is relayed as it is, and needs nothing from
     * it. */
    switch (type) {
    case 'B': /* portal NUL, statement NUL, ... */
        n = sl_ext_name(payload, len, &name);
        if (n < 0 || (size_t)n + 1 >= len) {
            n2 = SL_EXT_TOO_LONG;
            name2 = NULL;
        } else {
            n2 = sl_ext_name(payload + n + 1, len - (size_t)n - 1, &name2);
        }
        if (n < 0 || n2 < 0) {
            if (sl_ext_guarded(c->ext) > 0) { /* cannot be compared with the server's 63 bytes */
                return refuse_ext(replacement,
                                  "sluice: a statement or portal name is too long to follow");
            }
            return SL_SCAN_RELAY;
        }
        g = sl_ext_stmt_guard(c->ext, name2, (size_t)n2);
        if (c->ext_bad && g != NULL) {
            return refuse_ext(replacement,
                              "sluice: too many messages are waiting for an answer to follow a "
                              "statement that has to be confirmed");
        }
        switch (sl_ext_bind(c->ext, name, (size_t)n, g)) {
        case SL_EXT_OK:
            return SL_SCAN_RELAY;
        case SL_EXT_NOMEM:
            return SL_SCAN_FAIL;
        default:
            return refuse_ext(replacement, "sluice: too many confirmable portals are open");
        }
    case 'D': /* 'S' or 'P', then the name */
    case 'C':
        if (len < 2 || (payload[0] != 'S' && payload[0] != 'P')) {
            if (type == 'D') {
                expect(c, SL_EXT_ROWDESC);
            }
            return SL_SCAN_RELAY; /* malformed: the server will say so */
        }
        n = sl_ext_name(payload + 1, len - 1, &name);
        if (n < 0) {
            if (sl_ext_guarded(c->ext) > 0) {
                return refuse_ext(replacement,
                                  "sluice: a statement or portal name is too long to follow");
            }
            if (type == 'D') {
                expect(c, payload[0] == 'S' ? SL_EXT_PARAMS : SL_EXT_ROWDESC);
                if (payload[0] == 'S') {
                    expect(c, SL_EXT_ROWDESC);
                }
            }
            return SL_SCAN_RELAY;
        }
        g = payload[0] == 'S' ? sl_ext_stmt_guard(c->ext, name, (size_t)n)
                              : sl_ext_portal_guard(c->ext, name, (size_t)n);
        if (type == 'D' && c->ext_bad && g != NULL) {
            return refuse_ext(replacement,
                              "sluice: too many messages are waiting for an answer to follow a "
                              "statement that has to be confirmed");
        }
        if (type == 'C') {
            if (payload[0] == 'S') {
                sl_ext_stmt_close(c->ext, name, (size_t)n);
            } else {
                sl_ext_portal_close(c->ext, name, (size_t)n);
            }
            return SL_SCAN_RELAY;
        }
        if (payload[0] == 'S') {
            expect(c, SL_EXT_PARAMS);
        }
        expect(c, g != NULL && g->rewritten ? SL_EXT_ROWDESC_G : SL_EXT_ROWDESC);
        return SL_SCAN_RELAY;
    case 'E': /* portal NUL, int32 maximum number of rows */
        n = sl_ext_name(payload, len, &name);
        if (c->mask_on && n >= 0 &&
            sl_ext_portal_guard(c->ext, name, (size_t)n) == NULL) { /* (a guarded one is masked by
                                                                       its confirmation) */
            return mask_execute(c, payload, (size_t)n, total, len, replacement);
        }
        if (c->mask_on && n < 0) {
            return refuse_ext(replacement, "sluice: a portal name is too long to follow");
        }
        if (n < 0) {
            if (sl_ext_guarded(c->ext) > 0) {
                return refuse_ext(replacement,
                                  "sluice: a statement or portal name is too long to follow");
            }
            expect(c, SL_EXT_EXEC);
            return SL_SCAN_RELAY;
        }
        g = sl_ext_portal_guard(c->ext, name, (size_t)n);
        if (g == NULL || (size_t)n + 5 != total || (size_t)n + 5 > len) {
            expect(c, SL_EXT_EXEC);
            return SL_SCAN_RELAY;
        }
        return begin_guard_ext(c, g, payload, (size_t)n, replacement);
    default:
        return SL_SCAN_RELAY;
    }
}

static const sl_scan_ops scan_ops = {on_statement, on_unreadable, on_frame_error, on_extended};

static void scan_c2u(sl_conn *c)
{
    int rc = sl_scan_run(&c->scan, &c->c2u, &scan_ops, c);

    note_busy(c);
    mask_check(c);

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

/* The startup packet again, with the application_name that the database will see tagged with the
 * id this connection has in sluice's log (" [sluice 42]"): a line of the database's own log or a
 * row of pg_stat_activity can then be found in the audit. The name the client gave stays in front,
 * cut to make room (the server keeps 63 bytes). Returns the new length of the packet, or 0 when it
 * could not be made (the client's own is used). */
static size_t tag_startup(sl_conn *c, const sl_pg_startup_packet *pkt)
{
    char tag[40];
    size_t taglen = (size_t)snprintf(tag, sizeof tag, " [sluice %llu]", (unsigned long long)c->id);
    const uint8_t *p = pkt->body;
    const uint8_t *end = pkt->body + pkt->body_len;
    sl_buf out;
    uint8_t head[8];
    const char *app = "";
    size_t applen = 0;

    if (sl_pg_startup_param(pkt, "application_name", &app, &applen) < 0 || applen > 4096) {
        return 0;
    }
    sl_buf_init(&out);
    memset(head, 0, sizeof head);
    sl_buf_append(&out, head, 8);
    while (p < end && *p != '\0') {
        const uint8_t *k = p;
        const uint8_t *kend = memchr(k, 0, (size_t)(end - k));
        const uint8_t *v;
        const uint8_t *vend;

        if (kend == NULL || kend + 1 >= end) {
            sl_buf_free(&out);
            return 0;
        }
        v = kend + 1;
        vend = memchr(v, 0, (size_t)(end - v));
        if (vend == NULL) {
            sl_buf_free(&out);
            return 0;
        }
        if (!(kend - k == 16 && memcmp(k, "application_name", 16) == 0)) {
            sl_buf_append(&out, k, (size_t)(vend - k) + 1); /* key NUL value NUL */
        }
        p = vend + 1;
    }
    {
        size_t room = 63 - taglen;
        size_t keep = applen < room ? applen : room;

        while (keep > 0 && keep < applen && (((const uint8_t *)app)[keep] & 0xc0) == 0x80) {
            keep--; /* not in the middle of a multi-byte character */
        }
        sl_buf_append(&out, "application_name", 17);
        sl_buf_append(&out, app, keep);
        sl_buf_append(&out, tag, taglen + 1);
    }
    sl_buf_append(&out, "", 1); /* the end of the list */
    {
        size_t total = sl_buf_len(&out);
        uint8_t *d = (uint8_t *)sl_buf_data(&out);

        sl_pg_put_be32(d, (uint32_t)total);
        sl_pg_put_be32(d + 4, pkt->code);
        if (sl_buf_replace(&c->c2u, 0, pkt->total_len, d, total) != 0) {
            sl_buf_free(&out);
            return 0;
        }
        sl_buf_free(&out);
        return total;
    }
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
            if (c->policy_ref != NULL && policy_now(c) != NULL) {
                sl_policy_limits(policy_now(c), c->user, c->user_len, c->database, c->database_len,
                                 &c->lim);
                if (c->lim.connections != 0 && c->count_user != NULL &&
                    c->count_user(c->count_ctx, c, c->user, c->user_len) >= c->lim.connections) {
                    char msg[200];

                    log_limit(c, "connections", c->lim.rule_connections);
                    snprintf(msg, sizeof msg,
                             "sluice: too many connections for this user (rule %s: at most %llu)",
                             c->lim.rule_connections, c->lim.connections);
                    fatal(c, "53300", msg, "connection_limit");
                    return;
                }
            }
            if (c->policy_ref != NULL && policy_now(c) != NULL && !setup_mask(c)) {
                fatal(c, "53200", "sluice: out of memory", "out_of_memory");
                return;
            }
            if (c->lim.nbudgets > 0 && !hold_budgets(c)) {
                fatal(c, "53300", "sluice: too many users have a budget at once",
                      "budget_unavailable");
                return;
            }
            if (enforcing(c) && wants_replication(&pkt)) {
                fatal(c, "42501", "sluice: replication connections are not allowed through sluice",
                      "replication_denied");
                return;
            }
            {
                size_t tagged = c->cfg->tag_application ? tag_startup(c, &pkt) : 0;

                begin_connect(c, tagged != 0 ? tagged : pkt.total_len);
            }
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

/* The answers of the guarded Execute are being read: the server has reached it. */
static int guard_live(const sl_conn *c)
{
    return c->g_ext && (c->g_front || (c->ext != NULL && sl_ext_front_guarded_exec(c->ext)));
}

static int srv_classify(void *ctx, uint8_t type, size_t payload_len)
{
    sl_conn *c = ctx;

    if (c->swallow > 0) {
        return SL_SRV_READ; /* the answers of a message of ours: read, and thrown away */
    }
    if (c->guard != NULL && (!c->g_ext || guard_live(c))) {
        return SL_SRV_READ; /* every answer to the statement is read, and kept or consumed */
    }
    if (c->cut != 0 && (type == 'D' || type == 'd')) {
        return SL_SRV_SKIP; /* the rest of a result that was cut, whoever cut it */
    }
    if (c->lim_on && (type == 'D' || type == 'd')) {
        /* a row (or a piece of COPY data) that would take the result or the connection past a limit
         * is not sent; decided before it goes, so the first one over is not the one that slips */
        if (c->cut != 0 || (c->lim.result_rows != 0 && c->res_rows >= c->lim.result_rows) ||
            (c->lim.result_bytes != 0 && c->res_bytes + 5 + payload_len > c->lim.result_bytes) ||
            (c->lim.total_bytes != 0 && c->total_bytes + 5 + payload_len > c->lim.total_bytes)) {
            return SL_SRV_SKIP;
        }
        if (c->bud_stream) {
            int kind;

            if (budget_row_hit(c, payload_len, &kind) != 0) {
                return SL_SRV_SKIP;
            }
        }
    }
    if (c->mask_on) {
        switch (type) {
        case 'T':
        case 'n':
        case 'E':
        case 'N':
            return SL_SRV_READ; /* the columns of the rows to come; what an error or a notice quotes
                                 */
        case 'd':
            return SL_SRV_SKIP; /* COPY data: no way to know where a value starts */
        case 'D':
            if (!mask_reads_rows(c)) {
                return SL_SRV_PASS; /* nothing in these columns is to be hidden: they stream */
            }
            return payload_len > SL_SRV_READ_MAX ? SL_SRV_SKIP : SL_SRV_READ;
        default:
            break;
        }
    }
    if (c->bud_changed && type == 'C') {
        return SL_SRV_READ; /* the tag says how many rows were changed */
    }
    if (c->cut != 0 && (type == 'C' || type == 'I' || type == 's')) {
        return SL_SRV_READ; /* the end of a result that was cut: it becomes an error */
    }
    if (c->cfg->log_results && (type == 'C' || type == 'E' || type == 'I' || type == 's')) {
        return SL_SRV_READ; /* the end of a result: its tag or its error code goes in the log */
    }
    if (type == 'Z' || (type == 'C' && c->tag_rewrite[0] != '\0') || (type == 'K' && !c->first_z)) {
        return SL_SRV_READ;
    }
    if (type == 'T' && c->ext != NULL && !c->ext_bad && sl_ext_front_guarded_rowdesc(c->ext)) {
        return SL_SRV_READ; /* the RowDescription of a statement that sluice gave a RETURNING */
    }
    return SL_SRV_PASS;
}

/* What an answer that is relayed unread means for the queue of answers the server owes. */
static void note_answer(sl_conn *c, int flags)
{
    if ((flags & SL_EXT_SKIPPED) && c->guard != NULL && c->g_ext && !c->g_front) {
        c->g_cancel = 1; /* the Execute that was being confirmed will not run */
    }
}

/* A row went to the client: it counts for the limits and the budgets. */
static void count_row(sl_conn *c, size_t payload_len)
{
    c->res_rows++;
    c->res_bytes += 5 + payload_len;
    c->total_bytes += 5 + payload_len;
    if (c->bud_stream) {
        int64_t now = sl_now_ms();

        for (size_t k = 0; k < c->lim.nbudgets; k++) {
            sl_budget_add(c->bud[k], now, SL_BUDGET_ROWS, 1);
            sl_budget_add(c->bud[k], now, SL_BUDGET_BYTES, 5 + payload_len);
        }
    }
}

static void srv_passed(void *ctx, uint8_t type, size_t payload_len)
{
    sl_conn *c = ctx;

    if (c->lim_on || c->cfg->log_results) {
        if (type == 'D' || type == 'd') {
            count_row(c, payload_len);
        } else if (type == 'C' || type == 'I' || type == 's' || type == 'E') {
            c->res_rows = 0; /* the end of a result */
            c->res_bytes = 0;
            c->cut = 0; /* (an error of the server's own takes the place of ours) */
        }
    }
    if (c->ext != NULL && !c->ext_bad && type != 'D') {
        note_answer(c, sl_ext_answer(c->ext, type));
    }
}

static void log_limit(const sl_conn *c, const char *kind, const char *rule)
{
    sl_log_ev ev;

    sl_metric_inc(SL_M_LIMITS, kind, NULL);
    sl_log_begin(&ev, "limit");
    sl_log_int(&ev, "id", (long long)c->id);
    sl_log_str(&ev, "user", c->user, c->user_len);
    sl_log_str(&ev, "database", c->database, c->database_len);
    sl_log_cstr(&ev, "kind", kind);
    sl_log_cstr(&ev, "rule", rule != NULL ? rule : "");
    sl_log_int(&ev, "rows", (long long)c->res_rows);
    sl_log_int(&ev, "bytes", (long long)c->res_bytes);
    sl_log_int(&ev, "total_bytes", (long long)c->total_bytes);
    sl_log_end(&ev);
}

/* The result went past a limit: what was sent stays sent, the rest was dropped, and the end of the
 * result is an error that says so. */
static int limit_error(sl_conn *c)
{
    char msg[300];
    const char *kind = c->cut == 1   ? "result_rows"
                       : c->cut == 2 ? "result_bytes"
                       : c->cut == 4 ? "budget_rows"
                       : c->cut == 5 ? "budget_bytes"
                       : c->cut == 6 ? "mask_row"
                       : c->cut == 7 ? "mask_copy"
                                     : "total_bytes";
    const char *rule = c->cut == 1                  ? c->lim.rule_rows
                       : c->cut == 2                ? c->lim.rule_bytes
                       : c->cut <= 5 && c->cut >= 4 ? c->lim.budgets[c->cut_bud].rule
                       : c->cut >= 6                ? c->mask_rule
                                                    : c->lim.rule_total;

    if (c->cut >= 6) {
        snprintf(msg, sizeof msg,
                 c->cut == 6
                     ? "sluice: a row could not be read to hide values in it (rule %s): the "
                       "rest of this result was not sent"
                     : "sluice: COPY ... TO STDOUT cannot be read to hide values in it (rule "
                       "%s): use a SELECT",
                 rule);
    } else if (c->cut >= 4) {
        const sl_budget_spec *s = &c->lim.budgets[c->cut_bud];
        int64_t now = sl_now_ms();
        int rows = c->cut == 4;

        snprintf(msg, sizeof msg,
                 "sluice: budget (rule %s): %llu %s in %s are used up; the rest was not sent, "
                 "more is possible in about %us",
                 rule, rows ? s->rows : s->bytes, rows ? "rows" : "bytes", window_text(s->window_s),
                 sl_budget_wait_s(c->bud[c->cut_bud], now, rows ? SL_BUDGET_ROWS : SL_BUDGET_BYTES,
                                  rows ? s->rows : s->bytes));
    } else if (c->cut == 1) {
        snprintf(msg, sizeof msg,
                 "sluice: result limit (rule %s): more than %llu rows; the rest was not sent", rule,
                 c->lim.result_rows);
    } else if (c->cut == 2) {
        snprintf(msg, sizeof msg,
                 "sluice: result limit (rule %s): more than %llu bytes; the rest was not sent",
                 rule, c->lim.result_bytes);
    } else {
        snprintf(
            msg, sizeof msg,
            "sluice: volume limit (rule %s): more than %llu bytes were sent on this connection; "
            "it is closed",
            rule, c->lim.total_bytes);
        c->close_after_z = 1;
    }
    log_limit(c, kind, rule);
    c->res_rows = c->res_bytes = 0;
    {
        const char *code = c->cut == 4 || c->cut == 5 ? "53400" : "54000";

        c->cut = 0;
        if (sl_pg_append_report(&c->srv.replacement, 'E', c->close_after_z ? "FATAL" : "ERROR",
                                code, msg, NULL, NULL) != 0) {
            c->g_nomem = 1;
            return SL_SRV_KEEP;
        }
        return SL_SRV_REPLACE;
    }
}

/* The end of a result, for the log: how it ended, how many rows and bytes, and how long it took
 * (since the previous result ended, or since the server became busy: the statements of a message
 * run one after the other). The text of an error is not logged, since it can quote values: its code
 * is. */
static void log_result(sl_conn *c, uint8_t type, const uint8_t *payload, size_t len)
{
    sl_log_ev ev;
    int64_t now = sl_now_ms();

    sl_log_begin(&ev, "result");
    sl_log_int(&ev, "id", (long long)c->id);
    sl_log_str(&ev, "user", c->user, c->user_len);
    sl_log_str(&ev, "database", c->database, c->database_len);
    sl_log_cstr(&ev, "kind",
                type == 'C'   ? "ok"
                : type == 'E' ? "error"
                : type == 'I' ? "empty"
                              : "suspended");
    if (type == 'C' && len > 0) {
        size_t n = len;

        while (n > 0 && payload[n - 1] == 0) {
            n--;
        }
        sl_log_str(&ev, "tag", (const char *)payload, n);
    } else if (type == 'E') {
        size_t pos = 0;

        while (pos < len && payload[pos] != 0) {
            uint8_t tag = payload[pos++];
            const uint8_t *end = memchr(payload + pos, 0, len - pos);
            size_t n = end != NULL ? (size_t)(end - (payload + pos)) : len - pos;

            if (tag == 'C') {
                sl_log_str(&ev, "sqlstate", (const char *)payload + pos, n);
                break;
            }
            pos += n + 1;
        }
    }
    sl_log_int(&ev, "rows", (long long)c->res_rows);
    sl_log_int(&ev, "bytes", (long long)c->res_bytes);
    if (c->mark_ms >= 0) {
        sl_log_int(&ev, "duration_ms", (long long)(now - c->mark_ms));
    }
    sl_log_end(&ev);
    c->mark_ms = now;
}

/* Masking of what the server sends (mask.h). Returns what srv_message should return, or -1 when the
 * message is none of its business. */
static int mask_message(sl_conn *c, uint8_t type, const uint8_t *payload, size_t len, int flags)
{
    sl_buf out;
    int rc;

    switch (type) {
    case 'T':
        (void)sl_mask_describe(c->mask, payload, len); /* when it fails the rows are refused */
        return (flags & SL_EXT_OURS) ? SL_SRV_DROP : SL_SRV_KEEP;
    case 'n':
        sl_mask_forget(c->mask);
        return (flags & SL_EXT_OURS) ? SL_SRV_DROP : SL_SRV_KEEP;
    case 'C':
    case 'I':
    case 's':
    case 'Z':
        sl_mask_forget(c->mask); /* the end of a result, or of the exchange */
        return -1;
    case 'D':
        sl_buf_init(&out);
        rc = sl_mask_row(c->mask, payload, len, &out);
        count_row(c, len);
        if (rc == SL_MASK_SAME) {
            sl_buf_free(&out);
            return SL_SRV_KEEP;
        }
        if (rc == SL_MASK_CHANGED) {
            uint8_t head[5];

            head[0] = 'D';
            sl_pg_put_be32(head + 1, (uint32_t)(4 + sl_buf_len(&out)));
            if (sl_buf_append(&c->srv.replacement, head, 5) != 0 ||
                sl_buf_append(&c->srv.replacement, sl_buf_data(&out), sl_buf_len(&out)) != 0) {
                sl_buf_free(&out);
                c->g_nomem = 1;
                return SL_SRV_KEEP;
            }
            c->masked_cells += sl_mask_take_count(c->mask);
            sl_buf_free(&out);
            return SL_SRV_REPLACE;
        }
        sl_buf_free(&out);
        if (rc == SL_MASK_NOMEM) {
            c->g_nomem = 1;
            return SL_SRV_DROP;
        }
        c->cut = 6; /* a row that does not fit its description: nothing more of this result */
        return SL_SRV_DROP;
    case 'E':
    case 'N':
        if (type == 'E') {
            sl_mask_forget(
                c->mask); /* no rows follow an error without a description of their own */
        }
        sl_buf_init(&out);
        rc = sl_mask_message(c->mask, payload, len, &out);
        if (rc == SL_MASK_SAME) {
            sl_buf_free(&out);
            return SL_SRV_KEEP;
        }
        if (rc == SL_MASK_CHANGED) {
            uint8_t head[5];

            head[0] = type;
            sl_pg_put_be32(head + 1, (uint32_t)(4 + sl_buf_len(&out)));
            if (sl_buf_append(&c->srv.replacement, head, 5) != 0 ||
                sl_buf_append(&c->srv.replacement, sl_buf_data(&out), sl_buf_len(&out)) != 0) {
                sl_buf_free(&out);
                c->g_nomem = 1;
                return SL_SRV_KEEP;
            }
            c->masked_cells += sl_mask_take_count(c->mask);
            sl_buf_free(&out);
            return SL_SRV_REPLACE;
        }
        sl_buf_free(&out);
        if (rc == SL_MASK_NOMEM) {
            c->g_nomem = 1;
            return SL_SRV_KEEP;
        }
        if (type == 'E' &&
            sl_pg_append_report(&c->srv.replacement, 'E', "ERROR", "XX000",
                                "sluice: an error message could not be read to hide values in it",
                                NULL, NULL) == 0) {
            return SL_SRV_REPLACE;
        }
        return SL_SRV_DROP;
    default:
        return -1;
    }
}

static int srv_message(void *ctx, uint8_t type, const uint8_t *payload, size_t len)
{
    sl_conn *c = ctx;
    int live = c->guard != NULL && c->g_ext && guard_live(c);
    int flags = 0;
    int rc = SL_SRV_KEEP;

    if (type == 'K' && len == 8) {
        memcpy(c->be_key, payload,
               8); /* the process and secret of the session: what a cancel needs */
        c->have_key = 1;
        return SL_SRV_KEEP;
    }
    if (c->cut != 0 && (type == 'C' || type == 'I' || type == 's')) {
        return limit_error(c);
    }
    if (type == 'Z' && len >= 1) {
        c->res_rows = c->res_bytes = 0;
        c->cut = 0;
        if (c->close_after_z) {
            c->closing = 1; /* what the client was owed has been sent: the connection ends */
            c->close_reason = c->z_reason != NULL ? c->z_reason : "volume_limit";
        }
        c->tx_status = payload[0];
        if (c->first_z && c->swallow == 0 && c->guard == NULL && c->bud_stmts) {
            const char *spent = budget_note_round_trip(c);

            if (spent != NULL) {
                log_limit(c, "statement_budget", spent);
                c->closing = 1; /* what the client was owed has been sent: the connection ends */
                c->close_reason = "statement_budget";
            }
        }
        if (c->first_z) {
            c->z_seen++;
        }
        c->first_z = 1;
        if (payload[0] == 'I' && c->ext != NULL) {
            sl_ext_portals_end(c->ext); /* the portals lived as long as the transaction */
        }
    }
    if (c->probe == 1) {
        probe_answer(c, type, payload, len);
    }
    if (c->swallow > 0) {
        if (type == 'Z') {
            c->swallow--;
        }
        return SL_SRV_DROP;
    }
    if (live) {
        c->g_front = 1;
    }
    if (c->guard != NULL && (!c->g_ext || live)) {
        sl_confirm_step step;

        rc = sl_confirm_server(c->guard, type, payload, len, &c->g_server, &c->g_client, &step);
        if (rc < 0) {
            c->g_nomem = 1;
            rc = SL_SRV_KEEP;
        } else {
            c->g_ask |= step.ask;
            if (step.done) {
                c->g_done = 1;
                c->srv.paused = 1; /* what follows is not part of the confirmation */
            }
        }
        if (c->g_ext && c->ext != NULL && !c->ext_bad) {
            (void)sl_ext_answer(c->ext, type); /* keeps the queue in step */
        }
        return rc;
    }
    if (type == 'C' && c->bud_changed && c->tag_rewrite[0] == '\0') {
        budget_note_tag(c, payload, len);
    }
    if (c->cfg->log_results && (type == 'C' || type == 'E' || type == 'I' || type == 's')) {
        if (!(type == 'C' && c->tag_rewrite[0] != '\0')) {
            log_result(c, type, payload, len);
        }
        c->res_rows = 0;
        c->res_bytes = 0;
        c->cut = 0;
    }
    if (c->ext != NULL && !c->ext_bad) {
        flags = sl_ext_answer(c->ext, type);
        note_answer(c, flags);
        if (type == 'T' && (flags & SL_EXT_TO_NODATA)) {
            /* the statement got a RETURNING that the client does not know about: it asked what the
             * result would look like and is told there is none, as for any DELETE */
            if (sl_buf_append(&c->srv.replacement, "n\0\0\0\4", 5) != 0) {
                c->g_nomem = 1;
                return SL_SRV_KEEP;
            }
            return SL_SRV_REPLACE;
        }
    }
    if (c->mask_on) {
        int r = mask_message(c, type, payload, len, flags);

        if (r >= 0) {
            return r;
        }
    }
    if (type == 'C' && c->tag_rewrite[0] != '\0') {
        /* the answer to the statement that a yes was turned into (COMMIT, RELEASE, SET): the client
         * gets the tag of its own statement instead. Anything else is not that answer (a prepared
         * yes is only parsed in its own cycle and run in the next one): the wait is over, and it is
         * left as it is. */
        size_t tl = strlen(c->tag_rewrite) + 1;
        uint8_t head[5];
        int ours = (len >= 3 && memcmp(payload, "SET", 3) == 0) ||
                   (len >= 6 && memcmp(payload, "COMMIT", 6) == 0) ||
                   (len >= 7 && memcmp(payload, "RELEASE", 7) == 0);

        if (!ours) {
            c->tag_rewrite[0] = '\0';
            return SL_SRV_KEEP;
        }

        head[0] = 'C';
        sl_pg_put_be32(head + 1, (uint32_t)(4 + tl));
        if (sl_buf_append(&c->srv.replacement, head, 5) != 0 ||
            sl_buf_append(&c->srv.replacement, c->tag_rewrite, tl) != 0) {
            c->g_nomem = 1;
            return SL_SRV_KEEP;
        }
        c->tag_rewrite[0] = '\0';
        return SL_SRV_REPLACE;
    }
    return SL_SRV_KEEP;
}

/* A row was not sent: say which limit it was, once per result. */
static void srv_skipped(void *ctx, uint8_t type, size_t payload_len)
{
    sl_conn *c = ctx;

    if (c->cut == 0) {
        if (c->lim.total_bytes != 0 && c->total_bytes + 5 + payload_len > c->lim.total_bytes) {
            c->cut = 3;
        } else if (c->lim.result_rows != 0 && c->res_rows >= c->lim.result_rows) {
            c->cut = 1;
        } else if (c->lim.result_bytes != 0 &&
                   c->res_bytes + 5 + payload_len > c->lim.result_bytes) {
            c->cut = 2;
        } else {
            int kind = SL_BUDGET_ROWS;
            size_t h = budget_row_hit(c, payload_len, &kind);

            c->cut = h == 0                   ? (c->mask_on ? (type == 'd' ? 7 : 6) : 2)
                     : kind == SL_BUDGET_ROWS ? 4
                                              : 5;
            c->cut_bud = h == 0 ? 0 : h - 1;
        }
    }
}

static const sl_srv_ops srv_ops = {srv_classify, srv_message, srv_passed, srv_skipped};

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
        if (c->guard != NULL && c->g_cancel) {
            guard_cancel(c);
            again = 1;
        } else if (c->guard != NULL) {
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
    probe_catalog(c);
    note_busy(c);
    mask_check(c);
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
    c->lim_on = c->lim.result_rows != 0 || c->lim.result_bytes != 0 || c->lim.total_bytes != 0 ||
                c->bud_stream;
    if (c->srv_on) {
        c->ext = sl_ext_new();
        if (c->ext == NULL) {
            finish(c, "out_of_memory");
            return;
        }
    }
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
