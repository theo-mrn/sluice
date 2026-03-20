#include "confirm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pg_proto.h"
#include "srvscan.h"

#define MAX_COLS 16
#define NAME_LEN 32
#define CELL_LEN 48
#define SAVEPOINT "sluice_guard"

typedef enum {
    ST_RUN,      /* the statement is running: its answer is being read */
    ST_UNDO,     /* the first attempt failed: it is being rolled back, to try the original */
    ST_ASK,      /* waiting for the person */
    ST_COMMIT,   /* yes: COMMIT sent */
    ST_ROLLBACK, /* no: ROLLBACK sent, an error of ours follows */
    ST_FAIL,     /* the statement failed for good: ROLLBACK sent, the server's error follows */
    ST_DONE
} state;

struct sl_confirm {
    state st;
    int in_tx;
    int returning_added; /* the statement being run is the one with RETURNING added */
    int tried_original;
    int client_returning;
    unsigned long long over_rows;

    char *sql;
    size_t sql_len;
    char *sql_ret;
    size_t sql_ret_len;

    char user[96];
    char database[96];
    char rule[72];
    char message[208];

    /* what the current attempt has answered */
    int prelude_done; /* the answer to BEGIN / SAVEPOINT has been read */
    int saw_error;
    int overflow;
    sl_buf cc;    /* the CommandComplete message */
    sl_buf error; /* the first ErrorResponse message */
    sl_buf
        client_rows; /* RowDescription, DataRow..., CommandComplete: for a client's own RETURNING */
    char tag[64];
    unsigned long long rows;

    /* the part to show */
    int ncols;
    char names[MAX_COLS][NAME_LEN];
    int sample_n;
    char cells[SL_CONFIRM_SAMPLE_ROWS][MAX_COLS][CELL_LEN];
    unsigned char is_null[SL_CONFIRM_SAMPLE_ROWS][MAX_COLS];

    sl_buf commit_error;
    const char *outcome;
    char why[96];
};

sl_confirm *sl_confirm_new(void)
{
    sl_confirm *c = calloc(1, sizeof *c);

    if (c != NULL) {
        sl_buf_init(&c->cc);
        sl_buf_init(&c->error);
        sl_buf_init(&c->client_rows);
        sl_buf_init(&c->commit_error);
        c->outcome = "error";
    }
    return c;
}

void sl_confirm_free(sl_confirm *c)
{
    if (c == NULL) {
        return;
    }
    free(c->sql);
    free(c->sql_ret);
    sl_buf_free(&c->cc);
    sl_buf_free(&c->error);
    sl_buf_free(&c->client_rows);
    sl_buf_free(&c->commit_error);
    free(c);
}

static char *dup_n(const char *s, size_t n)
{
    char *d = malloc(n + 1);

    if (d != NULL) {
        memcpy(d, s, n);
        d[n] = '\0';
    }
    return d;
}

static void copy_text(char *dst, size_t cap, const char *src, size_t n)
{
    if (n >= cap) {
        n = cap - 1;
    }
    if (src != NULL && n > 0) {
        memcpy(dst, src, n);
    } else {
        n = 0;
    }
    dst[n] = '\0';
}

/* ---- messages ---- */

static int add_query(sl_buf *out, const char *prefix, const char *text, size_t len)
{
    size_t plen = strlen(prefix);
    uint8_t head[5];

    head[0] = 'Q';
    sl_pg_put_be32(head + 1, (uint32_t)(4 + plen + len + 1));
    return sl_buf_append(out, head, 5) != 0 || sl_buf_append(out, prefix, plen) != 0 ||
                   (len > 0 && sl_buf_append(out, text, len) != 0) || sl_buf_append(out, "", 1) != 0
               ? -1
               : 0;
}

static int add_ready(sl_buf *out, uint8_t status)
{
    uint8_t m[6];

    m[0] = 'Z';
    sl_pg_put_be32(m + 1, 5);
    m[5] = status;
    return sl_buf_append(out, m, 6);
}

/* A message as it came, rebuilt from its type and payload. */
static int add_message(sl_buf *out, uint8_t type, const uint8_t *payload, size_t len)
{
    uint8_t head[5];

    head[0] = type;
    sl_pg_put_be32(head + 1, (uint32_t)(4 + len));
    return sl_buf_append(out, head, 5) != 0 || (len > 0 && sl_buf_append(out, payload, len) != 0)
               ? -1
               : 0;
}

static int send_begin(sl_confirm *c, sl_buf *to_server)
{
    const char *text = c->returning_added ? c->sql_ret : c->sql;
    size_t len = c->returning_added ? c->sql_ret_len : c->sql_len;

    return add_query(to_server, c->in_tx ? "SAVEPOINT " SAVEPOINT "; " : "BEGIN; ", text, len);
}

static int send_commit(sl_confirm *c, sl_buf *to_server)
{
    return add_query(to_server, c->in_tx ? "RELEASE SAVEPOINT " SAVEPOINT : "COMMIT", "", 0);
}

static int send_rollback(sl_confirm *c, sl_buf *to_server)
{
    return add_query(to_server,
                     c->in_tx ? "ROLLBACK TO SAVEPOINT " SAVEPOINT "; RELEASE SAVEPOINT " SAVEPOINT
                              : "ROLLBACK",
                     "", 0);
}

/* ---- starting ---- */

int sl_confirm_start(sl_confirm *c, const sl_confirm_args *a, sl_buf *to_server)
{
    c->in_tx = a->tx_status == 'T';
    c->client_returning = a->client_returning;
    c->over_rows = a->over_rows;
    c->sql = dup_n(a->sql, a->sql_len);
    c->sql_len = a->sql_len;
    if (a->sql_returning != NULL) {
        c->sql_ret = dup_n(a->sql_returning, a->sql_returning_len);
        c->sql_ret_len = a->sql_returning_len;
        c->returning_added = c->sql_ret != NULL;
    }
    if (c->sql == NULL || (a->sql_returning != NULL && c->sql_ret == NULL)) {
        return -1;
    }
    c->tried_original = !c->returning_added; /* nothing else to fall back to */
    copy_text(c->user, sizeof c->user, a->user, a->user_len);
    copy_text(c->database, sizeof c->database, a->database, a->database_len);
    copy_text(c->rule, sizeof c->rule, a->rule, a->rule ? strlen(a->rule) : 0);
    copy_text(c->message, sizeof c->message, a->message, a->message ? strlen(a->message) : 0);
    c->st = ST_RUN;
    return send_begin(c, to_server);
}

/* ---- reading the answer ---- */

static void forget_attempt(sl_confirm *c)
{
    c->prelude_done = 0;
    c->saw_error = 0;
    c->overflow = 0;
    sl_buf_free(&c->cc);
    sl_buf_free(&c->error);
    sl_buf_free(&c->client_rows);
    c->tag[0] = '\0';
    c->rows = 0;
    c->ncols = 0;
    c->sample_n = 0;
}

static uint16_t be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

/* RowDescription: the names of the columns. */
static void read_names(sl_confirm *c, const uint8_t *p, size_t len)
{
    size_t pos = 2;
    int n;

    if (len < 2) {
        return;
    }
    n = be16(p);
    c->ncols = 0;
    for (int i = 0; i < n && c->ncols < MAX_COLS; i++) {
        const uint8_t *end = memchr(p + pos, 0, len - pos);
        size_t l;

        if (pos >= len || end == NULL) {
            return;
        }
        l = (size_t)(end - (p + pos));
        copy_text(c->names[c->ncols], NAME_LEN, (const char *)p + pos, l);
        c->ncols++;
        pos += l + 1 + 18;
        if (pos > len) {
            return;
        }
    }
}

/* DataRow: the first rows are kept, cut to a width that fits a terminal. */
static void read_row(sl_confirm *c, const uint8_t *p, size_t len)
{
    size_t pos = 2;
    int n;
    int col;

    if (c->sample_n >= SL_CONFIRM_SAMPLE_ROWS || len < 2) {
        return;
    }
    n = be16(p);
    for (col = 0; col < n && col < MAX_COLS; col++) {
        int32_t l;

        if (pos + 4 > len) {
            return;
        }
        l = (int32_t)sl_pg_get_be32(p + pos);
        pos += 4;
        if (l < 0) {
            c->is_null[c->sample_n][col] = 1;
            c->cells[c->sample_n][col][0] = '\0';
            continue;
        }
        if (pos + (size_t)l > len) {
            return;
        }
        c->is_null[c->sample_n][col] = 0;
        copy_text(c->cells[c->sample_n][col], CELL_LEN, (const char *)p + pos, (size_t)l);
        pos += (size_t)l;
    }
    for (; col < MAX_COLS && c->ncols > 0 && col < c->ncols; col++) {
        c->cells[c->sample_n][col][0] = '\0';
    }
    c->sample_n++;
}

/* "DELETE 41234" and "UPDATE 3" end with the number of rows; "INSERT 0 5" does too. */
static void read_tag(sl_confirm *c, const uint8_t *p, size_t len)
{
    size_t l = len;
    size_t i;

    while (l > 0 && p[l - 1] == 0) {
        l--;
    }
    copy_text(c->tag, sizeof c->tag, (const char *)p, l);
    c->rows = 0;
    for (i = l; i > 0 && p[i - 1] != ' '; i--) {
    }
    for (; i < l; i++) {
        if (p[i] >= '0' && p[i] <= '9' && c->rows < (1ULL << 60)) {
            c->rows = c->rows * 10 + (unsigned long long)(p[i] - '0');
        }
    }
}

static int is_async(uint8_t type)
{
    return type == 'N' || type == 'A' || type == 'S';
}

/* Gives the client the end of the exchange: the answer it expects, and ReadyForQuery. */
static int deliver(sl_confirm *c, sl_buf *to_client, uint8_t status, int error_instead,
                   const sl_buf *error)
{
    const sl_buf *body;

    if (error_instead) {
        body = error;
    } else {
        body = c->client_returning ? &c->client_rows : &c->cc;
    }
    if (sl_buf_len(body) > 0 &&
        sl_buf_append(to_client, sl_buf_data(body), sl_buf_len(body)) != 0) {
        return -1;
    }
    c->st = ST_DONE;
    return add_ready(to_client, status);
}

static int our_error(sl_confirm *c, sl_buf *to_client, uint8_t status)
{
    char text[512]; /* the longest rule name, reason and message fit */
    sl_buf err;
    int rc;

    snprintf(text, sizeof text, "sluice: not confirmed (rule %s): %s.%s%s Nothing was changed.",
             c->rule, c->why[0] ? c->why : "refused", c->message[0] ? " " : "", c->message);
    sl_buf_init(&err);
    if (sl_pg_append_error(&err, "ERROR", "42501", text) != 0) {
        sl_buf_free(&err);
        return -1;
    }
    rc = deliver(c, to_client, status, 1, &err);
    sl_buf_free(&err);
    return rc;
}

/* The statement went through. Not above the threshold: commit. Otherwise: ask. */
static int statement_done(sl_confirm *c, sl_buf *to_server, sl_confirm_step *step)
{
    if (c->overflow) {
        snprintf(c->why, sizeof c->why, "the result is too large to confirm");
        c->outcome = "too_large";
        c->st = ST_ROLLBACK;
        return send_rollback(c, to_server);
    }
    if (c->rows <= c->over_rows) {
        c->outcome = "auto";
        c->st = ST_COMMIT;
        return send_commit(c, to_server);
    }
    c->st = ST_ASK;
    step->ask = 1;
    return 0;
}

static int on_run(sl_confirm *c, uint8_t type, const uint8_t *p, size_t len, sl_buf *to_server,
                  sl_confirm_step *step)
{
    switch (type) {
    case 'C':
        if (!c->prelude_done) {
            c->prelude_done = 1; /* BEGIN or SAVEPOINT */
            return 0;
        }
        read_tag(c, p, len);
        if (add_message(&c->cc, 'C', p, len) != 0) {
            return -1;
        }
        return c->client_returning ? add_message(&c->client_rows, 'C', p, len) : 0;
    case 'T':
        read_names(c, p, len);
        return c->client_returning ? add_message(&c->client_rows, 'T', p, len) : 0;
    case 'D':
        read_row(c, p, len);
        if (c->client_returning && !c->overflow) {
            if (sl_buf_len(&c->client_rows) + len + 5 > SL_CONFIRM_HELD_MAX) {
                c->overflow = 1;
                sl_buf_free(&c->client_rows);
                return 0;
            }
            return add_message(&c->client_rows, 'D', p, len);
        }
        return 0;
    case 'E':
        if (!c->saw_error) {
            c->saw_error = 1;
            return add_message(&c->error, 'E', p, len);
        }
        return 0;
    case 'Z': {
        uint8_t status = len >= 1 ? p[0] : 'I';

        (void)status;
        if (!c->saw_error) {
            return statement_done(c, to_server, step);
        }
        if (c->returning_added && !c->tried_original) {
            /* maybe it was the RETURNING that failed: undo, and run the statement as it was written
             */
            c->st = ST_UNDO;
            return send_rollback(c, to_server);
        }
        if (c->in_tx) {
            /* the transaction of the client is now aborted, as it would have been: the error is its
             * own */
            c->outcome = "error";
            return -2; /* handled by the caller of on_run: deliver the error and the status */
        }
        c->outcome = "error";
        c->st = ST_FAIL;
        return send_rollback(c, to_server);
    }
    default:
        return 0;
    }
}

int sl_confirm_server(sl_confirm *c, uint8_t type, const uint8_t *payload, size_t len,
                      sl_buf *to_server, sl_buf *to_client, sl_confirm_step *step)
{
    int keep = is_async(type) ? SL_SRV_KEEP : SL_SRV_DROP;
    uint8_t status = type == 'Z' && len >= 1 ? payload[0] : 'I';
    int rc = 0;

    step->ask = 0;
    step->done = 0;
    if (keep == SL_SRV_KEEP) {
        return keep;
    }
    switch (c->st) {
    case ST_RUN:
        rc = on_run(c, type, payload, len, to_server, step);
        if (rc == -2) { /* failed inside the client's own transaction */
            if (deliver(c, to_client, status, 1, &c->error) != 0) {
                return -1;
            }
            step->done = 1;
            return keep;
        }
        break;
    case ST_UNDO:
        if (type == 'Z') {
            forget_attempt(c);
            c->returning_added = 0;
            c->tried_original = 1;
            c->st = ST_RUN;
            rc = send_begin(c, to_server);
        }
        break;
    case ST_ASK:
        /* the server itself ended it (idle_in_transaction_session_timeout, say) */
        if (type == 'E') {
            c->outcome = "error";
            if (add_message(to_client, 'E', payload, len) != 0) {
                return -1;
            }
            c->st = ST_DONE;
            step->done = 1;
        }
        break;
    case ST_COMMIT:
        if (type == 'E' && sl_buf_len(&c->commit_error) == 0) {
            rc = add_message(&c->commit_error, 'E', payload, len);
        } else if (type == 'Z') {
            rc = deliver(c, to_client, status, sl_buf_len(&c->commit_error) > 0, &c->commit_error);
            step->done = 1;
        }
        break;
    case ST_ROLLBACK:
        if (type == 'Z') {
            rc = our_error(c, to_client, status);
            step->done = 1;
        }
        break;
    case ST_FAIL:
        if (type == 'Z') {
            rc = deliver(c, to_client, status, 1, &c->error);
            step->done = 1;
        }
        break;
    case ST_DONE:
        break;
    }
    return rc != 0 ? -1 : keep;
}

int sl_confirm_answer(sl_confirm *c, int yes, const char *outcome, sl_buf *to_server)
{
    if (c->st != ST_ASK) {
        return 0;
    }
    if (yes) {
        c->outcome = "yes";
        c->st = ST_COMMIT;
        return send_commit(c, to_server);
    }
    c->outcome = outcome != NULL ? outcome : "no";
    if (strcmp(c->outcome, "timeout") == 0) {
        snprintf(c->why, sizeof c->why, "nobody answered in time, so it was rolled back");
    } else if (strcmp(c->outcome, "no_terminal") == 0) {
        snprintf(c->why, sizeof c->why, "there is no terminal to ask on, so it was rolled back");
    } else {
        snprintf(c->why, sizeof c->why, "refused by the person asked");
    }
    c->st = ST_ROLLBACK;
    return send_rollback(c, to_server);
}

/* ---- showing it ---- */

static void clean(char *out, size_t cap, const char *in, size_t max_chars)
{
    size_t n = 0;

    for (; *in && n + 1 < cap; in++) {
        unsigned char ch = (unsigned char)*in;

        if (n >= max_chars) {
            if (n >= 3) {
                memcpy(out + n - 3, "...", 3);
            }
            break;
        }
        out[n++] = (ch >= 0x20 && ch < 0x7f) ? (char)ch : (ch == '\n' || ch == '\t' ? ' ' : '?');
    }
    out[n] = '\0';
}

size_t sl_confirm_render(const sl_confirm *c, char *out, size_t cap)
{
    size_t n = 0;
    char who[220];
    char sql[360];
    char rule[80];
    int widths[MAX_COLS] = {0};
    const char *verb = strncmp(c->tag, "UPDATE", 6) == 0 ? "changed" : "deleted";
    int shown = c->sample_n;

#define EMIT(...)                                                                                  \
    do {                                                                                           \
        if (n < cap) {                                                                             \
            int w_ = snprintf(out + n, cap - n, __VA_ARGS__);                                      \
            if (w_ > 0) {                                                                          \
                n += (size_t)w_ < cap - n ? (size_t)w_ : cap - n - 1;                              \
            }                                                                                      \
        }                                                                                          \
    } while (0)

    snprintf(who, sizeof who, "%s@%s", c->user[0] ? c->user : "?",
             c->database[0] ? c->database : "?");
    clean(who, sizeof who, who, 100);
    clean(rule, sizeof rule, c->rule, 60);
    clean(sql, sizeof sql, c->sql, 300);
    EMIT("\n%s   rule: %s\n  %s\n", who, rule, sql);
    EMIT("  %s %llu row%s (not committed yet)", verb, c->rows, c->rows == 1 ? "" : "s");
    if (c->ncols == 0 || shown == 0) {
        EMIT("%s\n",
             c->returning_added || c->client_returning ? "" : "; the rows are not available");
    } else {
        int cols = c->ncols < MAX_COLS ? c->ncols : MAX_COLS;

        EMIT("; the first %d:\n", shown);
        for (int j = 0; j < cols; j++) {
            char tmp[CELL_LEN];

            clean(tmp, sizeof tmp, c->names[j], 24);
            widths[j] = (int)strlen(tmp);
            for (int i = 0; i < shown; i++) {
                char cell[CELL_LEN];

                clean(cell, sizeof cell, c->is_null[i][j] ? "NULL" : c->cells[i][j], 24);
                if ((int)strlen(cell) > widths[j]) {
                    widths[j] = (int)strlen(cell);
                }
            }
        }
        EMIT("   ");
        for (int j = 0; j < cols; j++) {
            char tmp[CELL_LEN];

            clean(tmp, sizeof tmp, c->names[j], 24);
            EMIT(" %-*s", widths[j], tmp);
        }
        EMIT("\n");
        for (int i = 0; i < shown; i++) {
            EMIT("   ");
            for (int j = 0; j < cols; j++) {
                char cell[CELL_LEN];

                clean(cell, sizeof cell, c->is_null[i][j] ? "NULL" : c->cells[i][j], 24);
                EMIT(" %-*s", widths[j], cell);
            }
            EMIT("\n");
        }
        if (c->rows > (unsigned long long)shown) {
            EMIT("    ... and %llu more\n", c->rows - (unsigned long long)shown);
        }
    }
    if (!c->returning_added && !c->client_returning && c->tried_original && c->sql_ret != NULL) {
        EMIT("  (the rows could not be read: the role may lack the right to read them)\n");
    }
    EMIT("commit? [y/N] ");
#undef EMIT
    return n;
}

void sl_confirm_overflow(sl_confirm *c)
{
    c->overflow = 1;
    sl_buf_free(&c->client_rows);
}

unsigned long long sl_confirm_rows(const sl_confirm *c)
{
    return c->rows;
}

const char *sl_confirm_outcome(const sl_confirm *c)
{
    return c->outcome;
}

int sl_confirm_has_detail(const sl_confirm *c)
{
    return c->sample_n > 0;
}
