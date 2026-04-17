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
    ST_XRUN,     /* extended protocol: the Execute is running, its answers are being read */
    ST_XASK,     /* ... waiting for the person */
    ST_XREFUSE,  /* ... a message that fails was sent: its error is consumed, then it is over */
    ST_DONE
} state;

/* One look at the statistics of the transaction: the tables that had counted something. */
typedef struct {
    int n;
    char name[SL_CONFIRM_LOOK_MAX][56];
    unsigned long long count[SL_CONFIRM_LOOK_MAX][3]; /* inserted, updated, deleted */
} sl_side;

struct sl_confirm {
    state st;
    int ext; /* extended protocol */
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
    sl_mask *mask; /* hides values in what is shown and given back; not owned; may be NULL */
    /* kept for undo (journal.h) */
    int journal;
    char schema[64];
    char table[64];
    int (*journal_fn)(void *ctx, sl_journal_entry *e);
    void *journal_ctx;
    sl_buf jr_desc; /* the RowDescription, as the server sent it */
    sl_buf jr_data; /* each DataRow, preceded by its length */
    size_t jr_rows; /* ... how many */
    int jr_over;    /* more than can be held */
    int jr_bad;     /* rows that are not the old and the new row side by side, as they should be */
    sl_buf cc;      /* the CommandComplete message */
    sl_buf error;   /* the first ErrorResponse message */
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

    /* what else the transaction changed: name, inserted, updated, deleted */
    int limit; /* an action = "limit" rule: the answer is the number of rows, nobody is asked */
    int plain; /* TRUNCATE or DROP: no rows to count, always asked, no looks */
    char kind;
    int side_on; /* the statement is run between two looks at the statistics of the transaction */
    int side_active;  /* ... in the attempt being read */
    int seq;          /* command completions seen in this attempt */
    int saw_describe; /* extended: the RowDescription of sluice's own Describe has come */
    int closes;       /* extended: CloseComplete answers seen after the second look */
    int side_n;       /* the tables the statement changed beyond itself, to be shown */
    char side_name[SL_CONFIRM_SIDE_MAX][56];
    unsigned long long side_count[SL_CONFIRM_SIDE_MAX][3];
    sl_side *look[2]; /* what the statistics said before and after: allocated when needed */
    int side_retry;   /* the look failed: the statement is run again without it */

    sl_buf commit_error;
    const char *outcome;
    char why[256];
};

sl_confirm *sl_confirm_new(void)
{
    sl_confirm *c = calloc(1, sizeof *c);

    if (c != NULL) {
        sl_buf_init(&c->cc);
        sl_buf_init(&c->error);
        sl_buf_init(&c->client_rows);
        sl_buf_init(&c->commit_error);
        sl_buf_init(&c->jr_desc);
        sl_buf_init(&c->jr_data);
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
    sl_buf_free(&c->jr_desc);
    sl_buf_free(&c->jr_data);
    free(c->look[0]);
    free(c->look[1]);
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

/* ---- hiding values (mask.h) ---- */

/* The rows of the statement are shown to the person who is asked, and a client's own RETURNING is
 * given back to the client: both go through the mask of the user. A row that cannot be masked is
 * left out of both, and the rows can no longer be given back whole. */
static void mask_describe(sl_confirm *c, const uint8_t *p, size_t len)
{
    if (c->mask != NULL) {
        (void)sl_mask_describe(c->mask, p, len);
    }
}

/* The row to use for p: the same, or a masked copy in *m. -1 when it cannot be masked. */
static int mask_row(sl_confirm *c, const uint8_t *p, size_t len, sl_buf *m, const uint8_t **rp,
                    size_t *rl)
{
    int rc;

    *rp = p;
    *rl = len;
    if (c->mask == NULL) {
        return 0;
    }
    rc = sl_mask_row(c->mask, p, len, m);
    if (rc == SL_MASK_CHANGED) {
        *rp = sl_buf_data(m);
        *rl = sl_buf_len(m);
        return 0;
    }
    if (rc == SL_MASK_SAME) {
        return 0;
    }
    c->overflow = 1;
    sl_buf_free(&c->client_rows);
    return -1;
}

/* An error of the server, kept to be given to the client: the values it quotes are hidden. */
static int add_error(sl_confirm *c, sl_buf *to, const uint8_t *p, size_t len)
{
    sl_buf m;
    int rc;

    if (c->mask == NULL) {
        return add_message(to, 'E', p, len);
    }
    sl_buf_init(&m);
    rc = sl_mask_message(c->mask, p, len, &m);
    if (rc == SL_MASK_CHANGED) {
        rc = add_message(to, 'E', sl_buf_data(&m), sl_buf_len(&m));
    } else if (rc == SL_MASK_SAME) {
        rc = add_message(to, 'E', p, len);
    } else {
        rc = -1;
    }
    sl_buf_free(&m);
    return rc;
}

static int send_begin(sl_confirm *c, sl_buf *to_server)
{
    const char *text = c->returning_added ? c->sql_ret : c->sql;
    size_t len = c->returning_added ? c->sql_ret_len : c->sql_len;
    const char *start = c->in_tx ? "SAVEPOINT " SAVEPOINT "; " : "BEGIN; ";

    c->side_active = c->side_on;
    if (!c->side_active) {
        return add_query(to_server, start, text, len);
    }
    /* BEGIN; <look>; <statement>; <look>: one message, so that nothing is reported in between */
    {
        sl_buf q;
        uint8_t head[5];
        int rc;

        sl_buf_init(&q);
        rc = sl_buf_append(&q, start, strlen(start)) != 0 ||
                     sl_buf_append(&q, SL_CONFIRM_SIDE_SQL, strlen(SL_CONFIRM_SIDE_SQL)) != 0 ||
                     sl_buf_append(&q, "; ", 2) != 0 || sl_buf_append(&q, text, len) != 0 ||
                     sl_buf_append(&q, "; ", 2) != 0 ||
                     sl_buf_append(&q, SL_CONFIRM_SIDE_SQL, strlen(SL_CONFIRM_SIDE_SQL)) != 0 ||
                     sl_buf_append(&q, "", 1) != 0
                 ? -1
                 : 0;
        head[0] = 'Q';
        sl_pg_put_be32(head + 1, (uint32_t)(4 + sl_buf_len(&q)));
        if (rc == 0) {
            rc = sl_buf_append(to_server, head, 5) != 0 ||
                         sl_buf_append(to_server, sl_buf_data(&q), sl_buf_len(&q)) != 0
                     ? -1
                     : 0;
        }
        sl_buf_free(&q);
        return rc;
    }
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
    c->journal = a->journal;
    c->journal_fn = a->journal_fn;
    c->journal_ctx = a->journal_ctx;
    snprintf(c->schema, sizeof c->schema, "%s", a->schema != NULL ? a->schema : "");
    snprintf(c->table, sizeof c->table, "%s", a->table != NULL ? a->table : "");
    c->mask = a->mask;
    if (c->mask != NULL) {
        sl_mask_forget(c->mask);
    }
    c->over_rows = a->over_rows;
    c->kind = (char)a->kind;
    c->plain = a->kind == 'T' || a->kind == 'R';
    c->limit = a->limit;
    c->side_on =
        a->side_effects && !c->plain && !c->limit; /* TRUNCATE leaves no counters to read */
    if (c->side_on) {
        c->look[0] = calloc(1, sizeof *c->look[0]);
        c->look[1] = calloc(1, sizeof *c->look[1]);
        if (c->look[0] == NULL || c->look[1] == NULL) {
            return -1;
        }
    }
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
    if (a->extended) {
        c->ext = 1;
        c->side_active = c->side_on;
        c->st = ST_XRUN;
        return 0;
    }
    c->st = ST_RUN;
    return send_begin(c, to_server);
}

/* ---- reading the answer ---- */

static void forget_attempt(sl_confirm *c)
{
    c->prelude_done = 0;
    c->saw_error = 0;
    c->overflow = 0;
    c->seq = 0;
    c->side_n = 0;
    for (int i = 0; i < 2; i++) {
        if (c->look[i] != NULL) {
            c->look[i]->n = 0;
        }
    }
    sl_buf_free(&c->cc);
    sl_buf_free(&c->error);
    sl_buf_free(&c->client_rows);
    sl_buf_free(&c->jr_desc);
    sl_buf_free(&c->jr_data);
    c->jr_rows = 0;
    c->jr_over = 0;
    c->jr_bad = 0;
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

/* Messages that are none of the exchange's: notices, notifications, parameter changes, and the
 * ParseComplete, BindComplete and CloseComplete of messages the client sent before the Execute
 * (which come first, as the server answers in order). They go to the client as they are. */
static int is_async(uint8_t type)
{
    return type == 'N' || type == 'A' || type == 'S' || type == '1' || type == '2' || type == '3';
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
    char text[768]; /* the longest rule name, reason and message fit */
    sl_buf err;
    int rc;

    snprintf(text, sizeof text, "sluice: %s (rule %s): %s.%s%s Nothing was changed.",
             c->limit ? "refused" : "not confirmed", c->rule, c->why[0] ? c->why : "refused",
             c->message[0] ? " " : "", c->message);
    sl_buf_init(&err);
    if (sl_pg_append_error(&err, "ERROR", "42501", text) != 0) {
        sl_buf_free(&err);
        return -1;
    }
    rc = deliver(c, to_client, status, 1, &err);
    sl_buf_free(&err);
    return rc;
}

/* ---- what else the statement changed ---- */

#define SIDE_STMT "sluice_side"
#define SIDE_PORTAL2 "sluice_side2"

static int add_ext(sl_buf *out, uint8_t type, const void *a, size_t an, const void *b, size_t bn)
{
    uint8_t head[5];

    head[0] = type;
    sl_pg_put_be32(head + 1, (uint32_t)(4 + an + bn));
    return sl_buf_append(out, head, 5) != 0 || (an > 0 && sl_buf_append(out, a, an) != 0) ||
                   (bn > 0 && sl_buf_append(out, b, bn) != 0)
               ? -1
               : 0;
}

/* Bind of `portal` to the statement of the look, without parameters, in text format: names with
 * their NUL, then three zero counts (parameter formats, parameters, result formats). */
static int add_bind(sl_buf *out, const char *portal, size_t portal_len)
{
    static const uint8_t zero3[6] = {0, 0, 0, 0, 0, 0};
    sl_buf body;
    int rc;

    sl_buf_init(&body);
    rc = sl_buf_append(&body, portal, portal_len) != 0 ||
                 sl_buf_append(&body, SIDE_STMT, sizeof SIDE_STMT) != 0 ||
                 sl_buf_append(&body, zero3, 6) != 0 ||
                 add_ext(out, 'B', sl_buf_data(&body), sl_buf_len(&body), NULL, 0) != 0
             ? -1
             : 0;
    sl_buf_free(&body);
    return rc;
}

int sl_confirm_ext_wrap(const sl_confirm *c, const uint8_t *portal, size_t portal_len,
                        const uint8_t *execute, size_t execute_len, sl_buf *out)
{
    static const uint8_t zero2[2] = {0, 0};
    static const uint8_t zero4[4] = {0, 0, 0, 0};
    static const char sql[] = SL_CONFIRM_SIDE_SQL;
    int rc = 0;
    sl_buf body;

    /* Describe(portal): the names of the columns, which the client may not have asked for */
    sl_buf_init(&body);
    rc |= sl_buf_append(&body, "P", 1) != 0 || sl_buf_append(&body, portal, portal_len) != 0 ||
          sl_buf_append(&body, "", 1) != 0;
    rc |= rc == 0 ? add_ext(out, 'D', sl_buf_data(&body), sl_buf_len(&body), NULL, 0) : -1;
    sl_buf_free(&body);
    if (c->side_on) { /* the first look, under names the client will not use */
        sl_buf_init(&body);
        rc |= sl_buf_append(&body, SIDE_STMT, sizeof SIDE_STMT) != 0 ||
              sl_buf_append(&body, sql, sizeof sql) != 0 || sl_buf_append(&body, zero2, 2) != 0;
        rc |= rc == 0 ? add_ext(out, 'P', sl_buf_data(&body), sl_buf_len(&body), NULL, 0) : -1;
        sl_buf_free(&body);
        rc |= add_bind(out, SIDE_STMT, sizeof SIDE_STMT) != 0;
        rc |= add_ext(out, 'E', SIDE_STMT, sizeof SIDE_STMT, zero4, 4) != 0;
    }
    rc |= add_ext(out, 'E', execute, execute_len, NULL, 0) != 0; /* the client's own */
    if (c->side_on) { /* the second look, then everything of ours is closed */
        rc |= add_bind(out, SIDE_PORTAL2, sizeof SIDE_PORTAL2) != 0;
        rc |= add_ext(out, 'E', SIDE_PORTAL2, sizeof SIDE_PORTAL2, zero4, 4) != 0;
        rc |= add_ext(out, 'C', "S", 1, SIDE_STMT, sizeof SIDE_STMT) != 0;
        rc |= add_ext(out, 'C', "P", 1, SIDE_STMT, sizeof SIDE_STMT) != 0;
        rc |= add_ext(out, 'C', "P", 1, SIDE_PORTAL2, sizeof SIDE_PORTAL2) != 0;
    }
    rc |= add_ext(out, 'H', NULL, 0, NULL, 0) != 0; /* the answers come now, not at the Sync */
    (void)portal;
    return rc != 0 ? -1 : 0;
}

/* One row of a look: table, inserted, updated, deleted, as text. */
static void read_look_row(sl_confirm *c, int which, const uint8_t *p, size_t len)
{
    sl_side *l = c->look[which];
    size_t pos = 2;
    char cell[64];

    if (l == NULL || l->n >= SL_CONFIRM_LOOK_MAX || len < 2 || be16(p) != 4) {
        return;
    }
    for (int col = 0; col < 4; col++) {
        int32_t n;

        if (pos + 4 > len) {
            return;
        }
        n = (int32_t)sl_pg_get_be32(p + pos);
        pos += 4;
        if (n < 0 || pos + (size_t)n > len) {
            return;
        }
        copy_text(cell, sizeof cell, (const char *)p + pos, (size_t)n);
        pos += (size_t)n;
        if (col == 0) {
            copy_text(l->name[l->n], sizeof l->name[0], cell, strlen(cell));
        } else {
            l->count[l->n][col - 1] = strtoull(cell, NULL, 10);
        }
    }
    l->n++;
}

/* The difference between the two looks, the biggest changes first. */
/* Is `name` (schema.table, as the statistics name it) the table the statement writes to? The
 * statement's own spelling is compared; with no schema written, the table name alone. */
static int own_table(const sl_confirm *c, const char *name)
{
    const char *dot = strchr(name, '.');
    size_t sl = c->schema[0] != '\0' ? strlen(c->schema) : 0;

    if (c->table[0] == '\0' || dot == NULL) {
        return 0;
    }
    if (sl > 0 && (size_t)(dot - name) != sl) {
        return 0;
    }
    if (sl > 0 && strncmp(name, c->schema, sl) != 0) {
        return 0;
    }
    return strcmp(dot + 1, c->table) == 0;
}

static void compute_side(sl_confirm *c)
{
    const sl_side *before = c->look[0];
    const sl_side *after = c->look[1];

    c->side_n = 0;
    if (!c->side_active || before == NULL || after == NULL) {
        return;
    }
    for (int i = 0; i < after->n; i++) {
        unsigned long long d[3];
        int pos;

        for (int k = 0; k < 3; k++) {
            d[k] = after->count[i][k];
        }
        for (int j = 0; j < before->n; j++) {
            if (strcmp(before->name[j], after->name[i]) == 0) {
                for (int k = 0; k < 3; k++) {
                    d[k] = d[k] > before->count[j][k] ? d[k] - before->count[j][k] : 0;
                }
                break;
            }
        }
        if (d[0] + d[1] + d[2] == 0) {
            continue;
        }
        /* the place in the list: deleted, then updated, then inserted, then name */
        for (pos = 0; pos < c->side_n; pos++) {
            const unsigned long long *o = c->side_count[pos];

            if (d[2] > o[2] || (d[2] == o[2] && (d[1] > o[1] || (d[1] == o[1] && d[0] > o[0])))) {
                break;
            }
        }
        if (pos >= SL_CONFIRM_SIDE_MAX) {
            continue;
        }
        if (c->side_n < SL_CONFIRM_SIDE_MAX) {
            c->side_n++;
        }
        for (int m = c->side_n - 1; m > pos; m--) {
            memcpy(c->side_name[m], c->side_name[m - 1], sizeof c->side_name[0]);
            memcpy(c->side_count[m], c->side_count[m - 1], sizeof c->side_count[0]);
        }
        copy_text(c->side_name[pos], sizeof c->side_name[0], after->name[i],
                  strlen(after->name[i]));
        for (int k = 0; k < 3; k++) {
            c->side_count[pos][k] = d[k];
        }
    }
}

/* ---- keeping the rows of a DELETE for undo (journal.h) ---- */

/* Did sluice add the RETURNING * that the rows come from? (In the extended protocol it was added to
 * the Parse, long before: the Execute is only read.) */
static int rows_are_ours(const sl_confirm *c)
{
    return c->returning_added || (c->ext && !c->client_returning);
}

static int keeping_rows(const sl_confirm *c)
{
    return c->journal != SL_JOURNAL_OFF && c->journal_fn != NULL &&
           (c->kind == 'D' || c->kind == 'U') && rows_are_ours(c);
}

/* The rows of an UPDATE that is kept for undo come as the old row and the new row side by side
 * (RETURNING OLD.*, NEW.*). The journal keeps them as they are; what is shown to the person and
 * hidden by the mask is the new row, which is what an UPDATE of a statement without that RETURNING
 * would have given. These cut the second half out of a RowDescription and of a DataRow. */
static int both_rows(const sl_confirm *c)
{
    return c->kind == 'U' && keeping_rows(c);
}

static int half_desc(const uint8_t *p, size_t len, sl_buf *out)
{
    size_t pos = 2, from = 0;
    unsigned n, half;
    uint8_t h[2];

    if (len < 2) {
        return -1;
    }
    n = be16(p);
    if (n == 0 || (n & 1) != 0) {
        return -1;
    }
    half = n / 2;
    for (unsigned i = 0; i < n; i++) {
        const uint8_t *nul = pos < len ? memchr(p + pos, 0, len - pos) : NULL;

        if (i == half) {
            from = pos;
        }
        if (nul == NULL || len - (size_t)(nul - p) - 1 < 18) {
            return -1;
        }
        pos = (size_t)(nul - p) + 1 + 18;
    }
    if (pos != len) {
        return -1;
    }
    h[0] = (uint8_t)(half >> 8);
    h[1] = (uint8_t)half;
    return sl_buf_append(out, h, 2) != 0 || sl_buf_append(out, p + from, len - from) != 0 ? -1 : 0;
}

static int half_row(const uint8_t *p, size_t len, sl_buf *out)
{
    size_t pos = 2, from = 0;
    unsigned n, half;
    uint8_t h[2];

    if (len < 2) {
        return -1;
    }
    n = be16(p);
    if (n == 0 || (n & 1) != 0) {
        return -1;
    }
    half = n / 2;
    for (unsigned i = 0; i < n; i++) {
        int32_t fl;

        if (i == half) {
            from = pos;
        }
        if (len - pos < 4) {
            return -1;
        }
        fl = (int32_t)sl_pg_get_be32(p + pos);
        pos += 4;
        if (fl >= 0) {
            if ((size_t)fl > len - pos) {
                return -1;
            }
            pos += (size_t)fl;
        } else if (fl != -1) {
            return -1;
        }
    }
    if (pos != len) {
        return -1;
    }
    h[0] = (uint8_t)(half >> 8);
    h[1] = (uint8_t)half;
    return sl_buf_append(out, h, 2) != 0 || sl_buf_append(out, p + from, len - from) != 0 ? -1 : 0;
}

/* What the person and the mask see of a RowDescription or a DataRow: p itself, or its new half. */
static void view(sl_confirm *c, int row, const uint8_t *p, size_t len, sl_buf *h,
                 const uint8_t **vp, size_t *vl)
{
    *vp = p;
    *vl = len;
    if (!both_rows(c)) {
        return;
    }
    if ((row ? half_row(p, len, h) : half_desc(p, len, h)) == 0) {
        *vp = sl_buf_data(h);
        *vl = sl_buf_len(h);
    } else {
        c->jr_bad = 1;
    }
}

static void journal_desc(sl_confirm *c, const uint8_t *p, size_t len)
{
    if (keeping_rows(c) && sl_buf_len(&c->jr_desc) == 0) {
        if (sl_buf_append(&c->jr_desc, p, len) != 0) {
            c->jr_over = 1;
        }
    }
}

static void journal_row(sl_confirm *c, const uint8_t *p, size_t len)
{
    uint8_t h[4];

    if (!keeping_rows(c) || c->jr_over) {
        return;
    }
    if (c->jr_rows >= SL_CONFIRM_JOURNAL_ROWS ||
        sl_buf_len(&c->jr_data) + len + 4 > SL_CONFIRM_JOURNAL_BYTES) {
        c->jr_over = 1;
        sl_buf_free(&c->jr_data);
        return;
    }
    sl_pg_put_be32(h, (uint32_t)len);
    if (sl_buf_append(&c->jr_data, h, 4) != 0 || sl_buf_append(&c->jr_data, p, len) != 0) {
        c->jr_over = 1;
        sl_buf_free(&c->jr_data);
        return;
    }
    c->jr_rows++;
}

/* Just before the COMMIT of a DELETE that a rule keeps for undo: its rows go to the journal. 0: go
 * on and commit. -1: do not apply it (the reason is in c->why, the outcome is "journal"): only with
 * SL_JOURNAL_REQUIRED, which is a promise that what is deleted can be put back. */
static int journal_gate(sl_confirm *c)
{
    sl_journal_entry e;
    sl_journal_side side[SL_CONFIRM_SIDE_MAX];
    const char *incomplete = NULL;
    int rc;

    if (c->journal == SL_JOURNAL_OFF || c->journal_fn == NULL) {
        return 0;
    }
    if (c->kind != 'D' && c->kind != 'U') {
        if (c->journal == SL_JOURNAL_REQUIRED) {
            snprintf(c->why, sizeof c->why,
                     "only the rows of a DELETE or an UPDATE can be recorded for undo");
            c->outcome = "journal";
            return -1;
        }
        return 0;
    }
    compute_side(c);
    memset(&e, 0, sizeof e);
    if (!rows_are_ours(c)) {
        incomplete = c->client_returning
                         ? "the statement has a RETURNING of its own: the columns it lists may not "
                           "be the whole row"
                     : c->kind == 'U'
                         ? "the server did not give the old rows back, so they were not kept "
                           "(RETURNING OLD needs PostgreSQL 18)"
                         : "the server did not give the rows back, so they were not kept";
    } else if (c->jr_bad) {
        incomplete = "the server gave back rows that are not the old and the new row";
    } else if (c->jr_over) {
        incomplete = "more rows than are kept for undo";
    } else if (c->table[0] == '\0') {
        incomplete = "the table the statement changes could not be named";
    } else if (c->jr_rows != c->rows) {
        incomplete = "not every row was kept";
    }
    e.user = c->user;
    e.user_len = strlen(c->user);
    e.database = c->database;
    e.database_len = strlen(c->database);
    e.rule = c->rule;
    e.protocol = c->ext ? "extended" : "simple";
    e.update = c->kind == 'U';
    e.sql = c->sql;
    e.sql_len = c->sql_len;
    e.schema = c->schema;
    e.table = c->table;
    e.tag = c->tag;
    e.rows = c->rows;
    e.incomplete = incomplete;
    if (incomplete == NULL || c->jr_rows > 0) {
        e.desc = sl_buf_data(&c->jr_desc);
        e.desc_len = sl_buf_len(&c->jr_desc);
        e.data = sl_buf_data(&c->jr_data);
        e.data_len = sl_buf_len(&c->jr_data);
        e.nrows = c->jr_rows;
        if (e.desc == NULL || e.data == NULL) {
            e.desc = e.data = NULL;
            e.nrows = 0;
        }
    }
    e.side_known = c->side_active && c->look[0] != NULL && c->look[1] != NULL;
    for (int i = 0; i < c->side_n; i++) {
        unsigned long long *own;

        side[e.nside].table = c->side_name[i];
        side[e.nside].inserted = c->side_count[i][0];
        side[e.nside].updated = c->side_count[i][1];
        side[e.nside].deleted = c->side_count[i][2];
        if (own_table(c, c->side_name[i])) {
            /* the rows of the statement itself are in the entry: only what is more is "else" */
            own = c->kind == 'D' ? &side[e.nside].deleted : &side[e.nside].updated;
            *own = *own > c->rows ? *own - c->rows : 0;
            if (side[e.nside].inserted + side[e.nside].updated + side[e.nside].deleted == 0) {
                continue;
            }
        }
        e.nside++;
    }
    e.side = side;
    if (incomplete == NULL && c->rows == 0) {
        return 0; /* it changed no row: there is nothing to put back, and nothing to write */
    }
    if (c->journal == SL_JOURNAL_REQUIRED && incomplete != NULL) {
        /* nothing is written: an entry for a DELETE that is not applied would put back rows that
         * were never gone */
        snprintf(c->why, sizeof c->why,
                 "the rows cannot all be recorded for undo, which this rule requires (%s)",
                 incomplete);
        c->outcome = "journal";
        return -1;
    }
    rc = c->journal_fn(c->journal_ctx, &e);
    if (c->journal == SL_JOURNAL_REQUIRED && rc != 0) {
        snprintf(c->why, sizeof c->why,
                 "the rows could not be recorded for undo, which this rule requires");
        c->outcome = "journal";
        return -1;
    }
    return 0;
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
    if (c->limit && c->rows > c->over_rows) {
        snprintf(c->why, sizeof c->why, "it touched %llu rows, more than the limit of %llu",
                 c->rows, c->over_rows);
        c->outcome = "limit";
        c->st = ST_ROLLBACK;
        return send_rollback(c, to_server);
    }
    if (!c->plain && c->rows <= c->over_rows) {
        if (journal_gate(c) != 0) {
            c->st = ST_ROLLBACK;
            return send_rollback(c, to_server);
        }
        c->outcome = "auto";
        c->st = ST_COMMIT;
        return send_commit(c, to_server);
    }
    compute_side(c);
    c->st = ST_ASK;
    step->ask = 1;
    return 0;
}

/* With the looks, a simple exchange is: BEGIN, look, statement, look. `seq` counts the completions
 * seen, so the rows and tag that arrive belong to the phase it says: 1 the first look, 2 the
 * statement, 3 the second look. */
static int on_run(sl_confirm *c, uint8_t type, const uint8_t *p, size_t len, sl_buf *to_server,
                  sl_confirm_step *step)
{
    int statement = !c->side_active || c->seq == 2;

    switch (type) {
    case 'C':
        c->seq++;
        if (c->seq == 1) {
            c->prelude_done = 1; /* BEGIN or SAVEPOINT */
            return 0;
        }
        if (c->side_active && (c->seq == 2 || c->seq == 4)) {
            return 0; /* a look is over */
        }
        read_tag(c, p, len);
        if (add_message(&c->cc, 'C', p, len) != 0) {
            return -1;
        }
        return c->client_returning ? add_message(&c->client_rows, 'C', p, len) : 0;
    case 'T':
        if (!statement) {
            return 0;
        }
        journal_desc(c, p, len);
        {
            sl_buf h;
            const uint8_t *vp;
            size_t vl;
            int rc;

            sl_buf_init(&h);
            view(c, 0, p, len, &h, &vp, &vl);
            read_names(c, vp, vl);
            mask_describe(c, vp, vl);
            rc = c->client_returning ? add_message(&c->client_rows, 'T', p, len) : 0;
            sl_buf_free(&h);
            return rc;
        }
    case 'D': {
        sl_buf m, hv;
        const uint8_t *rp, *vp;
        size_t rl, vl;
        int rc = 0;

        if (!statement) {
            read_look_row(c, c->seq == 1 ? 0 : 1, p, len);
            return 0;
        }
        journal_row(c, p, len); /* as the server gave it: what is kept for undo is not hidden */
        sl_buf_init(&m);
        sl_buf_init(&hv);
        view(c, 1, p, len, &hv, &vp, &vl);
        if (mask_row(c, vp, vl, &m, &rp, &rl) == 0) {
            read_row(c, rp, rl);
            if (c->client_returning && !c->overflow) {
                if (sl_buf_len(&c->client_rows) + rl + 5 > SL_CONFIRM_HELD_MAX) {
                    c->overflow = 1;
                    sl_buf_free(&c->client_rows);
                } else {
                    rc = add_message(&c->client_rows, 'D', rp, rl);
                }
            }
        }
        sl_buf_free(&m);
        sl_buf_free(&hv);
        return rc;
    }
    case 'E':
        if (!c->saw_error) {
            c->saw_error = 1;
            return add_error(c, &c->error, p, len);
        }
        return 0;
    case 'Z': {
        if (!c->saw_error) {
            return statement_done(c, to_server, step);
        }
        if (c->side_active && (c->seq < 2 || c->seq >= 3)) {
            /* it was a look that failed (a server without those statistics), before the statement
             * or after it: undo, and run the statement again without looking */
            c->side_on = 0;
            c->side_retry = 1;
            c->st = ST_UNDO;
            return send_rollback(c, to_server);
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

/* ---- the extended protocol ---- */

/* A message that cannot succeed, for the server to fail on: it aborts the cycle (and the
 * transaction), which is how a statement that was run is undone. */
static int add_failing_parse(sl_buf *out)
{
    static const char sql[] = "select 'sluice: not confirmed'::int";
    uint8_t head[5];
    static const uint8_t tail[2] = {0, 0}; /* no parameter types */

    head[0] = 'P';
    sl_pg_put_be32(head + 1, (uint32_t)(4 + 1 + sizeof sql + sizeof tail)); /* "" + sql + NUL + n */
    return sl_buf_append(out, head, 5) != 0 || sl_buf_append(out, "", 1) != 0 ||
                   sl_buf_append(out, sql, sizeof sql) != 0 ||
                   sl_buf_append(out, tail, sizeof tail) != 0
               ? -1
               : 0;
}

/* What the client is owed for its Execute. */
static int deliver_body(sl_confirm *c, sl_buf *to_client, sl_confirm_step *step)
{
    const sl_buf *body = c->client_returning ? &c->client_rows : &c->cc;

    if (sl_buf_len(body) > 0 &&
        sl_buf_append(to_client, sl_buf_data(body), sl_buf_len(body)) != 0) {
        return -1;
    }
    c->st = ST_DONE;
    step->done = 1;
    return 0;
}

/* Not confirmed: our error goes to the client now, and the message that fails is sent so that the
 * server undoes what the statement did. Its own error is consumed when it comes. */
static int refuse(sl_confirm *c, sl_buf *to_server, sl_buf *to_client)
{
    char text[768];
    sl_buf err;
    int rc;

    snprintf(text, sizeof text, "sluice: %s (rule %s): %s.%s%s Nothing was changed.",
             c->limit ? "refused" : "not confirmed", c->rule, c->why[0] ? c->why : "refused",
             c->message[0] ? " " : "", c->message);
    sl_buf_init(&err);
    rc = sl_pg_append_error(&err, "ERROR", "42501", text) != 0 ||
                 sl_buf_append(to_client, sl_buf_data(&err), sl_buf_len(&err)) != 0 ||
                 add_failing_parse(to_server) != 0
             ? -1
             : 0;
    sl_buf_free(&err);
    c->st = ST_XREFUSE;
    return rc;
}

/* The statement has been answered (and, with the looks, so have they): above the threshold the
 * person is asked, below it the client simply gets its answer. */
static int xdecide(sl_confirm *c, sl_buf *to_server, sl_buf *to_client, sl_confirm_step *step)
{
    if (c->overflow) {
        snprintf(c->why, sizeof c->why, "the result is too large to confirm");
        c->outcome = "too_large";
        return refuse(c, to_server, to_client);
    }
    if (c->limit && c->rows > c->over_rows) {
        snprintf(c->why, sizeof c->why, "it touched %llu rows, more than the limit of %llu",
                 c->rows, c->over_rows);
        c->outcome = "limit";
        return refuse(c, to_server, to_client);
    }
    if (!c->plain && c->rows <= c->over_rows) {
        if (journal_gate(c) != 0) {
            return refuse(c, to_server, to_client);
        }
        c->outcome = "auto";
        return deliver_body(c, to_client, step);
    }
    compute_side(c);
    c->st = ST_XASK;
    step->ask = 1;
    return 0;
}

/* Our own error, when a look fails: the server now ignores everything up to the Sync, which will
 * roll the cycle back, so the client is told, and nothing is committed. */
static void clean(char *out, size_t cap, const char *in, size_t max_chars);

/* The text of the M field of an ErrorResponse. */
static void error_text(const uint8_t *p, size_t len, char *out, size_t cap)
{
    size_t pos = 0;

    out[0] = '\0';
    while (pos < len && p[pos] != 0) {
        uint8_t tag = p[pos++];
        const uint8_t *end = memchr(p + pos, 0, len - pos);
        size_t n = end != NULL ? (size_t)(end - (p + pos)) : len - pos;

        if (tag == 'M') {
            copy_text(out, cap, (const char *)p + pos, n);
            return;
        }
        pos += n + 1;
    }
}

static int look_failed(sl_confirm *c, const uint8_t *server_error, size_t server_error_len,
                       sl_buf *to_client, sl_confirm_step *step)
{
    char text[640];
    char said[200];
    sl_buf err;
    int rc;

    error_text(server_error, server_error_len, said, sizeof said);
    clean(said, sizeof said, said, 150);
    snprintf(text, sizeof text,
             "sluice: could not look at what the statement changes besides its own rows (rule %s), "
             "so nothing was committed. The server said: %s. If this server cannot answer, set "
             "side_effects = \"off\" in that rule.",
             c->rule, said);
    sl_buf_init(&err);
    rc = sl_pg_append_error(&err, "ERROR", "58000", text) != 0 ||
                 sl_buf_append(to_client, sl_buf_data(&err), sl_buf_len(&err)) != 0
             ? -1
             : 0;
    sl_buf_free(&err);
    c->outcome = "error";
    c->st = ST_DONE;
    step->done = 1;
    return rc;
}

/* The answers of the Describe, the first look, the Execute and the second look that sluice sent,
 * in that order. `seq` counts the terminal messages: with the looks 0 is the first look, 1 the
 * statement, 2 the second look; without them 0 is the statement. */
static int on_xrun(sl_confirm *c, uint8_t type, const uint8_t *p, size_t len, sl_buf *to_server,
                   sl_buf *to_client, sl_confirm_step *step)
{
    int statement = !c->side_active || c->seq == 1;

    switch (type) {
    case 'T':
        if (!c->saw_describe) {
            c->saw_describe = 1;
            sl_buf h;
            const uint8_t *vp;
            size_t vl;

            journal_desc(c, p, len);
            sl_buf_init(&h);
            view(c, 0, p, len, &h, &vp, &vl);
            read_names(c, vp, vl); /* ours, not the client's: never given to it */
            mask_describe(c, vp, vl);
            sl_buf_free(&h);
        }
        return 0;
    case 'D': {
        sl_buf m, hv;
        const uint8_t *rp, *vp;
        size_t rl, vl;
        int rc = 0;

        if (!statement) {
            read_look_row(c, c->seq == 0 ? 0 : 1, p, len);
            return 0;
        }
        journal_row(c, p, len); /* as the server gave it: what is kept for undo is not hidden */
        sl_buf_init(&m);
        sl_buf_init(&hv);
        view(c, 1, p, len, &hv, &vp, &vl);
        if (mask_row(c, vp, vl, &m, &rp, &rl) == 0) {
            read_row(c, rp, rl);
            if (c->client_returning && !c->overflow) {
                if (sl_buf_len(&c->client_rows) + rl + 5 > SL_CONFIRM_HELD_MAX) {
                    c->overflow = 1;
                    sl_buf_free(&c->client_rows);
                } else {
                    rc = add_message(&c->client_rows, 'D', rp, rl);
                }
            }
        }
        sl_buf_free(&m);
        sl_buf_free(&hv);
        return rc;
    }
    case 'C':
    case 'I':
    case 's':
        c->seq++;
        if (c->side_active && c->seq == 1) {
            return 0; /* the first look is over */
        }
        if (c->side_active && c->seq == 3) {
            c->closes = 0; /* the second look is over: the three Close answers are to come */
            return 0;
        }
        if (type == 'C') {
            read_tag(c, p, len);
        }
        if (add_message(&c->cc, type, p, len) != 0) {
            return -1;
        }
        if (c->client_returning && !c->overflow &&
            add_message(&c->client_rows, type, p, len) != 0) {
            return -1;
        }
        return c->side_active ? 0 : xdecide(c, to_server, to_client, step);
    case '3':
        /* CloseComplete: the three that follow the looks are ours (they come last) */
        if (c->side_active && c->seq == 3 && ++c->closes == 3) {
            return xdecide(c, to_server, to_client, step);
        }
        return 0;
    case 'E':
        if (c->side_active && (c->seq == 0 || c->seq >= 2)) {
            return look_failed(c, p, len, to_client,
                               step); /* before the statement ran, or after it */
        }
        c->outcome = "error"; /* the statement failed: the error is the client's own */
        c->st = ST_DONE;
        step->done = 1;
        return add_message(to_client, 'E', p, len);
    default:
        return 0;
    }
}

int sl_confirm_server(sl_confirm *c, uint8_t type, const uint8_t *payload, size_t len,
                      sl_buf *to_server, sl_buf *to_client, sl_confirm_step *step)
{
    /* once our own Describe has been answered, the ParseComplete, BindComplete and CloseComplete
     * that follow are those of messages of ours (the client's own came before it) */
    int ours = c->ext && c->saw_describe && (type == '1' || type == '2' || type == '3');
    int keep = is_async(type) && !ours ? SL_SRV_KEEP : SL_SRV_DROP;
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
            if (!c->side_retry) {
                c->returning_added = 0;
                c->tried_original = 1;
            }
            c->side_retry = 0;
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
            rc = add_error(c, &c->commit_error, payload, len);
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
    case ST_XRUN:
        rc = on_xrun(c, type, payload, len, to_server, to_client, step);
        break;
    case ST_XASK:
        /* the server ended it by itself (a statement timeout, a terminated session) */
        if (type == 'E') {
            c->outcome = "error";
            rc = add_message(to_client, 'E', payload, len);
            c->st = ST_DONE;
            step->done = 1;
        }
        break;
    case ST_XREFUSE:
        if (type == 'E') { /* the error of the message that fails: ours was given already */
            c->st = ST_DONE;
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
        if (journal_gate(c) != 0) {
            c->st = ST_ROLLBACK;
            return send_rollback(c, to_server);
        }
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

int sl_confirm_answer_ext(sl_confirm *c, int yes, const char *outcome, sl_buf *to_server,
                          sl_buf *to_client, sl_confirm_step *step)
{
    step->ask = 0;
    step->done = 0;
    if (c->st != ST_XASK) {
        return 0;
    }
    if (yes) {
        if (journal_gate(c) != 0) {
            return refuse(c, to_server, to_client);
        }
        c->outcome = "yes";
        return deliver_body(c, to_client, step);
    }
    c->outcome = outcome != NULL ? outcome : "no";
    if (strcmp(c->outcome, "timeout") == 0) {
        snprintf(c->why, sizeof c->why, "nobody answered in time, so it was rolled back");
    } else if (strcmp(c->outcome, "no_terminal") == 0) {
        snprintf(c->why, sizeof c->why, "there is no terminal to ask on, so it was rolled back");
    } else {
        snprintf(c->why, sizeof c->why, "refused by the person asked");
    }
    return refuse(c, to_server, to_client);
}

int sl_confirm_is_extended(const sl_confirm *c)
{
    return c->ext;
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

static size_t render(const sl_confirm *c, char *out, size_t cap, int with_prompt);

size_t sl_confirm_render(const sl_confirm *c, char *out, size_t cap)
{
    return render(c, out, cap, 1);
}

size_t sl_confirm_render_body(const sl_confirm *c, char *out, size_t cap)
{
    return render(c, out, cap, 0);
}

size_t sl_confirm_render_brief(const sl_confirm *c, char *out, size_t cap, int rows)
{
    size_t n = 0;
    int shown = c->sample_n < rows ? c->sample_n : rows;
    int cols = c->ncols < MAX_COLS ? c->ncols : MAX_COLS;
    int widths[MAX_COLS] = {0};
    const char *verb = strncmp(c->tag, "DELETE", 6) == 0 ? "deleted" : "changed";

#define EMIT(...)                                                                                  \
    do {                                                                                           \
        if (n < cap) {                                                                             \
            int w_ = snprintf(out + n, cap - n, __VA_ARGS__);                                      \
            if (w_ > 0) {                                                                          \
                n += (size_t)w_ < cap - n ? (size_t)w_ : cap - n - 1;                              \
            }                                                                                      \
        }                                                                                          \
    } while (0)

    out[0] = '\0';
    if (c->plain) {
        char sql[360];

        clean(sql, sizeof sql, c->sql, 300);
        EMIT("%s: %s\nnothing to count or show, and not final yet\n", c->tag[0] ? c->tag : "done",
             sql);
        return n;
    }
    EMIT("%s %llu row%s", verb, c->rows, c->rows == 1 ? "" : "s");
    if (shown == 0 || cols == 0) {
        EMIT("%s\n",
             c->returning_added || c->client_returning ? "" : " (the rows are not available)");
    } else {
        EMIT(shown < (int)c->rows ? ", the first %d:\n" : ":\n", shown);
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
        for (int i = -1; i < shown; i++) { /* -1: the names of the columns */
            char line[512];
            size_t l = 0;

            for (int j = 0; j < cols; j++) {
                char cell[CELL_LEN];
                int w;

                clean(cell, sizeof cell,
                      i < 0 ? c->names[j] : (c->is_null[i][j] ? "NULL" : c->cells[i][j]), 24);
                w = snprintf(line + l, sizeof line - l, "%s%-*s", j ? "  " : "  ", widths[j], cell);
                if (w > 0) {
                    l += (size_t)w < sizeof line - l ? (size_t)w : sizeof line - l - 1;
                }
            }
            while (l > 0 && line[l - 1] == ' ') { /* no trailing blanks */
                l--;
            }
            line[l] = '\0';
            EMIT("%s\n", line);
        }
        if (c->rows > (unsigned long long)shown) {
            EMIT("  ... and %llu more\n", c->rows - (unsigned long long)shown);
        }
    }
    if (c->side_n > 0) {
        EMIT("also changed:");
        for (int i = 0; i < c->side_n; i++) {
            char tname[64];
            const char *nm;

            clean(tname, sizeof tname, c->side_name[i], 48);
            nm = strncmp(tname, "public.", 7) == 0 ? tname + 7 : tname;
            EMIT("%s %s", i ? "," : "", nm);
            if (c->side_count[i][2] > 0) {
                EMIT(" %llu deleted", c->side_count[i][2]);
            } else if (c->side_count[i][1] > 0) {
                EMIT(" %llu updated", c->side_count[i][1]);
            } else {
                EMIT(" %llu inserted", c->side_count[i][0]);
            }
        }
        EMIT("%s\n", c->in_tx ? " (this transaction so far)" : "");
    }
#undef EMIT
    return n;
}

const char *sl_confirm_resolution_sql(const sl_confirm *c, int yes)
{
    if (c->ext) {
        return yes ? "SET sluice.confirmed = 'on'" : NULL; /* no result, so its tag can be ours */
    }
    if (c->in_tx) {
        return yes ? "RELEASE SAVEPOINT " SAVEPOINT : "ROLLBACK TO SAVEPOINT " SAVEPOINT;
    }
    return yes ? "COMMIT" : "ROLLBACK";
}

int sl_confirm_journal_gate(sl_confirm *c)
{
    return journal_gate(c);
}

const char *sl_confirm_why(const sl_confirm *c)
{
    return c->why;
}

const char *sl_confirm_tag(const sl_confirm *c)
{
    return c->tag;
}

const char *sl_confirm_rule(const sl_confirm *c)
{
    return c->rule;
}

const char *sl_confirm_message(const sl_confirm *c)
{
    return c->message;
}

void sl_confirm_set_outcome(sl_confirm *c, const char *outcome)
{
    c->outcome = outcome;
}

static size_t render(const sl_confirm *c, char *out, size_t cap, int with_prompt)
{
    size_t n = 0;
    char who[220];
    char sql[360];
    char rule[80];
    int widths[MAX_COLS] = {0};
    const char *verb = strncmp(c->tag, "DELETE", 6) == 0 ? "deleted" : "changed";
    int shown = c->sample_n < SL_CONFIRM_TERMINAL_ROWS ? c->sample_n : SL_CONFIRM_TERMINAL_ROWS;

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
    if (c->plain) {
        EMIT("  %s (not committed yet; there are no rows to show)\n", c->tag[0] ? c->tag : "done");
        if (with_prompt) {
            EMIT("commit? [y/N] ");
        }
        return n;
    }
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
    if (c->side_n > 0) {
        EMIT("  tables changed in this transaction (cascades and triggers included)%s:\n",
             c->in_tx ? ", counting what it did before" : "");
        for (int i = 0; i < c->side_n; i++) {
            char tname[64];
            const char *sep = "";

            clean(tname, sizeof tname, c->side_name[i], 48);
            EMIT("    %-30s", tname);
            if (c->side_count[i][2] > 0) {
                EMIT("%s%llu deleted", sep, c->side_count[i][2]);
                sep = ", ";
            }
            if (c->side_count[i][1] > 0) {
                EMIT("%s%llu updated", sep, c->side_count[i][1]);
                sep = ", ";
            }
            if (c->side_count[i][0] > 0) {
                EMIT("%s%llu inserted", sep, c->side_count[i][0]);
            }
            EMIT("\n");
        }
    }
    if (with_prompt) {
        EMIT("commit? [y/N] ");
    }
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
