/* Fuzz targets for everything in sluice that reads bytes it does not control.
 *
 * One entry point, LLVMFuzzerTestOneInput, in the libFuzzer convention. The first byte of the input
 * picks the target, the rest is that target's input. Crashes and sanitizer reports are not the only
 * failures: each target also checks invariants and aborts when one does not hold. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "admin.h"
#include "budget.h"
#include "buf.h"
#include "config.h"
#include "confirm.h"
#include "extstate.h"
#include "journal.h"
#include "json.h"
#include "log.h"
#include "mask.h"
#include "metrics.h"
#include "pg_proto.h"
#include "policy.h"
#include "scanner.h"
#include "sql_check.h"
#include "srvscan.h"
#include "undo.h"

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "invariant violated: %s (%s:%d)\n", #cond, __FILE__, __LINE__);        \
            abort();                                                                               \
        }                                                                                          \
    } while (0)

static int within(const void *p, size_t len, const uint8_t *base, size_t n)
{
    const uint8_t *q = p;

    return q >= base && len <= n && (size_t)(q - base) <= n - len;
}

/* A copy of the input with a NUL after it, for the functions that take C strings. */
static char *as_string(const uint8_t *d, size_t n)
{
    char *s = malloc(n + 1);

    CHECK(s != NULL);
    memcpy(s, d, n);
    s[n] = '\0';
    return s;
}

/* ---- protocol framing ---- */

static void t_startup(const uint8_t *d, size_t n)
{
    static const char *const keys[] = {"user", "database", "application_name", "replication", ""};
    sl_pg_startup_packet p;
    int rc = sl_pg_parse_startup_packet(d, n, &p);

    CHECK(rc == SL_PG_OK || rc == SL_PG_NEED_MORE || rc == SL_PG_ERROR);
    if (rc != SL_PG_OK) {
        return;
    }
    CHECK(p.total_len >= 8 && p.total_len <= n && p.total_len <= SL_PG_MAX_STARTUP_LEN);
    CHECK(p.body == d + 8 && p.body_len == p.total_len - 8);
    if (p.kind == SL_PG_STARTUP_MESSAGE) {
        for (size_t i = 0; i < sizeof keys / sizeof keys[0]; i++) {
            const char *v = NULL;
            size_t vl = 0;
            int r = sl_pg_startup_param(&p, keys[i], &v, &vl);

            CHECK(r == -1 || r == 0 || r == 1);
            if (r == 1) {
                CHECK(within(v, vl, p.body, p.body_len));
            }
        }
    }
}

static void t_message(const uint8_t *d, size_t n)
{
    sl_pg_header h;
    sl_pg_message m;
    int rh = sl_pg_parse_header(d, n, &h);
    int rm = sl_pg_parse_message(d, n, &m);

    if (rh == SL_PG_OK) {
        CHECK(h.payload_len <= SL_PG_MAX_MESSAGE_LEN - 4);
    }
    if (rm == SL_PG_OK) {
        CHECK(rh == SL_PG_OK && m.type == h.type && m.payload_len == h.payload_len);
        CHECK(m.total_len == 5 + m.payload_len && m.total_len <= n && m.payload == d + 5);
    }
    if (rm == SL_PG_ERROR) {
        CHECK(rh == SL_PG_ERROR); /* a bad header is the only way to fail on a complete message */
    }
}

static void t_statements(const uint8_t *d, size_t n)
{
    sl_pg_statement st;

    if (sl_pg_statement_from_query(d, n, &st) == SL_PG_OK) {
        CHECK(within(st.sql, st.sql_len, d, n) && st.sql_len == n - 1);
        CHECK(memchr(st.sql, 0, st.sql_len) == NULL);
    } else {
        CHECK(st.sql == NULL && st.sql_len == 0);
    }
    if (sl_pg_statement_from_parse(d, n, &st) == SL_PG_OK) {
        CHECK(within(st.name, st.name_len, d, n) && within(st.sql, st.sql_len, d, n));
        CHECK(memchr(st.name, 0, st.name_len) == NULL && memchr(st.sql, 0, st.sql_len) == NULL);
        CHECK(st.name_len + 1 + st.sql_len + 1 + 2 <= n);
    } else {
        CHECK(st.sql == NULL && st.name == NULL);
    }
}

/* The statement that blocks another one must not let its reason out of the string literal, whatever
 * the reason is: this is the one place where bytes of the policy (and of a parse error) end up
 * inside SQL. */
static void t_blocking_message(const uint8_t *d, size_t n)
{
    char *reason = as_string(d, n);
    sl_buf out;
    sl_pg_message m;
    sl_pg_statement st;

    sl_buf_init(&out);
    CHECK(sl_pg_append_failing_query(&out, reason) == 0);
    CHECK(sl_pg_parse_message(sl_buf_data(&out), sl_buf_len(&out), &m) == SL_PG_OK &&
          m.type == 'Q');
    CHECK(m.total_len == sl_buf_len(&out));
    CHECK(sl_pg_statement_from_query(m.payload, m.payload_len, &st) == SL_PG_OK);

    /* select '<body>'::int, and in the body every quote is doubled */
    CHECK(st.sql_len >= 14 && memcmp(st.sql, "select '", 8) == 0 &&
          memcmp(st.sql + st.sql_len - 6, "'::int", 6) == 0);
    for (size_t i = 8; i < st.sql_len - 6; i++) {
        unsigned char ch = (unsigned char)st.sql[i];

        CHECK(ch >= 0x20 && ch < 0x7f && ch != '\\');
        if (ch == '\'') {
            CHECK(i + 1 < st.sql_len - 6 && st.sql[i + 1] == '\'');
            i++;
        }
    }
    sl_buf_free(&out);

    /* the same for the extended protocol, which must also keep the name it was given */
    sl_buf_init(&out);
    CHECK(sl_pg_append_failing_parse(&out, "stmt", 4, reason) == 0);
    CHECK(sl_pg_parse_message(sl_buf_data(&out), sl_buf_len(&out), &m) == SL_PG_OK &&
          m.type == 'P');
    CHECK(sl_pg_statement_from_parse(m.payload, m.payload_len, &st) == SL_PG_OK);
    CHECK(st.name_len == 4 && memcmp(st.name, "stmt", 4) == 0);
    sl_buf_free(&out);
    free(reason);
}

/* The server's authentication offer: when it is rewritten, the new one must be a valid message that
 * offers exactly the old mechanisms minus SCRAM-SHA-256-PLUS, in the same order. */
static void t_sasl(const uint8_t *d, size_t n)
{
    static const char plus[] = "SCRAM-SHA-256-PLUS";
    sl_buf out;
    sl_buf again;
    sl_pg_message m;
    int rc;

    sl_buf_init(&out);
    sl_buf_init(&again);
    rc = sl_pg_sasl_drop_plus(d, n, &out);
    CHECK(rc == 0 || rc == 1);
    if (rc == 0) {
        CHECK(sl_buf_len(&out) == 0);
    } else {
        const uint8_t *old = d + 4;
        const uint8_t *oldend = d + n - 1;
        const uint8_t *p;

        CHECK(sl_pg_parse_message(sl_buf_data(&out), sl_buf_len(&out), &m) == SL_PG_OK);
        CHECK(m.type == 'R' && m.total_len == sl_buf_len(&out) && m.payload_len >= 6);
        CHECK(sl_pg_get_be32(m.payload) == 10 && m.payload[m.payload_len - 1] == 0);
        CHECK(m.payload_len < n);

        /* walk both lists: the new one is the old one without the PLUS entries */
        p = m.payload + 4;
        while (old < oldend && *old != 0) {
            size_t ol = strlen((const char *)old);

            if (ol == sizeof plus - 1 && memcmp(old, plus, ol) == 0) {
                old += ol + 1;
                continue;
            }
            CHECK(*p != 0 && strlen((const char *)p) == ol && memcmp(p, old, ol) == 0);
            p += ol + 1;
            old += ol + 1;
        }
        CHECK(*p == 0 && p == m.payload + m.payload_len - 1); /* nothing more, final NUL */

        /* applied to its own result, there is nothing left to drop */
        CHECK(sl_pg_sasl_drop_plus(m.payload, m.payload_len, &again) == 0);
    }
    sl_buf_free(&out);
    sl_buf_free(&again);
}

/* ---- JSON and the log ---- */

static int utf8_ok(const uint8_t *s, size_t n, size_t *used)
{
    size_t k;

    if (s[0] < 0x80) {
        *used = 1;
        return 1;
    }
    if (s[0] >= 0xC2 && s[0] <= 0xDF) {
        k = 2;
    } else if (s[0] >= 0xE0 && s[0] <= 0xEF) {
        k = 3;
    } else if (s[0] >= 0xF0 && s[0] <= 0xF4) {
        k = 4;
    } else {
        return 0;
    }
    if (n < k) {
        return 0;
    }
    for (size_t i = 1; i < k; i++) {
        if ((s[i] & 0xC0) != 0x80) {
            return 0;
        }
    }
    if ((s[0] == 0xE0 && s[1] < 0xA0) || (s[0] == 0xED && s[1] > 0x9F) ||
        (s[0] == 0xF0 && s[1] < 0x90) || (s[0] == 0xF4 && s[1] > 0x8F)) {
        return 0;
    }
    *used = k;
    return 1;
}

static void t_json(const uint8_t *d, size_t n)
{
    sl_buf out;
    const uint8_t *s;
    size_t len;
    size_t i;

    sl_buf_init(&out);
    CHECK(sl_json_append_string(&out, d, n) == 0);
    s = sl_buf_data(&out);
    len = sl_buf_len(&out);

    /* whatever the input, the output is one valid JSON string made of valid UTF-8 */
    CHECK(len >= 2 && s[0] == '"' && s[len - 1] == '"');
    for (i = 1; i < len - 1;) {
        size_t used;

        if (s[i] == '\\') {
            CHECK(i + 1 < len - 1);
            if (s[i + 1] == 'u') {
                CHECK(i + 6 < len);
                for (size_t k = 2; k <= 5; k++) {
                    CHECK((s[i + k] >= '0' && s[i + k] <= '9') ||
                          (s[i + k] >= 'a' && s[i + k] <= 'f'));
                }
                i += 6;
            } else {
                CHECK(strchr("\"\\nrtbf", s[i + 1]) != NULL);
                i += 2;
            }
            continue;
        }
        CHECK(s[i] != '"' && s[i] >= 0x20);
        CHECK(utf8_ok(s + i, len - 1 - i, &used));
        i += used;
    }
    CHECK(sl_json_utf8_prefix(d, n, n / 2) <= n / 2 + 0);
    {
        size_t cut = sl_json_utf8_prefix(d, n, n / 2);

        CHECK(n <= n / 2 || cut <= n / 2);
        CHECK(cut == n || n == 0 || (d[cut] & 0xC0) != 0x80 || cut == 0);
    }
    sl_buf_free(&out);
}

/* ---- configuration ---- */

static void t_address(const uint8_t *d, size_t n)
{
    char *spec = as_string(d, n);
    char host[64];
    char port[8];

    if (sl_addr_parse(spec, host, sizeof host, port, sizeof port) == 0) {
        long p;
        char *end;

        CHECK(host[0] != '\0' && strlen(host) < sizeof host);
        CHECK(port[0] != '\0' && strlen(port) < sizeof port);
        p = strtol(port, &end, 10);
        CHECK(*end == '\0' && p >= 0 && p <= 65535);
        CHECK(strchr(host, ']') == NULL && strchr(host, '[') == NULL);
    }
    free(spec);
}

static void t_policy(const uint8_t *d, size_t n)
{
    static const uint32_t flags[] = {0,
                                     SL_SQL_UNBOUNDED_WRITE,
                                     SL_SQL_DDL | SL_SQL_NOT_READ_ONLY,
                                     SL_SQL_DROP | SL_SQL_DDL,
                                     SL_SQL_PROCEDURAL | SL_SQL_NOT_READ_ONLY,
                                     SL_SQL_MULTI | SL_SQL_TRUNCATE};
    sl_policy p;
    char err[256];

    if (sl_policy_parse(&p, (const char *)d, n, "fuzz", err, sizeof err) != 0) {
        CHECK(strncmp(err, "fuzz:", 5) == 0);
        CHECK(p.rules == NULL && p.nrules == 0);
        return;
    }
    for (size_t i = 0; i < p.nrules; i++) {
        CHECK(p.rules[i].name != NULL && p.rules[i].name[0] != '\0');
        if (p.rules[i].any) {
            CHECK(p.rules[i].match == 0);
        } else {
            CHECK(p.rules[i].match != 0 &&
                  (p.rules[i].match & (p.rules[i].match - 1)) == 0); /* one flag */
        }
        CHECK((p.rules[i].ntables == 0) == (p.rules[i].tables == NULL));
        if (p.rules[i].budget) {
            CHECK(p.rules[i].conn_limit && p.rules[i].limit &&
                  (p.rules[i].budget_rows | p.rules[i].budget_bytes | p.rules[i].budget_changed |
                   p.rules[i].budget_statements) != 0);
        }
        CHECK((p.rules[i].nfunctions == 0) == (p.rules[i].functions == NULL));
        CHECK((p.rules[i].nfingerprints == 0) == (p.rules[i].fingerprints == NULL));
        CHECK((p.rules[i].noutside_fingerprints == 0) == (p.rules[i].outside_fingerprints == NULL));
        CHECK(p.rules[i].nduring <= SL_MAX_WINDOWS && p.rules[i].nexcept_during <= SL_MAX_WINDOWS);
        CHECK(!p.rules[i].dry_run || ((p.rules[i].deny || p.rules[i].confirm) &&
                                      !p.rules[i].conn_limit && !p.rules[i].mask));
        CHECK(!p.rules[i].kill || p.rules[i].deny);
        CHECK(p.rules[i].via == SL_VIA_DEFAULT || p.rules[i].confirm);
        CHECK((p.rules[i].noutside == 0) == (p.rules[i].outside_tables == NULL));
        for (size_t j = 0; j < i; j++) {
            CHECK(strcmp(p.rules[i].name, p.rules[j].name) != 0);
        }
    }
    {
        sl_sql_info info;
        sl_verdict v;

        /* flags only: no information about tables */
        info.flags = (uint32_t *)flags;
        info.group = NULL;
        info.tables = NULL;
        info.count = sizeof flags / sizeof flags[0];
        info.top_level = info.count;
        v = sl_policy_evaluate(&p, &info, "app", 3, "db", 2);
        CHECK(v.deny == (v.rule != NULL && !v.confirm)); /* a rule that asks is not a refusal */
        CHECK(!(v.deny && v.confirm));
        if (v.rule != NULL) {
            char reason[300];

            sl_policy_reason(v.rule, reason, sizeof reason);
            CHECK(strncmp(reason, "blocked by rule ", 16) == 0);
        }
    }
    {
        sl_limits lim;

        sl_policy_limits(&p, "app", 3, "db", 2, &lim);
        CHECK(lim.nbudgets <= SL_MAX_BUDGETS);
        for (size_t i = 0; i < lim.nbudgets; i++) {
            CHECK(lim.budgets[i].window_s >= 60 && lim.budgets[i].window_s <= 7 * 86400);
            CHECK(lim.budgets[i].rule[0] != '\0');
        }
    }
    /* real statements with their tables, judged by whatever policy the fuzzer made */
    {
        static const char *const sqls[] = {
            "select * from orders o join public.products p on true",
            "merge into orders using secret on true when matched then delete",
            "delete from ledger",
            "update archive.ledger set a = 1 where id = 1",
            "begin; select * from a; drop table b",
            "do $$ begin end $$",
            "select 1",
        };

        for (size_t i = 0; i < sizeof sqls / sizeof sqls[0]; i++) {
            sl_sql_info info;
            char err2[128];

            CHECK(sl_sql_classify_with_tables(sqls[i], strlen(sqls[i]), &info, err2, sizeof err2) ==
                  0);
            {
                sl_verdict v = sl_policy_evaluate(&p, &info, "agent", 5, "db", 2);

                CHECK(v.deny ==
                      (v.rule != NULL && !v.confirm)); /* a rule that asks is not a refusal */
                CHECK(!(v.deny && v.confirm));
            }
            sl_sql_info_free(&info);
        }
    }
    (void)sl_policy_needs_tables(&p);
    sl_policy_free(&p);
}

/* ---- the PostgreSQL parser ---- */

static void t_sql(const uint8_t *d, size_t n)
{
    sl_sql_info info;
    char err[256];
    char *sql;

    if (n > 2048) {
        n = 2048; /* the parser is the slow part: keep inputs small */
    }
    sql = as_string(d, n);
    /* every other input also asks for the tables */
    if ((n > 0 && (d[0] & 1) ? sl_sql_classify_with_tables
                             : sl_sql_classify)(sql, strlen(sql), &info, err, sizeof err) == 0) {
        CHECK(info.count >= info.top_level);
        CHECK(info.count == 0 || (info.flags != NULL && info.group != NULL));
        if (info.top_level > 1) {
            for (size_t i = 0; i < info.count; i++) {
                CHECK(info.flags[i] & SL_SQL_MULTI);
            }
        }
        for (size_t i = 0; i < info.count; i++) {
            CHECK(info.group[i] < info.top_level);
            CHECK(i == 0 || info.group[i] >= info.group[i - 1]); /* in the order of the message */
        }
        if (info.tables != NULL) {
            for (size_t g = 0; g < info.top_level; g++) {
                for (size_t t = 0; t < info.tables[g].count; t++) {
                    CHECK(info.tables[g].items[t].schema != NULL &&
                          info.tables[g].items[t].name != NULL);
                }
            }
        }
        sl_sql_info_free(&info);
    } else {
        CHECK(info.flags == NULL && info.count == 0 && err[0] != '\0');
    }

    /* what may be logged without the values */
    {
        sl_sql_redacted rd;
        char rerr[256];

        if (sl_sql_redact(sql, strlen(sql), &rd, rerr, sizeof rerr) == 0) {
            CHECK(strlen(rd.fingerprint) == 16);
            for (size_t i = 0; i < 16; i++) {
                CHECK((rd.fingerprint[i] >= '0' && rd.fingerprint[i] <= '9') ||
                      (rd.fingerprint[i] >= 'a' && rd.fingerprint[i] <= 'f'));
            }
            if (rd.text != NULL) {
                sl_sql_redacted again;

                /* The normalized text is for reading, not for replaying: "do $1" is not SQL. When
                 * it does parse, normalizing it again changes nothing and still gives a clean text.
                 */
                if (sl_sql_redact(rd.text, strlen(rd.text), &again, rerr, sizeof rerr) == 0) {
                    CHECK(again.text != NULL && strcmp(again.text, rd.text) == 0);
                    sl_sql_redacted_free(&again);
                }
            }
            sl_sql_redacted_free(&rd);
        } else {
            CHECK(rd.text == NULL && rd.fingerprint[0] == '\0');
            CHECK(strstr(rerr, " at or near") == NULL); /* the message does not quote the SQL */
        }
    }
    free(sql);
}

/* ---- the byte queue, against a plain array ---- */

static void t_buf(const uint8_t *d, size_t n)
{
    enum { MODEL_MAX = 1 << 16 };
    static uint8_t model[MODEL_MAX];
    sl_buf b;
    size_t mlen = 0;
    size_t i = 0;

    sl_buf_init(&b);
    while (i + 2 <= n) {
        uint8_t op = d[i++] % 4;
        uint8_t arg = d[i++];

        if (op == 0) { /* append */
            size_t k = arg < n - i ? arg : n - i;

            if (mlen + k > MODEL_MAX) {
                break;
            }
            CHECK(sl_buf_append(&b, d + i, k) == 0);
            memcpy(model + mlen, d + i, k);
            mlen += k;
            i += k;
        } else if (op == 1) { /* consume */
            sl_buf_consume(&b, arg);
            if (arg >= mlen) {
                mlen = 0;
            } else {
                memmove(model, model + arg, mlen - arg);
                mlen -= arg;
            }
        } else if (op == 2) { /* replace */
            uint8_t fill[64];
            size_t pos = arg % (mlen + 1);
            size_t old_len;
            size_t new_len;

            if (i + 2 > n) {
                break;
            }
            old_len = d[i++] % (mlen - pos + 1);
            new_len = d[i++] % 64;
            if (mlen - old_len + new_len > MODEL_MAX) {
                break;
            }
            memset(fill, arg ^ 0x5a, sizeof fill);
            CHECK(sl_buf_replace(&b, pos, old_len, fill, new_len) == 0);
            memmove(model + pos + new_len, model + pos + old_len, mlen - pos - old_len);
            memcpy(model + pos, fill, new_len);
            mlen = mlen - old_len + new_len;
        } else { /* reserve then commit part of it */
            size_t want = (size_t)arg + 1;
            size_t used = want / 2;
            uint8_t *p;

            if (mlen + used > MODEL_MAX) {
                break;
            }
            p = sl_buf_reserve(&b, want);
            CHECK(p != NULL);
            memset(p, arg, want);
            sl_buf_commit(&b, used);
            memset(model + mlen, arg, used);
            mlen += used;
        }
        CHECK(sl_buf_len(&b) == mlen);
        CHECK(mlen == 0 || memcmp(sl_buf_data(&b), model, mlen) == 0);
    }
    sl_buf_free(&b);
}

/* ---- the message scanner ---- */

typedef struct {
    int block_statements;
    int block_unreadable;
    int close_on_frame_error;
    size_t blocked;
    size_t frame_errors;
    int ext_on;    /* the hook for Bind, Describe, Execute, Close and Sync is installed */
    int ext_block; /* ... and refuses the ones whose first byte is odd */
} fz_ctx;

/* A blocked message is replaced by a Query that holds the word "blocked". */
static int fz_block(sl_buf *replacement)
{
    static const uint8_t msg[] = {'Q', 0, 0, 0, 12, 'b', 'l', 'o', 'c', 'k', 'e', 'd', 0};

    return sl_buf_append(replacement, msg, sizeof msg) == 0 ? SL_SCAN_BLOCK : SL_SCAN_FAIL;
}

/* The decisions depend on the bytes of the message only, never on how the stream was cut. */
static int fz_statement(void *ctx, uint8_t type, const uint8_t *payload, size_t len,
                        sl_buf *replacement)
{
    fz_ctx *c = ctx;

    (void)type;
    if (c->block_statements && len > 0 && (payload[0] & 1)) {
        c->blocked++;
        return fz_block(replacement);
    }
    return SL_SCAN_RELAY;
}

static int fz_unreadable(void *ctx, uint8_t type, size_t payload_len, int too_big,
                         sl_buf *replacement)
{
    fz_ctx *c = ctx;

    (void)type;
    (void)too_big;
    if (c->block_unreadable && (payload_len & 1)) {
        c->blocked++;
        return fz_block(replacement);
    }
    return SL_SCAN_RELAY;
}

static int fz_frame_error(void *ctx)
{
    fz_ctx *c = ctx;

    c->frame_errors++;
    return c->close_on_frame_error;
}

/* Bind, Describe, Execute, Close, Sync: decided on the first bytes only (never a Sync). */
static int fz_extended(void *ctx, uint8_t type, const uint8_t *payload, size_t len, size_t total,
                       sl_buf *replacement)
{
    fz_ctx *c = ctx;

    CHECK(len <= total && len <= SL_SCAN_PEEK && (len == total || len == SL_SCAN_PEEK));
    if (c->ext_block && type != 'S' && len > 0 && (payload[0] & 1)) {
        c->blocked++;
        return fz_block(replacement);
    }
    return SL_SCAN_RELAY;
}

static const sl_scan_ops fz_ops = {fz_statement, fz_unreadable, fz_frame_error, NULL};
static const sl_scan_ops fz_ops_ext = {fz_statement, fz_unreadable, fz_frame_error, fz_extended};

/* Plays the connection, with reads of the lengths given by `cuts` (cycled); 0 cuts means one single
 * read. Fills `out` with what is sent. Checks the bounds after every read. */
static int fz_drive(const uint8_t *in, size_t n, const uint8_t *cuts, size_t ncuts, fz_ctx *ctx,
                    size_t inspect_max, int fastpath, sl_buf *out)
{
    sl_scan s;
    sl_buf buf;
    int rc = SL_SCAN_OK;
    size_t pos = 0;
    size_t i = 0;

    sl_scan_init(&s, fastpath, inspect_max);
    sl_buf_init(&buf);
    while (pos < n && rc == SL_SCAN_OK) {
        size_t k = ncuts ? 1 + (size_t)(cuts[i++ % ncuts] % 23) : n;

        if (k > n - pos) {
            k = n - pos;
        }
        CHECK(sl_buf_append(&buf, in + pos, k) == 0);
        pos += k;
        rc = sl_scan_run(&s, &buf, ctx->ext_on ? &fz_ops_ext : &fz_ops, ctx);
        CHECK(rc == SL_SCAN_OK || rc == SL_SCAN_CLOSE);
        CHECK(s.released <= sl_buf_len(&buf));
        /* nothing but one message that fits is ever held back (when the connection is to be closed,
         * what is left is never sent, so it is not held either) */
        CHECK(rc != SL_SCAN_OK ||
              sl_buf_len(&buf) - s.released <=
                  5 + (ctx->ext_on && SL_SCAN_PEEK > inspect_max ? SL_SCAN_PEEK : inspect_max));
        CHECK(sl_buf_append(out, sl_buf_data(&buf), s.released) == 0);
        sl_buf_consume(&buf, s.released);
        s.released = 0;
    }
    if (rc == SL_SCAN_OK) {
        CHECK(sl_buf_append(out, sl_buf_data(&buf), sl_buf_len(&buf)) == 0); /* the client left */
    }
    sl_buf_free(&buf);
    return rc;
}

/* A second, deliberately simple implementation of what the scanner should do: it reads the whole
 * stream at once, with no state to carry from one read to the next. The scanner, which has to cope
 * with any cut of the stream, must give exactly the same output. Returns SL_SCAN_OK or
 * SL_SCAN_CLOSE. */
static int fz_model(const uint8_t *in, size_t n, fz_ctx *ctx, size_t limit, int fastpath,
                    sl_buf *out)
{
    size_t pos = 0;

    while (pos < n) {
        size_t left = n - pos;
        const uint8_t *m = in + pos;
        uint32_t len32;
        size_t plen;
        size_t take;
        int too_big;

        if (left < 5) { /* a header cut short: the client left, it goes through as it is */
            CHECK(sl_buf_append(out, m, left) == 0);
            return SL_SCAN_OK;
        }
        len32 = sl_pg_get_be32(m + 1);
        if (len32 < 4 || len32 > SL_PG_MAX_MESSAGE_LEN) {
            ctx->frame_errors++;
            if (ctx->close_on_frame_error) {
                return SL_SCAN_CLOSE;
            }
            CHECK(sl_buf_append(out, m, left) == 0);
            return SL_SCAN_OK;
        }
        plen = len32 - 4;
        take = left < 5 + plen ? left : 5 + plen; /* what of this message is there */
        too_big = (m[0] == 'Q' || m[0] == 'P') && plen > limit;

        if (ctx->ext_on && (m[0] == 'B' || m[0] == 'D' || m[0] == 'E' || m[0] == 'C' ||
                            m[0] == 'S' || (m[0] == 'F' && !fastpath))) {
            size_t need = plen < SL_SCAN_PEEK ? plen : SL_SCAN_PEEK;

            if (left <
                5 + need) { /* the start is not all there: held until the end of the stream */
                CHECK(sl_buf_append(out, m, left) == 0);
                return SL_SCAN_OK;
            }
            if (ctx->ext_block && m[0] != 'S' && need > 0 && (m[5] & 1)) {
                sl_buf rep;

                sl_buf_init(&rep);
                ctx->blocked++;
                CHECK(fz_block(&rep) == SL_SCAN_BLOCK &&
                      sl_buf_append(out, sl_buf_data(&rep), sl_buf_len(&rep)) == 0);
                sl_buf_free(&rep); /* the header is replaced, the rest is not sent */
            } else {
                CHECK(sl_buf_append(out, m, take) == 0);
            }
        } else if ((m[0] == 'Q' || m[0] == 'P') && !too_big) {
            if (left < 5 + plen) { /* incomplete: held until the end of the stream */
                CHECK(sl_buf_append(out, m, left) == 0);
                return SL_SCAN_OK;
            }
            if (ctx->block_statements && plen > 0 && (m[5] & 1)) {
                sl_buf rep;

                sl_buf_init(&rep);
                ctx->blocked++;
                CHECK(fz_block(&rep) == SL_SCAN_BLOCK &&
                      sl_buf_append(out, sl_buf_data(&rep), sl_buf_len(&rep)) == 0);
                sl_buf_free(&rep);
            } else {
                CHECK(sl_buf_append(out, m, take) == 0);
            }
        } else if (too_big || (m[0] == 'F' && fastpath)) {
            if (ctx->block_unreadable && (plen & 1)) {
                sl_buf rep;

                sl_buf_init(&rep);
                ctx->blocked++;
                CHECK(fz_block(&rep) == SL_SCAN_BLOCK &&
                      sl_buf_append(out, sl_buf_data(&rep), sl_buf_len(&rep)) == 0);
                sl_buf_free(&rep); /* the header is replaced, the body is not sent */
            } else {
                CHECK(sl_buf_append(out, m, take) == 0);
            }
        } else {
            CHECK(sl_buf_append(out, m, take) == 0);
        }
        pos += take;
    }
    return SL_SCAN_OK;
}

/* The stream, cut in three different ways, must give the same bytes and the same verdicts, and the
 * same ones as the reference model; and when nothing is blocked, every byte that went in comes out.
 */
static void t_scanner(const uint8_t *d, size_t n)
{
    static const size_t limits[] = {8, 32, 256, 4096};
    sl_buf whole;
    sl_buf cut;
    sl_buf bytes;
    fz_ctx a = {0};
    fz_ctx b = {0};
    fz_ctx c = {0};
    size_t limit;
    int fastpath;
    int ra;
    int rb;
    int rc;

    if (n < 2) {
        return;
    }
    a.block_statements = b.block_statements = c.block_statements = d[0] & 1;
    a.block_unreadable = b.block_unreadable = c.block_unreadable = (d[0] >> 1) & 1;
    a.close_on_frame_error = b.close_on_frame_error = c.close_on_frame_error = (d[0] >> 2) & 1;
    fastpath = (d[0] >> 3) & 1;
    limit = limits[(d[0] >> 4) & 3];
    a.ext_on = b.ext_on = c.ext_on = (d[0] >> 6) & 1;
    a.ext_block = b.ext_block = c.ext_block = (d[0] >> 7) & 1;
    sl_buf_init(&whole);
    sl_buf_init(&cut);
    sl_buf_init(&bytes);

    ra = fz_drive(d + 2, n - 2, NULL, 0, &a, limit, fastpath, &whole); /* one read */
    rb = fz_drive(d + 2, n - 2, d + 1, 1, &b, limit, fastpath, &cut);  /* irregular reads */
    {
        uint8_t one = 0; /* 1 + 0 % 23: a byte at a time */

        rc = fz_drive(d + 2, n - 2, &one, 1, &c, limit, fastpath, &bytes);
    }

    CHECK(ra == rb && ra == rc);
    CHECK(sl_buf_len(&whole) == sl_buf_len(&cut) && sl_buf_len(&whole) == sl_buf_len(&bytes));
    CHECK(sl_buf_len(&whole) == 0 ||
          (memcmp(sl_buf_data(&whole), sl_buf_data(&cut), sl_buf_len(&whole)) == 0 &&
           memcmp(sl_buf_data(&whole), sl_buf_data(&bytes), sl_buf_len(&whole)) == 0));
    CHECK(a.blocked == b.blocked && a.blocked == c.blocked);
    CHECK(a.frame_errors == b.frame_errors && a.frame_errors == c.frame_errors);
    CHECK(a.frame_errors <= 1);

    /* and the same as an independent reading of the whole stream */
    {
        fz_ctx m = {a.block_statements, a.block_unreadable, a.close_on_frame_error, 0, 0,
                    a.ext_on,           a.ext_block};
        sl_buf expected;
        int rm;

        sl_buf_init(&expected);
        rm = fz_model(d + 2, n - 2, &m, limit, fastpath, &expected);
        CHECK(rm == ra);
        CHECK(sl_buf_len(&expected) == sl_buf_len(&whole));
        CHECK(sl_buf_len(&expected) == 0 ||
              memcmp(sl_buf_data(&expected), sl_buf_data(&whole), sl_buf_len(&expected)) == 0);
        CHECK(m.blocked == a.blocked && m.frame_errors == a.frame_errors);
        sl_buf_free(&expected);
    }

    if (ra == SL_SCAN_OK && a.blocked == 0) {
        CHECK(sl_buf_len(&whole) == n - 2 &&
              (n == 2 || memcmp(sl_buf_data(&whole), d + 2, n - 2) == 0));
    }
    if (ra == SL_SCAN_CLOSE) {
        CHECK(a.frame_errors == 1);
        /* without blocking, what was sent is a prefix of what came in (blocked messages are
         * replaced by longer ones, so with blocking the model above is the check) */
        CHECK(a.blocked > 0 || (sl_buf_len(&whole) <= n - 2 &&
                                (sl_buf_len(&whole) == 0 ||
                                 memcmp(sl_buf_data(&whole), d + 2, sl_buf_len(&whole)) == 0)));
    }
    sl_buf_free(&whole);
    sl_buf_free(&cut);
    sl_buf_free(&bytes);
}

/* ---- the server's stream (srvscan.c): the same bytes, cut in different ways, must give the same
 * output and the same messages read ---- */

typedef struct {
    uint8_t mask;
    unsigned seen;
    char order[256];
} ss_fake;

static int ss_classify(void *ctx, uint8_t type, size_t len)
{
    ss_fake *f = ctx;

    (void)len;
    if ((f->mask & 0x20) && type == 'E') {
        return SL_SRV_SKIP;
    }
    if (((f->mask & 1) && type == 'Z') || ((f->mask & 2) && type == 'C') ||
        ((f->mask & 4) && type == 'D') || ((f->mask & 8) && type == 'T')) {
        return SL_SRV_READ;
    }
    return SL_SRV_PASS;
}

static int ss_message(void *ctx, uint8_t type, const uint8_t *payload, size_t len)
{
    ss_fake *f = ctx;

    CHECK(payload != NULL || len == 0);
    if (f->seen < sizeof f->order) {
        f->order[f->seen] = (char)type;
    }
    f->seen++;
    return ((f->mask & 0x10) && type == 'C') ? SL_SRV_DROP : SL_SRV_KEEP;
}

static int ss_run(const uint8_t *d, size_t n, uint8_t mask, int chunked, sl_buf *out, ss_fake *f,
                  unsigned *oversized)
{
    static const sl_srv_ops ops = {ss_classify, ss_message, NULL, NULL};
    sl_srv s;
    sl_buf buf;
    size_t pos = 0;
    uint32_t prng = 12345u + n;
    int rc = SL_SRV_OK;

    memset(f, 0, sizeof *f);
    f->mask = mask;
    *oversized = 0;
    sl_srv_init(&s, 0, (mask & 0x40) ? 64 : SL_SRV_READ_MAX);
    sl_buf_init(&buf);
    while (pos < n) {
        size_t k = n - pos;

        if (chunked) {
            prng = prng * 1103515245u + 12345u;
            k = 1 + (prng >> 16) % 9;
            if (k > n - pos) {
                k = n - pos;
            }
        }
        CHECK(sl_buf_append(&buf, d + pos, k) == 0);
        pos += k;
        rc = sl_srv_run(&s, &buf, &(ops), f, oversized);
        CHECK(s.released <= sl_buf_len(&buf));
        CHECK(sl_buf_append(out, sl_buf_data(&buf), s.released) == 0);
        sl_buf_consume(&buf, s.released);
        s.released = 0;
    }
    sl_buf_free(&buf);
    return rc;
}

static void t_srvscan(const uint8_t *d, size_t n)
{
    sl_buf whole;
    sl_buf cut;
    ss_fake fw;
    ss_fake fc;
    unsigned ow;
    unsigned oc;
    int rw;
    int rc;

    if (n < 1) {
        return;
    }
    sl_buf_init(&whole);
    sl_buf_init(&cut);
    rw = ss_run(d + 1, n - 1, d[0], 0, &whole, &fw, &ow);
    rc = ss_run(d + 1, n - 1, d[0], 1, &cut, &fc, &oc);
    CHECK(rw == rc);
    CHECK(sl_buf_len(&whole) == sl_buf_len(&cut));
    CHECK(sl_buf_len(&whole) == 0 ||
          memcmp(sl_buf_data(&whole), sl_buf_data(&cut), sl_buf_len(&whole)) == 0);
    CHECK(fw.seen == fc.seen && ow == oc);
    CHECK(memcmp(fw.order, fc.order, fw.seen < sizeof fw.order ? fw.seen : sizeof fw.order) == 0);
    /* nothing is dropped or thrown away: what goes out is what came in */
    if (!(d[0] & 0x30) && !(d[0] & 0x40) && rw == SL_SRV_OK) {
        CHECK(sl_buf_len(&whole) <= n - 1);
    }
    CHECK(sl_buf_len(&whole) <= n - 1);
    sl_buf_free(&whole);
    sl_buf_free(&cut);
}

/* ---- the confirmation (confirm.c): any answer from the server, in any order ---- */

static void t_confirm(const uint8_t *d, size_t n)
{
    static const char types[] = "CTDEZNASIGHWcdn123";
    sl_confirm *c;
    sl_confirm_args a;
    sl_buf to_server;
    sl_buf to_client;
    sl_confirm_step step;
    size_t pos = 1;
    int answered = 0;
    int finished = 0;
    char text[512];

    if (n < 2) {
        return;
    }
    memset(&a, 0, sizeof a);
    a.sql = "delete from users where a = 1";
    a.sql_len = strlen(a.sql);
    if (!(d[0] & 1)) {
        a.sql_returning = "delete from users where a = 1 RETURNING *";
        a.sql_returning_len = strlen(a.sql_returning);
    }
    a.client_returning = (d[0] >> 1) & 1;
    a.tx_status = (d[0] & 4) ? 'T' : 'I';
    a.over_rows = (d[0] >> 3) & 7;
    a.extended = (d[0] >> 6) & 1;
    a.user = "agent\033";
    a.user_len = 6;
    a.database = "db";
    a.database_len = 2;
    a.rule = "r";
    a.message = "m";
    c = sl_confirm_new();
    CHECK(c != NULL);
    if (c == NULL) {
        return;
    }
    sl_buf_init(&to_server);
    sl_buf_init(&to_client);
    CHECK(sl_confirm_start(c, &a, &to_server) == 0);
    while (pos + 2 <= n && !finished) {
        uint8_t type = (uint8_t)types[d[pos] % (sizeof types - 1)];
        size_t len = d[pos + 1] % 48;
        uint8_t payload[48];

        pos += 2;
        if (len > n - pos) {
            len = n - pos;
        }
        memcpy(payload, d + pos, len);
        pos += len;
        memset(&step, 0, sizeof step);
        {
            int rc = sl_confirm_server(c, type, payload, len, &to_server, &to_client, &step);

            CHECK(rc == SL_SRV_KEEP || rc == SL_SRV_DROP || rc == -1);
        }
        if (step.ask && !answered) {
            answered = 1;
            (void)sl_confirm_render(c, text,
                                    sizeof text); /* too small a buffer is fine: it is cut */
            if (a.extended) {
                sl_confirm_step st2;

                CHECK(sl_confirm_answer_ext(c, (int)(d[pos - 1] & 1), "no", &to_server, &to_client,
                                            &st2) == 0);
                if (st2.done) {
                    step.done = 1;
                }
            } else {
                CHECK(sl_confirm_answer(c, (int)(d[pos - 1] & 1), "no", &to_server) == 0);
            }
        }
        finished = step.done;
        /* the text shown can never write on the terminal */
        for (const char *p = text; answered && *p; p++) {
            CHECK((unsigned char)*p == '\n' ||
                  ((unsigned char)*p >= 0x20 && (unsigned char)*p < 0x7f));
        }
    }
    CHECK(sl_buf_len(&to_server) < (1u << 20));
    sl_confirm_free(c);
    sl_buf_free(&to_server);
    sl_buf_free(&to_client);
}

/* ---- what is remembered of the extended protocol (extstate.c) ---- */

static void t_extstate(const uint8_t *d, size_t n)
{
    static const char types[] = "tTnDCIsEZ12N";
    sl_ext *e = sl_ext_new();
    size_t pos = 0;

    CHECK(e != NULL);
    if (e == NULL) {
        return;
    }
    while (pos + 2 <= n) {
        uint8_t op = d[pos] % 12;
        uint8_t arg = d[pos + 1];
        char name[80];
        size_t len =
            arg % 4 == 0 ? 0 : (arg % 4 == 3 ? 70 : 1 + arg % 3); /* "", 1-3 bytes, too long */
        const sl_ext_entry *g;
        sl_ext_guard gd = {
            "delete from t", 13, "rule", "message", 3, (arg >> 2) & 1, 1, 'D', 0, 0, 0, NULL, NULL};

        pos += 2;
        memset(name, 'a' + (arg >> 3) % 4, sizeof name);
        name[len] = '\0';
        switch (op) {
        case 0:
            (void)sl_ext_parse_guarded(e, name, len, &gd);
            break;
        case 1:
            sl_ext_parse_plain(e, name, len);
            break;
        case 2:
            g = sl_ext_stmt_guard(e, name, len);
            (void)sl_ext_bind(e, name, len, g);
            break;
        case 3:
            sl_ext_stmt_close(e, name, len);
            break;
        case 4:
            sl_ext_portal_close(e, name, len);
            break;
        case 5:
        case 6:
            (void)sl_ext_expect(e, arg % 7);
            break;
        case 7:
        case 8:
        case 9:
            (void)sl_ext_answer(e, (uint8_t)types[arg % (sizeof types - 1)]);
            break;
        case 10:
            sl_ext_portals_end(e);
            break;
        default:
            (void)sl_ext_guard_pending(e);
            (void)sl_ext_front_guarded_exec(e);
            (void)sl_ext_front_guarded_rowdesc(e);
            break;
        }
        CHECK(e->len <= SL_EXT_SLOTS_MAX && e->head < SL_EXT_SLOTS_MAX);
        CHECK(e->nstmts <= SL_EXT_GUARDED_MAX && e->nportals <= SL_EXT_GUARDED_MAX);
        for (size_t i = 0; i < e->nstmts; i++) {
            CHECK(e->stmts[i] != NULL && strlen(e->stmts[i]->name) <= SL_EXT_NAME_MAX &&
                  e->stmts[i]->sql != NULL);
        }
    }
    sl_ext_free(e);
}

/* ---- the counters of the budgets: time moves forward and back, names come and go ---- */

static void t_budget(const uint8_t *d, size_t n)
{
    static const unsigned windows[] = {60, 61, 3600, 86400, 7 * 86400};
    sl_budget *b = sl_budget_new();
    sl_budget_entry *held[8] = {0};
    int64_t now = 0;
    size_t pos = 0;

    CHECK(b != NULL);
    if (b == NULL) {
        return;
    }
    while (pos + 3 <= n) {
        uint8_t op = d[pos] % 6;
        uint8_t arg = d[pos + 1];
        uint8_t val = d[pos + 2];
        size_t slot = arg % 8;
        char user[8];

        pos += 3;
        snprintf(user, sizeof user, "u%u", (unsigned)(arg >> 3) % 6);
        switch (op) {
        case 0:
            if (held[slot] == NULL) {
                held[slot] =
                    sl_budget_acquire(b, "rule", user, strlen(user), windows[val % 5], now);
            }
            break;
        case 1:
            if (held[slot] != NULL) {
                sl_budget_release(b, held[slot], now);
                held[slot] = NULL;
            }
            break;
        case 2:
            sl_budget_add(held[slot], now, val % SL_BUDGET_KINDS, (unsigned long long)val * val);
            break;
        case 3:
            now += (int64_t)val * (arg % 2 ? 60000 : 1000); /* forward */
            break;
        case 4:
            now -= (int64_t)val * 1000; /* the clock goes back: nothing may break */
            break;
        default:
            if (held[slot] != NULL) {
                unsigned long long used = sl_budget_used(held[slot], now, val % SL_BUDGET_KINDS);
                unsigned w = sl_budget_wait_s(held[slot], now, val % SL_BUDGET_KINDS, 1 + val);

                (void)used;
                CHECK(w <= 7 * 86400);
                if (used < 1 + (unsigned long long)val) {
                    CHECK(w == 0);
                }
            }
            break;
        }
    }
    for (size_t i = 0; i < 8; i++) {
        sl_budget_release(b, held[i], now);
    }
    sl_budget_free(b);
}

/* ---- hiding values in rows and messages: any bytes, never a crash, always well framed ---- */

/* Is this the payload of a DataRow that a client can read: n fields, each framed, nothing after? */
static int framed_row(const uint8_t *p, size_t len, unsigned *ncols)
{
    size_t pos = 2;

    if (len < 2) {
        return 0;
    }
    *ncols = (unsigned)((p[0] << 8) | p[1]);
    for (unsigned i = 0; i < *ncols; i++) {
        int32_t l;

        if (len - pos < 4) {
            return 0;
        }
        l = (int32_t)sl_pg_get_be32(p + pos);
        pos += 4;
        if (l == -1) {
            continue;
        }
        if (l < 0 || (size_t)l > len - pos) {
            return 0;
        }
        pos += (size_t)l;
    }
    return pos == len;
}

static void t_mask(const uint8_t *d, size_t n)
{
    static const char *const names[] = {"id", "email", "Email", "note", "x"};
    static const char *const values[] = {"ana@example.com",
                                         "4111111111111111",
                                         "FR7630006000011234567890189",
                                         "plain",
                                         "",
                                         "a@b.cc and 4111 1111 1111 1111",
                                         "@@@",
                                         "9999999999999999999"};
    static const uint32_t types[] = {23, 25, 1043, 114, 3802, 17, 2950, 1700};
    static const uint8_t key[] = "fuzz key fuzz key fuzz key";
    const char *plain[] = {"email", "x"};
    const char *qualified[] = {"users.email", "public.t.x"};
    const char *const *columns = n > 0 && (d[0] & 0x80) ? qualified : plain;
    sl_mask_rule_view r;
    sl_mask *m;
    size_t pos;

    if (n < 3) {
        return;
    }
    r.name = "fuzz";
    r.columns = (char *const *)columns;
    r.ncolumns = d[0] & 1 ? 2 : 0;
    r.detect = (unsigned)(d[0] >> 1) & 7;
    r.how = (d[0] >> 4) & 3;
    m = sl_mask_new(&r, 1, key, sizeof key - 1);
    CHECK(m != NULL);
    if (m == NULL) {
        return;
    }
    pos = 1;
    while (pos + 2 <= n) {
        uint8_t op = d[pos] % 6;
        uint8_t arg = d[pos + 1];
        sl_buf in;
        sl_buf out;
        size_t take = n - pos - 2 < arg ? n - pos - 2 : arg;
        const uint8_t *raw = d + pos + 2;

        pos += 2 + take;
        sl_buf_init(&in);
        sl_buf_init(&out);
        switch (op) {
        case 0: /* any bytes as a description */
            (void)sl_mask_describe(m, raw, take);
            break;
        case 1: { /* any bytes as a row */
            int rc = sl_mask_row(m, raw, take, &out);
            unsigned nc;

            if (rc == SL_MASK_CHANGED) {
                CHECK(framed_row(sl_buf_data(&out), sl_buf_len(&out), &nc));
            } else {
                CHECK(sl_buf_len(&out) == 0);
            }
            break;
        }
        case 3: /* any bytes as a row of the answer about the tables, and how it ends */
            if (arg & 1) {
                sl_mask_catalog_start(m);
            }
            (void)sl_mask_catalog_row(m, raw, take);
            if (arg & 2) {
                sl_mask_catalog_end(m, (arg & 4) != 0);
            }
            break;
        case 2: { /* any bytes as an error */
            int rc = sl_mask_message(m, raw, take, &out);

            if (rc == SL_MASK_CHANGED) {
                CHECK(sl_buf_len(&out) > 0 && sl_buf_data(&out)[sl_buf_len(&out) - 1] == 0);
            } else {
                CHECK(sl_buf_len(&out) == 0);
            }
            break;
        }
        default: { /* a description and a row that fit, built from what the bytes choose */
            unsigned nc = 1 + arg % 4;
            uint8_t b[2];
            unsigned got;

            b[0] = 0;
            b[1] = (uint8_t)nc;
            sl_buf_append(&in, b, 2);
            for (unsigned i = 0; i < nc; i++) {
                const char *nm = names[(take > i ? raw[i] : i) % 5];
                uint8_t f[18] = {0};
                uint32_t t = types[(take > i ? raw[i] >> 3 : 1) % 8];

                sl_buf_append(&in, nm, strlen(nm) + 1);
                sl_pg_put_be32(f + 6, t);
                f[17] = (uint8_t)((arg >> i) & 1);
                sl_buf_append(&in, f, 18);
            }
            CHECK(sl_mask_describe(m, sl_buf_data(&in), sl_buf_len(&in)) == 0);
            sl_buf_free(&in);
            sl_buf_init(&in);
            b[1] = (uint8_t)nc;
            sl_buf_append(&in, b, 2);
            for (unsigned i = 0; i < nc; i++) {
                const char *v = values[(take > i ? raw[take - 1 - i] : i) % 8];
                uint8_t l[4];

                if ((take > i ? raw[i] : 0) % 7 == 0) {
                    sl_pg_put_be32(l, 0xffffffffu);
                    sl_buf_append(&in, l, 4);
                } else {
                    sl_pg_put_be32(l, (uint32_t)strlen(v));
                    sl_buf_append(&in, l, 4);
                    sl_buf_append(&in, v, strlen(v));
                }
            }
            got = (unsigned)sl_mask_row(m, sl_buf_data(&in), sl_buf_len(&in), &out);
            CHECK((int)got == SL_MASK_SAME || (int)got == SL_MASK_CHANGED);
            if ((int)got == SL_MASK_CHANGED) {
                CHECK(framed_row(sl_buf_data(&out), sl_buf_len(&out), &nc));
                /* what was hidden is not found again in what is sent */
                {
                    sl_buf again;
                    int rc;

                    sl_buf_init(&again);
                    rc = sl_mask_row(m, sl_buf_data(&out), sl_buf_len(&out), &again);
                    if (r.how == SL_MASK_NULL) {
                        CHECK(rc == SL_MASK_SAME || rc == SL_MASK_CHANGED);
                    } else if (r.ncolumns == 0) {
                        CHECK(rc == SL_MASK_SAME); /* by pattern only: nothing is left to find */
                    }
                    sl_buf_free(&again);
                }
            }
            break;
        }
        }
        (void)sl_mask_take_count(m);
        sl_buf_free(&in);
        sl_buf_free(&out);
    }
    sl_mask_free(m);
}

/* ---- the journal of deleted rows: any line is read without a crash, and any rows are written as a
 * line that reads back ---- */

static void t_undo(const uint8_t *d, size_t n)
{
    sl_undo_entry u;
    char err[200];
    sl_buf sql;

    if (n < 2) {
        return;
    }
    if (d[0] & 1) { /* any bytes as a line of the journal */
        if (sl_undo_parse((const char *)d + 1, n - 1, &u, err, sizeof err) == 0) {
            sl_buf_init(&sql);
            for (int partial = 0; partial < 2; partial++) {
                sl_buf_free(&sql);
                sl_buf_init(&sql);
                if (sl_undo_sql(&u, partial, &sql, err, sizeof err) == 0) {
                    CHECK(memchr(sl_buf_data(&sql), 0, sl_buf_len(&sql)) == NULL);
                }
            }
            sl_buf_free(&sql);
            sl_undo_free(&u);
        }
        return;
    } else { /* any bytes as the description and the rows of an entry */
        sl_journal_entry e;
        sl_buf line;
        size_t cut = 1 + (size_t)d[1] % (n - 1);
        const uint8_t *body = d + 2;
        size_t blen = n - 2;
        size_t split = blen == 0 ? 0 : (size_t)(cut % (blen + 1));

        memset(&e, 0, sizeof e);
        e.user = "u\"\n";
        e.user_len = 3;
        e.database = "db";
        e.database_len = 2;
        e.rule = "r";
        e.protocol = "simple";
        e.sql = "delete from t";
        e.sql_len = 13;
        e.schema = "s";
        e.table = "t";
        e.tag = "DELETE 1";
        e.rows = d[0] >> 1;
        e.nrows = (size_t)(d[0] >> 2) & 7;
        e.desc = body;
        e.desc_len = split;
        e.data = body + split;
        e.data_len = blen - split;
        e.side_known = d[0] & 2;
        e.update = d[1] >> 7; /* the old row and the new row side by side */
        sl_buf_init(&line);
        CHECK(sl_journal_format(&e, "0123456789abcdef", 1700000000, &line) == 0);
        CHECK(sl_buf_len(&line) > 1 && sl_buf_data(&line)[sl_buf_len(&line) - 1] == '\n');
        CHECK(memchr(sl_buf_data(&line), '\n', sl_buf_len(&line)) ==
              sl_buf_data(&line) + sl_buf_len(&line) - 1);
        CHECK(sl_undo_parse((const char *)sl_buf_data(&line), sl_buf_len(&line), &u, err,
                            sizeof err) == 0);
        sl_undo_free(&u);
        sl_buf_free(&line);
    }
}

/* ---- the admin listener and the counters ---- */

static int fz_gauges_calls;

static void fz_gauges(void *ctx, sl_metrics_gauges *g)
{
    (void)ctx;
    fz_gauges_calls++;
    g->version = "fuzz";
    g->now_unix = 10;
}

static int fz_json(void *ctx, sl_buf *out)
{
    (void)ctx;
    return sl_buf_append(out, "[]\n", 3);
}

static int fz_text(void *ctx, const char *id, sl_buf *out)
{
    (void)ctx;
    (void)id;
    return sl_buf_append(out, "q\n", 2);
}

static int fz_answer(void *ctx, const char *id, int yes)
{
    (void)ctx;
    (void)id;
    (void)yes;
    return -1;
}

/* Any method, path and Authorization header get an answer that is a well-formed response; any label
 * lands in the text of the counters without breaking its lines. */
static void t_admin(const uint8_t *d, size_t n)
{
    static sl_admin *a;
    char method[16], path[200], auth[120];
    size_t m, p, q;
    sl_buf out;
    int status;

    if (n < 3) {
        return;
    }
    if (a == NULL) {
        sl_admin_ops ops = {NULL, fz_gauges, fz_json, fz_text, fz_answer};
        char err[100];

        sl_log_set_sink(fopen("/dev/null", "w")); /* the refusals it logs are not the point */
        a = sl_admin_new("127.0.0.1", "0", "fuzz-token-0123456789", 21, &ops, err, sizeof err);
        if (a == NULL) {
            return;
        }
    }
    m = (size_t)d[0] % sizeof method;
    p = (size_t)d[1] % sizeof path;
    q = (size_t)d[2] % sizeof auth;
    for (size_t i = 0; i < n - 3 && i < sizeof method - 1; i++) {
        method[i] = d[3 + i] == 0 ? 'x' : (char)d[3 + i];
    }
    if (n >= 3) {
        method[m < n - 3 ? m : n - 3] = '\0';
    }
    snprintf(path, sizeof path, "/%.*s", (int)(p < n - 3 ? p : n - 3), (const char *)d + 3);
    snprintf(auth, sizeof auth, "Bearer %.*s", (int)(q < n - 3 ? q : n - 3), (const char *)d + 3);
    for (char *c = path; *c; c++) {
        if (*c == '\0') {
            break;
        }
    }
    sl_buf_init(&out);
    status = sl_admin_respond(a, method, path, d[0] & 1 ? auth : NULL, &out);
    CHECK(status >= 200 && status < 500);
    CHECK(sl_buf_len(&out) > 12 && memcmp(sl_buf_data(&out), "HTTP/1.1 ", 9) == 0);
    sl_buf_free(&out);
    sl_metric_inc(SL_M_RULE_HITS, path, auth);
    sl_buf_init(&out);
    {
        sl_metrics_gauges g = {1, 2, 3, 4, 5, "fuzz"};

        CHECK(sl_metrics_render(&out, &g) == 0);
    }
    sl_buf_free(&out);
    (void)fz_gauges_calls;
}

/* ---- entry point ---- */

typedef void (*target_fn)(const uint8_t *, size_t);

static const target_fn targets[] = {
    t_startup, t_message, t_statements, t_blocking_message, t_json,    t_address,  t_policy, t_sql,
    t_buf,     t_sasl,    t_scanner,    t_srvscan,          t_confirm, t_extstate, t_budget, t_mask,
    t_undo,    t_admin};

size_t sluice_fuzz_target_count(void)
{
    return sizeof targets / sizeof targets[0];
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0) {
        return 0;
    }
    targets[data[0] % (sizeof targets / sizeof targets[0])](data + 1, size - 1);
    return 0;
}
