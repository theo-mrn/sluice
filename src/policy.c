#include "policy.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#define POLICY_MAX_BYTES (1u << 20)
#define DEFAULT_CONFIRM_TIMEOUT_S 120u
#define MAX_CONFIRM_TIMEOUT_S 3600u
#define NAME_MAX_LEN 64
#define MESSAGE_MAX_LEN 200
#define ITEM_MAX_LEN 128

typedef struct {
    const char *source;
    unsigned line;
    char *err;
    size_t errcap;
} ctx;

static int fail(ctx *x, const char *fmt, ...)
{
    va_list ap;
    int n = snprintf(x->err, x->errcap, "%s:%u: ", x->source, x->line);

    if (n > 0 && (size_t)n < x->errcap) {
        va_start(ap, fmt);
        vsnprintf(x->err + n, x->errcap - (size_t)n, fmt, ap);
        va_end(ap);
    }
    return -1;
}

static const struct {
    const char *name;
    uint32_t flag;
} matchers[] = {
    {"update_or_delete_without_where", SL_SQL_UNBOUNDED_WRITE},
    {"delete", SL_SQL_DELETE},
    {"update", SL_SQL_UPDATE},
    {"ddl", SL_SQL_DDL},
    {"drop", SL_SQL_DROP},
    {"truncate", SL_SQL_TRUNCATE},
    {"not_read_only", SL_SQL_NOT_READ_ONLY},
    {"procedural", SL_SQL_PROCEDURAL},
    {"multi_statement", SL_SQL_MULTI},
    {"set_session", SL_SQL_SET_SESSION},
    {"dangerous", SL_SQL_DANGEROUS},
};

/* ---- values ---- */

static void skip_ws(const char **p)
{
    while (**p == ' ' || **p == '\t') {
        (*p)++;
    }
}

/* *pp is on the opening quote of a "basic" or 'literal' string. */
static int parse_string(ctx *x, const char **pp, char **out)
{
    const char *p = *pp;
    char quote = *p++;
    size_t cap = 32;
    size_t n = 0;
    char *buf = malloc(cap);

    if (buf == NULL) {
        return fail(x, "out of memory");
    }
    for (;;) {
        char ch = *p;

        if (ch == '\0') {
            free(buf);
            return fail(x, "unterminated string");
        }
        p++;
        if (ch == quote) {
            break;
        }
        if (quote == '"' && ch == '\\') {
            switch (*p) {
            case '"':
                ch = '"';
                break;
            case '\\':
                ch = '\\';
                break;
            case 'n':
                ch = '\n';
                break;
            case 't':
                ch = '\t';
                break;
            case 'r':
                ch = '\r';
                break;
            default:
                free(buf);
                return fail(x, "unsupported escape sequence in a string");
            }
            p++;
        } else if ((unsigned char)ch < 0x20 && ch != '\t') {
            free(buf);
            return fail(x, "control character in a string");
        }
        if (n + 2 > cap) {
            char *bigger = realloc(buf, cap * 2);

            if (bigger == NULL) {
                free(buf);
                return fail(x, "out of memory");
            }
            buf = bigger;
            cap *= 2;
        }
        buf[n++] = ch;
    }
    buf[n] = '\0';
    *out = buf;
    *pp = p;
    return 0;
}

static void free_list(char **items, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        free(items[i]);
    }
    free(items);
}

/* *pp is on '['. One line only. */
static int parse_list(ctx *x, const char **pp, char ***out, size_t *count)
{
    const char *p = *pp + 1;
    char **items = NULL;
    size_t n = 0;
    size_t cap = 0;

    for (;;) {
        char *s;

        skip_ws(&p);
        if (*p == ']') {
            p++;
            break;
        }
        if (*p != '"' && *p != '\'') {
            free_list(items, n);
            return fail(x, "a list holds strings, like [\"a\", \"b\"]");
        }
        if (parse_string(x, &p, &s) != 0) {
            free_list(items, n);
            return -1;
        }
        if (n == cap) {
            size_t bigger_cap = cap ? cap * 2 : 4;
            char **bigger = realloc(items, bigger_cap * sizeof *bigger);

            if (bigger == NULL) {
                free(s);
                free_list(items, n);
                return fail(x, "out of memory");
            }
            items = bigger;
            cap = bigger_cap;
        }
        items[n++] = s;

        skip_ws(&p);
        if (*p == ',') {
            p++;
        } else if (*p == ']') {
            p++;
            break;
        } else {
            free_list(items, n);
            return fail(x, "expected ',' or ']' in a list");
        }
    }
    *out = items;
    *count = n;
    *pp = p;
    return 0;
}

/* A list may run over several lines, with comments between its items and a comma after the last
 * (as in TOML). `c` is on the opening [ of a value, in the buffer whose lines are cut at their
 * newline (*nl is the NUL that ended this one). When the list does not close on this line, the
 * lines it spans are joined in place into one, the comments inside it blanked, and *nl is moved to
 * the end of the line where it closes. Returns 0, or -1 when it never closes. */
static int join_list_lines(char *c, char *end, char **nl, unsigned *lines)
{
    char quote = 0;
    char *p = c;

    for (; p <= end; p++) {
        if (*p == '\0' && p == *nl) {
            *p = ' '; /* the end of the line that was cut: the list goes on */
            (*lines)++;
            continue;
        }
        if (*p == '\0') {
            return -1;
        }
        if (quote != 0) {
            if (*p == '\\' && quote == '"' && p[1] != '\0') {
                p++;
            } else if (*p == quote) {
                quote = 0;
            } else if (*p == '\n') {
                return -1; /* a string does not run over a line */
            }
        } else if (*p == '"' || *p == '\'') {
            quote = *p;
        } else if (*p == '#') {
            while (p < end && *p != '\n') {
                *p++ = ' ';
            }
            p--;
        } else if (*p == '\n') {
            *p = ' ';
            (*lines)++;
        } else if (*p == ']') {
            if (*lines > 0) { /* it closed on a later line: that line ends the value */
                char *e = strchr(p, '\n');

                if (e != NULL) {
                    *e = '\0';
                }
                *nl = e;
            }
            return 0;
        }
    }
    return -1;
}

/* After a value only blanks and a comment may follow. */
static int expect_end_of_line(ctx *x, const char *p)
{
    skip_ws(&p);
    if (*p != '\0' && *p != '#') {
        return fail(x, "unexpected text after the value");
    }
    return 0;
}

/* ---- the file ---- */

#define SEEN_NAME (UINT64_C(1) << 0)
#define SEEN_MATCH (UINT64_C(1) << 1)
#define SEEN_ACTION (UINT64_C(1) << 2)
#define SEEN_USERS (UINT64_C(1) << 3)
#define SEEN_DATABASES (UINT64_C(1) << 4)
#define SEEN_MESSAGE (UINT64_C(1) << 5)
#define SEEN_TABLES (UINT64_C(1) << 6)
#define SEEN_OUTSIDE (UINT64_C(1) << 7)
#define SEEN_OVER (UINT64_C(1) << 8)
#define SEEN_EXCEPT (UINT64_C(1) << 9)
#define SEEN_SIDE (UINT64_C(1) << 10)
#define SEEN_MAXROWS (UINT64_C(1) << 11)
#define SEEN_RROWS (UINT64_C(1) << 12)
#define SEEN_RBYTES (UINT64_C(1) << 13)
#define SEEN_TBYTES (UINT64_C(1) << 14)
#define SEEN_DUR (UINT64_C(1) << 15)
#define SEEN_IDLE (UINT64_C(1) << 16)
#define SEEN_CONNS (UINT64_C(1) << 17)
#define SEEN_VIA (UINT64_C(1) << 18)
#define SEEN_BROWS (UINT64_C(1) << 19)
#define SEEN_BBYTES (UINT64_C(1) << 20)
#define SEEN_BCHANGED (UINT64_C(1) << 21)
#define SEEN_WINDOW (UINT64_C(1) << 22)
#define SEEN_COLUMNS (UINT64_C(1) << 23)
#define SEEN_DETECT (UINT64_C(1) << 24)
#define SEEN_HOW (UINT64_C(1) << 25)
#define SEEN_JOURNAL (UINT64_C(1) << 26)
#define SEEN_FUNCTIONS (UINT64_C(1) << 27)
#define SEEN_DRY (UINT64_C(1) << 28)
#define SEEN_DURING (UINT64_C(1) << 29)
#define SEEN_DURING_NOT (UINT64_C(1) << 30)
#define SEEN_VFROM (UINT64_C(1) << 31)
#define SEEN_VUNTIL (UINT64_C(1) << 32)
#define SEEN_FP (UINT64_C(1) << 33)
#define SEEN_OUTFP (UINT64_C(1) << 34)
#define SEEN_BSTMT (UINT64_C(1) << 35)
#define SEEN_TXN (UINT64_C(1) << 36)

static void free_rule(sl_rule *r)
{
    free(r->name);
    free(r->message);
    free_list(r->users, r->nusers);
    free_list(r->except_users, r->nexcept);
    free_list(r->databases, r->ndatabases);
    free_list(r->tables, r->ntables);
    free_list(r->outside_tables, r->noutside);
    free_list(r->functions, r->nfunctions);
    free_list(r->fingerprints, r->nfingerprints);
    free_list(r->outside_fingerprints, r->noutside_fingerprints);
    free_list(r->mask_columns, r->nmask_columns);
    memset(r, 0, sizeof *r);
}

void sl_policy_free(sl_policy *p)
{
    for (size_t i = 0; i < p->nrules; i++) {
        free_rule(&p->rules[i]);
    }
    free(p->rules);
    memset(p, 0, sizeof *p);
    p->deny_uninspectable = 1;
    p->confirm_timeout_s = DEFAULT_CONFIRM_TIMEOUT_S;
}

/* "table" or "schema.table": each part 1 to 63 characters of letters, digits, '_', '$' and '-'.
 * These names are compared to what the SQL parser reports, and end up in the log. */
static int valid_table_entry(const char *s);

static int valid_fingerprint(const char *s)
{
    if (strlen(s) != 16) {
        return 0;
    }
    for (; *s; s++) {
        if (!((*s >= '0' && *s <= '9') || (*s >= 'a' && *s <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

/* ---- time ---- */

static long long g_fixed_time = -1;

void sl_policy_set_time(long long unix)
{
    g_fixed_time = unix;
}

static long long now_unix(void)
{
    return g_fixed_time >= 0 ? g_fixed_time : (long long)time(NULL);
}

/* days since 1970-01-01 of a civil date (proleptic Gregorian) */
static long long days_from_civil(long long y, unsigned m, unsigned d)
{
    long long era;
    unsigned yoe, doy, doe;

    y -= m <= 2;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = (unsigned)(y - era * 400);
    doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (long long)doe - 719468;
}

/* "2026-12-01", or "2026-12-01T18:30Z" / "2026-12-01T18:30:15Z" (always UTC). 0, or -1. */
int sl_policy_parse_instant(const char *s, long long *out)
{
    unsigned y, mo, d, h = 0, mi = 0, se = 0;
    int n = 0;
    int got = sscanf(s, "%4u-%2u-%2u%n", &y, &mo, &d, &n);

    if (got != 3 || n != 10 || mo < 1 || mo > 12 || d < 1 || d > 31) {
        return -1;
    }
    if (s[n] != '\0') {
        int m2 = 0;

        if (s[n] != 'T' || sscanf(s + n + 1, "%2u:%2u%n", &h, &mi, &m2) != 2 || m2 != 5) {
            return -1;
        }
        n += 1 + m2;
        if (s[n] == ':') {
            int m3 = 0;

            if (sscanf(s + n + 1, "%2u%n", &se, &m3) != 1 || m3 != 2) {
                return -1;
            }
            n += 1 + m3;
        }
        if (s[n] != 'Z' || s[n + 1] != '\0' || h > 23 || mi > 59 || se > 59) {
            return -1;
        }
    }
    *out = days_from_civil(y, mo, d) * 86400 + (long long)h * 3600 + (long long)mi * 60 + se;
    return 0;
}

static int day_index(const char *s, size_t n)
{
    static const char *const names[] = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"};

    for (int i = 0; i < 7; i++) {
        if (n == 3 && strncasecmp(s, names[i], 3) == 0) {
            return i;
        }
    }
    return -1;
}

/* "mon-fri 08:00-19:00", "sat,sun 00:00-24:00", "22:00-06:00" (every day, past midnight). 0, or -1.
 */
static int parse_week_window(const char *s, sl_window *w)
{
    const char *sp = strchr(s, ' ');
    const char *t = sp != NULL ? sp + 1 : s;
    unsigned h1, m1, h2, m2;
    int n = 0;

    w->days = 0x7f;
    if (sp != NULL) {
        w->days = 0;
        for (const char *p = s; p < sp;) {
            const char *e = p;
            int a, b;

            while (e < sp && *e != ',' && *e != '-') {
                e++;
            }
            a = day_index(p, (size_t)(e - p));
            b = a;
            if (e < sp && *e == '-') {
                const char *f = e + 1;

                while (f < sp && *f != ',') {
                    f++;
                }
                b = day_index(e + 1, (size_t)(f - e - 1));
                e = f;
            }
            if (a < 0 || b < 0) {
                return -1;
            }
            for (int k = a;; k = (k + 1) % 7) { /* mon-fri, and also sat-mon */
                w->days |= (uint8_t)(1u << k);
                if (k == b) {
                    break;
                }
            }
            p = e < sp ? e + 1 : e;
        }
    }
    if (sscanf(t, "%2u:%2u-%2u:%2u%n", &h1, &m1, &h2, &m2, &n) != 4 || t[n] != '\0' || h1 > 23 ||
        m1 > 59 || m2 > 59 || h2 > 24 || (h2 == 24 && m2 != 0)) {
        return -1;
    }
    w->from = (uint16_t)(h1 * 60 + m1);
    w->to = (uint16_t)(h2 * 60 + m2);
    return w->from == w->to ? -1 : 0;
}

static int in_windows(const sl_window *w, size_t n, long long now)
{
    long long days = now / 86400;
    unsigned minute = (unsigned)((now % 86400) / 60);
    int wd = (int)((days % 7 + 11) % 7); /* 1970-01-01 was a Thursday: Monday is 0 */

    for (size_t i = 0; i < n; i++) {
        int today = (w[i].days >> wd) & 1;
        int yesterday = (w[i].days >> ((wd + 6) % 7)) & 1;

        if (w[i].to > w[i].from) {
            if (today && minute >= w[i].from && minute < w[i].to) {
                return 1;
            }
        } else if ((today && minute >= w[i].from) || (yesterday && minute < w[i].to)) {
            return 1; /* past midnight: the part before it belongs to the day that started it */
        }
    }
    return 0;
}

static int time_fits(const sl_rule *r)
{
    long long now;

    if (r->nduring == 0 && r->nexcept_during == 0 && r->valid_from == 0 && r->valid_until == 0) {
        return 1;
    }
    now = now_unix();
    return !(r->valid_from != 0 && now < r->valid_from) &&
           !(r->valid_until != 0 && now >= r->valid_until) &&
           (r->nduring == 0 || in_windows(r->during, r->nduring, now)) &&
           (r->nexcept_during == 0 || !in_windows(r->except_during, r->nexcept_during, now));
}

/* name, schema.name, or either with a * at the end (a prefix) */
static int valid_function_entry(const char *s)
{
    size_t n = strlen(s);
    char copy[160];

    if (n == 0 || n >= sizeof copy) {
        return 0;
    }
    memcpy(copy, s, n + 1);
    if (copy[n - 1] == '*') {
        copy[n - 1] = '\0';
        if (copy[0] == '\0' || copy[strlen(copy) - 1] == '.') {
            return 0;
        }
    }
    for (const char *q = copy; *q; q++) {
        if (*q == '-') {
            return 0; /* a table may have one; a function written without quotes does not */
        }
    }
    return copy[0] == '\0' ? 0 : valid_table_entry(copy);
}

static int valid_table_entry(const char *s)
{
    size_t part = 0;
    int dots = 0;

    for (; *s; s++) {
        unsigned char ch = (unsigned char)*s;

        if (ch == '.') {
            if (part == 0 || ++dots > 1) {
                return 0;
            }
            part = 0;
            continue;
        }
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
              ch == '_' || ch == '$' || ch == '-') ||
            ++part > 63) {
            return 0;
        }
    }
    return part > 0;
}

static int ident_char_ok(char ch)
{
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
           ch == '_' || ch == '.' || ch == ':' || ch == '-';
}

/* Checks a rule once all its keys have been read. */
static int check_rule(ctx *x, const sl_policy *p, const sl_rule *r, uint64_t seen, size_t index)
{
    size_t len;

    if (!(seen & SEEN_NAME)) {
        return fail(x, "this rule has no name");
    }
    if (!(seen & SEEN_MATCH)) {
        return fail(x, "rule '%s' has no match", r->name);
    }
    len = strlen(r->name);
    if (len == 0 || len > NAME_MAX_LEN) {
        return fail(x, "a rule name must have 1 to %d characters", NAME_MAX_LEN);
    }
    for (size_t i = 0; i < len; i++) {
        if (!ident_char_ok(r->name[i])) {
            return fail(x, "rule name '%s': only letters, digits and _ . : - are allowed", r->name);
        }
    }
    if ((seen & SEEN_OVER) && (!r->confirm || r->limit)) {
        return fail(x, "rule '%s': over_rows only goes with action = \"confirm\"", r->name);
    }
    if ((seen & SEEN_SIDE) && (!r->confirm || r->limit)) {
        return fail(x, "rule '%s': side_effects only goes with action = \"confirm\"", r->name);
    }
    if ((seen & SEEN_VIA) && (!r->confirm || r->limit)) {
        return fail(x, "rule '%s': confirm_via only goes with action = \"confirm\"", r->name);
    }
    if ((r->nduring > 0 || r->nexcept_during > 0 || r->valid_from != 0 || r->valid_until != 0) &&
        (r->conn_limit || r->mask)) {
        return fail(x,
                    "rule '%s': during, except_during, valid_from and valid_until go with rules "
                    "about statements, not with limits of a connection or mask",
                    r->name);
    }
    if (r->valid_from != 0 && r->valid_until != 0 && r->valid_until <= r->valid_from) {
        return fail(x, "rule '%s': valid_until is not after valid_from", r->name);
    }
    if (r->dry_run && (r->conn_limit || r->mask || r->alert || (!r->deny && !r->confirm))) {
        return fail(x,
                    "rule '%s': dry_run goes with a rule that refuses or asks about statements "
                    "(deny, kill, confirm or a limit with max_rows)",
                    r->name);
    }
    if (seen & SEEN_JOURNAL) {
        if (!r->confirm || r->conn_limit || r->mask || (r->limit && !(seen & SEEN_MAXROWS))) {
            return fail(
                x,
                "rule '%s': journal only goes with action = \"confirm\" or action = \"limit\" "
                "(with max_rows)",
                r->name);
        }
        if (r->any || (r->match != SL_SQL_DELETE && r->match != SL_SQL_UPDATE)) {
            return fail(x,
                        "rule '%s': journal keeps the rows a DELETE removes or the old values of "
                        "an UPDATE (PostgreSQL 18 or later): write match = \"delete\" or "
                        "match = \"update\"",
                        r->name);
        }
    }
    if ((seen & (SEEN_COLUMNS | SEEN_DETECT | SEEN_HOW)) && !r->mask) {
        return fail(x, "rule '%s': columns, detect and how only go with action = \"mask\"",
                    r->name);
    }
    if (r->mask) {
        if (!(seen & (SEEN_COLUMNS | SEEN_DETECT))) {
            return fail(x,
                        "rule '%s': action = \"mask\" needs columns (names to hide) or detect "
                        "(what to look for in any text)",
                        r->name);
        }
        if (!r->any || r->ntables > 0 || r->noutside > 0) {
            return fail(x,
                        "rule '%s': a mask is about the rows a user gets, not about a kind of "
                        "statement or a table: write match = \"any\", and no tables",
                        r->name);
        }
        if (r->conn_limit || r->over_rows != 0 || (seen & (SEEN_OVER | SEEN_SIDE | SEEN_MAXROWS))) {
            return fail(x, "rule '%s': a mask has no row counts or limits", r->name);
        }
        {
            size_t n = 1;

            for (size_t i = 0; i < index; i++) {
                n += p->rules[i].mask != 0;
            }
            if (n > SL_MASK_MAX_RULES) {
                return fail(x, "at most %d rules may be masks", SL_MASK_MAX_RULES);
            }
        }
    }
    if ((seen & SEEN_WINDOW) && !r->budget) {
        return fail(x,
                    "rule '%s': window only goes with budget_rows, budget_bytes, budget_changed or "
                    "budget_statements",
                    r->name);
    }
    if (r->budget) {
        size_t n = 1;

        for (size_t i = 0; i < index; i++) {
            n += p->rules[i].budget != 0;
        }
        if (n > SL_MAX_BUDGETS) {
            return fail(x, "at most %d rules may have a budget", SL_MAX_BUDGETS);
        }
    }
    if ((seen & SEEN_MAXROWS) && !r->limit) {
        return fail(x, "rule '%s': max_rows only goes with action = \"limit\"", r->name);
    }
    if (r->conn_limit) {
        if (!r->limit) {
            return fail(
                x,
                "rule '%s': max_result_rows, max_result_bytes, max_total_bytes, "
                "max_duration, max_idle_in_transaction, max_transaction, max_connections and the "
                "budgets "
                "only go with "
                "action = \"limit\"",
                r->name);
        }
        if (seen & SEEN_MAXROWS) {
            return fail(x,
                        "rule '%s': max_rows caps a DELETE or UPDATE, the other limits cap a "
                        "connection: use two rules",
                        r->name);
        }
        if (!r->any || r->ntables > 0 || r->noutside > 0) {
            return fail(
                x,
                "rule '%s': a limit on results, volume or duration is about the connection, "
                "not about a kind of statement or a table: write match = \"any\", and no "
                "tables",
                r->name);
        }
    } else if (r->limit && !(seen & SEEN_MAXROWS)) {
        return fail(
            x,
            "rule '%s': action = \"limit\" needs max_rows (rows of a DELETE or UPDATE), or "
            "max_result_rows, max_result_bytes, max_total_bytes, max_duration, "
            "max_idle_in_transaction, max_transaction, max_connections, budget_rows, budget_bytes, "
            "budget_changed, budget_statements",
            r->name);
    }
    for (size_t i = 0; i < index; i++) {
        if (strcmp(p->rules[i].name, r->name) == 0) {
            return fail(x, "two rules are named '%s'", r->name);
        }
    }
    return 0;
}

/* "100": a count of rows, written as a string because the policy format has no numbers. */
static int parse_count(const char *s, unsigned long long *out)
{
    unsigned long long v = 0;
    size_t n = 0;

    for (; s[n]; n++) {
        if (s[n] < '0' || s[n] > '9' || n >= 15) {
            return 0;
        }
        v = v * 10 + (unsigned long long)(s[n] - '0');
    }
    *out = v;
    return n > 0;
}

/* "4096", "10K", "10MB", "2G": a number of bytes (1024 to the K), at least 1. */
static int parse_bytes(const char *s, unsigned long long *out)
{
    unsigned long long v = 0;
    size_t n = 0;

    while (s[n] >= '0' && s[n] <= '9' && n < 12) {
        v = v * 10 + (unsigned long long)(s[n] - '0');
        n++;
    }
    if (n == 0 || v == 0) {
        return 0;
    }
    {
        const char *u = s + n;

        if (*u == '\0' || strcmp(u, "B") == 0) {
            *out = v;
            return 1;
        }
        if (strcmp(u, "K") == 0 || strcmp(u, "KB") == 0) {
            v <<= 10;
        } else if (strcmp(u, "M") == 0 || strcmp(u, "MB") == 0) {
            v <<= 20;
        } else if (strcmp(u, "G") == 0 || strcmp(u, "GB") == 0) {
            v <<= 30;
        } else {
            return 0;
        }
    }
    *out = v;
    return 1;
}

/* "30m", "1h", "24h", "7d": the window of a budget, from a minute to a week. */
static int parse_window(const char *s, unsigned *out)
{
    unsigned long long v = 0;
    size_t n = 0;

    while (s[n] >= '0' && s[n] <= '9' && n < 6) {
        v = v * 10 + (unsigned long long)(s[n] - '0');
        n++;
    }
    if (n == 0 || s[n] == '\0' || s[n + 1] != '\0') {
        return 0;
    }
    if (s[n] == 'm') {
        v *= 60;
    } else if (s[n] == 'h') {
        v *= 3600;
    } else if (s[n] == 'd') {
        v *= 86400;
    } else {
        return 0;
    }
    if (v < 60 || v > 7 * 86400) {
        return 0;
    }
    *out = (unsigned)v;
    return 1;
}

/* "90", "90s", "2m", "1h": a number of seconds, at least 1 and at most an hour. */
static int parse_duration(const char *s, unsigned *out)
{
    unsigned long long v = 0;
    size_t n = 0;

    while (s[n] >= '0' && s[n] <= '9' && n < 6) {
        v = v * 10 + (unsigned long long)(s[n] - '0');
        n++;
    }
    if (n == 0) {
        return 0;
    }
    if (s[n] == 'm' && s[n + 1] == '\0') {
        v *= 60;
    } else if (s[n] == 'h' && s[n + 1] == '\0') {
        v *= 3600;
    } else if (!(s[n] == '\0' || (s[n] == 's' && s[n + 1] == '\0'))) {
        return 0;
    }
    if (v < 1 || v > MAX_CONFIRM_TIMEOUT_S) {
        return 0;
    }
    *out = (unsigned)v;
    return 1;
}

int sl_policy_parse(sl_policy *p, const char *text, size_t len, const char *source, char *err,
                    size_t errcap)
{
    ctx x = {source, 0, err, errcap};
    char *buf;
    char *line;
    char *end;
    int in_rule = 0;
    unsigned seen_top = 0;
    uint64_t seen = 0;
    unsigned rule_line = 0;
    int rc = -1;

    memset(p, 0, sizeof *p);
    p->deny_uninspectable = 1;
    p->confirm_timeout_s = DEFAULT_CONFIRM_TIMEOUT_S;

    if (len > POLICY_MAX_BYTES) {
        return fail(&x, "the policy is larger than %u bytes", POLICY_MAX_BYTES);
    }
    buf = malloc(len + 1);
    if (buf == NULL) {
        return fail(&x, "out of memory");
    }
    memcpy(buf, text, len);
    buf[len] = '\0';
    if (strlen(buf) != len) {
        free(buf);
        return fail(&x, "the policy contains a NUL byte");
    }

    line = buf;
    end = buf + len;
    while (line <= end) {
        char *nl = strchr(line, '\n');
        const char *c;
        size_t ll;

        x.line++;
        if (nl != NULL) {
            *nl = '\0';
        }
        ll = strlen(line);
        if (ll > 0 && line[ll - 1] == '\r') {
            line[ll - 1] = '\0';
        }

        c = line;
        skip_ws(&c);
        if (*c == '\0' || *c == '#') {
            goto next_line;
        }

        if (*c == '[') {
            /* only [[rule]] exists */
            sl_rule *r;
            sl_rule *grown;

            if (strncmp(c, "[[rule]]", 8) != 0) {
                fail(&x, "unknown table (the only one is [[rule]])");
                goto out;
            }
            if (expect_end_of_line(&x, c + 8) != 0) {
                goto out;
            }
            if (in_rule) {
                unsigned here = x.line;

                x.line = rule_line;
                if (check_rule(&x, p, &p->rules[p->nrules - 1], seen, p->nrules - 1) != 0) {
                    goto out;
                }
                x.line = here;
            }
            grown = realloc(p->rules, (p->nrules + 1) * sizeof *grown);
            if (grown == NULL) {
                fail(&x, "out of memory");
                goto out;
            }
            p->rules = grown;
            r = &p->rules[p->nrules++];
            memset(r, 0, sizeof *r);
            r->deny = 1;
            in_rule = 1;
            seen = 0;
            rule_line = x.line;
        } else {
            /* key = value */
            char key[32];
            size_t kl = 0;
            sl_rule *r = in_rule ? &p->rules[p->nrules - 1] : NULL;
            char *str = NULL;
            char **list = NULL;
            size_t list_n = 0;
            int is_list = 0;

            while (ident_char_ok(c[kl]) && c[kl] != '.' && c[kl] != ':' && kl < sizeof key - 1) {
                key[kl] = c[kl];
                kl++;
            }
            key[kl] = '\0';
            if (kl == 0) {
                fail(&x, "expected a key");
                goto out;
            }
            c += kl;
            skip_ws(&c);
            if (*c != '=') {
                fail(&x, "expected '=' after '%s'", key);
                goto out;
            }
            c++;
            skip_ws(&c);

            if (strncmp(c, "\"\"\"", 3) == 0 || strncmp(c, "'''", 3) == 0) {
                fail(&x, "multi-line strings are not supported");
                goto out;
            }
            if (*c == '"' || *c == '\'') {
                if (parse_string(&x, &c, &str) != 0) {
                    goto out;
                }
            } else if (*c == '[') {
                is_list = 1;
                {
                    unsigned more = 0;

                    if (join_list_lines((char *)(uintptr_t)c, end, &nl, &more) != 0) {
                        fail(&x, "a list is never closed (it needs a ])");
                        goto out;
                    }
                    if (parse_list(&x, &c, &list, &list_n) != 0) {
                        goto out; /* reported at the line where the list starts */
                    }
                    x.line += more;
                }
            } else {
                fail(&x,
                     "unsupported value for '%s': only strings and lists of strings are accepted",
                     key);
                goto out;
            }
            if (expect_end_of_line(&x, c) != 0) {
                free(str);
                free_list(list, list_n);
                goto out;
            }

#define NEED_STRING()                                                                              \
    do {                                                                                           \
        if (is_list) {                                                                             \
            fail(&x, "'%s' takes a string, not a list", key);                                      \
            free_list(list, list_n);                                                               \
            goto out;                                                                              \
        }                                                                                          \
    } while (0)
#define NEED_LIST()                                                                                \
    do {                                                                                           \
        if (!is_list) {                                                                            \
            fail(&x, "'%s' takes a list of strings, like [\"a\", \"b\"]", key);                    \
            free(str);                                                                             \
            goto out;                                                                              \
        }                                                                                          \
        if (list_n == 0) {                                                                         \
            fail(&x, "'%s' is an empty list, which would match nobody", key);                      \
            free_list(list, list_n);                                                               \
            goto out;                                                                              \
        }                                                                                          \
        for (size_t i_ = 0; i_ < list_n; i_++) {                                                   \
            if (list[i_][0] == '\0' || strlen(list[i_]) > ITEM_MAX_LEN) {                          \
                fail(&x, "'%s' holds an empty or too long entry", key);                            \
                free_list(list, list_n);                                                           \
                goto out;                                                                          \
            }                                                                                      \
        }                                                                                          \
    } while (0)
#define ONCE(bit)                                                                                  \
    do {                                                                                           \
        if (seen & (bit)) {                                                                        \
            fail(&x, "'%s' is given twice", key);                                                  \
            free(str);                                                                             \
            free_list(list, list_n);                                                               \
            goto out;                                                                              \
        }                                                                                          \
        seen |= (bit);                                                                             \
    } while (0)

            if (!in_rule) {
                if (strcmp(key, "mode") == 0 || strcmp(key, "on_uninspectable") == 0) {
                    unsigned bit = key[0] == 'm' ? 1u : 2u;

                    NEED_STRING();
                    if (seen_top & bit) {
                        fail(&x, "'%s' is given twice", key);
                        free(str);
                        goto out;
                    }
                    seen_top |= bit;
                    if (bit == 1u) {
                        if (strcmp(str, "audit") == 0) {
                            p->mode = SL_MODE_AUDIT;
                        } else if (strcmp(str, "enforce") == 0) {
                            p->mode = SL_MODE_ENFORCE;
                        } else {
                            fail(&x, "mode must be \"audit\" or \"enforce\"");
                            free(str);
                            goto out;
                        }
                    } else {
                        if (strcmp(str, "deny") == 0) {
                            p->deny_uninspectable = 1;
                        } else if (strcmp(str, "allow") == 0) {
                            p->deny_uninspectable = 0;
                        } else {
                            fail(&x, "on_uninspectable must be \"deny\" or \"allow\"");
                            free(str);
                            goto out;
                        }
                    }
                    free(str);
                } else if (strcmp(key, "confirm_timeout") == 0) {
                    NEED_STRING();
                    if (seen_top & 4u) {
                        fail(&x, "'%s' is given twice", key);
                        free(str);
                        goto out;
                    }
                    seen_top |= 4u;
                    if (!parse_duration(str, &p->confirm_timeout_s)) {
                        fail(&x, "confirm_timeout is a time from 1 second to 1 hour, like \"90s\" "
                                 "or \"2m\"");
                        free(str);
                        goto out;
                    }
                    free(str);
                } else {
                    fail(&x,
                         "unknown key '%s' (before the first [[rule]] only mode, on_uninspectable "
                         "and confirm_timeout exist)",
                         key);
                    free(str);
                    free_list(list, list_n);
                    goto out;
                }
            } else if (strcmp(key, "name") == 0) {
                NEED_STRING();
                ONCE(SEEN_NAME);
                r->name = str;
            } else if (strcmp(key, "match") == 0) {
                size_t k;

                NEED_STRING();
                ONCE(SEEN_MATCH);
                if (strcmp(str, "any") == 0) {
                    r->any = 1; /* every statement: the table or user conditions do the choosing */
                    free(str);
                } else {
                    for (k = 0; k < sizeof matchers / sizeof matchers[0]; k++) {
                        if (strcmp(str, matchers[k].name) == 0) {
                            r->match = matchers[k].flag;
                            break;
                        }
                    }
                    if (k == sizeof matchers / sizeof matchers[0]) {
                        fail(&x, "unknown match '%s'", str);
                        free(str);
                        goto out;
                    }
                    free(str);
                }
            } else if (strcmp(key, "action") == 0) {
                NEED_STRING();
                ONCE(SEEN_ACTION);
                if (strcmp(str, "deny") == 0) {
                    r->deny = 1;
                } else if (strcmp(str, "allow") == 0) {
                    r->deny = 0;
                } else if (strcmp(str, "confirm") == 0) {
                    r->deny = 0;
                    r->confirm = 1;
                } else if (strcmp(str, "limit") == 0) {
                    r->deny = 0;
                    r->confirm = 1; /* it runs the statement and looks at the count, like confirm */
                    r->limit = 1;
                } else if (strcmp(str, "mask") == 0) {
                    r->deny = 0;
                    r->mask = 1;
                } else if (strcmp(str, "alert") == 0) {
                    r->deny = 0;
                    r->alert = 1;
                } else if (strcmp(str, "kill") == 0) {
                    r->deny = 1;
                    r->kill = 1;
                } else {
                    fail(&x, "action must be \"deny\", \"allow\", \"confirm\", \"limit\", "
                             "\"mask\", \"alert\" or \"kill\"");
                    free(str);
                    goto out;
                }
                free(str);
            } else if (strcmp(key, "over_rows") == 0) {
                unsigned long long v = 0;

                NEED_STRING();
                ONCE(SEEN_OVER);
                if (!parse_count(str, &v)) {
                    fail(&x, "over_rows is a number of rows written as a string, like \"100\"");
                    free(str);
                    goto out;
                }
                free(str);
                r->over_rows = v;
            } else if (strcmp(key, "max_rows") == 0) {
                unsigned long long v = 0;

                NEED_STRING();
                ONCE(SEEN_MAXROWS);
                if (!parse_count(str, &v)) {
                    fail(&x, "max_rows is a number of rows written as a string, like \"1000\"");
                    free(str);
                    goto out;
                }
                free(str);
                r->over_rows = v;
            } else if (strcmp(key, "max_result_rows") == 0) {
                NEED_STRING();
                ONCE(SEEN_RROWS);
                if (!parse_count(str, &r->max_result_rows) || r->max_result_rows == 0) {
                    fail(&x,
                         "max_result_rows is a number of rows written as a string, like \"10000\"");
                    free(str);
                    goto out;
                }
                free(str);
                r->conn_limit = 1;
            } else if (strcmp(key, "max_result_bytes") == 0 ||
                       strcmp(key, "max_total_bytes") == 0) {
                int total = key[4] == 't';

                NEED_STRING();
                ONCE(total ? SEEN_TBYTES : SEEN_RBYTES);
                if (!parse_bytes(str, total ? &r->max_total_bytes : &r->max_result_bytes)) {
                    fail(&x, "%s is a size written as a string, like \"10MB\" or \"500K\"", key);
                    free(str);
                    goto out;
                }
                free(str);
                r->conn_limit = 1;
            } else if (strcmp(key, "max_duration") == 0) {
                NEED_STRING();
                ONCE(SEEN_DUR);
                if (!parse_duration(str, &r->max_duration_s)) {
                    fail(&x,
                         "max_duration is a time from 1 second to 1 hour, like \"30s\" or \"5m\"");
                    free(str);
                    goto out;
                }
                free(str);
                r->conn_limit = 1;
            } else if (strcmp(key, "max_idle_in_transaction") == 0) {
                NEED_STRING();
                ONCE(SEEN_IDLE);
                if (!parse_duration(str, &r->max_idle_in_transaction_s)) {
                    fail(&x,
                         "max_idle_in_transaction is a time from 1 second to 1 hour, like \"2m\"");
                    free(str);
                    goto out;
                }
                free(str);
                r->conn_limit = 1;
            } else if (strcmp(key, "max_transaction") == 0) {
                NEED_STRING();
                ONCE(SEEN_TXN);
                if (!parse_duration(str, &r->max_transaction_s)) {
                    fail(&x, "max_transaction is a time from 1 second to 1 hour, like \"10m\"");
                    free(str);
                    goto out;
                }
                free(str);
                r->conn_limit = 1;
            } else if (strcmp(key, "budget_rows") == 0 || strcmp(key, "budget_changed") == 0 ||
                       strcmp(key, "budget_statements") == 0) {
                int changed = key[7] == 'c';
                int stmts = key[7] == 's';
                unsigned long long *to = stmts     ? &r->budget_statements
                                         : changed ? &r->budget_changed
                                                   : &r->budget_rows;

                NEED_STRING();
                ONCE(stmts ? SEEN_BSTMT : changed ? SEEN_BCHANGED : SEEN_BROWS);
                if (!parse_count(str, to) || *to == 0) {
                    fail(&x, "%s is a number written as a string, like \"100000\"", key);
                    free(str);
                    goto out;
                }
                free(str);
                r->conn_limit = r->budget = 1;
            } else if (strcmp(key, "budget_bytes") == 0) {
                NEED_STRING();
                ONCE(SEEN_BBYTES);
                if (!parse_bytes(str, &r->budget_bytes)) {
                    fail(&x,
                         "budget_bytes is a size written as a string, like \"500MB\" or \"2G\"");
                    free(str);
                    goto out;
                }
                free(str);
                r->conn_limit = r->budget = 1;
            } else if (strcmp(key, "window") == 0) {
                NEED_STRING();
                ONCE(SEEN_WINDOW);
                if (!parse_window(str, &r->window_s)) {
                    fail(
                        &x,
                        "window is a time from 1 minute to 7 days, like \"30m\", \"1h\" or \"7d\"");
                    free(str);
                    goto out;
                }
                free(str);
            } else if (strcmp(key, "max_connections") == 0) {
                NEED_STRING();
                ONCE(SEEN_CONNS);
                if (!parse_count(str, &r->max_connections) || r->max_connections == 0) {
                    fail(&x, "max_connections is a number written as a string, like \"2\"");
                    free(str);
                    goto out;
                }
                free(str);
                r->conn_limit = 1;
            } else if (strcmp(key, "columns") == 0) {
                NEED_LIST();
                ONCE(SEEN_COLUMNS);
                if (list_n > SL_MASK_MAX_COLUMNS) {
                    fail(&x, "columns holds at most %d names", SL_MASK_MAX_COLUMNS);
                    free_list(list, list_n);
                    goto out;
                }
                for (size_t i_ = 0; i_ < list_n; i_++) {
                    /* column, table.column or schema.table.column: each part at most 63 bytes */
                    size_t parts = 1, run = 0;
                    int bad_ = list[i_][0] == '\0';

                    for (const char *q_ = list[i_];; q_++) {
                        if (*q_ == '.' || *q_ == '\0') {
                            bad_ |= run == 0 || run > SL_MASK_NAME_MAX;
                            run = 0;
                            if (*q_ == '\0') {
                                break;
                            }
                            parts++;
                        } else {
                            run++;
                        }
                    }
                    if (bad_ || parts > 3) {
                        fail(&x,
                             "a name in columns is column, table.column or schema.table.column, "
                             "each part of 1 to %d bytes",
                             SL_MASK_NAME_MAX);
                        free_list(list, list_n);
                        goto out;
                    }
                }
                r->mask_columns = list;
                r->nmask_columns = list_n;
            } else if (strcmp(key, "detect") == 0) {
                NEED_LIST();
                ONCE(SEEN_DETECT);
                for (size_t i_ = 0; i_ < list_n; i_++) {
                    if (strcmp(list[i_], "email") == 0) {
                        r->mask_detect |= SL_MASK_EMAIL;
                    } else if (strcmp(list[i_], "card") == 0) {
                        r->mask_detect |= SL_MASK_CARD;
                    } else if (strcmp(list[i_], "iban") == 0) {
                        r->mask_detect |= SL_MASK_IBAN;
                    } else {
                        fail(&x, "detect takes \"email\", \"card\" and \"iban\"");
                        free_list(list, list_n);
                        goto out;
                    }
                }
                free_list(list, list_n);
            } else if (strcmp(key, "how") == 0) {
                NEED_STRING();
                ONCE(SEEN_HOW);
                if (strcmp(str, "hash") == 0) {
                    r->mask_how = SL_MASK_HASH;
                } else if (strcmp(str, "partial") == 0) {
                    r->mask_how = SL_MASK_PARTIAL;
                } else if (strcmp(str, "null") == 0) {
                    r->mask_how = SL_MASK_NULL;
                } else if (strcmp(str, "redact") == 0) {
                    r->mask_how = SL_MASK_REDACT;
                } else {
                    fail(&x, "how is \"hash\" (the default), \"partial\", \"null\" or \"redact\"");
                    free(str);
                    goto out;
                }
                free(str);
            } else if (strcmp(key, "journal") == 0) {
                NEED_STRING();
                ONCE(SEEN_JOURNAL);
                if (strcmp(str, "on") == 0) {
                    r->journal = SL_JOURNAL_ON;
                } else if (strcmp(str, "required") == 0) {
                    r->journal = SL_JOURNAL_REQUIRED;
                } else {
                    fail(&x, "journal is \"on\" (record the rows when it can) or \"required\" (do "
                             "not apply "
                             "the DELETE when it cannot)");
                    free(str);
                    goto out;
                }
                free(str);
            } else if (strcmp(key, "confirm_via") == 0) {
                NEED_STRING();
                ONCE(SEEN_VIA);
                if (strcmp(str, "session") == 0) {
                    r->via = SL_VIA_SESSION;
                } else if (strcmp(str, "operator") == 0) {
                    r->via = SL_VIA_OPERATOR;
                } else {
                    fail(&x, "confirm_via is \"session\" (the person who sent the statement) or "
                             "\"operator\" (the terminal or command of the proxy)");
                    free(str);
                    goto out;
                }
                free(str);
            } else if (strcmp(key, "side_effects") == 0) {
                NEED_STRING();
                ONCE(SEEN_SIDE);
                if (strcmp(str, "on") != 0 && strcmp(str, "off") != 0) {
                    fail(&x, "side_effects is \"on\" (the default) or \"off\"");
                    free(str);
                    goto out;
                }
                r->no_side_effects = strcmp(str, "off") == 0;
                free(str);
            } else if (strcmp(key, "message") == 0) {
                NEED_STRING();
                ONCE(SEEN_MESSAGE);
                if (strlen(str) > MESSAGE_MAX_LEN) {
                    fail(&x, "the message is longer than %d characters", MESSAGE_MAX_LEN);
                    free(str);
                    goto out;
                }
                for (const char *m = str; *m; m++) {
                    if ((unsigned char)*m < 0x20 || (unsigned char)*m > 0x7e || *m == '\\') {
                        fail(&x, "the message may only hold printable ASCII, without backslashes");
                        free(str);
                        goto out;
                    }
                }
                r->message = str;
            } else if (strcmp(key, "users") == 0) {
                NEED_LIST();
                ONCE(SEEN_USERS);
                r->users = list;
                r->nusers = list_n;
            } else if (strcmp(key, "except_users") == 0) {
                NEED_LIST();
                ONCE(SEEN_EXCEPT);
                r->except_users = list;
                r->nexcept = list_n;
            } else if (strcmp(key, "databases") == 0) {
                NEED_LIST();
                ONCE(SEEN_DATABASES);
                r->databases = list;
                r->ndatabases = list_n;
            } else if (strcmp(key, "tables") == 0 || strcmp(key, "outside_tables") == 0) {
                int outside = key[0] == 'o';

                NEED_LIST();
                ONCE(outside ? SEEN_OUTSIDE : SEEN_TABLES);
                for (size_t i_ = 0; i_ < list_n; i_++) {
                    if (!valid_table_entry(list[i_])) {
                        fail(&x,
                             "'%s' holds '%s', which is not a table name (use name or schema.name, "
                             "made of "
                             "letters, digits and _ $ -)",
                             key, list[i_]);
                        free_list(list, list_n);
                        goto out;
                    }
                }
                if (outside) {
                    r->outside_tables = list;
                    r->noutside = list_n;
                } else {
                    r->tables = list;
                    r->ntables = list_n;
                }
            } else if (strcmp(key, "during") == 0 || strcmp(key, "except_during") == 0) {
                int inverse = key[0] == 'e';
                sl_window *dst = inverse ? r->except_during : r->during;

                NEED_LIST();
                ONCE(inverse ? SEEN_DURING_NOT : SEEN_DURING);
                if (list_n > SL_MAX_WINDOWS) {
                    fail(&x, "'%s' holds at most %d windows", key, SL_MAX_WINDOWS);
                    free_list(list, list_n);
                    goto out;
                }
                for (size_t i_ = 0; i_ < list_n; i_++) {
                    if (parse_week_window(list[i_], &dst[i_]) != 0) {
                        fail(&x,
                             "'%s' holds '%s': a window is days and hours in UTC, like "
                             "\"mon-fri 08:00-19:00\", \"sat,sun 00:00-24:00\" or \"22:00-06:00\"",
                             key, list[i_]);
                        free_list(list, list_n);
                        goto out;
                    }
                }
                if (inverse) {
                    r->nexcept_during = list_n;
                } else {
                    r->nduring = list_n;
                }
                free_list(list, list_n);
            } else if (strcmp(key, "valid_from") == 0 || strcmp(key, "valid_until") == 0) {
                int from = key[6] == 'f';
                long long t = 0;

                NEED_STRING();
                ONCE(from ? SEEN_VFROM : SEEN_VUNTIL);
                if (sl_policy_parse_instant(str, &t) != 0) {
                    fail(&x,
                         "'%s' is a moment in UTC, like \"2026-12-01\" or \"2026-12-01T18:30Z\"",
                         key);
                    free(str);
                    goto out;
                }
                free(str);
                if (from) {
                    r->valid_from = t;
                } else {
                    r->valid_until = t;
                }
            } else if (strcmp(key, "fingerprints") == 0 ||
                       strcmp(key, "outside_fingerprints") == 0) {
                int outside = key[0] == 'o';

                NEED_LIST();
                ONCE(outside ? SEEN_OUTFP : SEEN_FP);
                for (size_t i_ = 0; i_ < list_n; i_++) {
                    if (!valid_fingerprint(list[i_])) {
                        fail(&x,
                             "'%s' holds '%s', which is not the shape of a query (16 hexadecimal "
                             "digits, as the log gives it: see sluice --learn)",
                             key, list[i_]);
                        free_list(list, list_n);
                        goto out;
                    }
                }
                if (outside) {
                    r->outside_fingerprints = list;
                    r->noutside_fingerprints = list_n;
                } else {
                    r->fingerprints = list;
                    r->nfingerprints = list_n;
                }
            } else if (strcmp(key, "dry_run") == 0) {
                NEED_STRING();
                ONCE(SEEN_DRY);
                if (strcmp(str, "on") != 0 && strcmp(str, "off") != 0) {
                    fail(&x, "dry_run is \"on\" (the rule only says what it would do) or \"off\"");
                    free(str);
                    goto out;
                }
                r->dry_run = strcmp(str, "on") == 0;
                free(str);
            } else if (strcmp(key, "functions") == 0) {
                NEED_LIST();
                ONCE(SEEN_FUNCTIONS);
                for (size_t i_ = 0; i_ < list_n; i_++) {
                    if (!valid_function_entry(list[i_])) {
                        fail(&x,
                             "'functions' holds '%s', which is not a function name (use name, "
                             "schema.name or a prefix ending in *, made of letters, digits and "
                             "_ $)",
                             list[i_]);
                        free_list(list, list_n);
                        goto out;
                    }
                }
                r->functions = list;
                r->nfunctions = list_n;
            } else {
                fail(&x, "unknown key '%s' in a rule", key);
                free(str);
                free_list(list, list_n);
                goto out;
            }
#undef NEED_STRING
#undef NEED_LIST
#undef ONCE
        }

    next_line:
        if (nl == NULL) {
            break;
        }
        line = nl + 1;
    }

    if (in_rule) {
        x.line = rule_line;
        if (check_rule(&x, p, &p->rules[p->nrules - 1], seen, p->nrules - 1) != 0) {
            goto out;
        }
    }
    rc = 0;

out:
    free(buf);
    if (rc != 0) {
        sl_policy_free(p);
    }
    return rc;
}

int sl_policy_load(sl_policy *p, const char *path, char *err, size_t errcap)
{
    FILE *f = fopen(path, "rb");
    char *text;
    size_t n;
    int rc;

    memset(p, 0, sizeof *p);
    p->deny_uninspectable = 1;
    p->confirm_timeout_s = DEFAULT_CONFIRM_TIMEOUT_S;
    if (f == NULL) {
        snprintf(err, errcap, "%s: %s", path, strerror(errno));
        return -1;
    }
    text = malloc(POLICY_MAX_BYTES + 2);
    if (text == NULL) {
        fclose(f);
        snprintf(err, errcap, "%s: out of memory", path);
        return -1;
    }
    n = fread(text, 1, POLICY_MAX_BYTES + 1, f);
    if (ferror(f)) {
        fclose(f);
        free(text);
        snprintf(err, errcap, "%s: cannot read the file", path);
        return -1;
    }
    fclose(f);
    rc = sl_policy_parse(p, text, n, path, err, errcap);
    free(text);
    return rc;
}

/* ---- evaluation ---- */

static int list_has(char *const *items, size_t n, const char *s, size_t len)
{
    if (n == 0) {
        return 1; /* no restriction */
    }
    for (size_t i = 0; i < n; i++) {
        if (strlen(items[i]) == len && memcmp(items[i], s, len) == 0) {
            return 1;
        }
    }
    return 0;
}

/* How a table written in the SQL stands against one entry of a rule ("table" or "schema.table"). */
typedef enum { TBL_NO, TBL_YES, TBL_MAYBE } tbl_match;

/* An entry without a schema is that table in any schema. An entry with a schema is that schema
 * only. A table written without a schema is in whichever schema the search_path of the session
 * says, and a client can change that at will (`SET search_path = tenant_b`): against an entry with
 * a schema it is MAYBE, and sluice does not guess. */
static tbl_match table_match(const sl_sql_table *t, const char *entry)
{
    const char *dot = strchr(entry, '.');
    const char *name = dot ? dot + 1 : entry;
    size_t schema_len = dot ? (size_t)(dot - entry) : 0;

    if (strcmp(t->name, name) != 0) {
        return TBL_NO;
    }
    if (!dot) {
        return TBL_YES;
    }
    if (t->schema[0] == '\0') {
        return TBL_MAYBE;
    }
    return strlen(t->schema) == schema_len && memcmp(t->schema, entry, schema_len) == 0 ? TBL_YES
                                                                                        : TBL_NO;
}

/* The best an entry of the list says about the table: YES if one is sure, else MAYBE if one is
 * unsure. */
static tbl_match in_list(const sl_sql_table *t, char *const *list, size_t n)
{
    tbl_match best = TBL_NO;

    for (size_t i = 0; i < n; i++) {
        tbl_match m = table_match(t, list[i]);

        if (m == TBL_YES) {
            return TBL_YES;
        }
        if (m == TBL_MAYBE) {
            best = TBL_MAYBE;
        }
    }
    return best;
}

/* ---- functions ---- */

/* Does the function a statement calls match an entry (name, schema.name, either with a * at the
 * end)? Names are compared without regard to case. A call written without a schema matches whatever
 * the entry's schema is (a function is found through the search_path, which a client can change); a
 * call with one has to agree. */
static int function_match(const sl_sql_table *f, const char *entry)
{
    const char *dot = strchr(entry, '.');
    const char *name = dot ? dot + 1 : entry;
    size_t nlen = strlen(name);
    int prefix = nlen > 0 && name[nlen - 1] == '*';

    if (prefix) {
        nlen--;
    }
    if (dot && f->schema[0] != '\0' &&
        (strlen(f->schema) != (size_t)(dot - entry) ||
         strncasecmp(f->schema, entry, (size_t)(dot - entry)) != 0)) {
        return 0;
    }
    return prefix ? strncasecmp(f->name, name, nlen) == 0
                  : strlen(f->name) == nlen && strncasecmp(f->name, name, nlen) == 0;
}

/* What a statement can do through functions it calls that reach outside the database: read files
 * of the server, run on other servers, sleep, stop other sessions, take part in replication or
 * the backup. A client that can call them can often do what DDL privileges would be needed for. */
static const char *const dangerous_functions[] = {
    "pg_read_file",
    "pg_read_binary_file",
    "pg_stat_file",
    "pg_ls_*",
    "pg_file_*",
    "pg_current_logfile",
    "lo_import",
    "lo_export",
    "lo_unlink",
    "dblink*",
    "pg_terminate_backend",
    "pg_cancel_backend",
    "pg_reload_conf",
    "pg_rotate_logfile",
    "pg_switch_wal",
    "pg_create_restore_point",
    "pg_promote",
    "pg_backup_start",
    "pg_backup_stop",
    "pg_start_backup",
    "pg_stop_backup",
    "pg_create_physical_replication_slot",
    "pg_create_logical_replication_slot",
    "pg_drop_replication_slot",
    "pg_copy_*_replication_slot",
    "pg_logical_slot_*",
    "pg_logical_emit_message",
    "pg_replication_origin_*",
    "pg_wal_replay_*",
    "pg_sleep*",
    "query_to_xml*", /* these run the SQL they are given as text */
    "cursor_to_xml*",
};

static int calls_one_of(const sl_sql_tables *t, char *const *list, size_t n)
{
    for (size_t i = 0; i < t->nfuncs; i++) {
        for (size_t k = 0; k < n; k++) {
            if (function_match(&t->funcs[i], list[k])) {
                return 1;
            }
        }
    }
    return 0;
}

/* The flags of statement s, with what only its function calls say: set_config() is a SET of the
 * session, and the functions of the list above are "dangerous". Needs the tables to have been
 * asked for (they come with the functions). */
static uint32_t flags_with_calls(const sl_sql_info *info, size_t s)
{
    uint32_t f = info->flags[s];
    const sl_sql_tables *t = NULL;
    size_t g = info->group != NULL ? info->group[s] : 0;
    static const char *const setters[] = {"set_config"};

    if (info->tables != NULL && g < info->top_level) {
        t = &info->tables[g];
    }
    if (t != NULL) {
        if (calls_one_of(t, (char *const *)(uintptr_t)setters, 1)) {
            f |= SL_SQL_SET_SESSION;
        }
        if (calls_one_of(t, (char *const *)(uintptr_t)dangerous_functions,
                         sizeof dangerous_functions / sizeof dangerous_functions[0])) {
            f |= SL_SQL_DANGEROUS;
        }
    }
    return f;
}

/* The conditions of a rule about the shape of the statement (the fingerprint of the message). When
 * the shape could not be had, a rule that is about shapes assumes the worst if it refuses or asks
 * (a shape it does not know is a new one), and does not apply otherwise. */
static int fingerprint_fit(const sl_rule *r, const sl_sql_info *info)
{
    int known = info->fingerprint[0] != '\0';
    int in_list = 0;

    if (r->nfingerprints == 0 && r->noutside_fingerprints == 0) {
        return 1;
    }
    if (!known) {
        return r->noutside_fingerprints > 0 && (r->deny || r->confirm);
    }
    if (r->nfingerprints > 0) {
        for (size_t i = 0; i < r->nfingerprints && !in_list; i++) {
            in_list = strcmp(info->fingerprint, r->fingerprints[i]) == 0;
        }
        if (!in_list) {
            return 0;
        }
    }
    if (r->noutside_fingerprints > 0) {
        for (size_t i = 0; i < r->noutside_fingerprints; i++) {
            if (strcmp(info->fingerprint, r->outside_fingerprints[i]) == 0) {
                return 0; /* a shape that was seen */
            }
        }
    }
    return 1;
}

/* The `functions` condition of a rule. Without the list of calls it cannot be known: a deny or
 * confirm rule assumes the worst. */
static int functions_fit(const sl_rule *r, const sl_sql_info *info, size_t s)
{
    size_t g = info->group != NULL ? info->group[s] : 0;

    if (r->nfunctions == 0) {
        return 1;
    }
    if (info->tables == NULL || g >= info->top_level) {
        return r->deny || r->confirm;
    }
    return calls_one_of(&info->tables[g], r->functions, r->nfunctions);
}

/* The conditions of a rule that are about tables, for statement s of info. */
static int tables_fit(const sl_rule *r, const sl_sql_info *info, size_t s)
{
    const sl_sql_tables *t = NULL;
    int unseen = (info->flags[s] & SL_SQL_TABLES_UNSEEN) != 0;

    if (r->ntables == 0 && r->noutside == 0) {
        return 1;
    }
    if (info->tables != NULL) {
        size_t g = info->group != NULL ? info->group[s] : 0;

        if (g < info->top_level) {
            t = &info->tables[g];
        }
    }
    if (t == NULL) {
        unseen = 1; /* nobody told us the tables */
    }
    if (unseen) {
        return r->deny ||
               r->confirm; /* a deny or confirm rule assumes the worst, an allow rule nothing */
    }
    /* Each condition is yes (1), no (0), or unknown (-1) when a table written without a schema is
     * compared with an entry that has one. A "no" ends it; an unknown one is treated like tables
     * sluice cannot see: a deny rule applies, an allow rule does not. */
    {
        int unknown = 0;

        if (r->ntables > 0) {
            int sure = 0;
            int unsure = 0;

            for (size_t i = 0; i < t->count && !sure; i++) {
                tbl_match m = in_list(&t->items[i], r->tables, r->ntables);

                sure = m == TBL_YES;
                unsure |= m == TBL_MAYBE;
            }
            if (!sure && !unsure) {
                return 0; /* it touches none of them */
            }
            unknown |= !sure;
        }
        if (r->noutside > 0) {
            int sure = 0;
            int unsure = 0;

            for (size_t i = 0; i < t->count && !sure; i++) {
                tbl_match m = in_list(&t->items[i], r->outside_tables, r->noutside);

                sure = m == TBL_NO; /* a table that is in none of them, for certain */
                unsure |= m == TBL_MAYBE;
            }
            if (!sure && !unsure) {
                return 0; /* every table is in the list, or there is none */
            }
            unknown |= !sure;
        }
        if (unknown) {
            return r->deny || r->confirm;
        }
    }
    return 1;
}

int sl_policy_needs_tables(const sl_policy *p)
{
    for (size_t i = 0; i < p->nrules; i++) {
        const sl_rule *r = &p->rules[i];

        /* the calls come with the tables */
        if (r->ntables > 0 || r->noutside > 0 || r->nfunctions > 0 || r->nfingerprints > 0 ||
            r->noutside_fingerprints > 0 ||
            (!r->any && (r->match & (SL_SQL_SET_SESSION | SL_SQL_DANGEROUS)))) {
            return 1;
        }
    }
    return 0;
}

/* Does the rule's condition (match, who, where, tables, functions) hold for statement s? */
static int rule_hits(const sl_rule *r, const sl_sql_info *info, size_t s, uint32_t flags,
                     const char *user, size_t user_len, const char *database, size_t database_len)
{
    return !r->conn_limit && !r->mask && (r->any || (flags & r->match)) && time_fits(r) &&
           functions_fit(r, info, s) && fingerprint_fit(r, info) &&
           list_has(r->users, r->nusers, user, user_len) &&
           !(r->nexcept > 0 && list_has(r->except_users, r->nexcept, user, user_len)) &&
           list_has(r->databases, r->ndatabases, database, database_len) && tables_fit(r, info, s);
}

sl_verdict sl_policy_evaluate(const sl_policy *p, const sl_sql_info *info, const char *user,
                              size_t user_len, const char *database, size_t database_len)
{
    sl_verdict v;

    memset(&v, 0, sizeof v);

    for (size_t s = 0; s < info->count; s++) {
        uint32_t flags = flags_with_calls(info, s);

        /* an alert is said whatever else is decided, and wherever its rule is in the file */
        for (size_t i = 0; i < p->nrules && v.alert == NULL; i++) {
            const sl_rule *r = &p->rules[i];

            if (r->alert && rule_hits(r, info, s, flags, user, user_len, database, database_len)) {
                v.alert = r;
            }
        }
        /* a rule that is being tried says what it would have done, and decides nothing */
        for (size_t i = 0; i < p->nrules && v.dry == NULL; i++) {
            const sl_rule *r = &p->rules[i];

            if (r->dry_run &&
                rule_hits(r, info, s, flags, user, user_len, database, database_len)) {
                v.dry = r;
            }
        }
        for (size_t i = 0; i < p->nrules; i++) {
            const sl_rule *r = &p->rules[i];

            if (r->alert || r->dry_run ||
                !rule_hits(r, info, s, flags, user, user_len, database, database_len)) {
                continue;
            }
            if (r->deny) {
                v.deny = 1;
                v.confirm = 0;
                v.rule = r;
                v.kill = r->kill;
                break; /* a denial wins over everything else in the message: but the alerts of the
                          statements after it are still looked for */
            }
            if (r->confirm && !v.confirm) {
                v.confirm = 1; /* the first one is kept; the other statements are still judged */
                v.rule = r;
            }
            break; /* decided by this rule: on to the next statement */
        }
        if (v.deny) {
            break;
        }
    }
    return v;
}

const char *sl_rule_would(const sl_rule *r)
{
    return r->kill ? "kill" : r->limit ? "limit" : r->confirm ? "confirm" : "deny";
}

void sl_policy_limits(const sl_policy *p, const char *user, size_t user_len, const char *database,
                      size_t database_len, sl_limits *out)
{
    memset(out, 0, sizeof *out);
    for (size_t i = 0; i < p->nrules; i++) {
        const sl_rule *r = &p->rules[i];

        if (!r->conn_limit || !list_has(r->users, r->nusers, user, user_len) ||
            (r->nexcept > 0 && list_has(r->except_users, r->nexcept, user, user_len)) ||
            !list_has(r->databases, r->ndatabases, database, database_len)) {
            continue;
        }
#define TAKE(field, rule_field, value)                                                             \
    if ((value) != 0 && (out->field == 0 || (value) < out->field)) {                               \
        out->field = (value);                                                                      \
        snprintf(out->rule_field, sizeof out->rule_field, "%s", r->name);                          \
    }
        TAKE(result_rows, rule_rows, r->max_result_rows)
        TAKE(result_bytes, rule_bytes, r->max_result_bytes)
        TAKE(total_bytes, rule_total, r->max_total_bytes)
        TAKE(duration_s, rule_duration, r->max_duration_s)
        TAKE(idle_in_transaction_s, rule_idle, r->max_idle_in_transaction_s)
        TAKE(transaction_s, rule_transaction, r->max_transaction_s)
        TAKE(connections, rule_connections, r->max_connections)
#undef TAKE
        if (r->budget && out->nbudgets < SL_MAX_BUDGETS) {
            sl_budget_spec *b = &out->budgets[out->nbudgets++];

            snprintf(b->rule, sizeof b->rule, "%s", r->name);
            b->window_s = r->window_s != 0 ? r->window_s : 3600;
            b->rows = r->budget_rows;
            b->bytes = r->budget_bytes;
            b->changed = r->budget_changed;
            b->statements = r->budget_statements;
        }
    }
}

int sl_policy_needs_journal(const sl_policy *p)
{
    for (size_t i = 0; i < p->nrules; i++) {
        if (p->rules[i].journal != SL_JOURNAL_OFF) {
            return 1;
        }
    }
    return 0;
}

size_t sl_policy_masks(const sl_policy *p, const char *user, size_t user_len, const char *database,
                       size_t database_len, sl_mask_rule_view out[SL_MASK_MAX_RULES])
{
    size_t n = 0;

    for (size_t i = 0; i < p->nrules && n < SL_MASK_MAX_RULES; i++) {
        const sl_rule *r = &p->rules[i];

        if (!r->mask || !list_has(r->users, r->nusers, user, user_len) ||
            (r->nexcept > 0 && list_has(r->except_users, r->nexcept, user, user_len)) ||
            !list_has(r->databases, r->ndatabases, database, database_len)) {
            continue;
        }
        out[n].name = r->name;
        out[n].columns = r->mask_columns;
        out[n].ncolumns = r->nmask_columns;
        out[n].detect = r->mask_detect;
        out[n].how = r->mask_how;
        n++;
    }
    return n;
}

void sl_policy_reason(const sl_rule *r, char *out, size_t cap)
{
    if (r->message != NULL) {
        snprintf(out, cap, "blocked by rule %s: %s", r->name, r->message);
    } else {
        snprintf(out, cap, "blocked by rule %s", r->name);
    }
}
