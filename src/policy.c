#include "policy.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

enum {
    SEEN_NAME = 1 << 0,
    SEEN_MATCH = 1 << 1,
    SEEN_ACTION = 1 << 2,
    SEEN_USERS = 1 << 3,
    SEEN_DATABASES = 1 << 4,
    SEEN_MESSAGE = 1 << 5,
    SEEN_TABLES = 1 << 6,
    SEEN_OUTSIDE = 1 << 7,
    SEEN_OVER = 1 << 8,
    SEEN_EXCEPT = 1 << 9,
};

static void free_rule(sl_rule *r)
{
    free(r->name);
    free(r->message);
    free_list(r->users, r->nusers);
    free_list(r->except_users, r->nexcept);
    free_list(r->databases, r->ndatabases);
    free_list(r->tables, r->ntables);
    free_list(r->outside_tables, r->noutside);
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
static int check_rule(ctx *x, const sl_policy *p, const sl_rule *r, unsigned seen, size_t index)
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
    if ((seen & SEEN_OVER) && !r->confirm) {
        return fail(x, "rule '%s': over_rows only goes with action = \"confirm\"", r->name);
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
    unsigned seen = 0;
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
                if (parse_list(&x, &c, &list, &list_n) != 0) {
                    goto out;
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
                } else {
                    fail(&x, "action must be \"deny\", \"allow\" or \"confirm\"");
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
        if (p->rules[i].ntables > 0 || p->rules[i].noutside > 0) {
            return 1;
        }
    }
    return 0;
}

sl_verdict sl_policy_evaluate(const sl_policy *p, const sl_sql_info *info, const char *user,
                              size_t user_len, const char *database, size_t database_len)
{
    sl_verdict v = {0, 0, NULL};

    for (size_t s = 0; s < info->count; s++) {
        for (size_t i = 0; i < p->nrules; i++) {
            const sl_rule *r = &p->rules[i];

            if ((!r->any && !(info->flags[s] & r->match)) ||
                !list_has(r->users, r->nusers, user, user_len) ||
                (r->nexcept > 0 && list_has(r->except_users, r->nexcept, user, user_len)) ||
                !list_has(r->databases, r->ndatabases, database, database_len) ||
                !tables_fit(r, info, s)) {
                continue;
            }
            if (r->deny) {
                v.deny = 1;
                v.confirm = 0;
                v.rule = r;
                return v; /* a denial wins over everything else in the message */
            }
            if (r->confirm && !v.confirm) {
                v.confirm = 1; /* the first one is kept; the other statements are still judged */
                v.rule = r;
            }
            break; /* decided by this rule: on to the next statement */
        }
    }
    return v;
}

void sl_policy_reason(const sl_rule *r, char *out, size_t cap)
{
    if (r->message != NULL) {
        snprintf(out, cap, "blocked by rule %s: %s", r->name, r->message);
    } else {
        snprintf(out, cap, "blocked by rule %s", r->name);
    }
}
