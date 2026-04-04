#include "undo.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINE_MAX_BYTES ((size_t)64 << 20)
#define MAX_DEPTH 8
#define MAX_COLS 2048
#define MAX_ROWS 5000000
#define ROWS_PER_INSERT 200

typedef struct {
    const char *p;
    const char *end;
    char *err;
    size_t errcap;
} rd;

/* A literal, whatever its length: the length is not written by hand. */
static int lit(sl_buf *b, const char *s)
{
    return sl_buf_append(b, s, strlen(s));
}

static int bad(rd *r, const char *msg)
{
    snprintf(r->err, r->errcap, "%s", msg);
    return -1;
}

static void ws(rd *r)
{
    while (r->p < r->end && (*r->p == ' ' || *r->p == '\t' || *r->p == '\r' || *r->p == '\n')) {
        r->p++;
    }
}

static int hex4(const char *p, unsigned *v)
{
    unsigned x = 0;

    for (int i = 0; i < 4; i++) {
        char c = p[i];

        x <<= 4;
        if (c >= '0' && c <= '9') {
            x |= (unsigned)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            x |= (unsigned)(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            x |= (unsigned)(c - 'A' + 10);
        } else {
            return -1;
        }
    }
    *v = x;
    return 0;
}

static int put_utf8(sl_buf *b, unsigned cp)
{
    uint8_t t[4];
    size_t n;

    if (cp < 0x80) {
        t[0] = (uint8_t)cp;
        n = 1;
    } else if (cp < 0x800) {
        t[0] = (uint8_t)(0xc0 | (cp >> 6));
        t[1] = (uint8_t)(0x80 | (cp & 0x3f));
        n = 2;
    } else if (cp < 0x10000) {
        t[0] = (uint8_t)(0xe0 | (cp >> 12));
        t[1] = (uint8_t)(0x80 | ((cp >> 6) & 0x3f));
        t[2] = (uint8_t)(0x80 | (cp & 0x3f));
        n = 3;
    } else {
        t[0] = (uint8_t)(0xf0 | (cp >> 18));
        t[1] = (uint8_t)(0x80 | ((cp >> 12) & 0x3f));
        t[2] = (uint8_t)(0x80 | ((cp >> 6) & 0x3f));
        t[3] = (uint8_t)(0x80 | (cp & 0x3f));
        n = 4;
    }
    return sl_buf_append(b, t, n);
}

/* A JSON string into a NUL-terminated copy. */
static int read_string(rd *r, char **out)
{
    sl_buf b;
    char *s;

    sl_buf_init(&b);
    if (r->p >= r->end || *r->p != '"') {
        return bad(r, "a string was expected");
    }
    r->p++;
    for (;;) {
        unsigned char c;

        if (r->p >= r->end) {
            sl_buf_free(&b);
            return bad(r, "a string does not end");
        }
        c = (unsigned char)*r->p++;
        if (c == '"') {
            break;
        }
        if (c < 0x20) {
            sl_buf_free(&b);
            return bad(r, "a control character in a string");
        }
        if (c == '\\') {
            unsigned cp;

            if (r->p >= r->end) {
                sl_buf_free(&b);
                return bad(r, "a string does not end");
            }
            c = (unsigned char)*r->p++;
            switch (c) {
            case '"':
            case '\\':
            case '/':
                sl_buf_append(&b, &c, 1);
                break;
            case 'b':
                lit(&b, "\b");
                break;
            case 'f':
                lit(&b, "\f");
                break;
            case 'n':
                lit(&b, "\n");
                break;
            case 'r':
                lit(&b, "\r");
                break;
            case 't':
                lit(&b, "\t");
                break;
            case 'u':
                if (r->end - r->p < 4 || hex4(r->p, &cp) != 0) {
                    sl_buf_free(&b);
                    return bad(r, "a bad \\u escape");
                }
                r->p += 4;
                if (cp >= 0xd800 && cp <= 0xdbff) {
                    unsigned lo;

                    if (r->end - r->p < 6 || r->p[0] != '\\' || r->p[1] != 'u' ||
                        hex4(r->p + 2, &lo) != 0 || lo < 0xdc00 || lo > 0xdfff) {
                        sl_buf_free(&b);
                        return bad(r, "a lone surrogate");
                    }
                    r->p += 6;
                    cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                } else if (cp >= 0xdc00 && cp <= 0xdfff) {
                    sl_buf_free(&b);
                    return bad(r, "a lone surrogate");
                }
                if (cp == 0) {
                    sl_buf_free(&b);
                    return bad(r, "a NUL in a string");
                }
                put_utf8(&b, cp);
                break;
            default:
                sl_buf_free(&b);
                return bad(r, "a bad escape");
            }
            continue;
        }
        sl_buf_append(&b, &c, 1);
    }
    s = malloc(sl_buf_len(&b) + 1);
    if (s == NULL) {
        sl_buf_free(&b);
        return bad(r, "out of memory");
    }
    if (sl_buf_len(&b) > 0) {
        memcpy(s, sl_buf_data(&b), sl_buf_len(&b));
    }
    s[sl_buf_len(&b)] = '\0';
    sl_buf_free(&b);
    *out = s;
    return 0;
}

static int read_uint(rd *r, unsigned long long *v)
{
    unsigned long long x = 0;
    size_t n = 0;

    while (r->p < r->end && *r->p >= '0' && *r->p <= '9' && n < 19) {
        x = x * 10 + (unsigned long long)(*r->p++ - '0');
        n++;
    }
    if (n == 0) {
        return bad(r, "a number was expected");
    }
    *v = x;
    return 0;
}

static int read_bool(rd *r, int *v)
{
    if (r->end - r->p >= 4 && memcmp(r->p, "true", 4) == 0) {
        r->p += 4;
        *v = 1;
        return 0;
    }
    if (r->end - r->p >= 5 && memcmp(r->p, "false", 5) == 0) {
        r->p += 5;
        *v = 0;
        return 0;
    }
    return bad(r, "true or false was expected");
}

static int skip_value(rd *r, int depth)
{
    ws(r);
    if (depth > MAX_DEPTH || r->p >= r->end) {
        return bad(r, "too deep, or cut short");
    }
    if (*r->p == '"') {
        char *s = NULL;

        if (read_string(r, &s) != 0) {
            return -1;
        }
        free(s);
        return 0;
    }
    if (*r->p == '{' || *r->p == '[') {
        char close = *r->p == '{' ? '}' : ']';

        r->p++;
        ws(r);
        if (r->p < r->end && *r->p == close) {
            r->p++;
            return 0;
        }
        for (;;) {
            if (close == '}') {
                char *k = NULL;

                ws(r);
                if (read_string(r, &k) != 0) {
                    return -1;
                }
                free(k);
                ws(r);
                if (r->p >= r->end || *r->p++ != ':') {
                    return bad(r, "a colon was expected");
                }
            }
            if (skip_value(r, depth + 1) != 0) {
                return -1;
            }
            ws(r);
            if (r->p < r->end && *r->p == ',') {
                r->p++;
                continue;
            }
            if (r->p < r->end && *r->p == close) {
                r->p++;
                return 0;
            }
            return bad(r, "a , or a closing bracket was expected");
        }
    }
    if (r->end - r->p >= 4 && memcmp(r->p, "null", 4) == 0) {
        r->p += 4;
        return 0;
    }
    if (r->end - r->p >= 4 && memcmp(r->p, "true", 4) == 0) {
        r->p += 4;
        return 0;
    }
    if (r->end - r->p >= 5 && memcmp(r->p, "false", 5) == 0) {
        r->p += 5;
        return 0;
    }
    {
        size_t n = 0;

        while (r->p < r->end && (*r->p == '-' || *r->p == '+' || *r->p == '.' || *r->p == 'e' ||
                                 *r->p == 'E' || (*r->p >= '0' && *r->p <= '9'))) {
            r->p++;
            n++;
        }
        return n > 0 ? 0 : bad(r, "a value was expected");
    }
}

static int read_columns(rd *r, sl_undo_entry *e)
{
    ws(r);
    if (r->p >= r->end || *r->p++ != '[') {
        return bad(r, "a list of columns was expected");
    }
    ws(r);
    if (r->p < r->end && *r->p == ']') {
        r->p++;
        return 0;
    }
    for (;;) {
        char **n;

        if (e->ncols >= MAX_COLS) {
            return bad(r, "too many columns");
        }
        n = realloc(e->columns, (e->ncols + 1) * sizeof *n);
        if (n == NULL) {
            return bad(r, "out of memory");
        }
        e->columns = n;
        e->columns[e->ncols] = NULL;
        if (read_string(r, &e->columns[e->ncols]) != 0) {
            return -1;
        }
        e->ncols++;
        ws(r);
        if (r->p < r->end && *r->p == ',') {
            r->p++;
            ws(r);
            continue;
        }
        if (r->p < r->end && *r->p == ']') {
            r->p++;
            return 0;
        }
        return bad(r, "a , or ] was expected");
    }
}

static int read_data(rd *r, sl_undo_entry *e, char ****dst, size_t *count)
{
    ws(r);
    if (r->p >= r->end || *r->p++ != '[') {
        return bad(r, "the rows were expected");
    }
    ws(r);
    if (r->p < r->end && *r->p == ']') {
        r->p++;
        return 0;
    }
    for (;;) {
        char ***n;
        char **row;

        if (*count >= MAX_ROWS) {
            return bad(r, "too many rows");
        }
        n = realloc(*dst, (*count + 1) * sizeof *n);
        if (n == NULL) {
            return bad(r, "out of memory");
        }
        *dst = n;
        (*dst)[*count] = NULL;
        row = calloc(e->ncols ? e->ncols : 1, sizeof *row);
        if (row == NULL) {
            return bad(r, "out of memory");
        }
        (*dst)[(*count)++] = row; /* released with the entry, whatever happens next */
        ws(r);
        if (r->p >= r->end || *r->p++ != '[') {
            return bad(r, "a row was expected");
        }
        for (size_t c = 0; c < e->ncols; c++) {
            ws(r);
            if (c > 0) {
                if (r->p >= r->end || *r->p++ != ',') {
                    return bad(r, "a row has fewer values than there are columns");
                }
                ws(r);
            }
            if (r->end - r->p >= 4 && memcmp(r->p, "null", 4) == 0) {
                r->p += 4;
                row[c] = NULL;
            } else if (read_string(r, &row[c]) != 0) {
                return -1;
            }
        }
        ws(r);
        if (r->p >= r->end || *r->p++ != ']') {
            return bad(r, "a row has more values than there are columns");
        }
        ws(r);
        if (r->p < r->end && *r->p == ',') {
            r->p++;
            continue;
        }
        if (r->p < r->end && *r->p == ']') {
            r->p++;
            return 0;
        }
        return bad(r, "a , or ] was expected");
    }
}

static int read_side(rd *r, sl_undo_entry *e)
{
    ws(r);
    if (r->p >= r->end || *r->p++ != '[') {
        return bad(r, "a list was expected");
    }
    ws(r);
    if (r->p < r->end && *r->p == ']') {
        r->p++;
        return 0;
    }
    for (;;) {
        sl_undo_side *n = realloc(e->side, (e->nside + 1) * sizeof *n);
        sl_undo_side *s;

        if (n == NULL || e->nside > 4096) {
            return bad(r, "too many tables, or out of memory");
        }
        e->side = n;
        s = &e->side[e->nside];
        memset(s, 0, sizeof *s);
        e->nside++;
        ws(r);
        if (r->p >= r->end || *r->p++ != '{') {
            return bad(r, "an object was expected");
        }
        for (;;) {
            char *k = NULL;
            int rc = 0;

            ws(r);
            if (read_string(r, &k) != 0) {
                return -1;
            }
            ws(r);
            if (r->p >= r->end || *r->p++ != ':') {
                free(k);
                return bad(r, "a colon was expected");
            }
            ws(r);
            if (strcmp(k, "table") == 0) {
                rc = read_string(r, &s->table);
            } else if (strcmp(k, "inserted") == 0) {
                rc = read_uint(r, &s->inserted);
            } else if (strcmp(k, "updated") == 0) {
                rc = read_uint(r, &s->updated);
            } else if (strcmp(k, "deleted") == 0) {
                rc = read_uint(r, &s->deleted);
            } else {
                rc = skip_value(r, 2);
            }
            free(k);
            if (rc != 0) {
                return -1;
            }
            ws(r);
            if (r->p < r->end && *r->p == ',') {
                r->p++;
                continue;
            }
            if (r->p < r->end && *r->p == '}') {
                r->p++;
                break;
            }
            return bad(r, "a , or } was expected");
        }
        ws(r);
        if (r->p < r->end && *r->p == ',') {
            r->p++;
            continue;
        }
        if (r->p < r->end && *r->p == ']') {
            r->p++;
            return 0;
        }
        return bad(r, "a , or ] was expected");
    }
}

void sl_undo_free(sl_undo_entry *e)
{
    free(e->id);
    free(e->ts);
    free(e->user);
    free(e->database);
    free(e->rule);
    free(e->protocol);
    free(e->sql);
    free(e->schema);
    free(e->table);
    free(e->tag);
    free(e->incomplete);
    free(e->kind);
    for (size_t i = 0; i < e->ncols; i++) {
        free(e->columns[i]);
    }
    free(e->columns);
    for (size_t i = 0; i < e->nrows; i++) {
        if (e->data[i] != NULL) {
            for (size_t c = 0; c < e->ncols; c++) {
                free(e->data[i][c]);
            }
        }
        free(e->data[i]);
    }
    free(e->data);
    for (size_t i = 0; i < e->nfresh; i++) {
        if (e->fresh[i] != NULL) {
            for (size_t c = 0; c < e->ncols; c++) {
                free(e->fresh[i][c]);
            }
        }
        free(e->fresh[i]);
    }
    free(e->fresh);
    for (size_t i = 0; i < e->nside; i++) {
        free(e->side[i].table);
    }
    free(e->side);
    memset(e, 0, sizeof *e);
}

int sl_undo_parse(const char *line, size_t len, sl_undo_entry *e, char *err, size_t errcap)
{
    rd r = {line, line + len, err, errcap};
    int have_id = 0;

    memset(e, 0, sizeof *e);
    ws(&r);
    if (r.p >= r.end || *r.p++ != '{') {
        bad(&r, "not an entry of the journal");
        return -1;
    }
    for (;;) {
        char *k = NULL;
        int rc = 0;
        char **dst = NULL;

        ws(&r);
        if (read_string(&r, &k) != 0) {
            goto fail;
        }
        ws(&r);
        if (r.p >= r.end || *r.p++ != ':') {
            free(k);
            bad(&r, "a colon was expected");
            goto fail;
        }
        ws(&r);
        if (strcmp(k, "id") == 0) {
            dst = &e->id;
        } else if (strcmp(k, "ts") == 0) {
            dst = &e->ts;
        } else if (strcmp(k, "user") == 0) {
            dst = &e->user;
        } else if (strcmp(k, "database") == 0) {
            dst = &e->database;
        } else if (strcmp(k, "rule") == 0) {
            dst = &e->rule;
        } else if (strcmp(k, "protocol") == 0) {
            dst = &e->protocol;
        } else if (strcmp(k, "sql") == 0) {
            dst = &e->sql;
        } else if (strcmp(k, "schema") == 0) {
            dst = &e->schema;
        } else if (strcmp(k, "table") == 0) {
            dst = &e->table;
        } else if (strcmp(k, "tag") == 0) {
            dst = &e->tag;
        } else if (strcmp(k, "incomplete") == 0) {
            dst = &e->incomplete;
        } else if (strcmp(k, "kind") == 0) {
            dst = &e->kind;
        }
        if (dst != NULL) {
            free(*dst);
            *dst = NULL;
            rc = read_string(&r, dst);
            have_id |= dst == &e->id;
        } else if (strcmp(k, "rows") == 0) {
            rc = read_uint(&r, &e->rows);
        } else if (strcmp(k, "complete") == 0) {
            rc = read_bool(&r, &e->complete);
        } else if (strcmp(k, "side_known") == 0) {
            rc = read_bool(&r, &e->side_known);
        } else if (strcmp(k, "columns") == 0) {
            rc = e->ncols == 0 && e->nrows == 0 ? read_columns(&r, e) : bad(&r, "columns twice");
        } else if (strcmp(k, "data") == 0) {
            rc = e->nrows == 0 ? read_data(&r, e, &e->data, &e->nrows) : bad(&r, "data twice");
        } else if (strcmp(k, "new") == 0) {
            rc = e->nfresh == 0 ? read_data(&r, e, &e->fresh, &e->nfresh) : bad(&r, "new twice");
        } else if (strcmp(k, "side") == 0) {
            rc = e->nside == 0 ? read_side(&r, e) : bad(&r, "side twice");
        } else {
            rc = skip_value(&r, 1);
        }
        free(k);
        if (rc != 0) {
            goto fail;
        }
        ws(&r);
        if (r.p < r.end && *r.p == ',') {
            r.p++;
            continue;
        }
        if (r.p < r.end && *r.p == '}') {
            r.p++;
            break;
        }
        bad(&r, "a , or } was expected");
        goto fail;
    }
    ws(&r);
    if (r.p != r.end || !have_id) {
        bad(&r, have_id ? "something after the entry" : "an entry with no id");
        goto fail;
    }
    if ((e->nrows > 0 || e->nfresh > 0) && e->ncols == 0) {
        bad(&r, "rows without columns");
        goto fail;
    }
    if (e->kind != NULL && strcmp(e->kind, "update") != 0 && strcmp(e->kind, "delete") != 0) {
        bad(&r, "an entry of a kind this version does not know");
        goto fail;
    }
    if (e->kind != NULL && strcmp(e->kind, "update") == 0 ? e->nfresh != e->nrows
                                                          : e->nfresh != 0) {
        bad(&r, "the old rows and the new rows of an update do not match");
        goto fail;
    }
    return 0;
fail:
    sl_undo_free(e);
    return -1;
}

/* ---- the script ---- */

static int quote_ident(sl_buf *o, const char *s)
{
    lit(o, "\"");
    for (; *s; s++) {
        if (*s == '"') {
            lit(o, "\"\"");
        } else {
            sl_buf_append(o, s, 1);
        }
    }
    return lit(o, "\"");
}

static int quote_lit(sl_buf *o, const char *s)
{
    lit(o, "'");
    for (; *s; s++) {
        if (*s == '\'') {
            lit(o, "''");
        } else {
            sl_buf_append(o, s, 1);
        }
    }
    return lit(o, "'");
}

/* A comment line: whatever the text holds, it stays a comment. */
static void comment(sl_buf *o, const char *prefix, const char *text)
{
    lit(o, "-- ");
    sl_buf_append(o, prefix, strlen(prefix));
    for (; text != NULL && *text; text++) {
        if (*text == '\n' || *text == '\r') {
            lit(o, " ");
        } else {
            sl_buf_append(o, text, 1);
        }
    }
    lit(o, "\n");
}

static int same(const char *a, const char *b)
{
    return a == NULL || b == NULL ? a == b : strcmp(a, b) == 0;
}

/* An UPDATE: each row is put back to the values it had, where it still has the values the UPDATE
 * gave it. If a row has changed since, or two rows look alike, the script stops and changes
 * nothing: the rows have no key here, and guessing which row is which would be worse than not
 * undoing. */
static void update_script(const sl_undo_entry *e, sl_buf *out)
{
    sl_buf body;
    char line[240];
    size_t skipped = 0;

    sl_buf_init(&body);
    lit(&body, "#variable_conflict use_column\nDECLARE sluice_undo_rows bigint;\nBEGIN\n");
    for (size_t i = 0; i < e->nrows; i++) {
        int unchanged = 1;
        int first = 1;

        for (size_t c = 0; c < e->ncols; c++) {
            if (!same(e->data[i][c], e->fresh[i][c])) {
                unchanged = 0;
            }
        }
        if (unchanged) {
            skipped++; /* the UPDATE did not change this row */
            continue;
        }
        lit(&body, "UPDATE ");
        if (e->schema != NULL && e->schema[0] != '\0') {
            quote_ident(&body, e->schema);
            lit(&body, ".");
        }
        quote_ident(&body, e->table);
        lit(&body, " SET ");
        for (size_t c = 0; c < e->ncols; c++) {
            if (same(e->data[i][c], e->fresh[i][c])) {
                continue;
            }
            lit(&body, first ? "" : ", ");
            first = 0;
            quote_ident(&body, e->columns[c]);
            lit(&body, " = ");
            if (e->data[i][c] == NULL) {
                lit(&body, "NULL");
            } else {
                quote_lit(&body, e->data[i][c]);
            }
        }
        lit(&body, " WHERE ");
        for (size_t c = 0; c < e->ncols; c++) {
            if (c > 0) {
                lit(&body, " AND ");
            }
            quote_ident(&body, e->columns[c]);
            lit(&body, " IS NOT DISTINCT FROM ");
            if (e->fresh[i][c] == NULL) {
                lit(&body, "NULL");
            } else {
                quote_lit(&body, e->fresh[i][c]);
            }
        }
        snprintf(line, sizeof line,
                 ";\nGET DIAGNOSTICS sluice_undo_rows = ROW_COUNT;\nIF sluice_undo_rows <> 1 THEN "
                 "RAISE EXCEPTION 'row %zu of the entry "
                 "matched %% rows, not 1: nothing was changed', sluice_undo_rows; END IF;\n",
                 i + 1);
        lit(&body, line);
    }
    lit(&body, "END\n");
    if (skipped > 0) {
        snprintf(line, sizeof line, "%zu row%s the UPDATE left as they were: nothing to put back",
                 skipped, skipped == 1 ? "" : "s");
        comment(out, "", line);
    }
    lit(out, "BEGIN;\nSET LOCAL standard_conforming_strings = on;\nDO ");
    sl_buf_append(&body, "", 1);
    quote_lit(out, (const char *)sl_buf_data(&body));
    lit(out, ";\nCOMMIT;\n");
    sl_buf_free(&body);
}

int sl_undo_sql(const sl_undo_entry *e, int partial, sl_buf *out, char *err, size_t errcap)
{
    char line[256];
    int update = e->kind != NULL && strcmp(e->kind, "update") == 0;

    if (e->table == NULL || e->table[0] == '\0' || e->ncols == 0) {
        snprintf(
            err, errcap,
            "this entry does not say which table or which columns: there is nothing to put back");
        return -1;
    }
    if (!e->complete && !partial) {
        snprintf(err, errcap,
                 "the rows of this entry are not all there (%s): --partial prints what there is",
                 e->incomplete != NULL ? e->incomplete : "no reason given");
        return -1;
    }
    snprintf(line, sizeof line, "sluice undo of entry %s: %s, %llu row%s, by %s on %s at %s", e->id,
             e->tag != NULL ? e->tag
             : update       ? "UPDATE"
                            : "DELETE",
             e->rows, e->rows == 1 ? "" : "s", e->user != NULL ? e->user : "?",
             e->database != NULL ? e->database : "?", e->ts != NULL ? e->ts : "?");
    comment(out, "", line);
    comment(out, "rule: ", e->rule);
    comment(out, "statement: ", e->sql);
    if (!e->complete) {
        comment(out, "PARTIAL: ", e->incomplete != NULL ? e->incomplete : "not every row is here");
    }
    if (!e->side_known) {
        comment(out, "",
                update ? "WARNING: what else the statement changed (cascades, triggers) was not "
                         "looked at: rows of other tables may have changed with these, and are not "
                         "here"
                       : "WARNING: what else the statement changed (cascades, triggers) was not "
                         "looked at: rows of other tables may have gone with these, and are not "
                         "here");
    }
    for (size_t i = 0; i < e->nside; i++) {
        if (e->side[i].deleted + e->side[i].updated + e->side[i].inserted > 0 &&
            e->side[i].table != NULL) {
            snprintf(line, sizeof line,
                     "WARNING: it also changed %s (%llu inserted, %llu updated, %llu deleted): "
                     "those rows are NOT in this script",
                     e->side[i].table, e->side[i].inserted, e->side[i].updated, e->side[i].deleted);
            comment(out, "", line);
        }
    }
    comment(out, "",
            "Run it with the search_path the statement had (the table is named as it was written). "
            "A column "
            "that is generated, or an identity column, may need to be removed or changed by hand.");
    if (update) {
        comment(
            out, "",
            "Each row gets its old values back only where it still has the values the UPDATE "
            "gave it (matched on every column); if a row changed since, or two rows look alike, "
            "the script stops and changes nothing. A generated column cannot be set and makes "
            "it stop.");
        update_script(e, out);
        return 0;
    }
    lit(out, "BEGIN;\nSET LOCAL standard_conforming_strings = on;\n");
    for (size_t r = 0; r < e->nrows; r += ROWS_PER_INSERT) {
        size_t last = r + ROWS_PER_INSERT < e->nrows ? r + ROWS_PER_INSERT : e->nrows;

        lit(out, "INSERT INTO ");
        if (e->schema != NULL && e->schema[0] != '\0') {
            quote_ident(out, e->schema);
            lit(out, ".");
        }
        quote_ident(out, e->table);
        lit(out, " (");
        for (size_t c = 0; c < e->ncols; c++) {
            if (c > 0) {
                lit(out, ", ");
            }
            quote_ident(out, e->columns[c]);
        }
        lit(out, ") OVERRIDING SYSTEM VALUE VALUES\n");
        for (size_t i = r; i < last; i++) {
            lit(out, "  (");
            for (size_t c = 0; c < e->ncols; c++) {
                if (c > 0) {
                    lit(out, ", ");
                }
                if (e->data[i][c] == NULL) {
                    lit(out, "NULL");
                } else {
                    quote_lit(out, e->data[i][c]);
                }
            }
            lit(out, i + 1 < last ? "),\n" : ");\n");
        }
    }
    lit(out, "COMMIT;\n");
    return 0;
}

/* ---- the command ---- */

static void usage(void)
{
    fprintf(stderr, "usage: sluice --undo FILE [--id ID] [--partial]\n"
                    "  lists the entries of the undo journal FILE, or with --id prints the SQL "
                    "that puts back the rows "
                    "of one\n"
                    "  (an entry whose rows are not all there is refused unless --partial). It "
                    "connects to nothing.\n");
}

int sl_undo_main(int argc, char **argv)
{
    const char *path = NULL;
    const char *id = NULL;
    int partial = 0;
    FILE *f;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int found = 0;
    int rc = 0;
    size_t lineno = 0;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--id") == 0 && i + 1 < argc) {
            id = argv[++i];
        } else if (strcmp(argv[i], "--partial") == 0) {
            partial = 1;
        } else if (path == NULL && argv[i][0] != '-') {
            path = argv[i];
        } else {
            usage();
            return 2;
        }
    }
    if (path == NULL) {
        usage();
        return 2;
    }
    f = fopen(path, "r");
    if (f == NULL) {
        fprintf(stderr, "sluice: cannot read %s\n", path);
        return 1;
    }
    if (id == NULL) {
        printf("%-16s  %-20s  %-12s  %-12s  %-24s  %-14s  %s\n", "ID", "TIME", "USER", "DATABASE",
               "TABLE", "TAG", "PUT BACK");
    }
    while ((n = getline(&line, &cap, f)) > 0) {
        sl_undo_entry e;
        char err[200];
        char table[160];

        lineno++;
        if ((size_t)n > LINE_MAX_BYTES) {
            fprintf(stderr, "sluice: line %zu of %s is too long to be an entry\n", lineno, path);
            rc = 1;
            continue;
        }
        if (sl_undo_parse(line, (size_t)n, &e, err, sizeof err) != 0) {
            fprintf(stderr, "sluice: line %zu of %s: %s\n", lineno, path, err);
            rc = 1;
            continue;
        }
        if (id == NULL) {
            snprintf(table, sizeof table, "%s%s%s", e.schema != NULL && e.schema[0] ? e.schema : "",
                     e.schema != NULL && e.schema[0] ? "." : "", e.table != NULL ? e.table : "?");
            printf("%-16s  %-20s  %-12.12s  %-12.12s  %-24.24s  %-14.14s  %s\n", e.id,
                   e.ts != NULL ? e.ts : "?", e.user != NULL ? e.user : "?",
                   e.database != NULL ? e.database : "?", table, e.tag != NULL ? e.tag : "?",
                   e.complete ? "yes" : "partly");
        } else if (strcmp(e.id, id) == 0) {
            sl_buf out;

            found = 1;
            sl_buf_init(&out);
            if (sl_undo_sql(&e, partial, &out, err, sizeof err) != 0) {
                fprintf(stderr, "sluice: %s\n", err);
                rc = 1;
            } else {
                fwrite(sl_buf_data(&out), 1, sl_buf_len(&out), stdout);
            }
            sl_buf_free(&out);
        }
        sl_undo_free(&e);
    }
    free(line);
    fclose(f);
    if (id != NULL && !found) {
        fprintf(stderr, "sluice: no entry %s in %s\n", id, path);
        return 1;
    }
    return rc;
}
