#include "mask.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "pg_proto.h"

#define KINDS 3 /* e-mail, card, IBAN */
#define TOKEN_MAX 40

typedef struct {
    char name[72];
    char columns[SL_MASK_MAX_COLUMNS][SL_MASK_NAME_MAX + 1];
    char tab[SL_MASK_MAX_COLUMNS][SL_MASK_NAME_MAX + 1]; /* "users.email": the table, or "" */
    char sch[SL_MASK_MAX_COLUMNS]
            [SL_MASK_NAME_MAX + 1]; /* "public.users.email": the schema, or "" */
    size_t ncolumns;
    unsigned detect;
    int how;
} rule;

typedef struct {
    uint8_t named;   /* picked by its name: the whole value is hidden */
    uint8_t scan;    /* the patterns are looked for in it */
    uint8_t as_text; /* a text can take the place of the value */
    uint8_t how;     /* for a named column */
    uint8_t binary;  /* the format of the column (only for the record: text-like bytes are equal) */
} column;

struct sl_mask {
    rule rules[SL_MASK_MAX_RULES];
    size_t nrules;
    unsigned detect_all;
    int detect_how[KINDS]; /* how each pattern is hidden: the first rule that asks for it decides */
    int named_any;
    uint8_t key[SL_MASK_KEY_MAX];
    size_t key_len;
    column *cols;
    size_t ncols;
    size_t cap;
    int described;
    int work;
    unsigned long long count;
    /* what the catalog said about the tables, for the names that are qualified (see mask.h) */
    int qualified;
    int probed;
    uint32_t *known; /* every table the server listed, sorted once the list is complete */
    size_t nknown, capknown;
    struct {
        uint32_t oid;
        uint16_t entry; /* rule * SL_MASK_MAX_COLUMNS + column */
    } *hits;
    size_t nhits, caphits;
};

/* ---- the patterns ---- */

static int is_digit(int c)
{
    return c >= '0' && c <= '9';
}

static int is_alpha(int c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static int is_alnum(int c)
{
    return is_digit(c) || is_alpha(c);
}

int sl_mask_luhn(const char *digits, size_t n)
{
    int sum = 0;
    int alt = 0;

    if (n == 0) {
        return 0;
    }
    for (size_t i = n; i > 0; i--) {
        int d = digits[i - 1] - '0';

        if (d < 0 || d > 9) {
            return 0;
        }
        if (alt) {
            d *= 2;
            if (d > 9) {
                d -= 9;
            }
        }
        sum += d;
        alt = !alt;
    }
    return sum % 10 == 0;
}

static int local_char(int c)
{
    return is_alnum(c) || c == '.' || c == '_' || c == '%' || c == '+' || c == '-' || c == '\'';
}

static int domain_char(int c)
{
    return is_alnum(c) || c == '.' || c == '-';
}

/* local@domain.tld: the local part and the domain are as long as the characters allow, the domain
 * has a dot, ends in letters (two at least), and does not end in a dot or a hyphen. */
static int find_email(const char *t, size_t len, size_t from, size_t *start, size_t *end)
{
    for (size_t at = from; at < len; at++) {
        size_t s;
        size_t e;
        size_t last_dot;

        if (t[at] != '@') {
            continue;
        }
        s = at;
        while (s > from && local_char((unsigned char)t[s - 1])) {
            s--;
        }
        if (s == at) {
            continue;
        }
        e = at + 1;
        while (e < len && domain_char((unsigned char)t[e])) {
            e++;
        }
        while (e > at + 1 && (t[e - 1] == '.' || t[e - 1] == '-')) {
            e--; /* a sentence's full stop is not part of the address */
        }
        last_dot = 0;
        for (size_t i = at + 1; i < e; i++) {
            if (t[i] == '.') {
                last_dot = i;
            }
        }
        if (last_dot == 0 || last_dot == at + 1 || e - last_dot - 1 < 2) {
            continue;
        }
        {
            int letters = 1;

            for (size_t i = last_dot + 1; i < e; i++) {
                letters &= is_alpha((unsigned char)t[i]);
            }
            if (!letters) {
                continue;
            }
        }
        *start = s;
        *end = e;
        return 1;
    }
    return 0;
}

/* 13 to 19 digits, in groups separated by one space or hyphen, that pass the Luhn check, and that
 * are not part of a longer run of digits. */
static int find_card(const char *t, size_t len, size_t from, size_t *start, size_t *end)
{
    size_t i = from;

    while (i < len) {
        size_t j;
        size_t last = 0;
        size_t digits = 0;
        char buf[24];

        if (!is_digit((unsigned char)t[i]) || (i > from && is_digit((unsigned char)t[i - 1]))) {
            i++;
            continue;
        }
        j = i;
        while (j < len) {
            if (is_digit((unsigned char)t[j])) {
                if (digits < sizeof buf) {
                    buf[digits] = t[j];
                }
                digits++;
                last = j;
                j++;
            } else if ((t[j] == ' ' || t[j] == '-') && j + 1 < len &&
                       is_digit((unsigned char)t[j + 1]) && digits > 0) {
                j++;
            } else {
                break;
            }
        }
        if (digits >= 13 && digits <= 19 && sl_mask_luhn(buf, digits)) {
            *start = i;
            *end = last + 1;
            return 1;
        }
        i = j > i ? j : i + 1;
    }
    return 0;
}

/* The check of an IBAN: the first four characters go to the end, the letters become numbers (A =
 * 10), and the result modulo 97 must be 1. */
static int iban_ok(const char *c, size_t n)
{
    unsigned long rem = 0;

    for (size_t k = 0; k < n; k++) {
        int ch = (unsigned char)c[(k + 4) % n];

        if (is_digit(ch)) {
            rem = (rem * 10 + (unsigned long)(ch - '0')) % 97;
        } else if (ch >= 'A' && ch <= 'Z') {
            rem = (rem * 100 + (unsigned long)(ch - 'A' + 10)) % 97;
        } else {
            return 0;
        }
    }
    return rem == 1;
}

/* Two capital letters, two digits, then up to 30 capitals and digits, in the electronic form or in
 * groups separated by a single space. */
static int find_iban(const char *t, size_t len, size_t from, size_t *start, size_t *end)
{
    for (size_t i = from; i + 15 <= len; i++) {
        char c[40];
        size_t n = 0;
        size_t j;
        size_t last;

        if (!(t[i] >= 'A' && t[i] <= 'Z' && t[i + 1] >= 'A' && t[i + 1] <= 'Z' &&
              is_digit((unsigned char)t[i + 2]) && is_digit((unsigned char)t[i + 3]))) {
            continue;
        }
        if (i > from && is_alnum((unsigned char)t[i - 1])) {
            continue;
        }
        j = i;
        last = i;
        while (j < len && n <= 34) {
            int ch = (unsigned char)t[j];

            if ((ch >= 'A' && ch <= 'Z') || is_digit(ch)) {
                c[n++] = (char)ch;
                last = j;
                j++;
            } else if (ch == ' ' && j + 1 < len && is_alnum((unsigned char)t[j + 1]) && n >= 4) {
                j++;
            } else {
                break;
            }
        }
        if (last + 1 < len && is_alnum((unsigned char)t[last + 1])) {
            continue; /* it goes on with something that is not part of an IBAN */
        }
        if (n >= 15 && n <= 34 && iban_ok(c, n)) {
            *start = i;
            *end = last + 1;
            return 1;
        }
    }
    return 0;
}

int sl_mask_find(unsigned kind, const char *text, size_t len, size_t from, size_t *start,
                 size_t *end)
{
    switch (kind) {
    case SL_MASK_EMAIL:
        return find_email(text, len, from, start, end);
    case SL_MASK_CARD:
        return find_card(text, len, from, start, end);
    case SL_MASK_IBAN:
        return find_iban(text, len, from, start, end);
    default:
        return 0;
    }
}

/* ---- hiding ---- */

static void hex_token(const sl_mask *m, const char *v, size_t n, char *out)
{
    static const char hex[] = "0123456789abcdef";
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdl = 0;

    if (HMAC(EVP_sha256(), m->key, (int)m->key_len, (const unsigned char *)v, n, md, &mdl) ==
            NULL ||
        mdl < 8) {
        memset(md, 0, 8); /* cannot happen with a key; and never the value itself */
    }
    out[0] = '~';
    for (int i = 0; i < 8; i++) {
        out[1 + 2 * i] = hex[md[i] >> 4];
        out[2 + 2 * i] = hex[md[i] & 15];
    }
    out[17] = '\0';
}

/* What is kept of a whole value that has no pattern to follow: its first character and its last,
 * when it is long enough for that to hide it. */
static size_t partial_plain(const char *v, size_t n, char *out)
{
    if (n < 6) {
        memcpy(out, "***", 3);
        return 3;
    }
    out[0] = v[0];
    memcpy(out + 1, "***", 3);
    out[4] = v[n - 1];
    return 5;
}

/* The partial form of a match of one pattern: the head of an address, the end of a number. At most
 * TOKEN_MAX bytes. kind 0: no pattern (a whole value). */
static size_t partial_match(unsigned kind, const char *v, size_t n, char *out)
{
    size_t o = 0;

    if (kind == SL_MASK_EMAIL) {
        const char *at = memchr(v, '@', n);
        const char *dot = NULL;

        for (size_t i = n; i > 0; i--) {
            if (v[i - 1] == '.') {
                dot = v + i - 1;
                break;
            }
        }
        if (at == NULL || dot == NULL || dot < at) {
            return partial_plain(v, n, out);
        }
        out[o++] = v[0];
        memcpy(out + o, "***@", 4);
        o += 4;
        out[o++] = at[1];
        memcpy(out + o, "***", 3);
        o += 3;
        {
            size_t tld = (size_t)(v + n - dot);

            if (tld > 8) {
                tld = 8;
            }
            memcpy(out + o, dot, tld);
            o += tld;
        }
        return o;
    }
    if (kind == SL_MASK_CARD || kind == SL_MASK_IBAN) {
        char tail[4];
        size_t t = 0;

        /* a card keeps its last four digits, an IBAN its country and its last four characters */
        for (size_t i = n; i > 0 && t < sizeof tail; i--) {
            if (is_alnum((unsigned char)v[i - 1])) {
                tail[sizeof tail - 1 - t++] = v[i - 1];
            }
        }
        if (kind == SL_MASK_IBAN) {
            out[o++] = v[0];
            out[o++] = v[1];
        }
        memcpy(out + o, "****", 4);
        o += 4;
        memcpy(out + o, tail + sizeof tail - t, t);
        return o + t;
    }
    return partial_plain(v, n, out);
}

/* The text that takes the place of v: its length, or 0 with *null set when the value becomes NULL.
 */
static size_t hide(const sl_mask *m, int how, unsigned kind, const char *v, size_t n, char *out,
                   int *null)
{
    *null = 0;
    switch (how) {
    case SL_MASK_NULL:
        *null = 1;
        return 0;
    case SL_MASK_REDACT:
        memcpy(out, "[masked]", 8);
        return 8;
    case SL_MASK_PARTIAL:
        return partial_match(kind, v, n, out);
    default:
        hex_token(m, v, n, out);
        return 17;
    }
}

/* ---- the object ---- */

static int ci_equal(const char *a, size_t an, const char *b)
{
    return strlen(b) == an && strncasecmp(a, b, an) == 0;
}

sl_mask *sl_mask_new(const sl_mask_rule_view *rules, size_t n, const uint8_t *key, size_t key_len)
{
    sl_mask *m;

    if (n > SL_MASK_MAX_RULES || key == NULL || key_len == 0 || key_len > SL_MASK_KEY_MAX) {
        return NULL;
    }
    m = calloc(1, sizeof *m);
    if (m == NULL) {
        return NULL;
    }
    memcpy(m->key, key, key_len);
    m->key_len = key_len;
    for (size_t k = 0; k < KINDS; k++) {
        m->detect_how[k] = -1;
    }
    for (size_t i = 0; i < n; i++) {
        rule *r = &m->rules[m->nrules++];

        snprintf(r->name, sizeof r->name, "%s", rules[i].name != NULL ? rules[i].name : "");
        for (size_t c = 0; c < rules[i].ncolumns && r->ncolumns < SL_MASK_MAX_COLUMNS; c++) {
            /* column, table.column or schema.table.column */
            const char *e = rules[i].columns[c];
            const char *d2 = strrchr(e, '.');
            const char *d1 = d2 != NULL ? memchr(e, '.', (size_t)(d2 - e)) : NULL;
            size_t k = r->ncolumns++;

            if (d2 == NULL) {
                snprintf(r->columns[k], sizeof r->columns[0], "%s", e);
            } else {
                snprintf(r->columns[k], sizeof r->columns[0], "%s", d2 + 1);
                if (d1 == NULL) {
                    snprintf(r->tab[k], sizeof r->tab[0], "%.*s", (int)(d2 - e), e);
                } else {
                    snprintf(r->sch[k], sizeof r->sch[0], "%.*s", (int)(d1 - e), e);
                    snprintf(r->tab[k], sizeof r->tab[0], "%.*s", (int)(d2 - d1 - 1), d1 + 1);
                }
                m->qualified++;
            }
        }
        r->detect = rules[i].detect;
        r->how = rules[i].how;
        m->named_any |= r->ncolumns > 0;
        for (size_t k = 0; k < KINDS; k++) {
            if ((r->detect & (1u << k)) && m->detect_how[k] < 0) {
                m->detect_how[k] = r->how;
            }
        }
        m->detect_all |= r->detect;
    }
    return m;
}

void sl_mask_free(sl_mask *m)
{
    if (m == NULL) {
        return;
    }
    free(m->cols);
    free(m->known);
    free(m->hits);
    memset(m->key, 0, sizeof m->key);
    free(m);
}

static int rd16(const uint8_t *p, size_t len, size_t *pos, unsigned *v)
{
    if (len - *pos < 2) {
        return -1;
    }
    *v = (unsigned)((p[*pos] << 8) | p[*pos + 1]);
    *pos += 2;
    return 0;
}

#define TYPE_CHAR 18
#define TYPE_NAME 19
#define TYPE_TEXT 25
#define TYPE_BPCHAR 1042
#define TYPE_VARCHAR 1043
#define TYPE_JSON 114
#define TYPE_JSONB 3802
#define TYPE_XML 142

void sl_mask_forget(sl_mask *m)
{
    m->described = 0;
    m->work = 0;
    m->ncols = 0;
}

int sl_mask_has_work(const sl_mask *m)
{
    return m->described && m->work;
}

int sl_mask_described(const sl_mask *m)
{
    return m->described;
}

/* Is the column, which has the name of entry k of rule r, one of the table that entry names? A name
 * that is not qualified always is. A qualified one is hidden unless the server said the column
 * comes from another table: when the column belongs to no table (a computed value), when the
 * catalog was not read, or when the table is not one it listed (made since), it is hidden. Hiding
 * too much is the safe way to be wrong. */
static int table_ok(const sl_mask *m, const rule *r, size_t k, size_t entry, uint32_t toid)
{
    size_t lo = 0, hi = m->nknown;

    if (r->tab[k][0] == '\0' || toid == 0 || !m->probed) {
        return 1;
    }
    for (size_t i = 0; i < m->nhits; i++) {
        if (m->hits[i].oid == toid && m->hits[i].entry == entry) {
            return 1;
        }
    }
    while (lo < hi) { /* a table the server listed, and that is not this one */
        size_t mid = lo + (hi - lo) / 2;

        if (m->known[mid] == toid) {
            return 0;
        }
        if (m->known[mid] < toid) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return 1;
}

int sl_mask_qualified(const sl_mask *m)
{
    return m != NULL && m->qualified > 0;
}

void sl_mask_catalog_start(sl_mask *m)
{
    m->probed = 0;
    m->nknown = 0;
    m->nhits = 0;
}

int sl_mask_catalog_row(sl_mask *m, const uint8_t *p, size_t len)
{
    size_t pos = 2;
    const uint8_t *f[3];
    size_t fl[3];
    uint64_t oid = 0;

    if (len < 2 || ((p[0] << 8) | p[1]) != 3) {
        return -1;
    }
    for (int i = 0; i < 3; i++) {
        int32_t l;

        if (len - pos < 4) {
            return -1;
        }
        l = (int32_t)sl_pg_get_be32(p + pos);
        pos += 4;
        if (l < 0 || (size_t)l > len - pos) {
            return -1;
        }
        f[i] = p + pos;
        fl[i] = (size_t)l;
        pos += (size_t)l;
    }
    if (pos != len || fl[0] == 0 || fl[0] > 10) {
        return -1;
    }
    for (size_t i = 0; i < fl[0]; i++) {
        if (f[0][i] < '0' || f[0][i] > '9') {
            return -1;
        }
        oid = oid * 10 + (uint64_t)(f[0][i] - '0');
    }
    if (oid == 0 || oid > 0xffffffffu) {
        return -1;
    }
    if (m->nknown >= SL_MASK_CATALOG_MAX) {
        return 0; /* more tables than are kept: the others are not known, so they are hidden */
    }
    if (m->nknown == m->capknown) {
        size_t cap = m->capknown ? m->capknown * 2 : 256;
        uint32_t *n = realloc(m->known, cap * sizeof *n);

        if (n == NULL) {
            return -1;
        }
        m->known = n;
        m->capknown = cap;
    }
    m->known[m->nknown++] = (uint32_t)oid;
    for (size_t r = 0; r < m->nrules; r++) {
        for (size_t k = 0; k < m->rules[r].ncolumns; k++) {
            const rule *ru = &m->rules[r];

            if (ru->tab[k][0] != '\0' && ci_equal((const char *)f[2], fl[2], ru->tab[k]) &&
                (ru->sch[k][0] == '\0' || ci_equal((const char *)f[1], fl[1], ru->sch[k]))) {
                if (m->nhits == m->caphits) {
                    size_t cap = m->caphits ? m->caphits * 2 : 16;
                    void *n = realloc(m->hits, cap * sizeof *m->hits);

                    if (n == NULL) {
                        return -1;
                    }
                    m->hits = n;
                    m->caphits = cap;
                }
                m->hits[m->nhits].oid = (uint32_t)oid;
                m->hits[m->nhits].entry = (uint16_t)(r * SL_MASK_MAX_COLUMNS + k);
                m->nhits++;
            }
        }
    }
    return 0;
}

static int cmp_oid(const void *a, const void *b)
{
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;

    return x < y ? -1 : x > y;
}

void sl_mask_catalog_end(sl_mask *m, int ok)
{
    if (ok) {
        if (m->nknown > 1) { /* (known is NULL when the list is empty) */
            qsort(m->known, m->nknown, sizeof *m->known, cmp_oid);
        }
    } else {
        m->nknown = 0;
        m->nhits = 0;
    }
    m->probed = ok;
}

int sl_mask_describe(sl_mask *m, const uint8_t *p, size_t len)
{
    size_t pos = 0;
    unsigned n;

    sl_mask_forget(m);
    if (rd16(p, len, &pos, &n) != 0 || n > SL_MASK_MAX_FIELDS) {
        return -1;
    }
    if (n > m->cap) {
        column *c = realloc(m->cols, n * sizeof *c);

        if (c == NULL) {
            return -1;
        }
        m->cols = c;
        m->cap = n;
    }
    for (unsigned i = 0; i < n; i++) {
        const uint8_t *nul = memchr(p + pos, 0, len - pos);
        size_t nlen;
        uint32_t type;
        unsigned format;
        column *c = &m->cols[i];

        if (nul == NULL) {
            return -1;
        }
        nlen = (size_t)(nul - (p + pos));
        if (len - (pos + nlen + 1) < 18) {
            return -1;
        }
        memset(c, 0, sizeof *c);
        {
            const uint8_t *f = nul + 1;

            type = (uint32_t)f[6] << 24 | (uint32_t)f[7] << 16 | (uint32_t)f[8] << 8 | f[9];
            format = (unsigned)((f[16] << 8) | f[17]);
        }
        c->as_text = type == TYPE_TEXT || type == TYPE_VARCHAR || type == TYPE_BPCHAR ||
                     type == TYPE_NAME || type == TYPE_CHAR;
        c->binary = format != 0;
        for (size_t r = 0; r < m->nrules && !c->named; r++) {
            for (size_t k = 0; k < m->rules[r].ncolumns; k++) {
                if (ci_equal((const char *)p + pos, nlen, m->rules[r].columns[k]) &&
                    table_ok(m, &m->rules[r], k, r * SL_MASK_MAX_COLUMNS + k,
                             (uint32_t)(nul[1]) << 24 | (uint32_t)nul[2] << 16 |
                                 (uint32_t)nul[3] << 8 | nul[4])) {
                    c->named = 1;
                    c->how = (uint8_t)m->rules[r].how;
                    break;
                }
            }
        }
        c->scan = !c->named && m->detect_all != 0 &&
                  (c->as_text || type == TYPE_JSON || type == TYPE_JSONB || type == TYPE_XML);
        m->work |= c->named || c->scan;
        pos += nlen + 1 + 18;
    }
    if (pos != len) {
        return -1;
    }
    m->ncols = n;
    m->described = 1;
    return 0;
}

unsigned long long sl_mask_take_count(sl_mask *m)
{
    unsigned long long n = m->count;

    m->count = 0;
    return n;
}

/* ---- rewriting ---- */

static int put16(sl_buf *o, unsigned v)
{
    uint8_t b[2] = {(uint8_t)(v >> 8), (uint8_t)v};

    return sl_buf_append(o, b, 2);
}

static int put32(sl_buf *o, uint32_t v)
{
    uint8_t b[4];

    sl_pg_put_be32(b, v);
    return sl_buf_append(o, b, 4);
}

/* The next match of each pattern, found once and kept until it has been passed: the whole text is
 * walked once per pattern whatever the number of matches. */
typedef struct {
    int valid;
    int none;
    size_t s, e;
} next_match;

/* Appends the text with its patterns hidden. 0: nothing was found (nothing appended); 1: done; -1:
 * out of memory. */
static int scan_text(sl_mask *m, const char *v, size_t n, sl_buf *to)
{
    next_match nm[KINDS];
    size_t at = 0;
    size_t pos = 0;
    int any = 0;

    memset(nm, 0, sizeof nm);
    for (;;) {
        int best = -1;
        char tok[TOKEN_MAX];
        size_t tl;
        int isnull;
        int how;

        for (unsigned k = 0; k < KINDS; k++) {
            if (!(m->detect_all & (1u << k)) || nm[k].none) {
                continue;
            }
            if (!nm[k].valid || nm[k].s < at) {
                nm[k].valid = sl_mask_find(1u << k, v, n, at, &nm[k].s, &nm[k].e);
                nm[k].none = !nm[k].valid;
                if (nm[k].none) {
                    continue;
                }
            }
            if (best < 0 || nm[k].s < nm[best].s) {
                best = (int)k;
            }
        }
        if (best < 0) {
            break;
        }
        how = m->detect_how[best] < 0 ? SL_MASK_HASH : m->detect_how[best];
        tl = hide(m, how, 1u << best, v + nm[best].s, nm[best].e - nm[best].s, tok, &isnull);
        if (isnull) {
            memcpy(tok, "[masked]", 8); /* inside a text there is no NULL to give */
            tl = 8;
        }
        if (sl_buf_append(to, v + pos, nm[best].s - pos) != 0 || sl_buf_append(to, tok, tl) != 0) {
            return -1;
        }
        pos = nm[best].e;
        at = pos;
        any = 1;
        m->count++;
    }
    if (!any) {
        return 0;
    }
    return sl_buf_append(to, v + pos, n - pos) == 0 ? 1 : -1;
}

/* A value that is, as a whole, an address, a card number or an IBAN is kept the way that pattern is
 * (for "partial"); anything else has no pattern (0). */
static unsigned whole_kind(const char *v, size_t n)
{
    static const unsigned kinds[] = {SL_MASK_EMAIL, SL_MASK_CARD, SL_MASK_IBAN};
    size_t s;
    size_t e;

    for (size_t k = 0; k < 3; k++) {
        if (sl_mask_find(kinds[k], v, n, 0, &s, &e) && s == 0 && e == n) {
            return kinds[k];
        }
    }
    return 0;
}

/* Does the row need any change? Walks it without writing anything. */
static int row_needs_work(sl_mask *m, const uint8_t *p, size_t len)
{
    size_t pos = 2;
    unsigned long long count = m->count;

    for (size_t i = 0; i < m->ncols; i++) {
        int32_t l;
        sl_buf scratch;
        int rc;

        if (len - pos < 4) {
            return 0;
        }
        l = (int32_t)sl_pg_get_be32(p + pos);
        pos += 4;
        if (l <= 0 || (size_t)l > len - pos) {
            continue;
        }
        if (m->cols[i].named) {
            m->count = count;
            return 1;
        }
        if (m->cols[i].scan) {
            sl_buf_init(&scratch);
            rc = scan_text(m, (const char *)p + pos, (size_t)l, &scratch);
            sl_buf_free(&scratch);
            m->count = count; /* the real count is made when the row is written */
            if (rc != 0) {
                return 1;
            }
        }
        pos += (size_t)l;
    }
    return 0;
}

int sl_mask_row(sl_mask *m, const uint8_t *p, size_t len, sl_buf *out)
{
    size_t pos = 0;
    unsigned n;
    sl_buf row;
    int rc = SL_MASK_BAD;

    if (!m->described || rd16(p, len, &pos, &n) != 0 || n != m->ncols) {
        return SL_MASK_BAD;
    }
    /* the framing of the row is checked first: a row that does not fit its description is refused
     * even when there is nothing to hide in it */
    for (unsigned i = 0; i < n; i++) {
        int32_t l;

        if (len - pos < 4) {
            return SL_MASK_BAD;
        }
        l = (int32_t)sl_pg_get_be32(p + pos);
        pos += 4;
        if (l == -1) {
            continue;
        }
        if (l < 0 || (size_t)l > len - pos) {
            return SL_MASK_BAD;
        }
        pos += (size_t)l;
    }
    if (pos != len) {
        return SL_MASK_BAD;
    }
    if (!row_needs_work(m, p, len)) {
        return SL_MASK_SAME;
    }

    sl_buf_init(&row);
    if (put16(&row, n) != 0) {
        rc = SL_MASK_NOMEM;
        goto done;
    }
    pos = 2;
    for (unsigned i = 0; i < n; i++) {
        const column *c = &m->cols[i];
        int32_t l = (int32_t)sl_pg_get_be32(p + pos);
        const char *v;

        pos += 4;
        if (l == -1) {
            if (put32(&row, 0xffffffffu) != 0) {
                rc = SL_MASK_NOMEM;
                goto done;
            }
            continue;
        }
        v = (const char *)p + pos;
        pos += (size_t)l;
        if (c->named && l > 0) {
            char tok[TOKEN_MAX];
            int isnull;
            size_t tl = hide(m, c->as_text ? c->how : SL_MASK_NULL, whole_kind(v, (size_t)l), v,
                             (size_t)l, tok, &isnull);

            m->count++;
            if (isnull ? put32(&row, 0xffffffffu) != 0
                       : (put32(&row, (uint32_t)tl) != 0 || sl_buf_append(&row, tok, tl) != 0)) {
                rc = SL_MASK_NOMEM;
                goto done;
            }
            continue;
        }
        if (c->scan && l > 0) {
            sl_buf text;
            int r;

            sl_buf_init(&text);
            r = scan_text(m, v, (size_t)l, &text);
            if (r < 0) {
                sl_buf_free(&text);
                rc = SL_MASK_NOMEM;
                goto done;
            }
            if (r > 0) {
                int bad = put32(&row, (uint32_t)sl_buf_len(&text)) != 0 ||
                          sl_buf_append(&row, sl_buf_data(&text), sl_buf_len(&text)) != 0;

                sl_buf_free(&text);
                if (bad) {
                    rc = SL_MASK_NOMEM;
                    goto done;
                }
                continue;
            }
            sl_buf_free(&text);
        }
        if (put32(&row, (uint32_t)l) != 0 || (l > 0 && sl_buf_append(&row, v, (size_t)l) != 0)) {
            rc = SL_MASK_NOMEM;
            goto done;
        }
    }
    rc = sl_buf_append(out, sl_buf_data(&row), sl_buf_len(&row)) == 0 ? SL_MASK_CHANGED
                                                                      : SL_MASK_NOMEM;
done:
    sl_buf_free(&row);
    return rc;
}

/* ---- errors and notices ---- */

static int name_is_masked(const sl_mask *m, const char *s, size_t n)
{
    while (n > 0 && (*s == ' ' || *s == '"')) {
        s++;
        n--;
    }
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '"')) {
        n--;
    }
    for (size_t r = 0; r < m->nrules; r++) {
        for (size_t k = 0; k < m->rules[r].ncolumns; k++) {
            if (ci_equal(s, n, m->rules[r].columns[k])) {
                return 1;
            }
        }
    }
    return 0;
}

/* "Key (a, b)=(1, x) already exists." and "Failing row contains (1, x, y)." quote the values of the
 * row. They are replaced when a column that is hidden could be among them (the first names its
 * columns; the second does not, so it is replaced whenever any column is hidden by name). */
static int quoted_values(const sl_mask *m, const char *v, size_t n, size_t *from, size_t *to)
{
    static const char fail[] = "Failing row contains (";
    static const char key[] = "Key (";
    size_t close = 0;

    for (size_t i = n; i > 0; i--) {
        if (v[i - 1] == ')') {
            close = i - 1;
            break;
        }
    }
    if (close == 0) {
        return 0;
    }
    if (n > sizeof fail - 1 && memcmp(v, fail, sizeof fail - 1) == 0 && m->named_any) {
        *from = sizeof fail - 1;
        *to = close;
        return *from <= *to;
    }
    if (n > sizeof key - 1 && memcmp(v, key, sizeof key - 1) == 0) {
        size_t sep = 0;
        size_t a = sizeof key - 1;
        int hit = 0;

        for (size_t i = a; i + 2 < n; i++) {
            if (v[i] == ')' && v[i + 1] == '=' && v[i + 2] == '(') {
                sep = i;
                break;
            }
        }
        if (sep == 0 || sep + 3 > close) {
            return 0;
        }
        for (size_t i = a; i <= sep; i++) {
            if (i == sep || v[i] == ',') {
                hit |= name_is_masked(m, v + a, i - a);
                a = i + 1;
            }
        }
        if (hit) {
            *from = sep + 3;
            *to = close;
            return 1;
        }
    }
    return 0;
}

int sl_mask_message(sl_mask *m, const uint8_t *p, size_t len, sl_buf *out)
{
    sl_buf msg;
    size_t pos = 0;
    int changed = 0;
    int rc = SL_MASK_SAME;

    sl_buf_init(&msg);
    while (pos < len && p[pos] != 0) {
        uint8_t type = p[pos];
        const uint8_t *nul = memchr(p + pos + 1, 0, len - pos - 1);
        const char *v = (const char *)p + pos + 1;
        size_t n;

        if (nul == NULL) {
            rc = SL_MASK_BAD;
            goto done;
        }
        n = (size_t)(nul - (const uint8_t *)v);
        pos += n + 2;
        if (sl_buf_append(&msg, &type, 1) != 0) {
            rc = SL_MASK_NOMEM;
            goto done;
        }
        if (type == 'M' || type == 'D' || type == 'H' || type == 'W' || type == 'q') {
            size_t from = 0;
            size_t to = 0;
            sl_buf text;
            int r;

            sl_buf_init(&text);
            if (type == 'D' && quoted_values(m, v, n, &from, &to)) {
                if (sl_buf_append(&text, v, from) != 0 ||
                    sl_buf_append(&text, "[masked]", 8) != 0 ||
                    sl_buf_append(&text, v + to, n - to) != 0) {
                    sl_buf_free(&text);
                    rc = SL_MASK_NOMEM;
                    goto done;
                }
                changed = 1;
                m->count++;
                v = (const char *)sl_buf_data(&text);
                n = sl_buf_len(&text);
            }
            if (m->detect_all != 0) {
                sl_buf scanned;

                sl_buf_init(&scanned);
                r = scan_text(m, v, n, &scanned);
                if (r < 0) {
                    sl_buf_free(&scanned);
                    sl_buf_free(&text);
                    rc = SL_MASK_NOMEM;
                    goto done;
                }
                if (r > 0) {
                    changed = 1;
                    r = sl_buf_append(&msg, sl_buf_data(&scanned), sl_buf_len(&scanned));
                } else {
                    r = sl_buf_append(&msg, v, n);
                }
                sl_buf_free(&scanned);
            } else {
                r = sl_buf_append(&msg, v, n);
            }
            sl_buf_free(&text);
            if (r != 0) {
                rc = SL_MASK_NOMEM;
                goto done;
            }
        } else if (sl_buf_append(&msg, v, n) != 0) {
            rc = SL_MASK_NOMEM;
            goto done;
        }
        if (sl_buf_append(&msg, "", 1) != 0) {
            rc = SL_MASK_NOMEM;
            goto done;
        }
    }
    if (!changed) {
        goto done;
    }
    if (sl_buf_append(&msg, "", 1) != 0 ||
        sl_buf_append(out, sl_buf_data(&msg), sl_buf_len(&msg)) != 0) {
        rc = SL_MASK_NOMEM;
        goto done;
    }
    rc = SL_MASK_CHANGED;
done:
    sl_buf_free(&msg);
    return rc;
}
