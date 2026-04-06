#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "check.h"
#include "mask.h"
#include "pg_proto.h"

static const uint8_t KEY[] = "0123456789abcdef0123456789abcdef";

/* ---- building messages ---- */

static void put16(sl_buf *b, unsigned v)
{
    uint8_t x[2] = {(uint8_t)(v >> 8), (uint8_t)v};

    sl_buf_append(b, x, 2);
}

static void put32(sl_buf *b, uint32_t v)
{
    uint8_t x[4];

    sl_pg_put_be32(x, v);
    sl_buf_append(b, x, 4);
}

typedef struct {
    const char *name;
    uint32_t type;
    unsigned format;
    uint32_t oid; /* the table the column comes from; 0: none */
} col;

static void describe(sl_buf *b, const col *cols, size_t n)
{
    put16(b, (unsigned)n);
    for (size_t i = 0; i < n; i++) {
        sl_buf_append(b, cols[i].name, strlen(cols[i].name) + 1);
        put32(b, cols[i].oid); /* table oid */
        put16(b, 0);           /* attnum */
        put32(b, cols[i].type);
        put16(b, 0xffff); /* typlen */
        put32(b, 0xffffffffu);
        put16(b, cols[i].format);
    }
}

/* a DataRow from strings; NULL is a NULL */
static void row(sl_buf *b, const char *const *vals, size_t n)
{
    put16(b, (unsigned)n);
    for (size_t i = 0; i < n; i++) {
        if (vals[i] == NULL) {
            put32(b, 0xffffffffu);
        } else {
            put32(b, (uint32_t)strlen(vals[i]));
            sl_buf_append(b, vals[i], strlen(vals[i]));
        }
    }
}

/* the value of field i of a DataRow payload; *null set for NULL */
static const char *field(const sl_buf *b, size_t i, size_t *len, int *null)
{
    const uint8_t *p = sl_buf_data(b);
    size_t pos = 2;

    for (size_t k = 0;; k++) {
        int32_t l = (int32_t)sl_pg_get_be32(p + pos);

        pos += 4;
        if (k == i) {
            *null = l == -1;
            *len = l == -1 ? 0 : (size_t)l;
            return (const char *)p + pos;
        }
        pos += l == -1 ? 0 : (size_t)l;
    }
}

static int field_is(const sl_buf *b, size_t i, const char *want)
{
    size_t l;
    int null;
    const char *v = field(b, i, &l, &null);

    return want == NULL ? null : (!null && l == strlen(want) && memcmp(v, want, l) == 0);
}

static sl_mask *make(const char *const *columns, size_t ncolumns, unsigned detect, int how)
{
    sl_mask_rule_view r = {"r", (char *const *)columns, ncolumns, detect, how};

    return sl_mask_new(&r, 1, KEY, sizeof KEY - 1);
}

/* ---- the patterns ---- */

static int finds(unsigned kind, const char *text, const char *want)
{
    size_t s;
    size_t e;

    if (!sl_mask_find(kind, text, strlen(text), 0, &s, &e)) {
        return want == NULL;
    }
    return want != NULL && strlen(want) == e - s && memcmp(text + s, want, e - s) == 0;
}

static void test_email(void)
{
    CHECK(finds(SL_MASK_EMAIL, "write to ana@example.com now", "ana@example.com"));
    CHECK(finds(SL_MASK_EMAIL, "ana.b+tag@sub.example.co.uk.", "ana.b+tag@sub.example.co.uk"));
    CHECK(finds(SL_MASK_EMAIL, "<o'brien@x.io>", "o'brien@x.io"));
    CHECK(finds(SL_MASK_EMAIL, "a@b.c", NULL));        /* a one-letter top level */
    CHECK(finds(SL_MASK_EMAIL, "@example.com", NULL)); /* nothing before */
    CHECK(finds(SL_MASK_EMAIL, "ana@example", NULL));  /* no dot */
    CHECK(finds(SL_MASK_EMAIL, "ana@.com", NULL));
    CHECK(finds(SL_MASK_EMAIL, "ana@host.123", NULL)); /* the end is not letters */
    CHECK(finds(SL_MASK_EMAIL, "user@localhost.localdomain", "user@localhost.localdomain"));
    CHECK(finds(SL_MASK_EMAIL, "no at sign here", NULL));
    CHECK(finds(SL_MASK_EMAIL, "@@@@", NULL));
}

static void test_card(void)
{
    CHECK(finds(SL_MASK_CARD, "card 4111111111111111 ok", "4111111111111111"));
    CHECK(finds(SL_MASK_CARD, "4111 1111 1111 1111", "4111 1111 1111 1111"));
    CHECK(finds(SL_MASK_CARD, "4111-1111-1111-1111.", "4111-1111-1111-1111"));
    CHECK(finds(SL_MASK_CARD, "5500005555555559", "5500005555555559"));
    CHECK(finds(SL_MASK_CARD, "378282246310005", "378282246310005"));         /* 15 digits */
    CHECK(finds(SL_MASK_CARD, "4111111111111112", NULL));                     /* fails Luhn */
    CHECK(finds(SL_MASK_CARD, "411111111111", NULL));                         /* 12 digits */
    CHECK(finds(SL_MASK_CARD, "41111111111111111111", NULL));                 /* 20 digits */
    CHECK(finds(SL_MASK_CARD, "2024-01-15 10:30:00", NULL));                  /* a timestamp */
    CHECK(finds(SL_MASK_CARD, "a1b2c3d4-e5f6-7890-abcd-ef1234567890", NULL)); /* a uuid */
    CHECK(finds(SL_MASK_CARD, "+33 6 12 34 56 78", NULL));                    /* a phone number */
    CHECK(sl_mask_luhn("79927398713", 11));
    CHECK(!sl_mask_luhn("79927398710", 11));
    CHECK(!sl_mask_luhn("", 0));
    CHECK(!sl_mask_luhn("12a4", 4));
}

static void test_iban(void)
{
    CHECK(finds(SL_MASK_IBAN, "FR7630006000011234567890189", "FR7630006000011234567890189"));
    CHECK(finds(SL_MASK_IBAN, "iban: GB82 WEST 1234 5698 7654 32 thanks",
                "GB82 WEST 1234 5698 7654 32"));
    CHECK(finds(SL_MASK_IBAN, "DE89370400440532013000", "DE89370400440532013000"));
    CHECK(finds(SL_MASK_IBAN, "DE89370400440532013001", NULL));       /* bad check digits */
    CHECK(finds(SL_MASK_IBAN, "fr7630006000011234567890189", NULL));  /* lower case */
    CHECK(finds(SL_MASK_IBAN, "XFR7630006000011234567890189", NULL)); /* part of a longer word */
    CHECK(finds(SL_MASK_IBAN, "FR76", NULL));
}

/* ---- rows ---- */

static void test_named_columns(void)
{
    const char *cols[] = {"Email", "ssn"};
    sl_mask *m = make(cols, 2, 0, SL_MASK_HASH);
    col d[] = {{"id", 23, 0, 0}, {"email", 25, 0, 0}, {"SSN", 1043, 0, 0}, {"note", 25, 0, 0}};
    const char *v[] = {"1", "ana@example.com", "123-45-6789", "hello"};
    const char *nul[] = {"2", NULL, "", "x"};
    sl_buf dd, r, out;
    char t1[32], t2[32];
    size_t l;
    int null;

    sl_buf_init(&dd);
    sl_buf_init(&r);
    sl_buf_init(&out);
    CHECK(m != NULL);
    describe(&dd, d, 4);
    CHECK(sl_mask_describe(m, sl_buf_data(&dd), sl_buf_len(&dd)) == 0);
    CHECK(sl_mask_has_work(m));
    row(&r, v, 4);
    CHECK(sl_mask_row(m, sl_buf_data(&r), sl_buf_len(&r), &out) == SL_MASK_CHANGED);
    CHECK(field_is(&out, 0, "1") && field_is(&out, 3, "hello"));
    {
        const char *a = field(&out, 1, &l, &null);

        CHECK(!null && l == 17 && a[0] == '~');
        memcpy(t1, a, l);
        t1[l] = 0;
        CHECK(!field_is(&out, 1, "ana@example.com"));
    }
    /* the same value gives the same token, another value another */
    sl_buf_free(&out);
    sl_buf_init(&out);
    CHECK(sl_mask_row(m, sl_buf_data(&r), sl_buf_len(&r), &out) == SL_MASK_CHANGED);
    {
        const char *a = field(&out, 1, &l, &null);

        memcpy(t2, a, l);
        t2[l] = 0;
        CHECK(strcmp(t1, t2) == 0);
    }
    /* a NULL and an empty string are left alone */
    sl_buf_free(&r);
    sl_buf_init(&r);
    sl_buf_free(&out);
    sl_buf_init(&out);
    row(&r, nul, 4);
    CHECK(sl_mask_row(m, sl_buf_data(&r), sl_buf_len(&r), &out) == SL_MASK_SAME);
    sl_buf_free(&dd);
    sl_buf_free(&r);
    sl_buf_free(&out);
    sl_mask_free(m);
}

/* A row of the answer to SL_MASK_CATALOG_SQL */
static void catalog_row(sl_buf *b, const char *oid, const char *schema, const char *table)
{
    const char *v[] = {oid, schema, table};

    row(b, v, 3);
}

static int email_hidden(sl_mask *m, uint32_t oid)
{
    col d[] = {{"id", 23, 0, oid}, {"email", 25, 0, oid}};
    const char *v[] = {"1", "ana@example.com"};
    sl_buf dd, r, out;
    int hidden;

    sl_buf_init(&dd);
    sl_buf_init(&r);
    sl_buf_init(&out);
    describe(&dd, d, 2);
    CHECK(sl_mask_describe(m, sl_buf_data(&dd), sl_buf_len(&dd)) == 0);
    row(&r, v, 2);
    hidden = sl_mask_row(m, sl_buf_data(&r), sl_buf_len(&r), &out) == SL_MASK_CHANGED;
    sl_buf_free(&dd);
    sl_buf_free(&r);
    sl_buf_free(&out);
    return hidden;
}

static void test_qualified_names(void)
{
    const char *cols[] = {"users.email", "Billing.Invoices.email", "plain"};
    sl_mask *m = make(cols, 3, 0, SL_MASK_REDACT);
    sl_buf r;

    CHECK(m != NULL && sl_mask_qualified(m));
    /* the catalog was not read: a qualified name hides like an unqualified one */
    CHECK(email_hidden(m, 16385) && email_hidden(m, 0));

    sl_mask_catalog_start(m);
    sl_buf_init(&r);
    catalog_row(&r, "16385", "public", "users");
    CHECK(sl_mask_catalog_row(m, sl_buf_data(&r), sl_buf_len(&r)) == 0);
    sl_buf_free(&r);
    sl_buf_init(&r);
    catalog_row(&r, "16390", "public", "orders");
    CHECK(sl_mask_catalog_row(m, sl_buf_data(&r), sl_buf_len(&r)) == 0);
    sl_buf_free(&r);
    sl_buf_init(&r);
    catalog_row(&r, "16400", "billing", "invoices");
    CHECK(sl_mask_catalog_row(m, sl_buf_data(&r), sl_buf_len(&r)) == 0);
    sl_buf_free(&r);
    sl_buf_init(&r);
    catalog_row(&r, "16401", "archive", "invoices");
    CHECK(sl_mask_catalog_row(m, sl_buf_data(&r), sl_buf_len(&r)) == 0);
    sl_buf_free(&r);
    sl_mask_catalog_end(m, 1);

    CHECK(email_hidden(m, 16385));  /* users.email: the table */
    CHECK(!email_hidden(m, 16390)); /* orders.email: another table the server listed */
    CHECK(email_hidden(m, 16400));  /* billing.invoices.email: schema and table */
    CHECK(!email_hidden(m, 16401)); /* archive.invoices: same table name, other schema */
    CHECK(email_hidden(m, 0));      /* not from a table: hidden */
    CHECK(email_hidden(m, 99999));  /* made since the list was read: hidden */

    /* the list ended in an error: back to hiding by name */
    sl_mask_catalog_start(m);
    sl_mask_catalog_end(m, 0);
    CHECK(email_hidden(m, 16390));
    sl_mask_free(m);

    /* without a qualified name there is nothing to ask */
    {
        const char *one[] = {"email"};

        m = make(one, 1, 0, SL_MASK_REDACT);
        CHECK(!sl_mask_qualified(m) && email_hidden(m, 16390));
        sl_mask_free(m);
    }
    /* a row of the answer that is not three texts is refused */
    {
        const char *one[] = {"email"};
        const char *two[] = {"1", "x"};

        m = make(one, 1, 0, SL_MASK_REDACT);
        sl_buf_init(&r);
        row(&r, two, 2);
        CHECK(sl_mask_catalog_row(m, sl_buf_data(&r), sl_buf_len(&r)) == -1);
        sl_buf_free(&r);
        sl_buf_init(&r);
        catalog_row(&r, "abc", "s", "t");
        CHECK(sl_mask_catalog_row(m, sl_buf_data(&r), sl_buf_len(&r)) == -1);
        sl_buf_free(&r);
        sl_mask_free(m);
    }
}

static void test_hows(void)
{
    const char *cols[] = {"email"};
    col d[] = {{"email", 25, 0, 0}};
    const char *v[] = {"ana@example.com"};
    struct {
        int how;
        const char *want; /* NULL: a NULL value */
    } cases[] = {
        {SL_MASK_NULL, NULL}, {SL_MASK_REDACT, "[masked]"}, {SL_MASK_PARTIAL, "a***@e***.com"}};

    for (size_t i = 0; i < 3; i++) {
        sl_mask *m = make(cols, 1, 0, cases[i].how);
        sl_buf dd, r, out;

        sl_buf_init(&dd);
        sl_buf_init(&r);
        sl_buf_init(&out);
        describe(&dd, d, 1);
        CHECK(sl_mask_describe(m, sl_buf_data(&dd), sl_buf_len(&dd)) == 0);
        row(&r, v, 1);
        CHECK(sl_mask_row(m, sl_buf_data(&r), sl_buf_len(&r), &out) == SL_MASK_CHANGED);
        CHECK(field_is(&out, 0, cases[i].want));
        sl_buf_free(&dd);
        sl_buf_free(&r);
        sl_buf_free(&out);
        sl_mask_free(m);
    }
    /* a whole value that is short is not given away by "partial" */
    {
        const char *c2[] = {"code"};
        col d2[] = {{"code", 25, 0, 0}};
        const char *v2[] = {"abc"};
        sl_mask *m = make(c2, 1, 0, SL_MASK_PARTIAL);
        sl_buf dd, r, out;

        sl_buf_init(&dd);
        sl_buf_init(&r);
        sl_buf_init(&out);
        describe(&dd, d2, 1);
        sl_mask_describe(m, sl_buf_data(&dd), sl_buf_len(&dd));
        row(&r, v2, 1);
        CHECK(sl_mask_row(m, sl_buf_data(&r), sl_buf_len(&r), &out) == SL_MASK_CHANGED);
        CHECK(field_is(&out, 0, "***"));
        sl_buf_free(&dd);
        sl_buf_free(&r);
        sl_buf_free(&out);
        sl_mask_free(m);
    }
}

static void test_types(void)
{
    /* a column picked by name that is not text becomes NULL, whatever `how` is; text types, in both
     * formats, become text */
    const char *cols[] = {"a", "b", "c", "d"};
    col d[] = {{"a", 23, 0, 0}, {"b", 25, 1, 0}, {"c", 1043, 0, 0}, {"d", 2950, 0, 0}};
    const char *v[] = {"42", "bin", "txt", "0a0b"};
    sl_mask *m = make(cols, 4, 0, SL_MASK_REDACT);
    sl_buf dd, r, out;

    sl_buf_init(&dd);
    sl_buf_init(&r);
    sl_buf_init(&out);
    describe(&dd, d, 4);
    sl_mask_describe(m, sl_buf_data(&dd), sl_buf_len(&dd));
    row(&r, v, 4);
    CHECK(sl_mask_row(m, sl_buf_data(&r), sl_buf_len(&r), &out) == SL_MASK_CHANGED);
    CHECK(field_is(&out, 0, NULL) && field_is(&out, 1, "[masked]") &&
          field_is(&out, 2, "[masked]") && field_is(&out, 3, NULL));
    sl_buf_free(&dd);
    sl_buf_free(&r);
    sl_buf_free(&out);
    sl_mask_free(m);
}

static void test_detectors_in_text(void)
{
    sl_mask *m = make(NULL, 0, SL_MASK_EMAIL | SL_MASK_CARD | SL_MASK_IBAN, SL_MASK_REDACT);
    col d[] = {{"id", 23, 0, 0}, {"notes", 25, 0, 0}, {"meta", 3802, 0, 0}, {"n", 1700, 0, 0}};
    const char *v[] = {"4111111111111111",
                       ("call ana@example.com or bob@example.org, card 4111 1111 1111 1111; "
                        "iban FR7630006000011234567890189."),
                       "{\"mail\": \"ana@example.com\"}", "4111111111111111"};
    sl_buf dd, r, out;

    sl_buf_init(&dd);
    sl_buf_init(&r);
    sl_buf_init(&out);
    describe(&dd, d, 4);
    sl_mask_describe(m, sl_buf_data(&dd), sl_buf_len(&dd));
    row(&r, v, 4);
    CHECK(sl_mask_row(m, sl_buf_data(&r), sl_buf_len(&r), &out) == SL_MASK_CHANGED);
    CHECK(field_is(&out, 0, "4111111111111111")); /* an integer column is not looked into */
    CHECK(field_is(&out, 1, "call [masked] or [masked], card [masked]; iban [masked]."));
    CHECK(field_is(&out, 2, "{\"mail\": \"[masked]\"}"));
    CHECK(field_is(&out, 3, "4111111111111111")); /* nor a numeric */
    CHECK(sl_mask_take_count(m) == 5 && sl_mask_take_count(m) == 0);
    sl_buf_free(&dd);
    sl_buf_free(&r);
    sl_buf_free(&out);
    sl_mask_free(m);
}

static void test_many_matches(void)
{
    /* no limit on how many are found in one value, and the walk is linear */
    sl_mask *m = make(NULL, 0, SL_MASK_EMAIL, SL_MASK_REDACT);
    col d[] = {{"t", 25, 0, 0}};
    sl_buf dd, r, out, big;
    size_t l;
    int null;
    const char *got;

    sl_buf_init(&dd);
    sl_buf_init(&r);
    sl_buf_init(&out);
    sl_buf_init(&big);
    for (int i = 0; i < 5000; i++) {
        sl_buf_append(&big, "a@b.cc ", 7);
    }
    sl_buf_append(&big, "", 1);
    describe(&dd, d, 1);
    sl_mask_describe(m, sl_buf_data(&dd), sl_buf_len(&dd));
    {
        const char *v[] = {(const char *)sl_buf_data(&big)};

        row(&r, v, 1);
    }
    CHECK(sl_mask_row(m, sl_buf_data(&r), sl_buf_len(&r), &out) == SL_MASK_CHANGED);
    got = field(&out, 0, &l, &null);
    CHECK(l == 5000 * 9 && memcmp(got, "[masked] [masked]", 17) == 0 && strstr(got, "@") == NULL);
    CHECK(sl_mask_take_count(m) == 5000);
    sl_buf_free(&dd);
    sl_buf_free(&r);
    sl_buf_free(&out);
    sl_buf_free(&big);
    sl_mask_free(m);
}

static void test_partial_in_text(void)
{
    sl_mask *m = make(NULL, 0, SL_MASK_EMAIL | SL_MASK_CARD | SL_MASK_IBAN, SL_MASK_PARTIAL);
    col d[] = {{"t", 25, 0, 0}};
    const char *v[] = {
        "ana@example.com / 4111 1111 1111 1111 / FR7630006000011234567890189 / x@y.org"};
    sl_buf dd, r, out;

    sl_buf_init(&dd);
    sl_buf_init(&r);
    sl_buf_init(&out);
    describe(&dd, d, 1);
    sl_mask_describe(m, sl_buf_data(&dd), sl_buf_len(&dd));
    row(&r, v, 1);
    CHECK(sl_mask_row(m, sl_buf_data(&r), sl_buf_len(&r), &out) == SL_MASK_CHANGED);
    CHECK(field_is(&out, 0, "a***@e***.com / ****1111 / FR****0189 / x***@y***.org"));
    sl_buf_free(&dd);
    sl_buf_free(&r);
    sl_buf_free(&out);
    sl_mask_free(m);
}

static void test_nothing_to_do(void)
{
    const char *cols[] = {"email"};
    col d[] = {{"id", 23, 0, 0}, {"name", 25, 0, 0}};
    const char *v[] = {"1", "Ana"};
    sl_mask *m = make(cols, 1, 0, SL_MASK_HASH);
    sl_buf dd, r, out;

    sl_buf_init(&dd);
    sl_buf_init(&r);
    sl_buf_init(&out);
    describe(&dd, d, 2);
    CHECK(sl_mask_describe(m, sl_buf_data(&dd), sl_buf_len(&dd)) == 0);
    CHECK(!sl_mask_has_work(m)); /* no such column, no pattern: the rows may go unread */
    row(&r, v, 2);
    CHECK(sl_mask_row(m, sl_buf_data(&r), sl_buf_len(&r), &out) == SL_MASK_SAME);
    CHECK(sl_buf_len(&out) == 0);
    sl_buf_free(&dd);
    sl_buf_free(&r);
    sl_buf_free(&out);
    sl_mask_free(m);
}

static void test_bad_input(void)
{
    const char *cols[] = {"email"};
    sl_mask *m = make(cols, 1, SL_MASK_EMAIL, SL_MASK_HASH);
    col d[] = {{"email", 25, 0, 0}, {"x", 25, 0, 0}};
    const char *v[] = {"a@b.com", "y"};
    sl_buf dd, r, out;
    uint8_t cut[64];

    sl_buf_init(&dd);
    sl_buf_init(&r);
    sl_buf_init(&out);
    /* a row before any description is refused */
    row(&r, v, 2);
    CHECK(sl_mask_row(m, sl_buf_data(&r), sl_buf_len(&r), &out) == SL_MASK_BAD);
    describe(&dd, d, 2);
    CHECK(sl_mask_describe(m, sl_buf_data(&dd), sl_buf_len(&dd)) == 0);
    CHECK(sl_mask_row(m, sl_buf_data(&r), sl_buf_len(&r), &out) == SL_MASK_CHANGED);
    /* every cut of the row, a wrong number of columns, bytes after the end */
    sl_buf_free(&out);
    sl_buf_init(&out);
    for (size_t n = 0; n < sl_buf_len(&r); n++) {
        CHECK(sl_mask_row(m, sl_buf_data(&r), n, &out) == SL_MASK_BAD);
    }
    memcpy(cut, sl_buf_data(&r), sl_buf_len(&r));
    CHECK(sl_mask_row(m, cut, sl_buf_len(&r), &out) == SL_MASK_CHANGED);
    cut[1] = 3;
    CHECK(sl_mask_row(m, cut, sl_buf_len(&r), &out) == SL_MASK_BAD);
    cut[1] = 2;
    cut[sl_buf_len(&r)] = 0;
    CHECK(sl_mask_row(m, cut, sl_buf_len(&r) + 1, &out) == SL_MASK_BAD);
    /* a length that lies */
    cut[5] = 0x7f;
    CHECK(sl_mask_row(m, cut, sl_buf_len(&r), &out) == SL_MASK_BAD);
    /* descriptions that are not well formed are refused, and leave no description */
    for (size_t n = 0; n < sl_buf_len(&dd); n++) {
        CHECK(sl_mask_describe(m, sl_buf_data(&dd), n) == -1 && !sl_mask_described(m));
    }
    CHECK(sl_mask_describe(m, (const uint8_t *)"\xff\xff", 2) == -1);
    sl_mask_forget(m);
    CHECK(!sl_mask_described(m));
    sl_buf_free(&dd);
    sl_buf_free(&r);
    sl_buf_free(&out);
    sl_mask_free(m);
}

/* ---- errors and notices ---- */

static void error_msg(sl_buf *b, const char *severity, const char *message, const char *detail)
{
    sl_buf_append(b, "S", 1);
    sl_buf_append(b, severity, strlen(severity) + 1);
    sl_buf_append(b, "M", 1);
    sl_buf_append(b, message, strlen(message) + 1);
    if (detail != NULL) {
        sl_buf_append(b, "D", 1);
        sl_buf_append(b, detail, strlen(detail) + 1);
    }
    sl_buf_append(b, "", 1);
}

static int has(const sl_buf *b, const char *s)
{
    const char *d = (const char *)sl_buf_data(b);
    size_t n = sl_buf_len(b);
    size_t k = strlen(s);

    for (size_t i = 0; i + k <= n; i++) {
        if (memcmp(d + i, s, k) == 0) {
            return 1;
        }
    }
    return 0;
}

static void test_messages(void)
{
    const char *cols[] = {"email"};
    sl_mask *m = make(cols, 1, SL_MASK_EMAIL, SL_MASK_REDACT);
    sl_buf in, out;

    sl_buf_init(&in);
    sl_buf_init(&out);
    error_msg(&in, "ERROR", "duplicate key value violates unique constraint \"users_email_key\"",
              "Key (email)=(ana@example.com) already exists.");
    CHECK(sl_mask_message(m, sl_buf_data(&in), sl_buf_len(&in), &out) == SL_MASK_CHANGED);
    CHECK(!has(&out, "ana@example") && has(&out, "Key (email)=([masked]) already exists.") &&
          has(&out, "users_email_key"));
    sl_buf_free(&in);
    sl_buf_free(&out);
    sl_buf_init(&in);
    sl_buf_init(&out);
    /* a Key of a column that is not hidden is left, but the patterns are still looked for */
    error_msg(&in, "ERROR", "oops", "Key (id)=(7) already exists.");
    CHECK(sl_mask_message(m, sl_buf_data(&in), sl_buf_len(&in), &out) == SL_MASK_SAME);
    sl_buf_free(&in);
    sl_buf_init(&in);
    error_msg(&in, "ERROR", "bad input for ana@example.com",
              "Failing row contains (1, secret, x@y.zz).");
    CHECK(sl_mask_message(m, sl_buf_data(&in), sl_buf_len(&in), &out) == SL_MASK_CHANGED);
    CHECK(!has(&out, "ana@example") && !has(&out, "secret") && !has(&out, "x@y.zz") &&
          has(&out, "Failing row contains ([masked])."));
    /* a multi-column key */
    sl_buf_free(&in);
    sl_buf_free(&out);
    sl_buf_init(&in);
    sl_buf_init(&out);
    error_msg(&in, "ERROR", "dup", "Key (tenant, \"Email\")=(5, ana@example.com) already exists.");
    CHECK(sl_mask_message(m, sl_buf_data(&in), sl_buf_len(&in), &out) == SL_MASK_CHANGED);
    CHECK(!has(&out, "ana@") && has(&out, "([masked])"));
    /* malformed: a field that does not end */
    sl_buf_free(&out);
    sl_buf_init(&out);
    CHECK(sl_mask_message(m, (const uint8_t *)"Mno end", 7, &out) == SL_MASK_BAD);
    sl_buf_free(&in);
    sl_buf_free(&out);
    sl_mask_free(m);
}

static void test_key_and_rules(void)
{
    const char *cols[] = {"email"};
    sl_mask_rule_view r = {"r", (char *const *)cols, 1, 0, SL_MASK_HASH};
    sl_mask *a = sl_mask_new(&r, 1, KEY, sizeof KEY - 1);
    uint8_t other[] = "another key entirely, another one";
    sl_mask *b = sl_mask_new(&r, 1, other, sizeof other - 1);
    col d[] = {{"email", 25, 0, 0}};
    const char *v[] = {"ana@example.com"};
    sl_buf dd, rr, o1, o2;

    sl_buf_init(&dd);
    sl_buf_init(&rr);
    sl_buf_init(&o1);
    sl_buf_init(&o2);
    describe(&dd, d, 1);
    sl_mask_describe(a, sl_buf_data(&dd), sl_buf_len(&dd));
    sl_mask_describe(b, sl_buf_data(&dd), sl_buf_len(&dd));
    row(&rr, v, 1);
    CHECK(sl_mask_row(a, sl_buf_data(&rr), sl_buf_len(&rr), &o1) == SL_MASK_CHANGED);
    CHECK(sl_mask_row(b, sl_buf_data(&rr), sl_buf_len(&rr), &o2) == SL_MASK_CHANGED);
    CHECK(sl_buf_len(&o1) == sl_buf_len(&o2) &&
          memcmp(sl_buf_data(&o1), sl_buf_data(&o2), sl_buf_len(&o1)) != 0);
    sl_mask_free(a);
    sl_mask_free(b);
    CHECK(sl_mask_new(&r, 1, NULL, 0) == NULL);
    CHECK(sl_mask_new(&r, SL_MASK_MAX_RULES + 1, KEY, sizeof KEY - 1) == NULL);
    sl_buf_free(&dd);
    sl_buf_free(&rr);
    sl_buf_free(&o1);
    sl_buf_free(&o2);
}

int main(void)
{
    test_email();
    test_card();
    test_iban();
    test_named_columns();
    test_hows();
    test_qualified_names();
    test_types();
    test_detectors_in_text();
    test_many_matches();
    test_partial_in_text();
    test_nothing_to_do();
    test_bad_input();
    test_messages();
    test_key_and_rules();
    return TEST_RESULT();
}
