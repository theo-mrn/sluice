#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "check.h"
#include "journal.h"
#include "pg_proto.h"
#include "undo.h"

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

/* a RowDescription of text columns */
static void desc(sl_buf *b, const char *const *names, size_t n)
{
    put16(b, (unsigned)n);
    for (size_t i = 0; i < n; i++) {
        sl_buf_append(b, names[i], strlen(names[i]) + 1);
        put32(b, 0);
        put16(b, 0);
        put32(b, 25);
        put16(b, 0xffff);
        put32(b, 0xffffffffu);
        put16(b, 0);
    }
}

/* a DataRow with its length in front, as the journal is given them */
static void row(sl_buf *b, const char *const *vals, size_t n, size_t *vlen)
{
    sl_buf r;

    sl_buf_init(&r);
    put16(&r, (unsigned)n);
    for (size_t i = 0; i < n; i++) {
        if (vals[i] == NULL) {
            put32(&r, 0xffffffffu);
        } else {
            size_t l = vlen != NULL && vlen[i] != (size_t)-1 ? vlen[i] : strlen(vals[i]);

            put32(&r, (uint32_t)l);
            sl_buf_append(&r, vals[i], l);
        }
    }
    put32(b, (uint32_t)sl_buf_len(&r));
    sl_buf_append(b, sl_buf_data(&r), sl_buf_len(&r));
    sl_buf_free(&r);
}

static int contains(const sl_buf *b, const char *s)
{
    size_t n = strlen(s);
    const char *d = (const char *)sl_buf_data(b);

    for (size_t i = 0; i + n <= sl_buf_len(b); i++) {
        if (memcmp(d + i, s, n) == 0) {
            return 1;
        }
    }
    return 0;
}

static sl_journal_entry base(void)
{
    sl_journal_entry e;

    memset(&e, 0, sizeof e);
    e.user = "agent";
    e.user_len = 5;
    e.database = "mydb";
    e.database_len = 4;
    e.rule = "confirm-deletes";
    e.protocol = "simple";
    e.sql = "delete from users where id < 5";
    e.sql_len = strlen(e.sql);
    e.schema = "public";
    e.table = "users";
    e.tag = "DELETE 3";
    return e;
}

static void test_round_trip(void)
{
    const char *cols[] = {"id", "ema\"il", "note"};
    const char *r1[] = {"1", "ana@example.com", "it's \\ a \"test\"\nline 2"};
    const char *r2[] = {"2", NULL, "é ☃ \xf0\x9f\x98\x80"};
    sl_buf d, data, line, sql;
    sl_journal_entry e = base();
    sl_journal_side side[] = {{"public.orders", 0, 0, 100}};
    sl_undo_entry u;
    char err[200];

    sl_buf_init(&d);
    sl_buf_init(&data);
    sl_buf_init(&line);
    sl_buf_init(&sql);
    desc(&d, cols, 3);
    row(&data, r1, 3, NULL);
    row(&data, r2, 3, NULL);
    e.desc = sl_buf_data(&d);
    e.desc_len = sl_buf_len(&d);
    e.data = sl_buf_data(&data);
    e.data_len = sl_buf_len(&data);
    e.nrows = e.rows = 2;
    e.side_known = 1;
    e.side = side;
    e.nside = 1;
    e.tag = "DELETE 2";
    CHECK(sl_journal_format(&e, "0123456789abcdef", 1700000000, &line) == 0);
    CHECK(sl_buf_len(&line) > 0 && sl_buf_data(&line)[sl_buf_len(&line) - 1] == '\n');
    CHECK(memchr(sl_buf_data(&line), '\n', sl_buf_len(&line)) ==
          sl_buf_data(&line) + sl_buf_len(&line) - 1);
    CHECK(sl_undo_parse((const char *)sl_buf_data(&line), sl_buf_len(&line), &u, err, sizeof err) ==
          0);
    CHECK(strcmp(u.id, "0123456789abcdef") == 0 && strcmp(u.ts, "2023-11-14T22:13:20Z") == 0);
    CHECK(u.complete && u.nrows == 2 && u.ncols == 3 && strcmp(u.columns[1], "ema\"il") == 0);
    CHECK(strcmp(u.data[0][2], r1[2]) == 0 && u.data[1][1] == NULL &&
          strcmp(u.data[1][2], r2[2]) == 0);
    CHECK(u.side_known && u.nside == 1 && u.side[0].deleted == 100);
    CHECK(sl_undo_sql(&u, 0, &sql, err, sizeof err) == 0);
    CHECK(contains(&sql, "INSERT INTO \"public\".\"users\" (\"id\", \"ema\"\"il\", \"note\") "
                         "OVERRIDING SYSTEM VALUE VALUES"));
    CHECK(contains(&sql, "('1', 'ana@example.com', 'it''s \\ a \"test\"\nline 2'),"));
    CHECK(contains(&sql, "('2', NULL, 'é ☃ \xf0\x9f\x98\x80');"));
    CHECK(contains(
        &sql,
        "public.orders (0 inserted, 0 updated, 100 deleted): those rows are NOT in this script"));
    CHECK(contains(&sql, "BEGIN;") && contains(&sql, "COMMIT;"));
    CHECK(memchr(sl_buf_data(&sql), 0, sl_buf_len(&sql)) == NULL); /* a script is text */
    CHECK(memchr(sl_buf_data(&line), 0, sl_buf_len(&line)) == NULL);
    /* a comment never holds a newline of the statement: it could not end the comment */
    sl_undo_free(&u);
    sl_buf_free(&d);
    sl_buf_free(&data);
    sl_buf_free(&line);
    sl_buf_free(&sql);
}

/* An UPDATE: each row is the old row and the new row side by side. */
static void test_update_round_trip(void)
{
    const char *cols[] = {"id", "name", "note", "id", "name", "note"};
    const char *r1[] = {"1", "o'ld", NULL, "1", "new\nname", "x"};
    const char *r2[] = {"2", "same", "same", "2", "same", "same"};
    sl_buf d, data, line, sql;
    sl_journal_entry e = base();
    sl_undo_entry u;
    char err[200];

    sl_buf_init(&d);
    sl_buf_init(&data);
    sl_buf_init(&line);
    sl_buf_init(&sql);
    desc(&d, cols, 6);
    row(&data, r1, 6, NULL);
    row(&data, r2, 6, NULL);
    e.update = 1;
    e.sql = "update users set name = 'new'";
    e.sql_len = strlen(e.sql);
    e.tag = "UPDATE 2";
    e.desc = sl_buf_data(&d);
    e.desc_len = sl_buf_len(&d);
    e.data = sl_buf_data(&data);
    e.data_len = sl_buf_len(&data);
    e.nrows = e.rows = 2;
    e.side_known = 1;
    CHECK(sl_journal_format(&e, "0123456789abcdef", 1700000000, &line) == 0);
    CHECK(contains(&line, "\"kind\":\"update\"") && contains(&line, "\"new\":[[") &&
          contains(&line, "\"columns\":[\"id\",\"name\",\"note\"]"));
    CHECK(sl_undo_parse((const char *)sl_buf_data(&line), sl_buf_len(&line), &u, err, sizeof err) ==
          0);
    CHECK(u.complete && u.nrows == 2 && u.nfresh == 2 && u.ncols == 3);
    CHECK(strcmp(u.data[0][1], "o'ld") == 0 && u.data[0][2] == NULL &&
          strcmp(u.fresh[0][1], "new\nname") == 0 && strcmp(u.fresh[0][2], "x") == 0);
    CHECK(sl_undo_sql(&u, 0, &sql, err, sizeof err) == 0);
    /* only the columns that changed are set, and the row is found by what the UPDATE gave it; the
     * body is a string literal, so every quote is doubled twice */
    CHECK(contains(&sql,
                   "UPDATE \"public\".\"users\" SET \"name\" = ''o''''ld'', \"note\" = NULL "
                   "WHERE \"id\" IS NOT DISTINCT FROM ''1'' AND \"name\" IS NOT DISTINCT FROM "
                   "''new\nname'' AND \"note\" IS NOT DISTINCT FROM ''x'';"));
    CHECK(contains(&sql, "GET DIAGNOSTICS sluice_undo_rows = ROW_COUNT;") &&
          contains(&sql, "RAISE EXCEPTION"));
    CHECK(contains(&sql, "1 row the UPDATE left as they were"));
    CHECK(contains(&sql, "DO '") && contains(&sql, "BEGIN;") && contains(&sql, "COMMIT;"));
    CHECK(!contains(&sql, "INSERT INTO"));
    CHECK(memchr(sl_buf_data(&sql), 0, sl_buf_len(&sql)) == NULL);
    sl_undo_free(&u);

    /* an odd number of columns is not an old row and a new row */
    sl_buf_free(&d);
    sl_buf_init(&d);
    desc(&d, cols, 5);
    e.desc = sl_buf_data(&d);
    e.desc_len = sl_buf_len(&d);
    sl_buf_free(&line);
    sl_buf_init(&line);
    CHECK(sl_journal_format(&e, "0123456789abcdef", 1700000000, &line) == 0);
    CHECK(contains(&line, "\"complete\":false") && contains(&line, "side by side"));
    sl_buf_free(&d);
    sl_buf_free(&data);
    sl_buf_free(&line);
    sl_buf_free(&sql);
}

static void test_incomplete_entries(void)
{
    const char *cols[] = {"id"};
    const char *good[] = {"1"};
    size_t badlen[] = {2};
    sl_buf d, data, line, sql;
    sl_journal_entry e = base();
    sl_undo_entry u;
    char err[200];

    sl_buf_init(&d);
    sl_buf_init(&data);
    sl_buf_init(&line);
    sl_buf_init(&sql);
    desc(&d, cols, 1);
    row(&data, good, 1, NULL);
    e.desc = sl_buf_data(&d);
    e.desc_len = sl_buf_len(&d);
    e.data = sl_buf_data(&data);
    e.data_len = sl_buf_len(&data);
    e.nrows = 1;
    e.rows = 3; /* the server said 3, only one was kept */
    CHECK(sl_journal_format(&e, "aaaaaaaaaaaaaaaa", 0, &line) == 0);
    CHECK(sl_undo_parse((const char *)sl_buf_data(&line), sl_buf_len(&line), &u, err, sizeof err) ==
          0);
    CHECK(!u.complete && u.incomplete != NULL);
    CHECK(sl_undo_sql(&u, 0, &sql, err, sizeof err) == -1 && strstr(err, "--partial") != NULL);
    CHECK(sl_undo_sql(&u, 1, &sql, err, sizeof err) == 0 && contains(&sql, "PARTIAL"));
    sl_undo_free(&u);

    /* a value that is not UTF-8 is not written as something else: the entry says so and keeps no
     * data */
    sl_buf_free(&data);
    sl_buf_init(&data);
    sl_buf_free(&line);
    sl_buf_init(&line);
    {
        const char *v[] = {"\xff\xfe"};

        row(&data, v, 1, badlen);
    }
    e.data = sl_buf_data(&data);
    e.data_len = sl_buf_len(&data);
    e.nrows = e.rows = 1;
    CHECK(sl_journal_format(&e, "bbbbbbbbbbbbbbbb", 0, &line) == 0);
    CHECK(!contains(&line, "\xef\xbf\xbd")); /* no replacement character in place of the value */
    CHECK(sl_undo_parse((const char *)sl_buf_data(&line), sl_buf_len(&line), &u, err, sizeof err) ==
          0);
    CHECK(!u.complete && u.nrows == 0 && strstr(u.incomplete, "UTF-8") != NULL);
    sl_undo_free(&u);

    /* rows not kept at all (a statement with its own RETURNING, a result too large) */
    sl_buf_free(&line);
    sl_buf_init(&line);
    memset(&e, 0, sizeof e);
    e = base();
    e.incomplete = "too many rows to keep";
    e.rows = 100000;
    CHECK(sl_journal_format(&e, "cccccccccccccccc", 0, &line) == 0);
    CHECK(sl_undo_parse((const char *)sl_buf_data(&line), sl_buf_len(&line), &u, err, sizeof err) ==
          0);
    CHECK(!u.complete && strcmp(u.incomplete, "too many rows to keep") == 0 && u.nrows == 0);
    CHECK(sl_undo_sql(&u, 1, &sql, err, sizeof err) ==
          -1); /* no columns: nothing to put back, even partly */
    sl_undo_free(&u);
    sl_buf_free(&d);
    sl_buf_free(&data);
    sl_buf_free(&line);
    sl_buf_free(&sql);
}

static void test_hostile_lines(void)
{
    const char *cols[] = {"a", "b"};
    const char *r[] = {"x", NULL};
    sl_buf d, data, line;
    sl_journal_entry e = base();
    sl_undo_entry u;
    char err[200];

    sl_buf_init(&d);
    sl_buf_init(&data);
    sl_buf_init(&line);
    desc(&d, cols, 2);
    row(&data, r, 2, NULL);
    e.desc = sl_buf_data(&d);
    e.desc_len = sl_buf_len(&d);
    e.data = sl_buf_data(&data);
    e.data_len = sl_buf_len(&data);
    e.nrows = e.rows = 1;
    CHECK(sl_journal_format(&e, "dddddddddddddddd", 0, &line) == 0);
    /* every cut of a good line is refused cleanly (the whole one, without its newline, is good) */
    for (size_t n = 0; n + 1 < sl_buf_len(&line); n++) {
        CHECK(sl_undo_parse((const char *)sl_buf_data(&line), n, &u, err, sizeof err) == -1);
    }
    CHECK(sl_undo_parse((const char *)sl_buf_data(&line), sl_buf_len(&line) - 1, &u, err,
                        sizeof err) == 0);
    sl_undo_free(&u);
    {
        static const char *const hostile[] = {
            "",
            "{}",
            "[]",
            "null",
            "{\"id\":1}",
            "{\"id\":\"x\",\"data\":[[\"a\"]]}",
            "{\"id\":\"x\",\"columns\":[\"a\"],\"data\":[[\"a\",\"b\"]]}",
            "{\"id\":\"x\",\"columns\":[\"a\"],\"data\":[[\"a\"]]} trailing",
            "{\"id\":\"x\",\"columns\":[\"a\"],\"data\":[[\"\\ud800\"]]}",
            "{\"id\":\"x\",\"columns\":[\"a\"],\"data\":[[\"\\u0000\"]]}",
            "{\"id\":\"x\",\"unknown\":{\"a\":[1,2,{\"b\":null}]},\"rows\":3}",
            "{\"id\":\"x\",\"rows\":99999999999999999999999}",
            "{\"id\":\"x\",\"columns\":[\"a\"],\"columns\":[\"b\"]}",
        };

        for (size_t i = 0; i < sizeof hostile / sizeof hostile[0]; i++) {
            int rc = sl_undo_parse(hostile[i], strlen(hostile[i]), &u, err, sizeof err);

            if (rc == 0) {
                sl_undo_free(&u);
            }
        }
        CHECK(sl_undo_parse(hostile[10], strlen(hostile[10]), &u, err, sizeof err) == 0 &&
              u.rows == 3);
        sl_undo_free(&u);
        CHECK(sl_undo_parse(hostile[7], strlen(hostile[7]), &u, err, sizeof err) == -1);
        CHECK(sl_undo_parse(hostile[8], strlen(hostile[8]), &u, err, sizeof err) == -1);
    }
    sl_buf_free(&d);
    sl_buf_free(&data);
    sl_buf_free(&line);
}

static void test_file(void)
{
    char path[] = "/tmp/sluice-journal-test-XXXXXX";
    int fd = mkstemp(path);
    sl_journal *j;
    sl_journal_entry e = base();
    char id[SL_JOURNAL_ID_LEN + 1];
    char id2[SL_JOURNAL_ID_LEN + 1];
    char err[200];
    struct stat st;
    FILE *f;
    char buf[4096];

    CHECK(fd >= 0);
    close(fd);
    unlink(path);
    e.incomplete = "no rows";
    j = sl_journal_open(path, 0, err, sizeof err);
    CHECK(j != NULL);
    CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600); /* the data is the owner's alone */
    CHECK(sl_journal_append(j, &e, id, err, sizeof err) == 0);
    CHECK(sl_journal_append(j, &e, id2, err, sizeof err) == 0 && strcmp(id, id2) != 0 &&
          strlen(id) == 16);
    sl_journal_close(j);
    f = fopen(path, "r");
    CHECK(f != NULL);
    {
        int lines = 0;

        while (fgets(buf, sizeof buf, f) != NULL) {
            sl_undo_entry u;

            CHECK(sl_undo_parse(buf, strlen(buf), &u, err, sizeof err) == 0);
            sl_undo_free(&u);
            lines++;
        }
        CHECK(lines == 2);
    }
    fclose(f);
    /* a limit: an entry that would go past it is refused and leaves the file as it was */
    CHECK(stat(path, &st) == 0);
    j = sl_journal_open(path, (unsigned long long)st.st_size + 10, err, sizeof err);
    CHECK(j != NULL && sl_journal_append(j, &e, id, err, sizeof err) == -1 &&
          strstr(err, "full") != NULL);
    sl_journal_close(j);
    {
        struct stat st2;

        CHECK(stat(path, &st2) == 0 && st2.st_size == st.st_size);
    }
    CHECK(sl_journal_open("/nonexistent-dir/j", 0, err, sizeof err) == NULL);
    unlink(path);
}

int main(void)
{
    test_round_trip();
    test_update_round_trip();
    test_incomplete_entries();
    test_hostile_lines();
    test_file();
    return TEST_RESULT();
}
