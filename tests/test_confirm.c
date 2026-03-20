#include <stdlib.h>

#include "check.h"
#include "confirm.h"
#include "pg_proto.h"
#include "srvscan.h"

/* ---- the server's side of the conversation, message by message ---- */

static size_t row_description(uint8_t *out, const char *const *names, int n)
{
    size_t pos = 0;

    out[pos++] = 0;
    out[pos++] = (uint8_t)n;
    for (int i = 0; i < n; i++) {
        size_t l = strlen(names[i]) + 1;

        memcpy(out + pos, names[i], l);
        pos += l;
        memset(out + pos, 0, 18);
        pos += 18;
    }
    return pos;
}

static size_t data_row(uint8_t *out, const char *const *vals, int n)
{
    size_t pos = 0;

    out[pos++] = 0;
    out[pos++] = (uint8_t)n;
    for (int i = 0; i < n; i++) {
        if (vals[i] == NULL) {
            sl_pg_put_be32(out + pos, 0xffffffffu);
            pos += 4;
            continue;
        }
        sl_pg_put_be32(out + pos, (uint32_t)strlen(vals[i]));
        pos += 4;
        memcpy(out + pos, vals[i], strlen(vals[i]));
        pos += strlen(vals[i]);
    }
    return pos;
}

typedef struct {
    sl_confirm *c;
    sl_buf to_server;
    sl_buf to_client;
    sl_confirm_step step;
    int async_kept;
} rig;

static void rig_init(rig *r)
{
    r->c = sl_confirm_new();
    sl_buf_init(&r->to_server);
    sl_buf_init(&r->to_client);
    memset(&r->step, 0, sizeof r->step);
    r->async_kept = 0;
    CHECK(r->c != NULL);
}

static void rig_free(rig *r)
{
    sl_confirm_free(r->c);
    sl_buf_free(&r->to_server);
    sl_buf_free(&r->to_client);
}

/* feeds one message; returns the step */
static void feed(rig *r, char type, const uint8_t *payload, size_t len)
{
    int rc = sl_confirm_server(r->c, (uint8_t)type, payload, len, &r->to_server, &r->to_client,
                               &r->step);

    CHECK(rc == SL_SRV_KEEP || rc == SL_SRV_DROP);
    r->async_kept += rc == SL_SRV_KEEP;
}

static void feed_z(rig *r, char status)
{
    uint8_t z = (uint8_t)status;

    feed(r, 'Z', &z, 1);
}

static void feed_c(rig *r, const char *tag)
{
    feed(r, 'C', (const uint8_t *)tag, strlen(tag) + 1);
}

static int has_text(const sl_buf *b, const char *needle)
{
    size_t n = strlen(needle);
    const uint8_t *d = sl_buf_data(b);

    if (d == NULL) {
        return 0;
    }
    for (size_t i = 0; i + n <= sl_buf_len(b); i++) {
        if (memcmp(d + i, needle, n) == 0) {
            return 1;
        }
    }
    return 0;
}

/* the text of the Query messages that were sent, one after the other, separated by '|' */
static void queries(const sl_buf *b, char *out, size_t cap)
{
    const uint8_t *d = sl_buf_data(b);
    size_t pos = 0;
    size_t n = 0;

    out[0] = '\0';
    while (d != NULL && pos + 5 <= sl_buf_len(b) && n + 2 < cap) {
        size_t l = sl_pg_get_be32(d + pos + 1);
        size_t text = l - 5;

        CHECK(d[pos] == 'Q');
        if (n > 0) {
            out[n++] = '|';
        }
        if (n + text + 1 >= cap) {
            break;
        }
        memcpy(out + n, d + pos + 5, text);
        n += text;
        out[n] = '\0';
        pos += 1 + l;
    }
}

static sl_confirm_args base_args(const char *sql, const char *with_returning, int tx)
{
    sl_confirm_args a;

    memset(&a, 0, sizeof a);
    a.sql = sql;
    a.sql_len = strlen(sql);
    a.sql_returning = with_returning;
    a.sql_returning_len = with_returning ? strlen(with_returning) : 0;
    a.tx_status = tx;
    a.over_rows = 1;
    a.user = "agent";
    a.user_len = 5;
    a.database = "mydb";
    a.database_len = 4;
    a.rule = "confirm-deletes";
    a.message = "A person has to confirm this.";
    return a;
}

/* answers of the server to BEGIN + DELETE ... RETURNING *: three rows deleted */
static void feed_delete_answer(rig *r, int rows)
{
    uint8_t buf[256];
    size_t n;
    const char *names[] = {"id", "email"};
    const char *v1[] = {"18", "ana@example.com"};
    const char *v2[] = {"52", NULL};
    const char *v3[] = {"7", "x\033[2Jy"};
    char tag[32];

    feed_c(r, "BEGIN");
    n = row_description(buf, names, 2);
    feed(r, 'T', buf, n);
    n = data_row(buf, v1, 2);
    feed(r, 'D', buf, n);
    if (rows > 1) {
        n = data_row(buf, v2, 2);
        feed(r, 'D', buf, n);
    }
    if (rows > 2) {
        n = data_row(buf, v3, 2);
        feed(r, 'D', buf, n);
    }
    snprintf(tag, sizeof tag, "DELETE %d", rows);
    feed_c(r, tag);
    feed_z(r, 'T');
}

static void test_yes(void)
{
    rig r;
    sl_confirm_args a = base_args("delete from users where id < 5",
                                  "delete from users where id < 5 RETURNING *", 'I');
    char q[256];
    char text[2048];

    rig_init(&r);
    CHECK(sl_confirm_start(r.c, &a, &r.to_server) == 0);
    queries(&r.to_server, q, sizeof q);
    CHECK_STR(q, "BEGIN; delete from users where id < 5 RETURNING *");
    sl_buf_free(&r.to_server);

    feed_delete_answer(&r, 3);
    CHECK(r.step.ask == 1 && r.step.done == 0);
    CHECK(sl_confirm_rows(r.c) == 3 && sl_confirm_has_detail(r.c));
    CHECK(sl_buf_len(&r.to_client) == 0); /* the client has seen nothing */

    CHECK(sl_confirm_render(r.c, text, sizeof text) > 0);
    CHECK(strstr(text, "agent@mydb") && strstr(text, "confirm-deletes"));
    CHECK(strstr(text, "deleted 3 rows") && strstr(text, "ana@example.com"));
    CHECK(strstr(text, "NULL") && strstr(text, "commit? [y/N]"));
    CHECK(strstr(text, "\033") == NULL); /* what the database holds cannot write on the terminal */
    CHECK(strstr(text, "x?[2Jy") != NULL);

    CHECK(sl_confirm_answer(r.c, 1, NULL, &r.to_server) == 0);
    queries(&r.to_server, q, sizeof q);
    CHECK_STR(q, "COMMIT");
    sl_buf_free(&r.to_server);
    feed_c(&r, "COMMIT");
    CHECK(r.step.done == 0);
    feed_z(&r, 'I');
    CHECK(r.step.done == 1);
    /* the client gets the statement's own answer ("DELETE 3") and ReadyForQuery, nothing else */
    CHECK(sl_buf_len(&r.to_client) == 5 + 9 + 6); /* "DELETE 3" and its NUL, then ReadyForQuery */
    CHECK(has_text(&r.to_client, "DELETE 3"));
    CHECK(!has_text(&r.to_client, "RETURNING") && !has_text(&r.to_client, "ana@"));
    CHECK(sl_buf_data(&r.to_client)[0] == 'C');
    CHECK(sl_buf_data(&r.to_client)[sl_buf_len(&r.to_client) - 1] == 'I');
    CHECK_STR(sl_confirm_outcome(r.c), "yes");
    rig_free(&r);
}

static void test_no(void)
{
    rig r;
    sl_confirm_args a = base_args("delete from users", "delete from users RETURNING *", 'I');
    char q[256];

    rig_init(&r);
    CHECK(sl_confirm_start(r.c, &a, &r.to_server) == 0);
    sl_buf_free(&r.to_server);
    feed_delete_answer(&r, 3);
    CHECK(r.step.ask == 1);
    CHECK(sl_confirm_answer(r.c, 0, "no", &r.to_server) == 0);
    queries(&r.to_server, q, sizeof q);
    CHECK_STR(q, "ROLLBACK");
    sl_buf_free(&r.to_server);
    feed_c(&r, "ROLLBACK");
    feed_z(&r, 'I');
    CHECK(r.step.done == 1);
    CHECK(sl_buf_data(&r.to_client)[0] == 'E');
    CHECK(has_text(&r.to_client, "42501") && has_text(&r.to_client, "not confirmed"));
    CHECK(has_text(&r.to_client, "confirm-deletes") && has_text(&r.to_client, "A person has to"));
    CHECK(has_text(&r.to_client, "Nothing was changed"));
    CHECK(sl_buf_data(&r.to_client)[sl_buf_len(&r.to_client) - 1] == 'I');
    CHECK_STR(sl_confirm_outcome(r.c), "no");
    rig_free(&r);

    /* the same for a person who did not answer, and for a machine with no terminal */
    for (int k = 0; k < 2; k++) {
        const char *why = k == 0 ? "timeout" : "no_terminal";

        rig_init(&r);
        CHECK(sl_confirm_start(r.c, &a, &r.to_server) == 0);
        sl_buf_free(&r.to_server);
        feed_delete_answer(&r, 3);
        CHECK(sl_confirm_answer(r.c, 0, why, &r.to_server) == 0);
        sl_buf_free(&r.to_server);
        feed_c(&r, "ROLLBACK");
        feed_z(&r, 'I');
        CHECK(r.step.done == 1 &&
              has_text(&r.to_client, k == 0 ? "nobody answered" : "no terminal"));
        CHECK_STR(sl_confirm_outcome(r.c), why);
        rig_free(&r);
    }
}

static void test_threshold(void)
{
    rig r;
    sl_confirm_args a = base_args("delete from users where id = 1",
                                  "delete from users where id = 1 RETURNING *", 'I');
    char q[256];

    rig_init(&r);
    CHECK(sl_confirm_start(r.c, &a, &r.to_server) == 0);
    sl_buf_free(&r.to_server);
    feed_delete_answer(&r, 1); /* one row: not above the threshold of 1 */
    CHECK(r.step.ask == 0);
    queries(&r.to_server, q, sizeof q);
    CHECK_STR(q, "COMMIT");
    sl_buf_free(&r.to_server);
    feed_c(&r, "COMMIT");
    feed_z(&r, 'I');
    CHECK(r.step.done == 1 && has_text(&r.to_client, "DELETE 1"));
    CHECK_STR(sl_confirm_outcome(r.c), "auto");
    rig_free(&r);

    /* always ask: a threshold of zero */
    a.over_rows = 0;
    rig_init(&r);
    CHECK(sl_confirm_start(r.c, &a, &r.to_server) == 0);
    sl_buf_free(&r.to_server);
    feed_delete_answer(&r, 1);
    CHECK(r.step.ask == 1);
    rig_free(&r);
}

static void test_in_transaction(void)
{
    rig r;
    sl_confirm_args a = base_args("update t set a = 1", "update t set a = 1 RETURNING *", 'T');
    char q[256];

    rig_init(&r);
    CHECK(sl_confirm_start(r.c, &a, &r.to_server) == 0);
    queries(&r.to_server, q, sizeof q);
    CHECK_STR(q, "SAVEPOINT sluice_guard; update t set a = 1 RETURNING *");
    sl_buf_free(&r.to_server);
    feed_c(&r, "SAVEPOINT");
    feed_c(&r, "UPDATE 40");
    feed_z(&r, 'T');
    CHECK(r.step.ask == 1);
    CHECK(sl_confirm_answer(r.c, 1, NULL, &r.to_server) == 0);
    queries(&r.to_server, q, sizeof q);
    CHECK_STR(q, "RELEASE SAVEPOINT sluice_guard");
    sl_buf_free(&r.to_server);
    feed_c(&r, "RELEASE");
    feed_z(&r, 'T');
    CHECK(r.step.done == 1 && has_text(&r.to_client, "UPDATE 40"));
    CHECK(sl_buf_data(&r.to_client)[sl_buf_len(&r.to_client) - 1] == 'T');
    rig_free(&r);

    rig_init(&r);
    CHECK(sl_confirm_start(r.c, &a, &r.to_server) == 0);
    sl_buf_free(&r.to_server);
    feed_c(&r, "SAVEPOINT");
    feed_c(&r, "UPDATE 40");
    feed_z(&r, 'T');
    CHECK(sl_confirm_answer(r.c, 0, "no", &r.to_server) == 0);
    queries(&r.to_server, q, sizeof q);
    CHECK_STR(q, "ROLLBACK TO SAVEPOINT sluice_guard; RELEASE SAVEPOINT sluice_guard");
    sl_buf_free(&r.to_server);
    feed_c(&r, "ROLLBACK");
    feed_c(&r, "RELEASE");
    feed_z(&r, 'T');
    CHECK(r.step.done == 1 && sl_buf_data(&r.to_client)[0] == 'E');
    CHECK(sl_buf_data(&r.to_client)[sl_buf_len(&r.to_client) - 1] ==
          'T'); /* the transaction goes on */
    CHECK(has_text(&r.to_client, "updated") == 0 && has_text(&r.to_client, "not confirmed"));
    rig_free(&r);
}

static void error_message(rig *r, const char *sqlstate, const char *text)
{
    uint8_t buf[200];
    size_t n = 0;

    buf[n++] = 'C';
    memcpy(buf + n, sqlstate, 6);
    n += 6;
    buf[n++] = 'M';
    memcpy(buf + n, text, strlen(text) + 1);
    n += strlen(text) + 1;
    buf[n++] = 0;
    feed(r, 'E', buf, n);
}

static void test_fallback_without_returning(void)
{
    rig r;
    sl_confirm_args a = base_args("delete from users", "delete from users RETURNING *", 'I');
    char q[256];
    char text[1024];

    rig_init(&r);
    CHECK(sl_confirm_start(r.c, &a, &r.to_server) == 0);
    sl_buf_free(&r.to_server);
    /* RETURNING needs the right to read, which this role does not have */
    feed_c(&r, "BEGIN");
    error_message(&r, "42501", "permission denied for table users");
    feed_z(&r, 'E');
    CHECK(r.step.done == 0 && r.step.ask == 0);
    queries(&r.to_server, q, sizeof q);
    CHECK_STR(q, "ROLLBACK");
    sl_buf_free(&r.to_server);
    feed_c(&r, "ROLLBACK");
    CHECK(sl_buf_len(&r.to_server) == 0);
    feed_z(&r, 'I');
    queries(&r.to_server, q, sizeof q);
    CHECK_STR(q, "BEGIN; delete from users"); /* as the client wrote it */
    sl_buf_free(&r.to_server);
    feed_c(&r, "BEGIN");
    feed_c(&r, "DELETE 9");
    feed_z(&r, 'T');
    CHECK(r.step.ask == 1 && sl_confirm_rows(r.c) == 9 && !sl_confirm_has_detail(r.c));
    CHECK(sl_confirm_render(r.c, text, sizeof text) > 0);
    CHECK(strstr(text, "deleted 9 rows") && strstr(text, "could not be read"));
    CHECK(sl_buf_len(&r.to_client) == 0); /* the first error never reached the client */
    rig_free(&r);

    /* in a transaction of the client: back to the savepoint, then again */
    a.tx_status = 'T';
    rig_init(&r);
    CHECK(sl_confirm_start(r.c, &a, &r.to_server) == 0);
    sl_buf_free(&r.to_server);
    feed_c(&r, "SAVEPOINT");
    error_message(&r, "42501", "permission denied");
    feed_z(&r, 'E');
    queries(&r.to_server, q, sizeof q);
    CHECK_STR(q, "ROLLBACK TO SAVEPOINT sluice_guard; RELEASE SAVEPOINT sluice_guard");
    sl_buf_free(&r.to_server);
    feed_c(&r, "ROLLBACK");
    feed_c(&r, "RELEASE");
    feed_z(&r, 'T');
    queries(&r.to_server, q, sizeof q);
    CHECK_STR(q, "SAVEPOINT sluice_guard; delete from users");
    rig_free(&r);
}

static void test_real_errors(void)
{
    rig r;
    sl_confirm_args a = base_args("delete from users", NULL, 'I'); /* no RETURNING to blame */
    char q[256];

    /* outside a transaction: rolled back, then the server's own error is the client's */
    rig_init(&r);
    CHECK(sl_confirm_start(r.c, &a, &r.to_server) == 0);
    queries(&r.to_server, q, sizeof q);
    CHECK_STR(q, "BEGIN; delete from users");
    sl_buf_free(&r.to_server);
    feed_c(&r, "BEGIN");
    error_message(&r, "23503", "violates foreign key constraint");
    feed_z(&r, 'E');
    queries(&r.to_server, q, sizeof q);
    CHECK_STR(q, "ROLLBACK");
    sl_buf_free(&r.to_server);
    feed_c(&r, "ROLLBACK");
    feed_z(&r, 'I');
    CHECK(r.step.done == 1 && sl_buf_data(&r.to_client)[0] == 'E');
    CHECK(has_text(&r.to_client, "23503") && has_text(&r.to_client, "foreign key"));
    CHECK(sl_buf_data(&r.to_client)[sl_buf_len(&r.to_client) - 1] == 'I');
    rig_free(&r);

    /* with the RETURNING added, the original is tried, and its error is the one the client gets */
    {
        sl_confirm_args b = base_args("delete from users", "delete from users RETURNING *", 'I');

        rig_init(&r);
        CHECK(sl_confirm_start(r.c, &b, &r.to_server) == 0);
        sl_buf_free(&r.to_server);
        feed_c(&r, "BEGIN");
        error_message(&r, "23503", "first");
        feed_z(&r, 'E');
        sl_buf_free(&r.to_server);
        feed_c(&r, "ROLLBACK");
        feed_z(&r, 'I');
        sl_buf_free(&r.to_server);
        feed_c(&r, "BEGIN");
        error_message(&r, "23503", "second");
        feed_z(&r, 'E');
        sl_buf_free(&r.to_server);
        feed_c(&r, "ROLLBACK");
        feed_z(&r, 'I');
        CHECK(r.step.done == 1 && has_text(&r.to_client, "second") &&
              !has_text(&r.to_client, "first"));
        rig_free(&r);
    }

    /* in a transaction of the client: the error and the status of an aborted transaction, at once
     */
    a.tx_status = 'T';
    rig_init(&r);
    CHECK(sl_confirm_start(r.c, &a, &r.to_server) == 0);
    sl_buf_free(&r.to_server);
    feed_c(&r, "SAVEPOINT");
    error_message(&r, "23503", "violates");
    feed_z(&r, 'E');
    CHECK(r.step.done == 1 && has_text(&r.to_client, "23503"));
    CHECK(sl_buf_data(&r.to_client)[sl_buf_len(&r.to_client) - 1] == 'E');
    CHECK(sl_buf_len(&r.to_server) == 0);
    rig_free(&r);
}

static void test_clients_own_returning(void)
{
    rig r;
    sl_confirm_args a = base_args("delete from users returning id", NULL, 'I');
    const char *names[] = {"id"};
    const char *v[] = {"18"};
    uint8_t buf[128];
    size_t n;

    a.client_returning = 1;
    rig_init(&r);
    CHECK(sl_confirm_start(r.c, &a, &r.to_server) == 0);
    sl_buf_free(&r.to_server);
    feed_c(&r, "BEGIN");
    n = row_description(buf, names, 1);
    feed(&r, 'T', buf, n);
    n = data_row(buf, v, 1);
    feed(&r, 'D', buf, n);
    feed(&r, 'D', buf, n);
    feed_c(&r, "DELETE 2");
    feed_z(&r, 'T');
    CHECK(r.step.ask == 1);
    CHECK(sl_confirm_answer(r.c, 1, NULL, &r.to_server) == 0);
    sl_buf_free(&r.to_server);
    feed_c(&r, "COMMIT");
    feed_z(&r, 'I');
    /* its own rows come back: RowDescription, two DataRows, CommandComplete, ReadyForQuery */
    CHECK(r.step.done == 1);
    CHECK(sl_buf_data(&r.to_client)[0] == 'T' && has_text(&r.to_client, "DELETE 2"));
    CHECK(sl_buf_len(&r.to_client) == (5 + 23) + 2 * (5 + 8) + (5 + 9) + 6);
    rig_free(&r);
}

static void test_commit_fails_and_server_interferes(void)
{
    rig r;
    sl_confirm_args a = base_args("delete from users", "delete from users RETURNING *", 'I');

    /* a deferred constraint fails at COMMIT: the client gets that error, as it would have */
    rig_init(&r);
    CHECK(sl_confirm_start(r.c, &a, &r.to_server) == 0);
    sl_buf_free(&r.to_server);
    feed_delete_answer(&r, 3);
    CHECK(sl_confirm_answer(r.c, 1, NULL, &r.to_server) == 0);
    sl_buf_free(&r.to_server);
    error_message(&r, "23505", "deferred");
    feed_z(&r, 'I');
    CHECK(r.step.done == 1 && has_text(&r.to_client, "23505") &&
          !has_text(&r.to_client, "DELETE 3"));
    rig_free(&r);

    /* notices and parameter changes go to the client at once, whatever the state */
    rig_init(&r);
    CHECK(sl_confirm_start(r.c, &a, &r.to_server) == 0);
    sl_buf_free(&r.to_server);
    feed(&r, 'N', (const uint8_t *)"Sx\0", 3);
    feed(&r, 'S', (const uint8_t *)"a\0b\0", 4);
    feed(&r, 'A', (const uint8_t *)"\0\0\0\1c\0\0", 8);
    CHECK(r.async_kept == 3);
    rig_free(&r);

    /* the server ends the session while the person is being asked */
    rig_init(&r);
    CHECK(sl_confirm_start(r.c, &a, &r.to_server) == 0);
    sl_buf_free(&r.to_server);
    feed_delete_answer(&r, 3);
    CHECK(r.step.ask == 1);
    error_message(&r, "25P03", "terminating connection due to idle-in-transaction timeout");
    CHECK(r.step.done == 1 && sl_buf_data(&r.to_client)[0] == 'E');
    CHECK_STR(sl_confirm_outcome(r.c), "error");
    rig_free(&r);

    /* an answer given when nobody is asking changes nothing */
    rig_init(&r);
    CHECK(sl_confirm_start(r.c, &a, &r.to_server) == 0);
    sl_buf_free(&r.to_server);
    CHECK(sl_confirm_answer(r.c, 1, NULL, &r.to_server) == 0 && sl_buf_len(&r.to_server) == 0);
    rig_free(&r);
}

static void test_render_is_safe(void)
{
    rig r;
    sl_confirm_args a =
        base_args("delete from t where x = '\033[31mred\033[0m'\n-- done", NULL, 'I');
    char text[2048];
    uint8_t buf[256];
    const char *names[] = {"na\033me", "b"};
    const char *v[] = {"very long value that goes on and on and on and on and on", "caf\xc3\xa9"};
    size_t n;

    a.user = "ev\033il";
    a.user_len = 6;
    rig_init(&r);
    CHECK(sl_confirm_start(r.c, &a, &r.to_server) == 0);
    sl_buf_free(&r.to_server);
    feed_c(&r, "BEGIN");
    n = row_description(buf, names, 2);
    feed(&r, 'T', buf, n);
    n = data_row(buf, v, 2);
    feed(&r, 'D', buf, n);
    feed_c(&r, "DELETE 5");
    feed_z(&r, 'T');
    CHECK(r.step.ask == 1);
    CHECK(sl_confirm_render(r.c, text, sizeof text) > 0);
    for (const char *p = text; *p; p++) {
        CHECK((unsigned char)*p == '\n' || ((unsigned char)*p >= 0x20 && (unsigned char)*p < 0x7f));
    }
    CHECK(strstr(text, "ev?il") && strstr(text, "na?me") && strstr(text, "caf??"));
    CHECK(strstr(text, "...")); /* the long value is cut */
    CHECK(strstr(text, "and 4 more"));
    /* a buffer that is too small is filled, not overrun */
    {
        char tiny[40];

        CHECK(sl_confirm_render(r.c, tiny, sizeof tiny) < sizeof tiny);
    }
    rig_free(&r);
}

int main(void)
{
    test_yes();
    test_no();
    test_threshold();
    test_in_transaction();
    test_fallback_without_returning();
    test_real_errors();
    test_clients_own_returning();
    test_commit_fails_and_server_interferes();
    test_render_is_safe();
    return TEST_RESULT();
}
