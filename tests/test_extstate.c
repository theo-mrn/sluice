#include <stdlib.h>

#include "check.h"
#include "extstate.h"

/* 0: not guarded, 1: guarded as the client wrote it, 2: with a RETURNING added */
static int guard(sl_ext *e, const char *n)
{
    const sl_ext_entry *x = sl_ext_stmt_guard(e, n, strlen(n));

    return x == NULL ? 0 : 1 + (x->rewritten != 0);
}

static sl_ext_guard G(const char *sql, int rewritten)
{
    sl_ext_guard g = {
        sql,  strlen(sql), "confirm-deletes", "ask first", 7, rewritten, 1, 'D', 0, 0, 0,
        NULL, NULL};

    return g;
}

static int parse_g(sl_ext *e, const char *name, const char *sql, int rewritten)
{
    sl_ext_guard g = G(sql, rewritten);

    return sl_ext_parse_guarded(e, name, strlen(name), &g);
}

static void test_names(void)
{
    const char *name;
    int n;

    n = sl_ext_name((const uint8_t *)"abc\0rest", 8, &name);
    CHECK(n == 3 && memcmp(name, "abc", 3) == 0);
    n = sl_ext_name((const uint8_t *)"\0x", 2, &name);
    CHECK(n == 0);
    CHECK(sl_ext_name((const uint8_t *)"abc", 3, &name) == SL_EXT_TOO_LONG); /* no terminator */
    {
        uint8_t big[100];

        memset(big, 'a', sizeof big);
        big[99] = 0;
        CHECK(sl_ext_name(big, sizeof big, &name) == SL_EXT_TOO_LONG);
        big[SL_EXT_NAME_MAX] = 0; /* 63 bytes is the longest */
        CHECK(sl_ext_name(big, sizeof big, &name) == SL_EXT_NAME_MAX);
        big[SL_EXT_NAME_MAX] = 'a';
        big[SL_EXT_NAME_MAX + 1] = 0; /* 64 is too long */
        CHECK(sl_ext_name(big, sizeof big, &name) == SL_EXT_TOO_LONG);
    }
}

static void test_statements(void)
{
    sl_ext *e = sl_ext_new();
    const sl_ext_entry *x;

    CHECK(e != NULL);
    CHECK(guard(e, "s1") == 0);
    CHECK(parse_g(e, "s1", "delete from a", 1) == SL_EXT_OK);
    CHECK(guard(e, "s1") == 2);
    x = sl_ext_stmt_guard(e, "s1", 2);
    CHECK_STR(x->sql, "delete from a");
    CHECK_STR(x->rule, "confirm-deletes");
    CHECK_STR(x->message, "ask first");
    CHECK(x->over_rows == 7 && x->sql_len == 13);
    /* sticky: a second Parse of the name, of anything, does not take the guard away, nor change it:
     * the server keeps the first statement and refuses the second */
    sl_ext_parse_plain(e, "s1", 2);
    CHECK(guard(e, "s1") == 2);
    CHECK(parse_g(e, "s1", "delete from b", 0) == SL_EXT_OK);
    CHECK(guard(e, "s1") == 2);
    CHECK_STR(sl_ext_stmt_guard(e, "s1", 2)->sql, "delete from a");
    CHECK(guard(e, "s2") == 0);
    sl_ext_stmt_close(e, "s1", 2);
    CHECK(guard(e, "s1") == 0);
    sl_ext_stmt_close(e, "nothing", 7); /* closing what is not there is fine */

    /* a client's own RETURNING: guarded, not rewritten */
    CHECK(parse_g(e, "s3", "delete from a returning id", 0) == SL_EXT_OK);
    CHECK(guard(e, "s3") == 1);

    /* the unnamed statement is replaced by every Parse */
    CHECK(parse_g(e, "", "delete from a", 1) == SL_EXT_OK);
    CHECK(sl_ext_stmt_guard(e, "", 0) != NULL && sl_ext_stmt_guard(e, "", 0)->rewritten);
    CHECK(parse_g(e, "", "delete from c", 1) == SL_EXT_OK);
    CHECK_STR(sl_ext_stmt_guard(e, "", 0)->sql, "delete from c");
    sl_ext_parse_plain(e, "", 0);
    CHECK(sl_ext_stmt_guard(e, "", 0) == NULL);
    CHECK(parse_g(e, "", "delete from a", 0) == SL_EXT_OK);
    sl_ext_stmt_close(e, "", 0);
    CHECK(sl_ext_stmt_guard(e, "", 0) == NULL);

    /* a long text is cut, a long name refused */
    {
        char *big = malloc(SL_EXT_SQL_MAX * 2);
        char longname[100];

        memset(big, 'x', SL_EXT_SQL_MAX * 2 - 1);
        big[SL_EXT_SQL_MAX * 2 - 1] = 0;
        CHECK(parse_g(e, "big", big, 1) == SL_EXT_OK);
        CHECK(sl_ext_stmt_guard(e, "big", 3)->sql_len == SL_EXT_SQL_MAX);
        memset(longname, 'n', sizeof longname);
        longname[99] = 0;
        CHECK(parse_g(e, longname, "delete from a", 1) == SL_EXT_TOO_LONG);
        free(big);
    }
    sl_ext_free(e);
}

static void test_table_full(void)
{
    sl_ext *e = sl_ext_new();
    char name[16];

    for (int i = 0; i < SL_EXT_GUARDED_MAX; i++) {
        snprintf(name, sizeof name, "s%d", i);
        CHECK(parse_g(e, name, "delete from a", 1) == SL_EXT_OK);
    }
    CHECK(parse_g(e, "one-too-many", "delete from a", 1) == SL_EXT_FULL);
    CHECK(parse_g(e, "s5", "delete from a", 1) == SL_EXT_OK); /* a name already there is not new */
    sl_ext_stmt_close(e, "s7", 2);
    CHECK(parse_g(e, "one-too-many", "delete from a", 1) == SL_EXT_OK);
    CHECK(guard(e, "s0") == 2 && guard(e, "s255") == 2); /* removal moved nothing it should not */
    sl_ext_free(e);
}

static void test_portals(void)
{
    sl_ext *e = sl_ext_new();
    const sl_ext_entry *s2;
    const sl_ext_entry *s1;

    parse_g(e, "st", "delete from a", 1);
    parse_g(e, "st2", "delete from a returning id", 0);
    s2 = sl_ext_stmt_guard(e, "st2", 3);
    s1 = sl_ext_stmt_guard(e, "st", 2);
    CHECK(sl_ext_bind(e, "p1", 2, s1) == SL_EXT_OK);
    CHECK(sl_ext_portal_guard(e, "p1", 2) != NULL && sl_ext_portal_guard(e, "p1", 2)->rewritten);
    CHECK_STR(sl_ext_portal_guard(e, "p1", 2)->sql, "delete from a");
    /* a portal outlives the statement it was made from */
    sl_ext_stmt_close(e, "st", 2);
    CHECK_STR(sl_ext_portal_guard(e, "p1", 2)->sql, "delete from a");
    /* a name keeps the guard it first got */
    CHECK(sl_ext_bind(e, "p1", 2, NULL) == SL_EXT_OK);
    CHECK(sl_ext_portal_guard(e, "p1", 2) != NULL);
    CHECK(sl_ext_bind(e, "", 0, s2) == SL_EXT_OK);
    CHECK(sl_ext_portal_guard(e, "", 0) != NULL && !sl_ext_portal_guard(e, "", 0)->rewritten);
    CHECK(sl_ext_bind(e, "", 0, NULL) == SL_EXT_OK); /* the unnamed one is replaced */
    CHECK(sl_ext_portal_guard(e, "", 0) == NULL);
    CHECK(sl_ext_guarded(e) == 2); /* st2 and p1 */
    sl_ext_portal_close(e, "p1", 2);
    CHECK(sl_ext_guarded(e) == 1);
    CHECK(sl_ext_bind(e, "p2", 2, s2) == SL_EXT_OK);
    CHECK(sl_ext_bind(e, "", 0, s2) == SL_EXT_OK);
    sl_ext_portals_end(e);
    CHECK(sl_ext_portal_guard(e, "p2", 2) == NULL && sl_ext_portal_guard(e, "", 0) == NULL);
    CHECK(sl_ext_guarded(e) == 1);
    {
        char longname[100];

        memset(longname, 'n', sizeof longname);
        longname[99] = 0;
        CHECK(sl_ext_bind(e, longname, 99, s2) == SL_EXT_TOO_LONG);
    }
    sl_ext_free(e);
}

/* P B D E S: ParseComplete, BindComplete (not tracked), RowDescription, rows, tag, ReadyForQuery */
static void test_one_cycle(void)
{
    sl_ext *e = sl_ext_new();

    CHECK(sl_ext_expect(e, SL_EXT_ROWDESC_G) == 0);
    CHECK(sl_ext_expect(e, SL_EXT_EXEC_G) == 0);
    CHECK(sl_ext_expect(e, SL_EXT_SYNC) == 0);
    CHECK(sl_ext_guard_pending(e));
    CHECK(sl_ext_answer(e, '1') == 0 && sl_ext_answer(e, '2') == 0);
    CHECK(sl_ext_front_guarded_rowdesc(e));
    CHECK(sl_ext_answer(e, 'T') == SL_EXT_TO_NODATA);
    CHECK(sl_ext_front_guarded_exec(e));
    CHECK(sl_ext_answer(e, 'T') ==
          0); /* the one of sluice's own Describe: part of the guarded Execute */
    CHECK(sl_ext_front_guarded_exec(e));
    CHECK(sl_ext_answer(e, 'D') == 0 && sl_ext_answer(e, 'D') == 0);
    CHECK(sl_ext_front_guarded_exec(e));
    CHECK(sl_ext_answer(e, 'C') == 0);
    CHECK(!sl_ext_front_guarded_exec(e) && !sl_ext_guard_pending(e));
    CHECK(sl_ext_answer(e, 'Z') == 0);
    CHECK(sl_ext_in_step(e));
    sl_ext_free(e);
}

static void test_plain_describe_is_left_alone(void)
{
    sl_ext *e = sl_ext_new();

    /* Describe of a statement: ParameterDescription then RowDescription; not guarded: left as it is
     */
    sl_ext_expect(e, SL_EXT_PARAMS);
    sl_ext_expect(e, SL_EXT_ROWDESC);
    sl_ext_expect(e, SL_EXT_SYNC);
    CHECK(sl_ext_answer(e, 't') == 0);
    CHECK(sl_ext_answer(e, 'T') == 0);
    CHECK(sl_ext_answer(e, 'Z') == 0);
    /* a guarded statement whose RowDescription is NoData already (the client's own RETURNING
     * absent) */
    sl_ext_expect(e, SL_EXT_ROWDESC_G);
    sl_ext_expect(e, SL_EXT_SYNC);
    CHECK(sl_ext_answer(e, 'n') == 0);
    CHECK(sl_ext_answer(e, 'Z') == 0);
    sl_ext_free(e);
}

/* Several cycles sent without waiting: one Z settles one cycle, not the next one's slots. */
static void test_pipelined_cycles(void)
{
    sl_ext *e = sl_ext_new();

    sl_ext_expect(e, SL_EXT_EXEC);
    sl_ext_expect(e, SL_EXT_SYNC);
    sl_ext_expect(e, SL_EXT_EXEC_G);
    sl_ext_expect(e, SL_EXT_SYNC);
    CHECK(!sl_ext_front_guarded_exec(e));
    CHECK(sl_ext_answer(e, 'C') == 0);
    CHECK(sl_ext_answer(e, 'Z') == 0);
    CHECK(sl_ext_front_guarded_exec(e)); /* the second cycle's Execute is next */
    CHECK(sl_ext_answer(e, 'C') == 0);
    CHECK(sl_ext_answer(e, 'Z') == 0);
    sl_ext_free(e);
}

/* The run-length encoding: thousands of plain Executes are a few slots. */
static void test_batch_is_small(void)
{
    sl_ext *e = sl_ext_new();

    for (int i = 0; i < 100000; i++) {
        CHECK(sl_ext_expect(e, SL_EXT_EXEC) == 0);
    }
    CHECK(e->len == 1);
    CHECK(sl_ext_expect(e, SL_EXT_SYNC) == 0);
    for (int i = 0; i < 100000; i++) {
        CHECK(sl_ext_answer(e, 'C') == 0);
    }
    CHECK(e->len == 1 && e->slots[e->head].kind == SL_EXT_SYNC);
    CHECK(sl_ext_answer(e, 'Z') == 0 && e->len == 0);
    sl_ext_free(e);
}

static void test_error_skips_the_cycle(void)
{
    sl_ext *e = sl_ext_new();

    /* P B D E (guarded) E (guarded) S, then the next cycle's Execute */
    sl_ext_expect(e, SL_EXT_ROWDESC);
    sl_ext_expect(e, SL_EXT_EXEC);
    sl_ext_expect(e, SL_EXT_EXEC_G);
    sl_ext_expect(e, SL_EXT_SYNC);
    sl_ext_expect(e, SL_EXT_EXEC_G);
    sl_ext_expect(e, SL_EXT_SYNC);
    /* the first Execute fails: the guarded one after it never runs */
    CHECK(sl_ext_answer(e, 'T') == 0);
    CHECK(sl_ext_answer(e, 'E') == SL_EXT_SKIPPED);
    CHECK(!sl_ext_in_step(e));
    CHECK(!sl_ext_front_guarded_exec(e)); /* nothing matches until the Z */
    CHECK(sl_ext_answer(e, 'C') == 0);    /* ignored */
    CHECK(sl_ext_answer(e, 'Z') == 0);
    CHECK(sl_ext_in_step(e));
    CHECK(sl_ext_front_guarded_exec(e)); /* the next cycle's slots are untouched */
    CHECK(sl_ext_answer(e, 'C') == 0 && sl_ext_answer(e, 'Z') == 0);
    sl_ext_free(e);
}

static void test_error_of_a_plain_statement_skips_nothing(void)
{
    sl_ext *e = sl_ext_new();

    sl_ext_expect(e, SL_EXT_EXEC);
    sl_ext_expect(e, SL_EXT_SYNC);
    CHECK(sl_ext_answer(e, 'E') == 0);
    CHECK(sl_ext_answer(e, 'Z') == 0 && e->len == 0);
    sl_ext_free(e);
}

static void test_simple_query_is_a_barrier(void)
{
    sl_ext *e = sl_ext_new();

    sl_ext_expect(e, SL_EXT_SIMPLE);
    sl_ext_expect(e, SL_EXT_EXEC_G);
    sl_ext_expect(e, SL_EXT_SYNC);
    /* the Query's own answers are none of the queue's business */
    CHECK(sl_ext_answer(e, 'T') == 0 && sl_ext_answer(e, 'D') == 0 && sl_ext_answer(e, 'C') == 0);
    CHECK(!sl_ext_front_guarded_exec(e));
    CHECK(sl_ext_answer(e, 'Z') == 0);
    CHECK(sl_ext_front_guarded_exec(e));
    sl_ext_free(e);
}

static void test_mismatch_gives_up_the_cycle(void)
{
    sl_ext *e = sl_ext_new();

    sl_ext_expect(e, SL_EXT_EXEC_G);
    sl_ext_expect(e, SL_EXT_SYNC);
    CHECK(sl_ext_answer(e, 't') == SL_EXT_SKIPPED); /* an answer nobody was waiting for */
    CHECK(!sl_ext_in_step(e));
    CHECK(sl_ext_answer(e, 'Z') == 0);
    CHECK(sl_ext_in_step(e) && e->len == 0);

    /* a ReadyForQuery with no barrier (the login's, or one of sluice's own) changes nothing */
    CHECK(sl_ext_answer(e, 'Z') == 0 && e->len == 0);
    sl_ext_expect(e, SL_EXT_EXEC_G);
    CHECK(sl_ext_answer(e, 'Z') == 0 && e->len == 1); /* no barrier yet: left alone */
    sl_ext_free(e);
}

static void test_executes_that_have_a_description_added(void)
{
    sl_ext *e = sl_ext_new();

    /* two such Executes pipelined, one of them preceded by the client's own Describe of the portal
     */
    sl_ext_expect(e, SL_EXT_EXEC_M);
    sl_ext_expect(e, SL_EXT_ROWDESC);
    sl_ext_expect(e, SL_EXT_EXEC_M);
    sl_ext_expect(e, SL_EXT_EXEC_M);
    sl_ext_expect(e, SL_EXT_SYNC);
    CHECK(e->len == 4);                          /* neighbours of one kind are one entry */
    CHECK(sl_ext_answer(e, 'T') == SL_EXT_OURS); /* the description of the first */
    CHECK(sl_ext_answer(e, 'C') == 0);           /* its tag */
    CHECK(sl_ext_answer(e, 'T') == 0);           /* the client's own Describe */
    CHECK(sl_ext_answer(e, 'n') == SL_EXT_OURS); /* NoData is ours as well */
    CHECK(sl_ext_answer(e, 'C') == 0);
    CHECK(sl_ext_answer(e, 'T') == SL_EXT_OURS);
    CHECK(sl_ext_answer(e, 'C') == 0 && e->len == 1);
    CHECK(sl_ext_answer(e, 'Z') == 0 && e->len == 0 && sl_ext_in_step(e));

    /* the tag with no description in front of it, or two descriptions: not what was waited for */
    sl_ext_expect(e, SL_EXT_EXEC_M);
    sl_ext_expect(e, SL_EXT_SYNC);
    sl_ext_answer(e, 'C');
    CHECK(!sl_ext_in_step(e));
    sl_ext_answer(e, 'Z');
    sl_ext_expect(e, SL_EXT_EXEC_M);
    sl_ext_expect(e, SL_EXT_SYNC);
    CHECK(sl_ext_answer(e, 'T') == SL_EXT_OURS);
    sl_ext_answer(e, 'T');
    CHECK(!sl_ext_in_step(e));
    sl_ext_answer(e, 'Z');
    /* an error in place of the description: the rest of the cycle is skipped, and the next one is
     * clean */
    sl_ext_expect(e, SL_EXT_EXEC_M);
    sl_ext_expect(e, SL_EXT_SYNC);
    sl_ext_expect(e, SL_EXT_EXEC_M);
    sl_ext_expect(e, SL_EXT_SYNC);
    sl_ext_answer(e, 'E');
    CHECK(!sl_ext_in_step(e));
    sl_ext_answer(e, 'Z');
    CHECK(sl_ext_in_step(e) && sl_ext_answer(e, 'T') == SL_EXT_OURS);
    sl_ext_free(e);
}

static void test_queue_full(void)
{
    sl_ext *e = sl_ext_new();
    int rc = 0;

    for (int i = 0; i < SL_EXT_SLOTS_MAX + 5 && rc == 0; i++) {
        rc = sl_ext_expect(e, SL_EXT_SYNC);
    }
    CHECK(rc == SL_EXT_FULL);
    CHECK(e->len == SL_EXT_SLOTS_MAX);
    for (int i = 0; i < SL_EXT_SLOTS_MAX; i++) {
        CHECK(sl_ext_answer(e, 'Z') == 0);
    }
    CHECK(e->len == 0);
    CHECK(sl_ext_expect(e, SL_EXT_EXEC) == 0); /* the ring wraps */
    sl_ext_free(e);
}

int main(void)
{
    test_names();
    test_statements();
    test_table_full();
    test_portals();
    test_one_cycle();
    test_plain_describe_is_left_alone();
    test_pipelined_cycles();
    test_batch_is_small();
    test_error_skips_the_cycle();
    test_error_of_a_plain_statement_skips_nothing();
    test_simple_query_is_a_barrier();
    test_mismatch_gives_up_the_cycle();
    test_executes_that_have_a_description_added();
    test_queue_full();
    return TEST_RESULT();
}
