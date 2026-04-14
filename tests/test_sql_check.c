#include <stdlib.h>

#include "check.h"
#include "sql_check.h"

#define UW SL_SQL_UNBOUNDED_WRITE
#define DDL SL_SQL_DDL
#define DRP SL_SQL_DROP
#define TRN SL_SQL_TRUNCATE
#define NRO SL_SQL_NOT_READ_ONLY
#define SSN SL_SQL_SET_SESSION
#define DNG SL_SQL_DANGEROUS
#define PRC SL_SQL_PROCEDURAL
#define MUL SL_SQL_MULTI
#define UNS SL_SQL_TABLES_UNSEEN

static void expect(int line, const char *sql, size_t n, const uint32_t *want)
{
    sl_sql_info info;
    char err[256];
    int ok = 1;

    if (sl_sql_classify(sql, strlen(sql), &info, err, sizeof err) != 0) {
        fprintf(stderr, "test_sql_check.c:%d: \"%s\" was refused: %s\n", line, sql, err);
        sl_test_failures++;
        return;
    }
    if (info.count != n) {
        ok = 0;
    }
    for (size_t i = 0; ok && i < n; i++) {
        /* DELETE and UPDATE have flags of their own, checked in test_kinds(): the older
         * expectations below are about the other flags */
        ok = (info.flags[i] & ~(uint32_t)(SL_SQL_DELETE | SL_SQL_UPDATE)) == want[i];
    }
    if (!ok) {
        fprintf(stderr, "test_sql_check.c:%d: \"%s\"\n  got %zu statements:", line, sql,
                info.count);
        for (size_t i = 0; i < info.count; i++) {
            fprintf(stderr, " 0x%02x", info.flags[i]);
        }
        fprintf(stderr, "\n  want %zu statements:", n);
        for (size_t i = 0; i < n; i++) {
            fprintf(stderr, " 0x%02x", want[i]);
        }
        fprintf(stderr, "\n");
        sl_test_failures++;
    }
    sl_sql_info_free(&info);
}

#define EXPECT(sql, ...)                                                                           \
    do {                                                                                           \
        const uint32_t want_[] = {__VA_ARGS__};                                                    \
        expect(__LINE__, (sql), sizeof want_ / sizeof want_[0], want_);                            \
    } while (0)

#define EXPECT_NONE(sql) expect(__LINE__, (sql), 0, NULL)

static void test_data(void)
{
    EXPECT("select 1", 0);
    EXPECT("select 1;", 0);
    EXPECT("select * from t where id = 1", 0);
    EXPECT("select 1 union select 2", 0);

    /* a WHERE clause is what matters, and it has to belong to the statement itself */
    EXPECT("delete from t", NRO | UW);
    EXPECT("delete from t where id = 1", NRO);
    EXPECT("delete from t where true", NRO); /* its content is not judged */
    EXPECT("delete from t using u where t.id = u.id", NRO);
    EXPECT("update t set a = 1", NRO | UW);
    EXPECT("update t set a = 1 where id = 2", NRO);
    EXPECT("update t set a = (select max(a) from u where u.x = 1)", NRO | UW);
    EXPECT("insert into t values (1)", NRO);
    EXPECT("insert into t select * from u", NRO);
    EXPECT("insert into t values (1) returning *", NRO);
    EXPECT("merge into t using s on t.id = s.id when matched then delete", NRO | UNS);

    /* SELECT that is not a plain read */
    EXPECT("select * from t for update", NRO);
    EXPECT("select * from t for share of t", NRO);
    EXPECT("select * into t2 from t", DDL | NRO);

    /* data-modifying CTEs run with the statement that carries them */
    EXPECT("with d as (delete from t returning *) select * from d", 0, NRO | UW);
    EXPECT("with d as (delete from t where id = 1 returning *) select * from d", 0, NRO);
    EXPECT("with d as (select 1) select * from d", 0, 0);
    EXPECT("with u as (update t set a = 1 returning *) insert into l select * from u", NRO,
           NRO | UW);

    /* wrappers: the statement inside counts when it really runs */
    EXPECT("explain select 1", 0);
    EXPECT("explain delete from t", 0);
    EXPECT("explain analyze delete from t", 0, NRO | UW);
    EXPECT("explain (analyze, verbose) delete from t where id = 1", 0, NRO);
    EXPECT("explain (analyze true, costs off) delete from t", 0, NRO | UW);
    EXPECT("explain (analyze false) delete from t", 0);
    EXPECT("explain (analyze off) delete from t", 0);
    /* the option can be a number, a keyword, or nothing; other options are no reason to look away
     */
    EXPECT("explain (analyze 0) delete from t", 0);
    EXPECT("explain (analyze 1) delete from t", 0, NRO | UW);
    EXPECT("explain (verbose, buffers) delete from t", 0);
    EXPECT("explain (verbose, analyze) delete from t", 0, NRO | UW);
    EXPECT("explain (analyze no) delete from t", 0);
    EXPECT("explain (analyze 1.5) delete from t", 0,
           NRO | UW); /* anything that is not plainly false runs it */
    EXPECT("prepare p as delete from t", 0, NRO | UW);
    EXPECT("prepare p (int) as select $1", 0, 0);
    EXPECT("declare c cursor for select 1", 0, 0);
    EXPECT("declare c cursor for select 1 for update", 0, NRO);
    EXPECT("copy (select 1) to stdout", NRO, 0);
    EXPECT("copy (delete from t returning *) to stdout", NRO, NRO | UW);
    EXPECT("copy t from stdin", NRO);
    EXPECT("copy t to stdout", NRO);
    EXPECT("copy t to '/tmp/x'", NRO | DNG);
    EXPECT("copy t from '/etc/passwd'", NRO | DNG);
    EXPECT("copy t to program 'ls'", NRO | DNG);
    EXPECT("copy (select 1) to program 'ls'", NRO | DNG, 0);
}

static void test_schema(void)
{
    EXPECT("create table t (i int)", DDL | NRO);
    EXPECT("create table t2 as select 1", DDL | NRO);
    EXPECT("create index i on t (a)", DDL | NRO);
    EXPECT("create view v as select 1", DDL | NRO);
    EXPECT("create schema s", DDL | NRO);
    EXPECT("create extension hstore", DDL | NRO);
    EXPECT("create function f() returns int language sql as 'select 1'", DDL | NRO | UNS);
    EXPECT("create role r", DDL | NRO);
    EXPECT("alter table t add column c int", DDL | NRO);
    EXPECT("alter table t rename to u", DDL | NRO | UNS);
    EXPECT("alter system set work_mem = '1MB'", DDL | NRO | UNS);
    EXPECT("grant select on t to r", DDL | NRO | UNS);
    EXPECT("revoke select on t from r", DDL | NRO | UNS);
    EXPECT("comment on table t is 'x'", DDL | NRO | UNS);

    EXPECT("drop table t", DDL | DRP | NRO);
    EXPECT("drop index i", DDL | DRP | NRO | UNS);
    EXPECT("drop database x", DDL | DRP | NRO);
    EXPECT("drop role r", DDL | DRP | NRO);
    EXPECT("truncate t", DDL | TRN | NRO);
    EXPECT("truncate t1, t2 cascade", DDL | TRN | NRO);
}

static void test_session(void)
{
    /* what a driver sends on its own, and what a read-only session may keep doing */
    EXPECT("begin", 0);
    EXPECT("start transaction", 0);
    EXPECT("commit", 0);
    EXPECT("rollback", 0);
    EXPECT("savepoint s", 0);
    EXPECT("release s", 0);
    EXPECT("rollback to s", 0);
    EXPECT("prepare transaction 'x'", NRO);
    EXPECT("commit prepared 'x'", NRO);
    EXPECT("rollback prepared 'x'", NRO);

    EXPECT("show all", 0);
    EXPECT("show search_path", 0);
    EXPECT("execute p", 0);
    EXPECT("deallocate p", 0);
    EXPECT("deallocate all", 0);
    EXPECT("discard all", 0);
    EXPECT("fetch 1 from c", 0);
    EXPECT("close c", 0);

    EXPECT("set application_name = 'x'", 0);
    EXPECT("set time zone 'UTC'", 0);
    EXPECT("set timezone to 'UTC'", 0);
    EXPECT("set search_path to a, b", 0);
    EXPECT("set local statement_timeout = 1000", 0);
    EXPECT("set myapp.user_id = '1'", 0);
    EXPECT("set transaction isolation level serializable", 0);
    EXPECT("set session characteristics as transaction read only", 0);
    EXPECT("reset all", 0);
    EXPECT("set role admin", NRO | SSN);
    EXPECT("set local role admin", NRO | SSN);
    EXPECT("set role none", NRO | SSN);
    EXPECT("reset role", NRO);
    EXPECT("set session authorization joe", NRO | SSN);
    EXPECT("set session_replication_role = replica", NRO);

    EXPECT("do $$ begin delete from t; end $$", PRC | NRO | UNS);
    EXPECT("call p()", PRC | NRO | UNS);

    EXPECT("vacuum t", NRO | UNS);
    EXPECT("analyze t", NRO | UNS);
    EXPECT("lock table t", NRO);
    EXPECT("listen c", NRO);
    EXPECT("notify c", NRO);
    EXPECT("refresh materialized view m", NRO);
    EXPECT("reindex table t", NRO | UNS);
    EXPECT("cluster t", NRO | UNS);
    EXPECT("checkpoint", NRO);
}

static void test_messages_with_several_statements(void)
{
    EXPECT("select 1; select 2", MUL, MUL);
    EXPECT("begin; delete from t; commit", MUL, NRO | UW | MUL, MUL);
    EXPECT("select 1; ; select 2", MUL, MUL);
    EXPECT_NONE("");
    EXPECT_NONE("   ");
    EXPECT_NONE(";");
}

/* The tables of each statement of a message, as "schema.name" or "name", commas inside a statement
 * and semicolons between statements: "a,b.c;d". */
static void tables_are(int line, const char *sql, const char *want)
{
    sl_sql_info info;
    char err[256];
    char got[512] = "";
    size_t used = 0;

    if (sl_sql_classify_with_tables(sql, strlen(sql), &info, err, sizeof err) != 0) {
        fprintf(stderr, "test_sql_check.c:%d: \"%s\" was refused: %s\n", line, sql, err);
        sl_test_failures++;
        return;
    }
    for (size_t g = 0; g < info.top_level; g++) {
        if (g > 0) {
            used += (size_t)snprintf(got + used, sizeof got - used, ";");
        }
        for (size_t t = 0; t < info.tables[g].count; t++) {
            const sl_sql_table *tb = &info.tables[g].items[t];

            used += (size_t)snprintf(got + used, sizeof got - used, "%s%s%s%s", t ? "," : "",
                                     tb->schema, tb->schema[0] ? "." : "", tb->name);
        }
    }
    if (strcmp(got, want) != 0) {
        fprintf(stderr, "test_sql_check.c:%d: \"%s\"\n  tables: %s\n  want:   %s\n", line, sql, got,
                want);
        sl_test_failures++;
    }
    sl_sql_info_free(&info);
}

#define TABLES(sql, want) tables_are(__LINE__, (sql), (want))

/* The functions a message calls, as "schema.name" or "name" (statements joined by ;). */
static void funcs_are(int line, const char *sql, const char *want)
{
    sl_sql_info info;
    char err[256];
    char got[512] = "";
    size_t used = 0;

    if (sl_sql_classify_with_tables(sql, strlen(sql), &info, err, sizeof err) != 0) {
        fprintf(stderr, "test_sql_check.c:%d: \"%s\" was refused: %s\n", line, sql, err);
        sl_test_failures++;
        return;
    }
    for (size_t g = 0; g < info.top_level; g++) {
        if (g > 0) {
            used += (size_t)snprintf(got + used, sizeof got - used, ";");
        }
        for (size_t t = 0; t < info.tables[g].nfuncs; t++) {
            const sl_sql_table *f = &info.tables[g].funcs[t];

            used += (size_t)snprintf(got + used, sizeof got - used, "%s%s%s%s", t ? "," : "",
                                     f->schema, f->schema[0] ? "." : "", f->name);
        }
    }
    if (strcmp(got, want) != 0) {
        fprintf(stderr, "test_sql_check.c:%d: \"%s\"\n  functions: %s\n  want:      %s\n", line,
                sql, got, want);
        sl_test_failures++;
    }
    sl_sql_info_free(&info);
}

#define FUNCS(sql, want) funcs_are(__LINE__, (sql), (want))

static void test_functions(void)
{
    FUNCS("select 1", "");
    FUNCS("select pg_read_file('/etc/passwd')", "pg_read_file");
    FUNCS("select pg_catalog.pg_sleep(1)", "pg_catalog.pg_sleep");
    FUNCS("select set_config('role', 'x', false), lower('A')", "set_config,lower");
    FUNCS("select * from t where id = (select max(id) from u)", "max");
    FUNCS("select * from generate_series(1, 3)", "generate_series");
    FUNCS("update t set a = nextval('s') where b = abs(-1)", "nextval,abs");
    FUNCS("with d as (delete from t returning dblink_exec('x','y')) select 1", "dblink_exec");
    FUNCS("delete from t returning pg_sleep(1)", "pg_sleep");
    FUNCS("declare c cursor for select pg_read_file('x')", "pg_read_file");
    FUNCS("create table x (a int default nextval('s'))", "nextval");
    FUNCS("select 'FuncCall pg_sleep'", "");                          /* a string says nothing */
    FUNCS("select \"\"\"FuncCall\"\":{\"\"funcname\"\":[\"\"\"", ""); /* nor does a name */
    FUNCS("select 1; select pg_sleep(1)", ";pg_sleep");
}

static void test_tables(void)
{
    sl_sql_info info;
    char err[256];

    /* what the parser reports, statement kind by statement kind */
    TABLES("select 1", "");
    TABLES("select * from generate_series(1, 3)", ""); /* a function is not a table */
    TABLES("select * from a join b.c on true", "a,b.c");
    TABLES("select * from only t", "t");
    TABLES("table t", "t");
    TABLES("select * from t as x, \"Odd Name\"", "t,Odd Name");
    TABLES("select * from public.t, t", "public.t,t");
    TABLES("select * from pg_catalog.pg_class", "pg_catalog.pg_class");
    TABLES("select * from t1 union select * from t2", "t1,t2");
    TABLES("select * from (select * from deep) s where exists (select 1 from sub)", "deep,sub");
    TABLES("with x as (select * from t) select * from x", "t"); /* a CTE is not a table */
    TABLES("with d as (delete from t returning *) select * from d", "t");
    TABLES("delete from t using u where t.id = u.id", "t,u");
    TABLES("insert into s.t select * from u", "s.t,u");
    TABLES("update t set a = (select max(b) from u)", "t,u");
    TABLES("select * into newt from old", "old,newt");
    TABLES("copy t from stdin", "t");
    TABLES("copy (select * from q) to stdout", "q");
    TABLES("explain analyze delete from t", "t");
    TABLES("prepare p as select * from pp", "pp");
    TABLES("create table x (i int)", "x");
    TABLES("create view v as select * from base", "v,base");
    TABLES("create index i on t (a)", "t");
    TABLES("alter table t add c int", "t");
    TABLES("drop table a, b.c", "a,b.c");
    TABLES("truncate t1, t2", "t1,t2");
    TABLES("lock table t", "t");
    TABLES("begin", "");
    TABLES("set search_path to x", "");
    TABLES("", "");

    /* a message with several statements gets each statement's own tables, whatever the spacing */
    TABLES("select * from a; delete from b where x = 1; select 1", "a;b;");
    TABLES("select * from a;select * from b", "a;b");
    TABLES("\n  select * from a ;  \n select * from b ; ", "a;b");
    TABLES("select ';' from a; select * from b", "a;b");
    TABLES("select * from a; ; ; select * from b", "a;b");
    TABLES("begin; update t set a = 1; commit", ";t;");

    /* the effective statements remember which statement of the message they come from */
    CHECK(sl_sql_classify_with_tables(
              "with d as (delete from t returning *) select * from d; select 1",
              strlen("with d as (delete from t returning *) select * from d; select 1"), &info, err,
              sizeof err) == 0);
    CHECK(info.top_level == 2 && info.count == 3 && info.group[0] == 0 && info.group[1] == 0 &&
          info.group[2] == 1);
    sl_sql_info_free(&info);

    /* tables are only listed when asked for */
    CHECK(sl_sql_classify("select * from t", strlen("select * from t"), &info, err, sizeof err) ==
              0 &&
          info.tables == NULL);
    sl_sql_info_free(&info);
    CHECK(sl_sql_classify_with_tables("", strlen(""), &info, err, sizeof err) == 0 &&
          info.tables != NULL && info.top_level == 0);
    sl_sql_info_free(&info);
    CHECK(sl_sql_classify_with_tables("select * from", strlen("select * from"), &info, err,
                                      sizeof err) == -1);
    CHECK(strstr(err, "syntax error") != NULL);
}

/* The statements whose tables the parser does not (fully) report must say so, and the others not.
 */
static void test_unseen(void)
{
    static const char *const seen[] = {
        "select * from t",
        "insert into t values (1)",
        "update t set a = 1",
        "delete from t where a = 1",
        "copy t to stdout",
        "truncate t",
        "create table t (i int)",
        "alter table t add c int",
        "create index i on t (a)",
        "drop table t",
        "lock table t",
        "begin",
        "show all",
        "set application_name = 'x'",
        "explain select 1",
        "listen c",
        "create role r",
        "create schema s",
        "refresh materialized view m",
        "create view v as select 1",
        "create table t2 as select 1",
        "prepare p as select 1",
        "deallocate p",
    };
    static const char *const unseen[] = {
        "merge into t using s on t.id = s.id when matched then delete",
        "comment on table t is 'x'",
        "grant select on all tables in schema public to r",
        "grant select on t to r",
        "drop schema s cascade",
        "drop index i",
        "drop view v",
        "vacuum",
        "vacuum t",
        "analyze",
        "create function f() returns int language sql as 'select 1'",
        "create trigger g before insert on t for each row execute function f()",
        "alter table t rename to u",
        "alter index i rename to j",
        "do $$ begin end $$",
        "call p()",
        "reindex table t",
        "cluster t",
        "create policy p on t using (true)",
        "alter system set work_mem = '1MB'",
    };

    for (size_t i = 0; i < sizeof seen / sizeof seen[0]; i++) {
        sl_sql_info info;
        char err[256];

        CHECK(sl_sql_classify(seen[i], strlen(seen[i]), &info, err, sizeof err) == 0);
        if (info.count > 0 && (info.flags[0] & SL_SQL_TABLES_UNSEEN)) {
            fprintf(stderr, "test_sql_check.c: \"%s\" should have its tables seen\n", seen[i]);
            sl_test_failures++;
        }
        sl_sql_info_free(&info);
    }
    for (size_t i = 0; i < sizeof unseen / sizeof unseen[0]; i++) {
        sl_sql_info info;
        char err[256];

        CHECK(sl_sql_classify(unseen[i], strlen(unseen[i]), &info, err, sizeof err) == 0);
        if (info.count == 0 || !(info.flags[0] & SL_SQL_TABLES_UNSEEN)) {
            fprintf(stderr, "test_sql_check.c: \"%s\" should be flagged as having unseen tables\n",
                    unseen[i]);
            sl_test_failures++;
        }
        sl_sql_info_free(&info);
    }
}

/* ---- logging without the values ---- */

static void redacted_is(int line, const char *sql, const char *want_text /* NULL: withheld */)
{
    sl_sql_redacted r;
    char err[256];

    if (sl_sql_redact(sql, strlen(sql), &r, err, sizeof err) != 0) {
        fprintf(stderr, "test_sql_check.c:%d: \"%s\" was refused: %s\n", line, sql, err);
        sl_test_failures++;
        return;
    }
    CHECK(strlen(r.fingerprint) == 16);
    /* whatever the outcome, the secret is not in what may be logged */
    CHECK(r.text == NULL || strstr(r.text, "hunter2") == NULL);
    if ((want_text == NULL) != (r.text == NULL) || (want_text && strcmp(want_text, r.text) != 0)) {
        fprintf(stderr, "test_sql_check.c:%d: \"%s\"\n  text: %s\n  want: %s\n", line, sql,
                r.text ? r.text : "(withheld)", want_text ? want_text : "(withheld)");
        sl_test_failures++;
    }
    sl_sql_redacted_free(&r);
}

#define REDACTED(sql, want) redacted_is(__LINE__, (sql), (want))

static void test_redaction(void)
{
    sl_sql_redacted a;
    sl_sql_redacted b;
    char err[256];

    /* the values become parameters */
    REDACTED("select * from users where email = 'a@b.c' and id = 42",
             "select * from users where email = $1 and id = $2");
    REDACTED("insert into users (name, pw) values ('bob', 'hunter2')",
             "insert into users (name, pw) values ($1, $2)");
    REDACTED("update users set pw = 'hunter2' where id = 7",
             "update users set pw = $1 where id = $2");
    REDACTED("select set_config('myapp.token', 'hunter2', false)", "select set_config($1, $2, $3)");
    REDACTED("set myapp.token = 'hunter2'", "set myapp.token = $1");
    REDACTED("alter role bob password 'hunter2'", "alter role bob password $1");
    REDACTED("create role eve login password 'hunter2'", "create role eve login password $1");
    REDACTED("select * from t where a = E'hunter2' and b = $$hunter2$$ and c = x'ff' and d = 1.5e3",
             "select * from t where a = $1 and b = $2 and c = $3 and d = $4");
    REDACTED("select 1; select 'hunter2'", "select $1; select $2");
    REDACTED("do $$ begin perform 'hunter2'; end $$", "do $1");
    REDACTED("select $1, $2 from t where a = 5", "select $1, $2 from t where a = $3");
    REDACTED("begin", "begin");

    /* what the normalizer leaves behind is not trusted: the text is withheld, the fingerprint stays
     */
    REDACTED("select * from t where a = 'it''s hunter2' -- hunter2 in a comment", NULL);
    REDACTED("select /* hunter2 */ 1", NULL);
    REDACTED("create server s foreign data wrapper w options (password 'hunter2')", NULL);
    REDACTED("copy t from program 'echo hunter2'", NULL);
    REDACTED("comment on table t is 'hunter2'", NULL);
    REDACTED("create table t (c text default 'hunter2')", NULL);
    REDACTED("prepare p as select * from t where a = 'hunter2'", NULL);
    REDACTED("alter table t add c int default 5", NULL);
    /* a function body is a literal, and it is masked like one */
    REDACTED("create function f() returns text language sql as $$ select 'hunter2' $$",
             "create function f() returns text language sql as $1");

    /* the fingerprint is the shape of the query: the same for other values, other for another query
     */
    CHECK(sl_sql_redact("select * from t where id = 1 and n = 'a'",
                        strlen("select * from t where id = 1 and n = 'a'"), &a, err,
                        sizeof err) == 0);
    CHECK(sl_sql_redact("select * from t where id = 99 and n = 'zzzz'",
                        strlen("select * from t where id = 99 and n = 'zzzz'"), &b, err,
                        sizeof err) == 0);
    CHECK_STR(a.fingerprint, b.fingerprint);
    sl_sql_redacted_free(&b);
    CHECK(sl_sql_redact("select * from t where id = 1 or n = 'a'",
                        strlen("select * from t where id = 1 or n = 'a'"), &b, err,
                        sizeof err) == 0);
    CHECK(strcmp(a.fingerprint, b.fingerprint) != 0);
    sl_sql_redacted_free(&a);
    sl_sql_redacted_free(&b);

    /* the normalized text is stable: normalizing it again changes nothing */
    CHECK(sl_sql_redact("select * from users where email = 'a@b.c' and id = 42",
                        strlen("select * from users where email = 'a@b.c' and id = 42"), &a, err,
                        sizeof err) == 0);
    CHECK(a.text != NULL);
    CHECK(sl_sql_redact(a.text, strlen(a.text), &b, err, sizeof err) == 0);
    CHECK(b.text != NULL && strcmp(a.text, b.text) == 0);
    sl_sql_redacted_free(&a);
    sl_sql_redacted_free(&b);

    /* SQL that does not parse: no fingerprint, and the message does not quote the SQL */
    CHECK(sl_sql_redact("select hunter2 from where", strlen("select hunter2 from where"), &a, err,
                        sizeof err) == -1);
    CHECK(strstr(err, "syntax error") != NULL && strstr(err, "hunter2") == NULL &&
          strstr(err, "at or near") == NULL);
    CHECK(sl_sql_redact("select 'hunter2", strlen("select 'hunter2"), &a, err, sizeof err) == -1);
    CHECK(strstr(err, "hunter2") == NULL);
    CHECK(a.text == NULL && a.fingerprint[0] == '\0');

    /* the cut itself */
    {
        char m[] = "syntax error at or near \"hunter2\"";
        char n[] = "syntax error at end of input";

        sl_sql_scrub_error(m);
        sl_sql_scrub_error(n);
        CHECK_STR(m, "syntax error");
        CHECK_STR(n, "syntax error at end of input");
    }
}

static void test_refusals_and_limits(void)
{
    sl_sql_info info;
    char err[256];

    CHECK(sl_sql_classify("selec 1", strlen("selec 1"), &info, err, sizeof err) == -1);
    CHECK(strstr(err, "syntax error") != NULL);
    CHECK(info.flags == NULL && info.count == 0);

    CHECK(sl_sql_classify("select 1 from", strlen("select 1 from"), &info, err, sizeof err) == -1);
    CHECK(sl_sql_classify("delete from t where", strlen("delete from t where"), &info, err,
                          sizeof err) == -1);

    /* long flat expressions are normal generated SQL: they must not trip the depth limit */
    {
        size_t terms = 1000;
        size_t cap = 16 + terms * 4;
        char *sql = malloc(cap);
        size_t n = (size_t)snprintf(sql, cap, "select 1");

        CHECK(sql != NULL);
        for (size_t i = 0; sql && i < terms; i++) {
            n += (size_t)snprintf(sql + n, cap - n, " + 1");
        }
        if (sql) {
            CHECK(sl_sql_classify(sql, n, &info, err, sizeof err) == 0);
            CHECK(info.count == 1 && info.flags[0] == 0);
            sl_sql_info_free(&info);
        }
        free(sql);
    }

    /* a long chain of UNION */
    {
        size_t arms = 400;
        size_t cap = 16 + arms * 16;
        char *sql = malloc(cap);
        size_t n = (size_t)snprintf(sql, cap, "select 1");

        CHECK(sql != NULL);
        for (size_t i = 0; sql && i < arms; i++) {
            n += (size_t)snprintf(sql + n, cap - n, " union select 2");
        }
        if (sql) {
            CHECK(sl_sql_classify(sql, n, &info, err, sizeof err) == 0);
            CHECK(info.count == 1 && info.flags[0] == 0);
            sl_sql_info_free(&info);
        }
        free(sql);
    }

    /* statements hidden in statements are followed only so far: deeper than that is never
     * read-only, and the answer is the same whatever the machine's stack */
    {
        char sql[1024] = "";

        /* with c1 as (with c2 as (... with c12 as (select 1) select 1 ...) select 1) select 1 */
        for (int i = 1; i <= 12; i++) {
            char one[32];

            snprintf(one, sizeof one, "with c%d as (", i);
            strcat(sql, one);
        }
        strcat(sql, "select 1");
        for (int i = 1; i <= 12; i++) {
            strcat(sql, ") select 1");
        }
        CHECK(sl_sql_classify(sql, strlen(sql), &info, err, sizeof err) == 0);
        {
            uint32_t all = 0;

            for (size_t i = 0; i < info.count; i++) {
                all |= info.flags[i];
            }
            CHECK(all & SL_SQL_NOT_READ_ONLY);
        }
        sl_sql_info_free(&info);
    }

    /* hostile nesting must end in an answer, never in a crash: accepted or refused, both are fine
     */
    {
        size_t depth = 20000;
        size_t cap = 2 * depth + 32;
        char *sql = malloc(cap);
        size_t n = 0;

        CHECK(sql != NULL);
        if (sql) {
            n += (size_t)snprintf(sql + n, cap - n, "select ");
            for (size_t i = 0; i < depth; i++) {
                sql[n++] = '(';
            }
            sql[n++] = '1';
            for (size_t i = 0; i < depth; i++) {
                sql[n++] = ')';
            }
            if (sl_sql_classify(sql, n, &info, err, sizeof err) == 0) {
                sl_sql_info_free(&info);
            }
        }
        free(sql);
    }
}

/* What the server reads another way once the session changes standard_conforming_strings or
 * client_encoding (see the comment in sql_check.c): a quote after a backslash. The statement
 * written here is one select as sluice reads it, and a delete for a server with
 * standard_conforming_strings off. */
static void expect_refused_as_ambiguous(int line, const char *sql, size_t len)
{
    sl_sql_info info;
    char err[256];

    if (sl_sql_classify(sql, len, &info, err, sizeof err) == 0) {
        fprintf(stderr, "test_sql_check.c:%d: \"%s\" was accepted, it reads two ways\n", line, sql);
        sl_sql_info_free(&info);
        sl_test_failures++;
    } else if (strstr(err, "backslash") == NULL) {
        fprintf(stderr, "test_sql_check.c:%d: refused for another reason: %s\n", line, err);
        sl_test_failures++;
    }
}

#define AMBIGUOUS(sql) expect_refused_as_ambiguous(__LINE__, (sql), strlen(sql))

static void test_ambiguous_strings(void)
{
    /* the bypass found on a real server: after SET standard_conforming_strings = off, the string
     * below ends at the quote on the second line, and what follows is a DELETE with no WHERE */
    AMBIGUOUS("select 'x\\'\n'; delete from t; --'");
    AMBIGUOUS("select 'a\\'");
    AMBIGUOUS("select 'a\\\\\\'"); /* three backslashes, then the quote */
    AMBIGUOUS("select 1 where x = 'a\\' and y = 'b'");
    AMBIGUOUS("select 'a'\n'b\\'");
    /* a multi-byte client_encoding can make the backslash the end of a character: E'..' is not safe
     * either, and neither is an even run, once there is a byte above 0x7f in the string */
    AMBIGUOUS("select E'caf\xc3\xa9\\' ; delete from t; --'");
    AMBIGUOUS("select 'caf\xc3\xa9\\\\' ; delete from t; --'");
    AMBIGUOUS("select U&'\xc3\xa9\\'");

    /* everything that is read the same way under every setting stays accepted */
    EXPECT("select 'a\\\\b'", 0); /* a\\b: no quote after the backslashes */
    EXPECT("select '\\d+'", 0);   /* the usual regular expression */
    EXPECT("select x ~ '^\\d{3}$' from t", 0);
    EXPECT("select 'C:\\\\'", 0);  /* an even run closes the string in both readings */
    EXPECT("select E'it\\'s'", 0); /* escape string, ASCII: a backslash escapes everywhere */
    EXPECT("select E'a\\\\'", 0);
    EXPECT("select $$it\\'s$$", 0); /* dollar quotes have no escape at all */
    EXPECT("select $q$a\\'b$q$", 0);
    EXPECT("select $$caf\xc3\xa9\\'x$$",
           0);                       /* even with a high byte: no escape inside dollar quotes */
    EXPECT("select 1 -- it\\'s", 0); /* a comment is not a string */
    EXPECT("select /* it\\'s */ 1", 0);
    EXPECT("select \"a\\b\"", 0);          /* nor is an identifier */
    EXPECT("select 'caf\xc3\xa9 \\n'", 0); /* a high byte, but no quote after a backslash */
    EXPECT("delete from t where id = 1 and n = 'a\\\\b'", NRO);
    /* and the usual SQL goes through the cheap path, with no backslash at all */
    EXPECT("select 'it''s'", 0);
}

/* The kind of statement, and what is needed to run a DELETE or an UPDATE inside a transaction. */
static void test_kinds(void)
{
    sl_sql_info info;
    char err[256];
    struct {
        const char *sql;
        unsigned flags; /* SL_SQL_DELETE and SL_SQL_UPDATE of the first effective statement */
        int kind;
        int returning;
    } cases[] = {
        {"delete from t", SL_SQL_DELETE, 'D', 0},
        {"delete from t where id = 1", SL_SQL_DELETE, 'D', 0},
        {"delete from t where id = 1 returning id", SL_SQL_DELETE, 'D', 1},
        {"delete from t returning *;", SL_SQL_DELETE, 'D', 1},
        {"update t set a = 1", SL_SQL_UPDATE, 'U', 0},
        {"update t set a = 1 where b = 2 returning a", SL_SQL_UPDATE, 'U', 1},
        {"with x as (select 1) delete from t using x", SL_SQL_DELETE, 'D', 0},
        {"select 1", 0, 0, 0},
        {"insert into t values (1)", 0, 0, 0},
        {"truncate t", 0, 'T', 1},
        {"truncate table a, b restart identity cascade", 0, 'T', 1},
        {"drop table t", 0, 'R', 1},
        {"drop table if exists a, b cascade", 0, 'R', 1},
        {"drop index i", 0, 'R', 1},
        {"drop view v", 0, 'R', 1},
        {"drop database d", 0, 0, 0}, /* cannot run in a transaction, nor be undone */
        {"drop role r", 0, 0, 0},
        {"drop table a; drop table b", 0, 0, 0}, /* two statements: no kind */
        {"merge into t using s on true when matched then delete", SL_SQL_DELETE, 'M', 0},
        {"merge into t using s on true when matched then update set a = 1", SL_SQL_UPDATE, 'M', 0},
        {"merge into t using s on true when matched and s.x then update set a = 1 when not matched "
         "then insert values (1) when matched then delete",
         SL_SQL_UPDATE | SL_SQL_DELETE, 'M', 0},
        {"merge into t using s on true when not matched then insert values (1)", 0, 'M', 0},
        {"merge into t using s on true when matched then do nothing", 0, 'M', 0},
        {"merge into t using s on true when matched then delete returning merge_action(), t.*",
         SL_SQL_DELETE, 'M', 1},
        {"insert into t values (1) on conflict (id) do update set a = 1", SL_SQL_UPDATE, 'I', 0},
        {"insert into t values (1) on conflict (id) do update set a = 1 returning id",
         SL_SQL_UPDATE, 'I', 1},
        {"insert into t values (1) on conflict do nothing", 0, 0, 0},
        {"insert into t values (1) on conflict (id) do update set a = 1; select 1", SL_SQL_UPDATE,
         0, 0},                                                /* two statements: no kind */
        {"delete from t; delete from u", SL_SQL_DELETE, 0, 0}, /* two statements: no kind */
    };

    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        const char *sql = cases[i].sql;

        CHECK(sl_sql_classify(sql, strlen(sql), &info, err, sizeof err) == 0);
        if (info.count > 0) {
            CHECK((info.flags[0] & (SL_SQL_DELETE | SL_SQL_UPDATE)) == cases[i].flags);
        }
        if (info.top_kind != cases[i].kind || info.top_returning != cases[i].returning) {
            fprintf(stderr, "test_sql_check.c: \"%s\": kind %c returning %d\n", sql,
                    info.top_kind ? info.top_kind : '-', info.top_returning);
            sl_test_failures++;
        }
        sl_sql_info_free(&info);
    }

    /* the table a DELETE or an UPDATE writes to */
    {
        static const struct {
            const char *sql, *schema, *table;
        } t[] = {
            {"delete from users", "", "users"},
            {"delete from public.users where id = 1", "public", "users"},
            {"delete from only \"Odd Name\" as o using other x where o.id = x.id", "", "Odd Name"},
            {"delete from s.t returning *", "s", "t"},
            {"update t set a = 1", "", "t"},
            {"update only s.t as x set a = 1 from o where o.id = x.id returning x.a", "s", "t"}};

        for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
            CHECK(sl_sql_classify(t[i].sql, strlen(t[i].sql), &info, err, sizeof err) == 0);
            CHECK(strcmp(info.top_schema, t[i].schema) == 0 &&
                  strcmp(info.top_table, t[i].table) == 0);
            sl_sql_info_free(&info);
        }
        {
            const char *sql = "insert into t values (1)"; /* no table is named for the others */

            CHECK(sl_sql_classify(sql, strlen(sql), &info, err, sizeof err) == 0);
            CHECK(info.top_table[0] == '\0');
            sl_sql_info_free(&info);
        }
    }

    /* a DELETE hidden in a CTE has its flag, and the message is not "a DELETE" as a whole */
    {
        const char *sql = "with d as (delete from t returning id) select * from d";
        uint32_t all = 0;

        CHECK(sl_sql_classify(sql, strlen(sql), &info, err, sizeof err) == 0);
        for (size_t i = 0; i < info.count; i++) {
            all |= info.flags[i];
        }
        CHECK(all & SL_SQL_DELETE);
        CHECK(info.top_kind == 0);
        sl_sql_info_free(&info);
    }
}

/* Where a statement ends, so that RETURNING * can follow it. */
static void test_statement_end(void)
{
    struct {
        const char *sql;
        const char *kept; /* the text up to that end */
    } cases[] = {
        {"delete from t", "delete from t"},
        {"delete from t;", "delete from t"},
        {"delete from t ;  ", "delete from t"},
        {"delete from t where id = 1 -- why", "delete from t where id = 1"},
        {"delete from t /* a */ where id = 1 /* b */;", "delete from t /* a */ where id = 1"},
        {"delete from t where name = 'a;b' ;", "delete from t where name = 'a;b'"},
        {"delete from t where id in (select 1);", "delete from t where id in (select 1)"},
        {"  delete from t\n", "  delete from t"},
        {"update t set a = $1 where b = $2", "update t set a = $1 where b = $2"},
    };

    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        size_t end = sl_sql_statement_end(cases[i].sql, strlen(cases[i].sql));

        if (end != strlen(cases[i].kept) || memcmp(cases[i].sql, cases[i].kept, end) != 0) {
            fprintf(stderr, "test_sql_check.c: end of \"%s\" is %zu, wanted \"%s\"\n", cases[i].sql,
                    end, cases[i].kept);
            sl_test_failures++;
        }
    }
    CHECK(sl_sql_statement_end("", 0) == 0);
    CHECK(sl_sql_statement_end("-- only a comment", 17) == 0);
    CHECK(sl_sql_statement_end(";", 1) == 0);
    CHECK(sl_sql_statement_end("select 'unterminated", 20) == 0); /* the lexer cannot read it */
}

int main(void)
{
    test_data();
    test_schema();
    test_session();
    test_messages_with_several_statements();
    test_tables();
    test_functions();
    test_unseen();
    test_redaction();
    test_refusals_and_limits();
    test_ambiguous_strings();
    test_kinds();
    test_statement_end();
    return TEST_RESULT();
}
