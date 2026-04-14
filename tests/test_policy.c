#include <stdlib.h>
#include <unistd.h>

#include "check.h"
#include "policy.h"

static int parse(sl_policy *p, const char *text, char *err, size_t errcap)
{
    return sl_policy_parse(p, text, strlen(text), "policy.toml", err, errcap);
}

/* The text must be refused, with a message that contains `fragment` and starts with
 * policy.toml:LINE. */
static void refuse(int line, const char *text, unsigned at_line, const char *fragment)
{
    sl_policy p;
    char err[256];
    char prefix[32];

    snprintf(prefix, sizeof prefix, "policy.toml:%u: ", at_line);
    if (parse(&p, text, err, sizeof err) == 0) {
        fprintf(stderr, "test_policy.c:%d: accepted, but should be refused:\n%s\n", line, text);
        sl_test_failures++;
        sl_policy_free(&p);
        return;
    }
    if (strncmp(err, prefix, strlen(prefix)) != 0 || strstr(err, fragment) == NULL) {
        fprintf(stderr, "test_policy.c:%d: wrong error.\n  got:  %s\n  want: %s... %s\n", line, err,
                prefix, fragment);
        sl_test_failures++;
    }
    CHECK(p.nrules == 0 && p.rules == NULL); /* nothing is left behind */
}

#define REFUSE(text, line, fragment) refuse(__LINE__, (text), (line), (fragment))

static void test_valid(void)
{
    sl_policy p;
    char err[256];

    /* nothing at all is a valid, empty policy with the safe defaults */
    CHECK(parse(&p, "", err, sizeof err) == 0);
    CHECK(p.mode == SL_MODE_AUDIT && p.deny_uninspectable == 1 && p.nrules == 0);
    sl_policy_free(&p);
    CHECK(parse(&p, "# only a comment\n\n   \n", err, sizeof err) == 0);
    sl_policy_free(&p);

    CHECK(parse(&p,
                "# production profile\n"
                "mode = \"enforce\"            # block, do not just log\n"
                "on_uninspectable = 'allow'\n"
                "\n"
                "[[rule]]\n"
                "name   = \"no-unbounded-write\"\n"
                "match  = \"update_or_delete_without_where\"\n"
                "\n"
                "[[rule]]\n"
                "name = \"migrations\"\n"
                "match = \"ddl\"\n"
                "action = \"allow\"\n"
                "users = [\"migrator\", 'deploy',]\n"
                "databases = [\"prod\"]\n"
                "\n"
                "[[rule]]\n"
                "name = \"no-ddl\"\n"
                "match = \"ddl\"\n"
                "message = \"schema changes go through migrations\"\n",
                err, sizeof err) == 0);
    CHECK(p.mode == SL_MODE_ENFORCE && p.deny_uninspectable == 0 && p.nrules == 3);
    CHECK_STR(p.rules[0].name, "no-unbounded-write");
    CHECK(p.rules[0].match == SL_SQL_UNBOUNDED_WRITE && p.rules[0].deny == 1);
    CHECK(p.rules[0].nusers == 0 && p.rules[0].message == NULL);
    CHECK(p.rules[1].deny == 0 && p.rules[1].nusers == 2 && p.rules[1].ndatabases == 1);
    CHECK_STR(p.rules[1].users[0], "migrator");
    CHECK_STR(p.rules[1].users[1], "deploy");
    CHECK_STR(p.rules[1].databases[0], "prod");
    CHECK_STR(p.rules[2].message, "schema changes go through migrations");
    sl_policy_free(&p);

    /* Windows line ends, no final newline, escapes in strings */
    CHECK(parse(&p, "mode = \"audit\"\r\n[[rule]]\r\nname = \"a\\\\b\"\r\nmatch = \"drop\"", err,
                sizeof err) == -1); /* a backslash is not allowed in a rule name... */
    CHECK(strstr(err, "only letters") != NULL);
    CHECK(parse(&p, "mode = \"audit\"\r\n[[rule]]\r\nname = \"a\"\r\nmatch = \"drop\"", err,
                sizeof err) == 0);
    CHECK(p.nrules == 1 && p.rules[0].match == SL_SQL_DROP);
    sl_policy_free(&p);

    /* every match name exists */
    {
        static const char *const names[] = {"update_or_delete_without_where",
                                            "ddl",
                                            "drop",
                                            "truncate",
                                            "not_read_only",
                                            "procedural",
                                            "multi_statement"};
        for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
            char text[200];

            snprintf(text, sizeof text, "[[rule]]\nname = \"r\"\nmatch = \"%s\"\n", names[i]);
            CHECK(parse(&p, text, err, sizeof err) == 0);
            sl_policy_free(&p);
        }
    }
}

static void test_refused(void)
{
    /* typos must not pass silently */
    REFUSE("mod = \"enforce\"\n", 1, "unknown key 'mod'");
    REFUSE("[[rule]]\nname = \"a\"\nmatch = \"ddl\"\nactions = \"deny\"\n", 4,
           "unknown key 'actions'");
    REFUSE("[[rule]]\nname = \"a\"\nmatch = \"dll\"\n", 3, "unknown match 'dll'");
    REFUSE("mode = \"enforced\"\n", 1, "mode must be");
    REFUSE("on_uninspectable = \"maybe\"\n", 1, "on_uninspectable must be");
    REFUSE("[[rule]]\nname = \"a\"\nmatch = \"ddl\"\naction = \"block\"\n", 4, "action must be");

    /* structure */
    REFUSE("[rules]\n", 1, "unknown table");
    REFUSE("[[rule]]\nname = \"a\"\n", 1, "has no match");
    REFUSE("[[rule]]\nmatch = \"ddl\"\n", 1, "no name");
    REFUSE("[[rule]]\nname = \"a\"\nmatch = \"ddl\"\n[[rule]]\nname = \"a\"\nmatch = \"drop\"\n", 4,
           "two rules are named 'a'");
    REFUSE("mode = \"audit\"\nmode = \"enforce\"\n", 2, "given twice");
    REFUSE("[[rule]]\nname = \"a\"\nname = \"b\"\nmatch = \"ddl\"\n", 3, "given twice");
    REFUSE("[[rule]] junk\n", 1, "unexpected text");
    REFUSE("[[rule]]\nname = \"a\" extra\nmatch = \"ddl\"\n", 2, "unexpected text");

    /* values outside the subset */
    REFUSE("mode = enforce\n", 1, "unsupported value");
    REFUSE("mode = 1\n", 1, "unsupported value");
    REFUSE("mode = true\n", 1, "unsupported value");
    REFUSE("[[rule]]\nname = \"a\"\nmatch = \"ddl\"\nusers = { a = 1 }\n", 4, "unsupported value");
    REFUSE("mode = \"\"\"multi\nline\"\"\"\n", 1, "multi-line strings are not supported");
    REFUSE("[[rule]]\nname = \"a\"\nmatch = \"ddl\"\nmessage = '''x'''\n", 4, "multi-line");
    REFUSE("mode = \"audit\n", 1, "unterminated");
    REFUSE("mode = \"a\\qb\"\n", 1, "unsupported escape");
    REFUSE("mode = ['audit']\n", 1, "takes a string");
    REFUSE("[[rule]]\nname = \"a\"\nmatch = \"ddl\"\nusers = \"app\"\n", 4, "takes a list");
    REFUSE("[[rule]]\nname = \"a\"\nmatch = \"ddl\"\nusers = []\n", 4, "empty list");
    REFUSE("[[rule]]\nname = \"a\"\nmatch = \"ddl\"\nusers = [\"\"]\n", 4, "empty or too long");
    REFUSE("[[rule]]\nname = \"a\"\nmatch = \"ddl\"\nusers = [1]\n", 4, "list holds strings");
    REFUSE("[[rule]]\nname = \"a\"\nmatch = \"ddl\"\nusers = [\"a\" \"b\"]\n", 4, "expected ','");
    REFUSE("[[rule]]\nname = \"a\"\nmatch = \"ddl\"\nusers = [\"a\"\n", 4, "never closed");

    /* names and messages end up in the error text the client sees: keep them plain */
    REFUSE("[[rule]]\nname = \"has space\"\nmatch = \"ddl\"\n", 1, "only letters");
    REFUSE("[[rule]]\nname = \"\"\nmatch = \"ddl\"\n", 1, "1 to 64");
    REFUSE("[[rule]]\nname = \"a'b\"\nmatch = \"ddl\"\n", 1, "only letters");
    REFUSE("[[rule]]\nname = \"a\"\nmatch = \"ddl\"\nmessage = \"back\\\\slash\"\n", 4,
           "printable ASCII");
    REFUSE("[[rule]]\nname = \"a\"\nmatch = \"ddl\"\nmessage = \"caf\xc3\xa9\"\n", 4,
           "printable ASCII");
    REFUSE("[[rule]]\nname = \"a\"\nmatch = \"ddl\"\nmessage = \"tab\\there\"\n", 4,
           "printable ASCII");

    /* a NUL byte hides things from the parser: refuse the file */
    {
        sl_policy p;
        char err[256];
        static const char nul[] = "mode = \"audit\"\n\0[[rule]]\n";

        CHECK(sl_policy_parse(&p, nul, sizeof nul - 1, "policy.toml", err, sizeof err) == -1);
        CHECK(strstr(err, "NUL") != NULL);
    }
}

static void write_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");

    CHECK(f != NULL);
    if (f != NULL) {
        CHECK(fwrite(text, 1, strlen(text), f) == strlen(text));
        fclose(f);
    }
}

static void test_load(void)
{
    sl_policy p;
    char err[256];
    char path[] = "/tmp/sluice-test-policy-XXXXXX";
    int fd = mkstemp(path);

    CHECK(sl_policy_load(&p, "/nonexistent/policy.toml", err, sizeof err) == -1);
    CHECK(strstr(err, "/nonexistent/policy.toml") != NULL);
    CHECK(strstr(err, "No such file") != NULL);

    CHECK(fd >= 0);
    if (fd < 0) {
        return;
    }
    close(fd);

    write_file(path, "mode = \"enforce\"\n[[rule]]\nname = \"a\"\nmatch = \"truncate\"\n");
    CHECK(sl_policy_load(&p, path, err, sizeof err) == 0);
    CHECK(p.mode == SL_MODE_ENFORCE && p.nrules == 1);
    sl_policy_free(&p);

    /* errors name the real file */
    write_file(path, "mode = \"audit\"\nbogus = \"x\"\n");
    CHECK(sl_policy_load(&p, path, err, sizeof err) == -1);
    CHECK(strncmp(err, path, strlen(path)) == 0);
    CHECK(strstr(err, ":2: unknown key 'bogus'") != NULL);

    /* a file over 1 MiB is refused instead of being read whole */
    {
        FILE *f = fopen(path, "wb");
        size_t i;

        CHECK(f != NULL);
        for (i = 0; f != NULL && i < (1u << 20) + 10; i++) {
            fputc('#', f);
        }
        if (f != NULL) {
            fclose(f);
        }
        CHECK(sl_policy_load(&p, path, err, sizeof err) == -1);
        CHECK(strstr(err, "larger than") != NULL);
    }
    unlink(path);
}

/* ---- evaluation ---- */

#define UW SL_SQL_UNBOUNDED_WRITE
#define DDL SL_SQL_DDL
#define DRP SL_SQL_DROP
#define NRO SL_SQL_NOT_READ_ONLY
#define MUL SL_SQL_MULTI

static sl_verdict eval(const sl_policy *p, const uint32_t *flags, size_t n, const char *user,
                       const char *db)
{
    sl_sql_info info;

    memset(&info, 0, sizeof info);
    info.flags = (uint32_t *)flags;
    info.count = n;
    info.top_level = n;
    return sl_policy_evaluate(p, &info, user, strlen(user), db, strlen(db));
}

static void test_evaluation(void)
{
    sl_policy p;
    char err[256];
    sl_verdict v;

    CHECK(
        parse(&p,
              "[[rule]]\n"
              "name = \"migrations\"\nmatch = \"ddl\"\naction = \"allow\"\nusers = [\"migrator\"]\n"
              "[[rule]]\n"
              "name = \"no-ddl\"\nmatch = \"ddl\"\n"
              "[[rule]]\n"
              "name = \"no-unbounded\"\nmatch = \"update_or_delete_without_where\"\n"
              "[[rule]]\n"
              "name = \"prod-drop\"\nmatch = \"drop\"\ndatabases = [\"prod\"]\n"
              "[[rule]]\n"
              "name = \"no-multi\"\nmatch = \"multi_statement\"\nusers = [\"agent\"]\n",
              err, sizeof err) == 0);

    /* nothing flagged: allowed */
    {
        const uint32_t none[] = {0};

        v = eval(&p, none, 1, "app", "prod");
        CHECK(!v.deny && v.rule == NULL);
        v = eval(&p, none, 0, "app", "prod"); /* an empty query */
        CHECK(!v.deny);
    }

    /* the first applicable rule decides, in file order */
    {
        const uint32_t ddl[] = {DDL | NRO};

        v = eval(&p, ddl, 1, "migrator", "prod");
        CHECK(!v.deny); /* allowed by "migrations" before "no-ddl" is reached */
        v = eval(&p, ddl, 1, "app", "prod");
        CHECK(v.deny && v.rule != NULL && strcmp(v.rule->name, "no-ddl") == 0);
    }

    /* every statement is judged on its own: an allow for one does not cover another */
    {
        const uint32_t mixed[] = {DDL | NRO, NRO | UW};

        v = eval(&p, mixed, 2, "migrator", "prod");
        CHECK(v.deny && strcmp(v.rule->name, "no-unbounded") == 0);
    }

    /* scoping by database and by user, exact and case-sensitive */
    {
        const uint32_t drop[] = {DDL | DRP | NRO};

        v = eval(&p, drop, 1, "migrator", "staging"); /* allowed as DDL by "migrations" */
        CHECK(!v.deny);
        v = eval(&p, drop, 1, "app", "staging"); /* "no-ddl" still catches it */
        CHECK(v.deny && strcmp(v.rule->name, "no-ddl") == 0);
        v = eval(&p, drop, 1, "Migrator", "staging"); /* case matters */
        CHECK(v.deny && strcmp(v.rule->name, "no-ddl") == 0);
    }
    {
        const uint32_t drop_only[] = {DRP};

        v = eval(&p, drop_only, 1, "app", "prod");
        CHECK(v.deny && strcmp(v.rule->name, "prod-drop") == 0);
        v = eval(&p, drop_only, 1, "app", "staging");
        CHECK(!v.deny); /* the rule is for prod only */
    }
    {
        const uint32_t multi[] = {MUL, MUL};

        v = eval(&p, multi, 2, "agent", "prod");
        CHECK(v.deny && strcmp(v.rule->name, "no-multi") == 0);
        v = eval(&p, multi, 2, "app", "prod");
        CHECK(!v.deny);
    }

    /* the text given to the client */
    {
        char reason[128];

        sl_policy_reason(&p.rules[1], reason, sizeof reason);
        CHECK_STR(reason, "blocked by rule no-ddl");
    }
    sl_policy_free(&p);

    CHECK(parse(&p, "[[rule]]\nname = \"w\"\nmatch = \"ddl\"\nmessage = \"use migrations\"\n", err,
                sizeof err) == 0);
    {
        char reason[128];

        sl_policy_reason(&p.rules[0], reason, sizeof reason);
        CHECK_STR(reason, "blocked by rule w: use migrations");
    }
    sl_policy_free(&p);

    /* no rules: everything is allowed */
    CHECK(parse(&p, "mode = \"enforce\"\n", err, sizeof err) == 0);
    {
        const uint32_t any[] = {DDL | DRP | NRO | UW};

        v = eval(&p, any, 1, "x", "y");
        CHECK(!v.deny);
    }
    sl_policy_free(&p);
}

/* ---- tables ---- */

static void test_tables_parse(void)
{
    sl_policy p;
    char err[256];

    CHECK(parse(&p,
                "[[rule]]\nname = \"a\"\nmatch = \"any\"\nusers = [\"agent\"]\n"
                "outside_tables = [\"orders\", \"public.products\", 'audit.log_2024']\n"
                "[[rule]]\nname = \"b\"\nmatch = \"not_read_only\"\ntables = [\"ledger\", "
                "\"Mixed-Case$1\"]\n",
                err, sizeof err) == 0);
    CHECK(p.nrules == 2 && p.rules[0].any == 1 && p.rules[0].match == 0);
    CHECK(p.rules[0].noutside == 3 && p.rules[0].ntables == 0);
    CHECK_STR(p.rules[0].outside_tables[1], "public.products");
    CHECK(p.rules[1].any == 0 && p.rules[1].ntables == 2 && p.rules[1].noutside == 0);
    CHECK(sl_policy_needs_tables(&p));
    sl_policy_free(&p);

    CHECK(parse(&p, "[[rule]]\nname = \"a\"\nmatch = \"ddl\"\n", err, sizeof err) == 0);
    CHECK(!sl_policy_needs_tables(&p)); /* no rule about tables: do not pay for the tables */
    sl_policy_free(&p);

    REFUSE("[[rule]]\nname = \"a\"\nmatch = \"ddl\"\ntables = \"ledger\"\n", 4, "takes a list");
    REFUSE("[[rule]]\nname = \"a\"\nmatch = \"ddl\"\ntables = []\n", 4, "empty list");
    REFUSE("[[rule]]\nname = \"a\"\nmatch = \"ddl\"\ntables = [\"a\"]\ntables = [\"b\"]\n", 5,
           "given twice");
    REFUSE("[[rule]]\nname = \"a\"\nmatch = \"ddl\"\ntables = [\"a.b.c\"]\n", 4,
           "not a table name");
    REFUSE("[[rule]]\nname = \"a\"\nmatch = \"ddl\"\ntables = [\".a\"]\n", 4, "not a table name");
    REFUSE("[[rule]]\nname = \"a\"\nmatch = \"ddl\"\ntables = [\"a.\"]\n", 4, "not a table name");
    REFUSE("[[rule]]\nname = \"a\"\nmatch = \"ddl\"\ntables = [\"a b\"]\n", 4, "not a table name");
    REFUSE("[[rule]]\nname = \"a\"\nmatch = \"ddl\"\ntables = [\"a\\\"b\"]\n", 4,
           "not a table name");
    REFUSE("[[rule]]\nname = \"a\"\nmatch = \"ddl\"\noutside_tables = [\"a;drop\"]\n", 4,
           "not a table name");
    REFUSE("[[rule]]\nname = \"a\"\nmatch = \"ddl\"\noutside_tables = [\"caf\xc3\xa9\"]\n", 4,
           "not a table name");
    REFUSE("[[rule]]\nname = \"a\"\nmatch = \"anything\"\n", 3, "unknown match");
}

/* The name of the rule that blocks `sql` for `user`, or "-". */
static const char *who(const sl_policy *p, const char *sql, const char *user)
{
    static char name[80];
    sl_sql_info info;
    char err[256];
    sl_verdict v;

    if (sl_sql_classify_with_tables(sql, strlen(sql), &info, err, sizeof err) != 0) {
        fprintf(stderr, "test_policy.c: \"%s\" was refused: %s\n", sql, err);
        sl_test_failures++;
        return "refused";
    }
    v = sl_policy_evaluate(p, &info, user, strlen(user), "db", 2);
    snprintf(name, sizeof name, "%s", v.deny ? v.rule->name : "-");
    sl_sql_info_free(&info);
    return name;
}

#define WHO(p, sql, user, want)                                                                    \
    do {                                                                                           \
        const char *got_ = who((p), (sql), (user));                                                \
        if (strcmp(got_, (want)) != 0) {                                                           \
            fprintf(stderr,                                                                        \
                    "test_policy.c:%d: \"%s\" as %s\n  blocked by: %s\n  want:       %s\n",        \
                    __LINE__, (sql), (user), got_, (want));                                        \
            sl_test_failures++;                                                                    \
        }                                                                                          \
    } while (0)

static void test_tables_evaluation(void)
{
    sl_policy p;
    char err[256];

    CHECK(parse(&p,
                "[[rule]]\nname = \"agent-sales-only\"\nmatch = \"any\"\nusers = [\"agent\"]\n"
                "outside_tables = [\"orders\", \"public.products\"]\n"
                "[[rule]]\nname = \"no-ledger-write\"\nmatch = \"not_read_only\"\ntables = "
                "[\"ledger\"]\n",
                err, sizeof err) == 0);

    /* an allowlist for the agent */
    WHO(&p, "select * from orders", "agent", "-");
    WHO(&p, "select * from orders o join public.products p on p.id = o.product_id", "agent", "-");
    /* `products` alone could be any schema (search_path), and the entry is public.products: not
     * trusted */
    WHO(&p, "select * from orders o join products p on p.id = o.product_id", "agent",
        "agent-sales-only");
    WHO(&p, "select * from public.products", "agent", "-");
    WHO(&p, "select * from other.products", "agent", "agent-sales-only"); /* another schema */
    WHO(&p, "select * from users", "agent", "agent-sales-only");
    WHO(&p, "select * from pg_catalog.pg_class", "agent", "agent-sales-only");
    WHO(&p, "select 1", "agent", "-"); /* no table at all */
    WHO(&p, "begin", "agent", "-");
    WHO(&p, "set application_name = 'x'", "agent", "-");
    WHO(&p, "select * from generate_series(1, 3)", "agent", "-");

    /* the ways round an allowlist */
    WHO(&p, "select * from orders where id = (select max(id) from secret)", "agent",
        "agent-sales-only");
    WHO(&p, "with x as (select * from secret) select * from x", "agent", "agent-sales-only");
    WHO(&p, "select * from orders union select * from secret", "agent", "agent-sales-only");
    WHO(&p, "select * from orders; select * from secret", "agent", "agent-sales-only");
    WHO(&p, "select * from orders;\n\n  select * from secret ;", "agent", "agent-sales-only");
    WHO(&p, "explain analyze select * from secret", "agent", "agent-sales-only");
    WHO(&p, "copy (select * from secret) to stdout", "agent", "agent-sales-only");
    WHO(&p, "prepare p as select * from secret", "agent", "agent-sales-only");
    WHO(&p, "merge into orders using secret on true when matched then delete", "agent",
        "agent-sales-only");
    WHO(&p, "do $$ begin perform 1 from secret; end $$", "agent", "agent-sales-only");
    WHO(&p, "call p()", "agent", "agent-sales-only");
    WHO(&p, "comment on table orders is 'x'", "agent", "agent-sales-only"); /* tables not seen */
    WHO(&p, "vacuum", "agent", "agent-sales-only");

    /* others are not concerned by the agent's rule */
    WHO(&p, "select * from users", "alice", "-");

    /* a rule about a table: statements that touch it, and that are not read-only */
    WHO(&p, "select * from ledger", "alice", "-");
    WHO(&p, "update ledger set a = 1 where id = 1", "alice", "no-ledger-write");
    WHO(&p, "delete from ledger where id = 1", "alice", "no-ledger-write");
    WHO(&p, "delete from other where id in (select id from ledger)", "alice", "no-ledger-write");
    /* A statement hidden in another one shares its tables: the DELETE of this CTE is not told apart
     * from the SELECT that reads ledger, so it counts as a write on a message that touches ledger.
     * Blocking too much rather than too little is the choice made for tables (docs/design.md,
     * section 15). */
    WHO(&p, "with d as (delete from other returning id) select * from ledger", "alice",
        "no-ledger-write");
    WHO(&p, "create table z (i int)", "alice", "-");
    WHO(&p, "drop table ledger", "alice", "no-ledger-write");
    WHO(&p, "truncate ledger", "alice", "no-ledger-write");
    WHO(&p, "update other set a = 1 where id = 1", "alice", "-");
    /* the tables of these cannot be known: a deny rule assumes the worst */
    WHO(&p, "merge into x using ledger on true when matched then delete", "alice",
        "no-ledger-write");
    WHO(&p, "grant select on all tables in schema public to r", "alice", "no-ledger-write");
    WHO(&p, "drop schema s cascade", "alice", "no-ledger-write");
    WHO(&p, "do $$ begin end $$", "alice", "no-ledger-write");
    /* but not the ones that touch no table, or whose tables are known to be elsewhere */
    WHO(&p, "begin", "alice", "-");
    WHO(&p, "set role admin", "alice", "-");
    WHO(&p, "alter table other add c int", "alice", "-");
    sl_policy_free(&p);

    /* a schema in the rule: only that schema, and the unqualified name of the SQL is taken to be in
     * it */
    CHECK(parse(&p,
                "[[rule]]\nname = \"w\"\nmatch = \"not_read_only\"\ntables = [\"public.ledger\"]\n",
                err, sizeof err) == 0);
    WHO(&p, "delete from ledger where id = 1", "u", "w");
    WHO(&p, "delete from public.ledger where id = 1", "u", "w");
    WHO(&p, "delete from archive.ledger where id = 1", "u", "-");
    sl_policy_free(&p);
    CHECK(parse(&p, "[[rule]]\nname = \"w\"\nmatch = \"not_read_only\"\ntables = [\"ledger\"]\n",
                err, sizeof err) == 0);
    WHO(&p, "delete from archive.ledger where id = 1", "u",
        "w"); /* no schema in the rule: any schema */
    WHO(&p, "delete from \"Ledger\" where id = 1", "u", "-"); /* quoted: a different table */
    sl_policy_free(&p);

    /* The search_path of a session is the client's to change: `SET search_path = tenant_b` then
     * `select * from orders` reads tenant_b.orders. A table written without a schema is no proof
     * against an entry that has one. Found on a real server, where it got past a rule meant to keep
     * an agent in tenant_a. */
    CHECK(parse(&p,
                "[[rule]]\nname = \"tenant-a-only\"\nmatch = \"any\"\noutside_tables = "
                "[\"tenant_a.orders\"]\n",
                err, sizeof err) == 0);
    WHO(&p, "select * from tenant_a.orders", "u", "-");
    WHO(&p, "select * from tenant_a.orders; select * from tenant_a.orders", "u", "-");
    WHO(&p, "select * from tenant_b.orders", "u", "tenant-a-only");
    WHO(&p, "select * from orders", "u", "tenant-a-only"); /* which schema? unknown */
    WHO(&p, "select * from tenant_a.orders o join orders x on true", "u", "tenant-a-only");
    WHO(&p, "select * from tenant_a.orders o join tenant_b.orders x on true", "u", "tenant-a-only");
    WHO(&p, "select * from other", "u", "tenant-a-only"); /* a table that is surely outside */
    WHO(&p, "select 1", "u", "-");
    sl_policy_free(&p);

    /* an entry without a schema is any schema: nothing is unknown, the unqualified name is that
     * table */
    CHECK(parse(&p, "[[rule]]\nname = \"o\"\nmatch = \"any\"\noutside_tables = [\"orders\"]\n", err,
                sizeof err) == 0);
    WHO(&p, "select * from orders", "u", "-");
    WHO(&p, "select * from tenant_b.orders", "u", "-");
    WHO(&p, "select * from other", "u", "o");
    sl_policy_free(&p);

    /* a rule on both conditions: a certain "no" on one of them ends it, whatever the other is
     * unsure of */
    CHECK(parse(&p,
                "[[rule]]\nname = \"both\"\nmatch = \"any\"\ntables = [\"a.t\"]\noutside_tables = "
                "[\"a.t\"]\n",
                err, sizeof err) == 0);
    WHO(&p, "select * from a.t", "u", "-");   /* touches a.t, and nothing outside it */
    WHO(&p, "select * from other", "u", "-"); /* touches none of the tables of `tables` */
    WHO(&p, "select * from t", "u", "both");  /* maybe a.t: unknown, so the deny rule applies */
    sl_policy_free(&p);

    /* an allow rule with a qualified entry does not apply to a table it cannot place: it assumes
     * nothing */
    CHECK(parse(&p,
                "[[rule]]\nname = \"free\"\nmatch = \"any\"\naction = \"allow\"\ntables = "
                "[\"scratch.t\"]\n"
                "[[rule]]\nname = \"no-writes\"\nmatch = \"not_read_only\"\n",
                err, sizeof err) == 0);
    WHO(&p, "delete from scratch.t where id = 1", "u", "-"); /* surely scratch.t: allowed */
    WHO(&p, "delete from t where id = 1", "u", "no-writes"); /* maybe: the allow rule is skipped */
    sl_policy_free(&p);

    /* the same for outside_tables on an allow rule: a table that is surely outside the list counts,
     * one that might be inside it does not */
    CHECK(parse(&p,
                "[[rule]]\nname = \"elsewhere-ok\"\nmatch = \"any\"\naction = "
                "\"allow\"\noutside_tables = [\"a.t\"]\n"
                "[[rule]]\nname = \"rest\"\nmatch = \"any\"\n",
                err, sizeof err) == 0);
    WHO(&p, "select * from z", "u", "-");      /* surely outside a.t: the allow rule applies */
    WHO(&p, "select * from t", "u", "rest");   /* maybe a.t: it does not */
    WHO(&p, "select * from a.t", "u", "rest"); /* inside */
    sl_policy_free(&p);

    /* an allow rule with a table condition assumes nothing about what it cannot see */
    CHECK(parse(&p,
                "[[rule]]\nname = \"scratch-ok\"\nmatch = \"ddl\"\naction = \"allow\"\ntables = "
                "[\"scratch\"]\n"
                "[[rule]]\nname = \"no-ddl\"\nmatch = \"ddl\"\n",
                err, sizeof err) == 0);
    WHO(&p, "alter table scratch add c int", "u", "-");
    WHO(&p, "alter table other add c int", "u", "no-ddl");
    WHO(&p, "comment on table scratch is 'x'", "u",
        "no-ddl"); /* tables unseen: the allow does not apply */
    WHO(&p, "drop schema scratch cascade", "u", "no-ddl");
    sl_policy_free(&p);

    /* without any information about tables, deny rules assume the worst and allow rules assume
     * nothing */
    CHECK(
        parse(
            &p,
            "[[rule]]\nname = \"a\"\nmatch = \"ddl\"\naction = \"allow\"\ntables = [\"scratch\"]\n"
            "[[rule]]\nname = \"b\"\nmatch = \"not_read_only\"\ntables = [\"ledger\"]\n",
            err, sizeof err) == 0);
    {
        sl_sql_info info;
        uint32_t f[] = {SL_SQL_DDL | SL_SQL_NOT_READ_ONLY};
        sl_verdict v;

        info.flags = f;
        info.group = NULL;
        info.count = 1;
        info.top_level = 1;
        info.tables = NULL;
        v = sl_policy_evaluate(&p, &info, "u", 1, "db", 2);
        CHECK(v.deny && strcmp(v.rule->name, "b") == 0);
    }
    sl_policy_free(&p);
}

static void test_spelling_and_files(void)
{
    sl_policy p;
    char err[256];

    /* the defaults can be written out, and say the same */
    CHECK(parse(&p,
                "on_uninspectable = \"deny\"\n[[rule]]\nname = \"r\"\nmatch = \"ddl\"\naction = "
                "\"deny\"\n",
                err, sizeof err) == 0);
    CHECK(p.deny_uninspectable == 1 && p.nrules == 1 && p.rules[0].deny == 1);
    sl_policy_free(&p);

    /* escapes of a "basic" string: they are read, and what they make is judged like any other text
     */
    CHECK(parse(&p, "[[rule]]\nname = \"a\\nb\"\nmatch = \"ddl\"\n", err, sizeof err) == -1);
    CHECK(strstr(err, "rule name") != NULL);
    CHECK(parse(&p, "[[rule]]\nname = \"a\\rb\"\nmatch = \"ddl\"\n", err, sizeof err) == -1);
    CHECK(parse(&p, "[[rule]]\nname = \"r\"\nmatch = \"ddl\"\nmessage = \"a\\tb\"\n", err,
                sizeof err) == -1);
    CHECK(strstr(err, "printable ASCII") != NULL);
    CHECK(parse(&p, "[[rule]]\nname = \"r\"\nmatch = \"ddl\"\nmessage = \"say \\\"hi\\\"\"\n", err,
                sizeof err) == 0);
    CHECK_STR(p.rules[0].message, "say \"hi\"");
    sl_policy_free(&p);

    /* a path that is not a file we can read (a directory) is an error with a message, never a
     * policy */
    CHECK(sl_policy_load(&p, "/", err, sizeof err) == -1);
    CHECK(strstr(err, "cannot read") != NULL || strstr(err, "directory") != NULL);
    CHECK(p.nrules == 0 && p.deny_uninspectable == 1);
}

static sl_verdict judge_as(const sl_policy *p, const char *sql, const char *user)
{
    sl_sql_info info;
    char err[256];
    sl_verdict v;

    CHECK(sl_sql_classify_with_tables(sql, strlen(sql), &info, err, sizeof err) == 0);
    v = sl_policy_evaluate(p, &info, user, strlen(user), "db", 2);
    sl_sql_info_free(&info);
    return v;
}

/* set_session, dangerous, the functions key, alert and kill */
static void test_calls_alerts_and_kills(void)
{
    sl_policy p;
    char err[256];
    sl_verdict v;

    CHECK(parse(&p,
                "mode = \"enforce\"\n"
                "[[rule]]\nname = \"no-escalation\"\nmatch = \"set_session\"\nusers = [\"agent\"]\n"
                "[[rule]]\nname = \"no-danger\"\nmatch = \"dangerous\"\naction = \"kill\"\n"
                "message = \"no\"\n"
                "[[rule]]\nname = \"honey\"\nmatch = \"any\"\naction = \"alert\"\n"
                "tables = [\"honeypot\"]\n"
                "[[rule]]\nname = \"no-slow\"\nmatch = \"any\"\nfunctions = [\"slow_*\", "
                "\"app.heavy\"]\n",
                err, sizeof err) == 0);
    CHECK(sl_policy_needs_tables(&p));
    CHECK(p.rules[1].kill && p.rules[1].deny && p.rules[2].alert && !p.rules[2].deny);
    CHECK(p.rules[3].nfunctions == 2);

    /* SET ROLE and set_config() are the same rule; only for the user it names */
    v = judge_as(&p, "set role admin", "agent");
    CHECK(v.deny && strcmp(v.rule->name, "no-escalation") == 0 && !v.kill);
    v = judge_as(&p, "select set_config('role', 'admin', false)", "agent");
    CHECK(v.deny && strcmp(v.rule->name, "no-escalation") == 0);
    v = judge_as(&p, "set role admin", "dba");
    CHECK(!v.deny);
    v = judge_as(&p, "reset role", "agent");
    CHECK(!v.deny);

    /* kill: refused, and it says the connection goes */
    v = judge_as(&p, "select pg_read_file('/etc/passwd')", "dba");
    CHECK(v.deny && v.kill && strcmp(v.rule->name, "no-danger") == 0);
    v = judge_as(&p, "copy t to program 'x'", "dba");
    CHECK(v.deny && v.kill);
    v = judge_as(&p, "copy t to stdout", "dba");
    CHECK(!v.deny);
    v = judge_as(&p, "delete from t returning pg_sleep(1)", "dba");
    CHECK(v.deny && v.kill);

    /* alert: said, not decided */
    v = judge_as(&p, "select * from honeypot", "dba");
    CHECK(!v.deny && v.alert != NULL && strcmp(v.alert->name, "honey") == 0);
    v = judge_as(&p, "select * from honeypot where pg_sleep(1) is null", "dba");
    CHECK(v.deny && v.kill && v.alert != NULL); /* ... and the rules after it still judge */
    v = judge_as(&p, "select 1", "dba");
    CHECK(!v.deny && v.alert == NULL);

    /* functions = [...]: by name, prefix, or schema.name; a schema that disagrees does not match */
    v = judge_as(&p, "select slow_report()", "dba");
    CHECK(v.deny && strcmp(v.rule->name, "no-slow") == 0);
    v = judge_as(&p, "select app.heavy()", "dba");
    CHECK(v.deny);
    v = judge_as(&p, "select heavy()", "dba"); /* found through the search_path: may be app's */
    CHECK(v.deny);
    v = judge_as(&p, "select other.heavy()", "dba");
    CHECK(!v.deny);
    v = judge_as(&p, "select fast_report()", "dba");
    CHECK(!v.deny);
    sl_policy_free(&p);

    /* the entries are names */
    CHECK(parse(&p, "[[rule]]\nname = \"a\"\nmatch = \"any\"\nfunctions = [\"a b\"]\n", err,
                sizeof err) == -1 &&
          strstr(err, "function name") != NULL);
    CHECK(parse(&p, "[[rule]]\nname = \"a\"\nmatch = \"any\"\nfunctions = [\"*\"]\n", err,
                sizeof err) == -1);
    CHECK(parse(&p, "[[rule]]\nname = \"a\"\nmatch = \"any\"\nfunctions = [\"a.b.c\"]\n", err,
                sizeof err) == -1);
    CHECK(parse(&p, "[[rule]]\nname = \"a\"\nmatch = \"any\"\naction = \"kill\"\nmessage = \"x\"\n",
                err, sizeof err) == 0);
    sl_policy_free(&p);
}

/* windows of time, dry runs */
static void test_time_and_dry_run(void)
{
    sl_policy p;
    char err[256];
    sl_verdict v;
    long long t;

    /* 2026-11-17 is a Tuesday, 2026-11-21 a Saturday */
    CHECK(sl_policy_parse_instant("2026-11-17T10:00Z", &t) == 0 && t == 1794909600LL);
    CHECK(sl_policy_parse_instant("2026-11-17", &t) == 0 && t == 1794873600LL);
    CHECK(sl_policy_parse_instant("2026-11-17T10:00:30Z", &t) == 0 && t == 1794909630LL);
    CHECK(sl_policy_parse_instant("2026-13-01", &t) == -1);
    CHECK(sl_policy_parse_instant("2026-11-17T25:00Z", &t) == -1);
    CHECK(sl_policy_parse_instant("2026-11-17 10:00", &t) == -1);

    CHECK(parse(&p,
                "[[rule]]\nname = \"office\"\nmatch = \"ddl\"\nduring = [\"mon-fri 08:00-19:00\"]\n"
                "[[rule]]\nname = \"night\"\nmatch = \"delete\"\n"
                "during = [\"22:00-06:00\", \"sat,sun 00:00-24:00\"]\n"
                "[[rule]]\nname = \"fri-sat\"\nmatch = \"truncate\"\nduring = [\"fri-sat "
                "20:00-24:00\"]\n",
                err, sizeof err) == 0);
    sl_policy_set_time(1794909600LL); /* Tuesday 10:00 */
    CHECK(judge_as(&p, "create table x (a int)", "u").deny);
    CHECK(!judge_as(&p, "delete from t where id = 1", "u").deny);
    sl_policy_set_time(1794909600LL + 14 * 3600); /* Tuesday 00:00 Wed... = Tuesday 24:00 */
    CHECK(!judge_as(&p, "create table x (a int)", "u").deny);
    CHECK(judge_as(&p, "delete from t where id = 1", "u").deny); /* 00:00 is in 22:00-06:00 */
    sl_policy_set_time(1794909600LL + 7 * 86400 - 5 * 3600 +
                       3600 * 3); /* Tuesday 08:00 next week */
    CHECK(judge_as(&p, "create table x (a int)", "u").deny);
    sl_policy_set_time(1794909600LL + 4 * 86400 + 14 * 3600); /* Saturday 00:00 */
    CHECK(judge_as(&p, "delete from t where id = 1", "u").deny);
    CHECK(!judge_as(&p, "create table x (a int)", "u").deny);
    sl_policy_set_time(1794909600LL + 3 * 86400 + 12 * 3600); /* Friday 22:00 */
    CHECK(judge_as(&p, "truncate t", "u").deny);
    sl_policy_set_time(1794909600LL + 3 * 86400 - 3 * 3600); /* Friday 07:00 */
    CHECK(!judge_as(&p, "truncate t", "u").deny);
    sl_policy_set_time(-1);
    sl_policy_free(&p);

    /* the windows are checked when the policy is read */
    CHECK(parse(&p, "[[rule]]\nname = \"a\"\nmatch = \"ddl\"\nduring = [\"funday 08:00-09:00\"]\n",
                err, sizeof err) == -1 &&
          strstr(err, "window") != NULL);
    CHECK(parse(&p, "[[rule]]\nname = \"a\"\nmatch = \"ddl\"\nduring = [\"08:00-08:00\"]\n", err,
                sizeof err) == -1);
    CHECK(parse(&p, "[[rule]]\nname = \"a\"\nmatch = \"ddl\"\nduring = [\"25:00-26:00\"]\n", err,
                sizeof err) == -1);
    CHECK(
        parse(&p,
              "[[rule]]\nname = \"a\"\nmatch = \"ddl\"\nvalid_from = \"2026-12-02\"\nvalid_until = "
              "\"2026-12-01\"\n",
              err, sizeof err) == -1 &&
        strstr(err, "not after") != NULL);
    CHECK(parse(&p,
                "[[rule]]\nname = \"a\"\nmatch = \"any\"\naction = \"limit\"\nmax_result_rows = "
                "\"5\"\nduring = [\"08:00-09:00\"]\n",
                err, sizeof err) == -1);

    /* dry_run: said, not done */
    CHECK(parse(&p,
                "[[rule]]\nname = \"try\"\nmatch = \"ddl\"\ndry_run = \"on\"\n"
                "[[rule]]\nname = \"real\"\nmatch = \"drop\"\n",
                err, sizeof err) == 0);
    v = judge_as(&p, "create table x (a int)", "u");
    CHECK(!v.deny && v.dry != NULL && strcmp(v.dry->name, "try") == 0);
    v = judge_as(&p, "drop table t", "u");
    CHECK(v.deny && strcmp(v.rule->name, "real") == 0 && v.dry != NULL);
    sl_policy_free(&p);
    CHECK(parse(&p,
                "[[rule]]\nname = \"a\"\nmatch = \"ddl\"\naction = \"allow\"\ndry_run = \"on\"\n",
                err, sizeof err) == -1 &&
          strstr(err, "dry_run") != NULL);
    CHECK(parse(&p, "[[rule]]\nname = \"a\"\nmatch = \"ddl\"\ndry_run = \"maybe\"\n", err,
                sizeof err) == -1);
}

/* lists over several lines, and rules about the shape of a statement */
static void test_multiline_and_shapes(void)
{
    sl_policy p;
    char err[256];
    sl_verdict v;
    sl_sql_info info;
    char known[40], ddl[40];

    CHECK(parse(&p,
                "[[rule]]\nname = \"a\"\nmatch = \"ddl\"\nusers = [\n  \"x\",  # first\n"
                "  # a line of its own\n  \"y\"\n]\ndatabases = [\"d\"]   # and a next key\n"
                "[[rule]]\nname = \"b\"\nmatch = \"drop\"\nusers = [\"z\",\n]\n",
                err, sizeof err) == 0 &&
          p.rules[0].nusers == 2 && strcmp(p.rules[0].users[1], "y") == 0 &&
          p.rules[0].ndatabases == 1 && p.rules[1].nusers == 1);
    sl_policy_free(&p);
    CHECK(parse(&p, "[[rule]]\nname = \"a\"\nmatch = \"ddl\"\nusers = [\n  \"x\"\nname = \"b\"\n",
                err, sizeof err) == -1 &&
          strstr(err, "never closed") != NULL);
    CHECK(parse(&p, "[[rule]]\nname = \"a\"\nmatch = \"ddl\"\nusers = [\n  \"x\"\n  \"y\"\n]\n",
                err, sizeof err) == -1 &&
          strstr(err, "expected ','") != NULL && strncmp(err, "policy.toml:4:", 14) == 0);

    /* the shape: the same for any values, not for another statement */
    CHECK(sl_sql_classify_with_tables("select * from t where id = 1", 28, &info, err, sizeof err) ==
          0);
    snprintf(known, sizeof known, "%s", info.fingerprint);
    sl_sql_info_free(&info);
    CHECK(strlen(known) == 16);
    CHECK(sl_sql_classify_with_tables("create table x (a int)", 22, &info, err, sizeof err) == 0);
    snprintf(ddl, sizeof ddl, "%s", info.fingerprint);
    sl_sql_info_free(&info);
    {
        char text[1024];

        snprintf(text, sizeof text,
                 "[[rule]]\nname = \"seen\"\nmatch = \"any\"\naction = \"allow\"\n"
                 "fingerprints = [\"%s\"]\n"
                 "[[rule]]\nname = \"new\"\nmatch = \"any\"\noutside_fingerprints = [\n  \"%s\", # "
                 "ok\n  \"%s\",\n]\n",
                 known, known, "0123456789abcdef");
        CHECK(parse(&p, text, err, sizeof err) == 0 && sl_policy_needs_tables(&p));
    }
    v = judge_as(&p, "select * from t where id = 99999", "u");
    CHECK(!v.deny); /* the same shape, other values */
    v = judge_as(&p, "select * from t where id = 1 or id = 2", "u");
    CHECK(v.deny && strcmp(v.rule->name, "new") == 0);
    v = judge_as(&p, "create table x (a int)", "u");
    CHECK(v.deny);
    CHECK(strcmp(ddl, known) != 0);
    sl_policy_free(&p);
    CHECK(parse(&p, "[[rule]]\nname = \"a\"\nmatch = \"any\"\nfingerprints = [\"xyz\"]\n", err,
                sizeof err) == -1 &&
          strstr(err, "shape of a query") != NULL);
    CHECK(parse(&p,
                "[[rule]]\nname = \"a\"\nmatch = \"any\"\nfingerprints = [\"0123456789ABCDEF\"]\n",
                err, sizeof err) == -1);
}

static void test_confirm_rules(void)
{
    sl_policy p;
    char err[256];
    sl_verdict v;

    CHECK(parse(&p,
                "confirm_timeout = \"90s\"\n"
                "[[rule]]\nname = \"c\"\nmatch = \"delete\"\naction = \"confirm\"\n"
                "over_rows = \"100\"\nmessage = \"ask a person\"\n"
                "[[rule]]\nname = \"u\"\nmatch = \"update\"\naction = \"confirm\"\n"
                "[[rule]]\nname = \"d\"\nmatch = \"drop\"\n",
                err, sizeof err) == 0);
    CHECK(p.confirm_timeout_s == 90 && p.nrules == 3);
    CHECK(p.rules[0].confirm == 1 && p.rules[0].deny == 0 && p.rules[0].over_rows == 100);
    CHECK(p.rules[1].confirm == 1 && p.rules[1].over_rows == 0);

    v = judge_as(&p, "delete from t where id = 1", "alice");
    CHECK(v.confirm == 1 && v.deny == 0 && v.rule != NULL && strcmp(v.rule->name, "c") == 0);
    v = judge_as(&p, "update t set a = 1", "alice");
    CHECK(v.confirm == 1 && strcmp(v.rule->name, "u") == 0);
    v = judge_as(&p, "select 1", "alice");
    CHECK(v.confirm == 0 && v.deny == 0 && v.rule == NULL);
    /* a denial in the same message wins over a confirmation, wherever it comes */
    v = judge_as(&p, "delete from t where id = 1; drop table x", "alice");
    CHECK(v.deny == 1 && v.confirm == 0 && strcmp(v.rule->name, "d") == 0);
    v = judge_as(&p, "drop table x; delete from t where id = 1", "alice");
    CHECK(v.deny == 1 && v.confirm == 0);
    /* two confirmations: the first one is the one named */
    v = judge_as(&p, "update t set a = 1; delete from t", "alice");
    CHECK(v.confirm == 1 && strcmp(v.rule->name, "u") == 0);
    sl_policy_free(&p);

    /* the defaults */
    CHECK(parse(&p, "[[rule]]\nname = \"c\"\nmatch = \"delete\"\naction = \"confirm\"\n", err,
                sizeof err) == 0);
    CHECK(p.confirm_timeout_s == 120);
    sl_policy_free(&p);

    /* what else the statement changed: on unless the rule says off */
    CHECK(parse(&p, "[[rule]]\nname = \"c\"\nmatch = \"delete\"\naction = \"confirm\"\n", err,
                sizeof err) == 0 &&
          p.rules[0].no_side_effects == 0);
    sl_policy_free(&p);
    CHECK(parse(&p,
                "[[rule]]\nname = \"c\"\nmatch = \"delete\"\naction = \"confirm\"\n"
                "side_effects = \"off\"\n",
                err, sizeof err) == 0 &&
          p.rules[0].no_side_effects == 1);
    sl_policy_free(&p);
    CHECK(parse(&p,
                "[[rule]]\nname = \"c\"\nmatch = \"delete\"\naction = \"confirm\"\n"
                "side_effects = \"on\"\n",
                err, sizeof err) == 0 &&
          p.rules[0].no_side_effects == 0);
    sl_policy_free(&p);
    CHECK(parse(&p,
                "[[rule]]\nname = \"c\"\nmatch = \"delete\"\naction = \"confirm\"\n"
                "side_effects = \"maybe\"\n",
                err, sizeof err) == -1 &&
          strstr(err, "side_effects") != NULL);
    CHECK(parse(&p,
                "[[rule]]\nname = \"c\"\nmatch = \"delete\"\naction = \"deny\"\n"
                "side_effects = \"off\"\n",
                err, sizeof err) == -1 &&
          strstr(err, "side_effects") != NULL); /* only goes with confirm */

    /* the durations */
    {
        const char *good[] = {"1", "90", "90s", "2m", "1h", "3600"};
        unsigned want[] = {1, 90, 90, 120, 3600, 3600};

        for (size_t i = 0; i < sizeof good / sizeof good[0]; i++) {
            char text[64];

            snprintf(text, sizeof text, "confirm_timeout = \"%s\"\n", good[i]);
            CHECK(parse(&p, text, err, sizeof err) == 0 && p.confirm_timeout_s == want[i]);
            sl_policy_free(&p);
        }
        const char *bad[] = {"0", "", "2d", "-5", "1.5m", "m", "3601", "2 m", "99999999"};

        for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            char text[64];

            snprintf(text, sizeof text, "confirm_timeout = \"%s\"\n", bad[i]);
            CHECK(parse(&p, text, err, sizeof err) == -1);
            CHECK(strstr(err, "confirm_timeout") != NULL);
        }
    }

    /* what is refused */
    CHECK(parse(&p, "confirm_timeout = \"1m\"\nconfirm_timeout = \"2m\"\n", err, sizeof err) == -1);
    CHECK(strstr(err, "given twice") != NULL);
    CHECK(parse(&p, "[[rule]]\nname = \"c\"\nmatch = \"delete\"\nover_rows = \"5\"\n", err,
                sizeof err) ==
          -1); /* over_rows without confirm: a rule that would not do what it says */
    CHECK(strstr(err, "over_rows") != NULL);
    CHECK(
        parse(&p,
              "[[rule]]\nname = \"c\"\nmatch = \"delete\"\naction = \"allow\"\nover_rows = \"5\"\n",
              err, sizeof err) == -1);
    {
        const char *bad[] = {"100x", "", "-1", "1.5", "1000000000000000000"};

        for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            char text[160];

            snprintf(text, sizeof text,
                     "[[rule]]\nname = \"c\"\nmatch = \"delete\"\naction = \"confirm\"\nover_rows "
                     "= \"%s\"\n",
                     bad[i]);
            CHECK(parse(&p, text, err, sizeof err) == -1 && strstr(err, "over_rows") != NULL);
        }
    }
    CHECK(
        parse(&p,
              "[[rule]]\nname = \"c\"\nmatch = \"delete\"\naction = \"confirm\"\nover_rows = 100\n",
              err, sizeof err) == -1); /* a number: the format has none */
    CHECK(parse(&p, "[[rule]]\nname = \"c\"\nmatch = \"delete\"\naction = \"maybe\"\n", err,
                sizeof err) == -1);
    CHECK(strstr(err, "confirm") != NULL);

    /* a confirm rule about tables assumes the worst about what it cannot see, like a deny rule */
    CHECK(parse(&p,
                "[[rule]]\nname = \"c\"\nmatch = \"any\"\naction = \"confirm\"\ntables = "
                "[\"ledger\"]\n",
                err, sizeof err) == 0);
    v = judge_as(&p, "delete from ledger where id = 1", "alice");
    CHECK(v.confirm == 1);
    v = judge_as(&p, "delete from other where id = 1", "alice");
    CHECK(v.confirm == 0);
    v = judge_as(&p, "merge into other using ledger on true when matched then delete", "alice");
    CHECK(v.confirm == 1); /* the source of a MERGE is not reported: the worst is assumed */
    sl_policy_free(&p);

    /* users and databases narrow it like any rule */
    CHECK(parse(&p,
                "[[rule]]\nname = \"c\"\nmatch = \"delete\"\naction = \"confirm\"\nusers = "
                "[\"agent\"]\n",
                err, sizeof err) == 0);
    CHECK(judge_as(&p, "delete from t", "agent").confirm == 1);
    CHECK(judge_as(&p, "delete from t", "alice").confirm == 0);
    sl_policy_free(&p);
}

static void test_except_users(void)
{
    sl_policy p;
    char err[256];

    /* "everybody but the application": a user nobody thought of is covered */
    CHECK(parse(&p,
                "[[rule]]\nname = \"c\"\nmatch = \"delete\"\naction = \"confirm\"\n"
                "except_users = [\"app\", \"worker\"]\n"
                "[[rule]]\nname = \"d\"\nmatch = \"ddl\"\naction = \"deny\"\nexcept_users = "
                "[\"migrator\"]\n",
                err, sizeof err) == 0);
    CHECK(p.rules[0].nexcept == 2 && p.rules[1].nexcept == 1);
    CHECK(judge_as(&p, "delete from t where id = 1", "app").confirm == 0);
    CHECK(judge_as(&p, "delete from t where id = 1", "worker").confirm == 0);
    CHECK(judge_as(&p, "delete from t where id = 1", "alice").confirm == 1);
    CHECK(judge_as(&p, "delete from t where id = 1", "a-user-created-tomorrow").confirm == 1);
    CHECK(judge_as(&p, "delete from t where id = 1", "").confirm == 1); /* no user at all */
    CHECK(judge_as(&p, "drop table t", "migrator").deny == 0);
    CHECK(judge_as(&p, "drop table t", "app").deny == 1); /* the app is covered by the other rule */
    CHECK(judge_as(&p, "create table x (i int)", "alice").deny == 1);
    CHECK(judge_as(&p, "create table x (i int)", "migrator").deny == 0);
    /* a name is matched whole: "ap" and "application" are not "app" */
    CHECK(judge_as(&p, "delete from t where id = 1", "ap").confirm == 1);
    CHECK(judge_as(&p, "delete from t where id = 1", "application").confirm == 1);
    sl_policy_free(&p);

    /* with users too: those users, minus these */
    CHECK(parse(&p,
                "[[rule]]\nname = \"c\"\nmatch = \"delete\"\naction = \"confirm\"\n"
                "users = [\"alice\", \"bob\"]\nexcept_users = [\"bob\"]\n",
                err, sizeof err) == 0);
    CHECK(judge_as(&p, "delete from t where id = 1", "alice").confirm == 1);
    CHECK(judge_as(&p, "delete from t where id = 1", "bob").confirm == 0);
    CHECK(judge_as(&p, "delete from t where id = 1", "carol").confirm == 0);
    sl_policy_free(&p);

    /* what is refused */
    CHECK(parse(&p, "[[rule]]\nname = \"c\"\nmatch = \"ddl\"\nexcept_users = []\n", err,
                sizeof err) == -1);
    CHECK(strstr(err, "empty list") != NULL);
    CHECK(parse(&p, "[[rule]]\nname = \"c\"\nmatch = \"ddl\"\nexcept_users = \"app\"\n", err,
                sizeof err) == -1);
    CHECK(parse(&p,
                "[[rule]]\nname = \"c\"\nmatch = \"ddl\"\nexcept_users = [\"a\"]\nexcept_users = "
                "[\"b\"]\n",
                err, sizeof err) == -1);
    CHECK(strstr(err, "given twice") != NULL);
}

static void test_limit_rules(void)
{
    sl_policy p;
    char err[256];

    CHECK(parse(&p,
                "[[rule]]\nname = \"cap\"\nmatch = \"delete\"\naction = \"limit\"\nmax_rows = "
                "\"1000\"\n",
                err, sizeof err) == 0);
    CHECK(p.rules[0].limit == 1 && p.rules[0].confirm == 1 && p.rules[0].deny == 0 &&
          p.rules[0].over_rows == 1000);
    sl_policy_free(&p);
    /* a limit needs its number, and the number needs the limit */
    CHECK(parse(&p, "[[rule]]\nname = \"cap\"\nmatch = \"delete\"\naction = \"limit\"\n", err,
                sizeof err) == -1 &&
          strstr(err, "needs max_rows") != NULL);
    CHECK(
        parse(
            &p,
            "[[rule]]\nname = \"c\"\nmatch = \"delete\"\naction = \"confirm\"\nmax_rows = \"5\"\n",
            err, sizeof err) == -1 &&
        strstr(err, "max_rows only goes with") != NULL);
    CHECK(parse(&p,
                "[[rule]]\nname = \"c\"\nmatch = \"delete\"\naction = \"limit\"\nmax_rows = "
                "\"5\"\nover_rows = \"2\"\n",
                err, sizeof err) == -1 &&
          strstr(err, "over_rows") != NULL);
    CHECK(parse(&p,
                "[[rule]]\nname = \"c\"\nmatch = \"delete\"\naction = \"limit\"\nmax_rows = 5\n",
                err, sizeof err) == -1 &&
          strstr(err, "max_rows") != NULL);
    CHECK(parse(&p,
                "[[rule]]\nname = \"c\"\nmatch = \"delete\"\naction = \"limit\"\nmax_rows = \"5\"\n"
                "side_effects = \"off\"\n",
                err, sizeof err) == -1);
    CHECK(parse(&p, "[[rule]]\nname = \"c\"\nmatch = \"delete\"\naction = \"nope\"\n", err,
                sizeof err) == -1 &&
          strstr(err, "\"limit\"") != NULL);
}

static void test_journal_key(void)
{
    sl_policy p;
    char err[256];

    CHECK(parse(&p,
                "[[rule]]\nname = \"a\"\nmatch = \"delete\"\naction = \"confirm\"\njournal = "
                "\"required\"\n"
                "[[rule]]\nname = \"b\"\nmatch = \"delete\"\naction = \"limit\"\nmax_rows = \"9\"\n"
                "journal = \"on\"\n"
                "[[rule]]\nname = \"c\"\nmatch = \"delete\"\naction = \"confirm\"\n",
                err, sizeof err) == 0);
    CHECK(p.rules[0].journal == SL_JOURNAL_REQUIRED && p.rules[1].journal == SL_JOURNAL_ON &&
          p.rules[2].journal == SL_JOURNAL_OFF && sl_policy_needs_journal(&p));
    sl_policy_free(&p);
    CHECK(parse(&p, "[[rule]]\nname = \"c\"\nmatch = \"delete\"\naction = \"confirm\"\n", err,
                sizeof err) == 0 &&
          !sl_policy_needs_journal(&p));
    sl_policy_free(&p);
    CHECK(parse(&p,
                "[[rule]]\nname = \"u\"\nmatch = \"update\"\naction = \"confirm\"\njournal = "
                "\"required\"\n",
                err, sizeof err) == 0 &&
          p.rules[0].journal == SL_JOURNAL_REQUIRED);
    sl_policy_free(&p);
#define BAD(text, word)                                                                            \
    CHECK(parse(&p, "[[rule]]\nname = \"j\"\n" text, err, sizeof err) == -1 &&                     \
          strstr(err, word) != NULL)
    BAD("match = \"ddl\"\naction = \"confirm\"\njournal = \"on\"\n", "match = \"delete\"");
    BAD("match = \"any\"\naction = \"confirm\"\njournal = \"on\"\n", "match = \"delete\"");
    BAD("match = \"delete\"\njournal = \"on\"\n", "journal only goes with");
    BAD("match = \"delete\"\naction = \"allow\"\njournal = \"on\"\n", "journal only goes with");
    BAD("match = \"delete\"\naction = \"confirm\"\njournal = \"maybe\"\n", "journal is");
    BAD("match = \"delete\"\naction = \"confirm\"\njournal = \"on\"\njournal = \"on\"\n", "twice");
#undef BAD
}

static void test_masks(void)
{
    sl_policy p;
    char err[256];
    sl_mask_rule_view v[SL_MASK_MAX_RULES];

    CHECK(
        parse(
            &p,
            "[[rule]]\nname = \"pii\"\nmatch = \"any\"\naction = \"mask\"\nusers = [\"agent\"]\n"
            "columns = [\"email\", \"Phone\"]\ndetect = [\"email\", \"card\"]\nhow = \"partial\"\n"
            "[[rule]]\nname = \"iban\"\nmatch = \"any\"\naction = \"mask\"\n"
            "detect = [\"iban\"]\n"
            "[[rule]]\nname = \"d\"\nmatch = \"ddl\"\n",
            err, sizeof err) == 0);
    CHECK(p.rules[0].mask && p.rules[0].nmask_columns == 2 &&
          p.rules[0].mask_detect == (SL_MASK_EMAIL | SL_MASK_CARD) &&
          p.rules[0].mask_how == SL_MASK_PARTIAL && p.rules[1].mask_how == SL_MASK_HASH);
    CHECK(sl_policy_masks(&p, "agent", 5, "db", 2, v) == 2 && strcmp(v[0].name, "pii") == 0 &&
          v[1].detect == SL_MASK_IBAN);
    CHECK(sl_policy_masks(&p, "app", 3, "db", 2, v) == 1 && strcmp(v[0].name, "iban") == 0);
    /* a mask never decides a statement */
    {
        sl_sql_info info;
        sl_verdict vd;
        const char *sql = "select 1";

        CHECK(sl_sql_classify(sql, strlen(sql), &info, err, sizeof err) == 0);
        vd = sl_policy_evaluate(&p, &info, "agent", 5, "db", 2);
        CHECK(vd.deny == 0 && vd.confirm == 0 && vd.rule == NULL);
        sl_sql_info_free(&info);
    }
    sl_policy_free(&p);

#define BAD(text, word)                                                                            \
    CHECK(parse(&p, "[[rule]]\nname = \"m\"\n" text, err, sizeof err) == -1 &&                     \
          strstr(err, word) != NULL)
    BAD("match = \"any\"\naction = \"mask\"\n", "columns"); /* nothing to hide */
    BAD("match = \"delete\"\naction = \"mask\"\ncolumns = [\"a\"]\n", "match = \"any\"");
    BAD("match = \"any\"\naction = \"mask\"\ncolumns = [\"a\"]\ntables = [\"t\"]\n", "tables");
    BAD("match = \"any\"\naction = \"mask\"\ndetect = [\"phone\"]\n", "detect");
    BAD("match = \"any\"\naction = \"mask\"\ncolumns = [\"a\"]\nhow = \"scramble\"\n", "how");
    BAD("match = \"any\"\naction = \"deny\"\ncolumns = [\"a\"]\n", "action = \"mask\"");
    BAD("match = \"any\"\naction = \"mask\"\ncolumns = [\"a\"]\nbudget_rows = \"5\"\n", "mask");
    BAD("match = \"any\"\naction = \"mask\"\ncolumns = [\"a\"]\nover_rows = \"5\"\n", "over_rows");
    BAD("match = \"any\"\naction = \"mask\"\ncolumns = []\n", "empty");
    BAD("match = \"any\"\naction = \"mask\"\ncolumns = [\"a.b.c.d\"]\n", "schema.table.column");
    BAD("match = \"any\"\naction = \"mask\"\ncolumns = [\".b\"]\n", "schema.table.column");
    BAD("match = \"any\"\naction = \"mask\"\ncolumns = [\"a..b\"]\n", "schema.table.column");
    BAD("match = \"any\"\naction = \"mask\"\ncolumns = [\"a.\"]\n", "schema.table.column");
    BAD("match = \"any\"\naction = \"mask\"\ncolumns = [\"a\"]\nhow = \"null\"\nhow = \"hash\"\n",
        "twice");
#undef BAD
    CHECK(parse(&p,
                "[[rule]]\nname = \"q\"\nmatch = \"any\"\naction = \"mask\"\n"
                "columns = [\"email\", \"users.email\", \"public.users.email\"]\n",
                err, sizeof err) == 0 &&
          p.rules[0].nmask_columns == 3);
    sl_policy_free(&p);
    {
        char text[8192] = "";
        size_t n = 0;

        for (int i = 0; i <= SL_MASK_MAX_RULES; i++) {
            n += (size_t)snprintf(text + n, sizeof text - n,
                                  "[[rule]]\nname = \"m%d\"\nmatch = \"any\"\naction = \"mask\"\n"
                                  "columns = [\"c\"]\n",
                                  i);
            if (i == SL_MASK_MAX_RULES - 1) {
                CHECK(parse(&p, text, err, sizeof err) == 0);
                sl_policy_free(&p);
            }
        }
        CHECK(parse(&p, text, err, sizeof err) == -1 && strstr(err, "at most") != NULL);
    }
}

static void test_confirm_via(void)
{
    sl_policy p;
    char err[256];

    CHECK(parse(&p,
                "[[rule]]\nname = \"a\"\nmatch = \"delete\"\naction = \"confirm\"\n"
                "confirm_via = \"operator\"\n"
                "[[rule]]\nname = \"b\"\nmatch = \"update\"\naction = \"confirm\"\n"
                "confirm_via = \"session\"\n"
                "[[rule]]\nname = \"c\"\nmatch = \"truncate\"\naction = \"confirm\"\n",
                err, sizeof err) == 0);
    CHECK(p.rules[0].via == SL_VIA_OPERATOR && p.rules[1].via == SL_VIA_SESSION &&
          p.rules[2].via == SL_VIA_DEFAULT);
    sl_policy_free(&p);
    CHECK(parse(&p,
                "[[rule]]\nname = \"a\"\nmatch = \"delete\"\naction = \"confirm\"\n"
                "confirm_via = \"slack\"\n",
                err, sizeof err) == -1 &&
          strstr(err, "\"operator\"") != NULL);
    /* only a confirmation is asked */
    CHECK(parse(&p, "[[rule]]\nname = \"a\"\nmatch = \"delete\"\nconfirm_via = \"session\"\n", err,
                sizeof err) == -1 &&
          strstr(err, "confirm_via") != NULL);
    CHECK(parse(&p,
                "[[rule]]\nname = \"a\"\nmatch = \"delete\"\naction = \"limit\"\nmax_rows = "
                "\"5\"\nconfirm_via = \"session\"\n",
                err, sizeof err) == -1);
    CHECK(parse(&p,
                "[[rule]]\nname = \"a\"\nmatch = \"delete\"\naction = \"confirm\"\n"
                "confirm_via = \"session\"\nconfirm_via = \"operator\"\n",
                err, sizeof err) == -1);
}

static void test_budgets(void)
{
    sl_policy p;
    char err[256];
    sl_limits lim;

    CHECK(parse(&p,
                "[[rule]]\nname = \"agent-reads\"\nmatch = \"any\"\naction = \"limit\"\n"
                "users = [\"agent\"]\nbudget_rows = \"100000\"\nbudget_bytes = \"50MB\"\n"
                "window = \"1h\"\n"
                "[[rule]]\nname = \"everyone-writes\"\nmatch = \"any\"\naction = \"limit\"\n"
                "budget_changed = \"1000\"\nwindow = \"7d\"\n"
                "[[rule]]\nname = \"default-window\"\nmatch = \"any\"\naction = \"limit\"\n"
                "except_users = [\"agent\"]\nbudget_rows = \"5\"\n",
                err, sizeof err) == 0);
    sl_policy_limits(&p, "agent", 5, "db", 2, &lim);
    CHECK(lim.nbudgets == 2);
    CHECK(strcmp(lim.budgets[0].rule, "agent-reads") == 0 && lim.budgets[0].rows == 100000 &&
          lim.budgets[0].bytes == 50ull << 20 && lim.budgets[0].window_s == 3600 &&
          lim.budgets[0].changed == 0);
    CHECK(strcmp(lim.budgets[1].rule, "everyone-writes") == 0 && lim.budgets[1].changed == 1000 &&
          lim.budgets[1].window_s == 7 * 86400);
    sl_policy_limits(&p, "app", 3, "db", 2, &lim);
    CHECK(lim.nbudgets == 2 && strcmp(lim.budgets[1].rule, "default-window") == 0 &&
          lim.budgets[1].window_s == 3600); /* no window: an hour */
    /* a budget does not decide a statement, and is no per-result limit */
    CHECK(lim.result_rows == 0 && lim.total_bytes == 0);
    sl_policy_free(&p);

    CHECK(parse(&p,
                "[[rule]]\nname = \"a\"\nmatch = \"any\"\naction = \"limit\"\nwindow = \"1h\"\n",
                err, sizeof err) == -1);
    CHECK(parse(&p,
                "[[rule]]\nname = \"a\"\nmatch = \"any\"\naction = \"limit\"\nbudget_rows = "
                "\"0\"\n",
                err, sizeof err) == -1);
    CHECK(parse(&p,
                "[[rule]]\nname = \"a\"\nmatch = \"any\"\naction = \"limit\"\nbudget_rows = "
                "\"5\"\nwindow = \"30s\"\n",
                err, sizeof err) == -1 &&
          strstr(err, "window") != NULL);
    CHECK(parse(&p,
                "[[rule]]\nname = \"a\"\nmatch = \"any\"\naction = \"limit\"\nbudget_rows = "
                "\"5\"\nwindow = \"8d\"\n",
                err, sizeof err) == -1);
    CHECK(parse(&p,
                "[[rule]]\nname = \"a\"\nmatch = \"any\"\naction = \"limit\"\nbudget_rows = "
                "\"5\"\nwindow = \"1week\"\n",
                err, sizeof err) == -1);
    /* about the user, not about a table or a kind of statement */
    CHECK(parse(&p,
                "[[rule]]\nname = \"a\"\nmatch = \"delete\"\naction = \"limit\"\nbudget_rows = "
                "\"5\"\n",
                err, sizeof err) == -1);
    CHECK(parse(&p,
                "[[rule]]\nname = \"a\"\nmatch = \"any\"\naction = \"deny\"\nbudget_rows = \"5\"\n",
                err, sizeof err) == -1);
    CHECK(parse(&p,
                "[[rule]]\nname = \"a\"\nmatch = \"any\"\naction = \"limit\"\nbudget_rows = "
                "\"5\"\ntables = [\"t\"]\n",
                err, sizeof err) == -1);
    /* a limit and a budget in one rule would mix two things */
    CHECK(parse(&p,
                "[[rule]]\nname = \"a\"\nmatch = \"any\"\naction = \"limit\"\nbudget_rows = "
                "\"5\"\nmax_rows = \"5\"\n",
                err, sizeof err) == -1);
    /* a connection keeps room for so many */
    {
        char text[4096] = "";
        size_t n = 0;

        for (int i = 0; i <= SL_MAX_BUDGETS; i++) {
            n += (size_t)snprintf(text + n, sizeof text - n,
                                  "[[rule]]\nname = \"r%d\"\nmatch = \"any\"\naction = \"limit\"\n"
                                  "budget_rows = \"5\"\n",
                                  i);
            if (i == SL_MAX_BUDGETS - 1) {
                CHECK(parse(&p, text, err, sizeof err) == 0);
                sl_policy_free(&p);
            }
        }
        CHECK(parse(&p, text, err, sizeof err) == -1 && strstr(err, "at most") != NULL);
    }
}

static void test_connection_limits(void)
{
    sl_policy p;
    char err[256];
    sl_limits lim;

    CHECK(parse(&p,
                "[[rule]]\nname = \"a\"\nmatch = \"any\"\naction = \"limit\"\n"
                "max_result_rows = \"1000\"\nmax_result_bytes = \"10MB\"\nmax_duration = \"30s\"\n"
                "[[rule]]\nname = \"b\"\nmatch = \"any\"\naction = \"limit\"\nusers = [\"agent\"]\n"
                "max_result_rows = \"50\"\nmax_total_bytes = \"1G\"\n"
                "[[rule]]\nname = \"c\"\nmatch = \"any\"\naction = \"limit\"\nexcept_users = "
                "[\"agent\"]\n"
                "max_duration = \"5m\"\n"
                "[[rule]]\nname = \"d\"\nmatch = \"ddl\"\n",
                err, sizeof err) == 0);
    CHECK(p.rules[0].conn_limit && p.rules[0].max_result_rows == 1000 &&
          p.rules[0].max_result_bytes == 10ull << 20 && p.rules[0].max_duration_s == 30);
    sl_policy_limits(&p, "agent", 5, "db", 2, &lim);
    CHECK(lim.result_rows == 50 && strcmp(lim.rule_rows, "b") == 0); /* the smallest */
    CHECK(lim.result_bytes == 10ull << 20 && lim.total_bytes == 1ull << 30);
    CHECK(lim.duration_s == 30 &&
          strcmp(lim.rule_duration, "a") == 0); /* c does not apply to agent */
    sl_policy_free(&p);
    CHECK(parse(&p,
                "[[rule]]\nname = \"i\"\nmatch = \"any\"\naction = "
                "\"limit\"\nmax_idle_in_transaction = \"2m\"\n"
                "[[rule]]\nname = \"n\"\nmatch = \"any\"\naction = \"limit\"\nusers = "
                "[\"agent\"]\nmax_connections = \"3\"\n"
                "[[rule]]\nname = \"n2\"\nmatch = \"any\"\naction = \"limit\"\nmax_connections = "
                "\"5\"\n"
                "[[rule]]\nname = \"i2\"\nmatch = \"any\"\naction = "
                "\"limit\"\nmax_idle_in_transaction = \"30s\"\n",
                err, sizeof err) == 0);
    sl_policy_limits(&p, "agent", 5, "db", 2, &lim);
    CHECK(lim.idle_in_transaction_s == 30 && strcmp(lim.rule_idle, "i2") == 0);
    CHECK(lim.connections == 3 && strcmp(lim.rule_connections, "n") == 0);
    sl_policy_limits(&p, "app", 3, "db", 2, &lim);
    CHECK(lim.connections == 5 && lim.idle_in_transaction_s == 30);
    sl_policy_free(&p);
    CHECK(parse(&p,
                "[[rule]]\nname = \"a\"\nmatch = \"any\"\naction = \"limit\"\n"
                "max_result_rows = \"1000\"\nmax_result_bytes = \"10MB\"\nmax_duration = \"30s\"\n"
                "[[rule]]\nname = \"b\"\nmatch = \"any\"\naction = \"limit\"\nusers = [\"agent\"]\n"
                "max_result_rows = \"50\"\nmax_total_bytes = \"1G\"\n"
                "[[rule]]\nname = \"c\"\nmatch = \"any\"\naction = \"limit\"\nexcept_users = "
                "[\"agent\"]\n"
                "max_duration = \"5m\"\n"
                "[[rule]]\nname = \"d\"\nmatch = \"ddl\"\n",
                err, sizeof err) == 0);
    sl_policy_limits(&p, "app", 3, "db", 2, &lim);
    CHECK(lim.result_rows == 1000 && lim.total_bytes == 0 && lim.duration_s == 30);
    /* these rules are not about statements: they never decide one */
    {
        sl_sql_info info;
        sl_verdict v;
        const char *sql = "drop table t";

        CHECK(sl_sql_classify(sql, strlen(sql), &info, err, sizeof err) == 0);
        v = sl_policy_evaluate(&p, &info, "agent", 5, "db", 2);
        CHECK(v.deny == 1 && strcmp(v.rule->name, "d") == 0);
        sl_sql_info_free(&info);
        sql = "delete from t where id = 1";
        CHECK(sl_sql_classify(sql, strlen(sql), &info, err, sizeof err) == 0);
        v = sl_policy_evaluate(&p, &info, "agent", 5, "db", 2);
        CHECK(v.deny == 0 && v.confirm == 0 && v.rule == NULL);
        sl_sql_info_free(&info);
    }
    sl_policy_free(&p);

    {
        static const struct {
            const char *body;
            const char *fragment;
        } bad[] = {
            {"match = \"any\"\naction = \"deny\"\nmax_result_rows = \"5\"\n",
             "only go with action"},
            {"match = \"ddl\"\naction = \"limit\"\nmax_result_rows = \"5\"\n", "match = \"any\""},
            {"match = \"any\"\naction = \"limit\"\nmax_result_rows = \"5\"\ntables = [\"t\"]\n",
             "no tables"},
            {"match = \"any\"\naction = \"limit\"\nmax_result_rows = \"5\"\nmax_rows = \"5\"\n",
             "use two rules"},
            {"match = \"any\"\naction = \"limit\"\nmax_result_rows = \"0\"\n", "max_result_rows"},
            {"match = \"any\"\naction = \"limit\"\nmax_result_bytes = \"10XB\"\n", "a size"},
            {"match = \"any\"\naction = \"limit\"\nmax_duration = \"0s\"\n", "max_duration"},
            {"match = \"any\"\naction = \"limit\"\nmax_duration = \"2d\"\n", "max_duration"},
            {"match = \"any\"\naction = \"limit\"\n", "needs max_rows"},
            {"match = \"any\"\naction = \"limit\"\nmax_idle_in_transaction = \"0s\"\n",
             "max_idle_in_transaction"},
            {"match = \"any\"\naction = \"limit\"\nmax_connections = \"0\"\n", "max_connections"},
            {"match = \"any\"\naction = \"limit\"\nmax_connections = 3\n", "max_connections"},
            {"match = \"any\"\naction = \"deny\"\nmax_connections = \"3\"\n",
             "only go with action"},
        };

        for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            char text[400];

            snprintf(text, sizeof text, "[[rule]]\nname = \"x\"\n%s", bad[i].body);
            CHECK(parse(&p, text, err, sizeof err) == -1);
            if (strstr(err, bad[i].fragment) == NULL) {
                fprintf(stderr, "test_policy.c: %s: %s\n", bad[i].body, err);
                sl_test_failures++;
            }
        }
    }
}

int main(void)
{
    test_tables_parse();
    test_tables_evaluation();
    test_valid();
    test_refused();
    test_load();
    test_evaluation();
    test_spelling_and_files();
    test_confirm_rules();
    test_calls_alerts_and_kills();
    test_time_and_dry_run();
    test_multiline_and_shapes();
    test_limit_rules();
    test_connection_limits();
    test_confirm_via();
    test_masks();
    test_journal_key();
    test_budgets();
    test_except_users();
    return TEST_RESULT();
}
