#ifndef SLUICE_POLICY_H
#define SLUICE_POLICY_H

/* The rules sluice applies to statements.
 *
 * The file is a strict subset of TOML. Anything outside the subset is an error that names the line,
 * and so is any key or value sluice does not know: a typo must never silently weaken a policy.
 *
 *   mode = "audit"            # "audit" (default): log what would be blocked. "enforce": block it.
 *   on_uninspectable = "deny" # "deny" (default) or "allow": what to do, in enforce mode, with SQL
 * that # cannot be understood (syntax error, over 1 MiB, malformed, fast-path call)
 *
 *   [[rule]]
 *   name      = "no-unbounded-write"           # required, unique: letters, digits and _ . : -
 *   match     = "update_or_delete_without_where"   # required, see below
 *   action    = "deny"                         # "deny" (default), "allow" or "confirm"
 *   over_rows = "100"                          # with confirm: only ask when more rows were touched
 *   users     = ["app", "worker"]              # optional: only for these users
 *   except_users = ["app"]                    # optional: for everyone but these users (a new user
 * is covered) databases = ["prod"]                       # optional: only on these databases tables
 * = ["ledger", "public.audit"]     # optional: only statements that touch one of these tables
 * outside_tables = ["orders", "products"]    # optional: only statements that touch a table NOT in
 * this list message   = "use a WHERE clause"           # optional text added to the error the
 * client gets
 *
 *   confirm_timeout = "2m"    # how long a person has to answer a confirmation (default 2 minutes)
 *
 * match: update_or_delete_without_where, delete, update, ddl, drop, truncate, not_read_only,
 * procedural, multi_statement, or any (every statement). See sql_check.h for what each means.
 *
 * action = "confirm" (see docs/design.md, section 20): the DELETE or UPDATE is run inside a
 * transaction that is not committed, and a person is shown what it did before it becomes final. A
 * "deny" elsewhere in the same message wins over a "confirm"; rules are otherwise as for "allow"
 * and "deny" (the first that applies to a statement decides).
 *
 * Evaluation: every statement of a message is judged on its own, against the rules in file order.
 * The first rule that applies to it (its match flag is set, the user, database and tables fit)
 * decides: "deny" blocks the message, "allow" lets that statement through. No rule applies:
 * allowed. A message is blocked as soon as one of its statements is denied.
 *
 * Tables. A name is "table" (in any schema) or "schema.table". A table written without a schema in
 * the SQL could be in any schema (the client chooses its search_path), so against an entry with a
 * schema the answer is "unknown", which is treated like a table sluice cannot see (see below).
 * Names are compared as the parser gives them: lower case unless they were quoted.
 *
 * When the tables of a statement cannot be known (MERGE, GRANT ON ALL TABLES, DO...: see
 * sql_check.h) a "deny" rule with a table condition assumes the worst and applies, and an "allow"
 * rule with a table condition assumes nothing and does not. A statement that touches no table at
 * all never satisfies outside_tables.
 *
 * Supported syntax: comments (#), [[rule]], key = "string" or 'string', and key = ["a", "b"] on one
 * line. */

#include <stddef.h>
#include <stdint.h>

#include "sql_check.h"

typedef enum { SL_MODE_AUDIT, SL_MODE_ENFORCE } sl_mode;

typedef struct {
    char *name;
    uint32_t match; /* one SL_SQL_* flag; 0 with any set */
    int any;        /* match = "any" */
    int deny;       /* 1 for "deny", 0 for "allow" or "confirm" */
    int confirm; /* 1 for "confirm": a DELETE or UPDATE is run, looked at, and confirmed by a person
                  */
    unsigned long long over_rows; /* confirm: only when more rows than this were touched */
    char **users;
    size_t nusers;
    char **except_users; /* the rule does not apply to these users, whoever else it applies to */
    size_t nexcept;
    char **databases;
    size_t ndatabases;
    char **tables; /* applies when the statement touches one of them */
    size_t ntables;
    char **outside_tables; /* applies when the statement touches a table that is not in the list */
    size_t noutside;
    char *message; /* NULL when absent */
} sl_rule;

typedef struct {
    sl_mode mode;
    int deny_uninspectable;
    unsigned confirm_timeout_s; /* how long a person has to answer a confirmation */
    sl_rule *rules;
    size_t nrules;
} sl_policy;

/* Parses text (len bytes, no NUL allowed). source names it in error messages ("policy.toml").
 * Returns 0, or -1 with "source:line: message" in err. On failure *p is left empty. */
int sl_policy_parse(sl_policy *p, const char *text, size_t len, const char *source, char *err,
                    size_t errcap);

/* Reads and parses a file (at most 1 MiB). */
int sl_policy_load(sl_policy *p, const char *path, char *err, size_t errcap);

void sl_policy_free(sl_policy *p);

typedef struct {
    int deny;
    int confirm;         /* no statement is denied, and one needs a person's confirmation */
    const sl_rule *rule; /* the rule that denied or asked to confirm, NULL when allowed */
} sl_verdict;

/* Non-zero when some rule talks about tables: only then is it worth asking
 * sl_sql_classify_with_tables for the tables of a statement. */
int sl_policy_needs_tables(const sl_policy *p);

/* Judges the statements of one message. info should come from sl_sql_classify_with_tables when
 * sl_policy_needs_tables says so; without table information a table condition is treated like a
 * statement whose tables are unseen. user and database are the values the client announced in its
 * startup packet (not NUL terminated, may be empty). */
sl_verdict sl_policy_evaluate(const sl_policy *p, const sl_sql_info *info, const char *user,
                              size_t user_len, const char *database, size_t database_len);

/* The text that goes in the error the client receives: "blocked by rule NAME" and the rule's
 * message. */
void sl_policy_reason(const sl_rule *r, char *out, size_t cap);

#endif
