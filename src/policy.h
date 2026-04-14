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

#include "journal.h"
#include "mask.h"
#include "sql_check.h"

typedef enum { SL_MODE_AUDIT, SL_MODE_ENFORCE } sl_mode;

/* A weekly window of time, in UTC: the days (bit 0 Monday ... bit 6 Sunday) and the minutes of the
 * day from, to to (to may be 1440; a window with to <= from runs past midnight into the next day).
 */
#define SL_MAX_WINDOWS 8
typedef struct {
    uint8_t days;
    uint16_t from, to;
} sl_window;

/* The time the rules use: the clock, or when `unix` is not -1 that moment (for tests and for
 * `sluice --check-policy --at`). */
void sl_policy_set_time(long long unix);
/* "2026-12-01", "2026-12-01T18:30Z" or "...T18:30:15Z", in UTC, as unix seconds. 0, or -1. */
int sl_policy_parse_instant(const char *s, long long *out);

/* Where a confirmation is asked (confirm_via). */
enum { SL_VIA_DEFAULT = 0, SL_VIA_SESSION = 1, SL_VIA_OPERATOR = 2 };

typedef struct {
    char *name;
    uint32_t match; /* one SL_SQL_* flag; 0 with any set */
    int any;        /* match = "any" */
    int deny;       /* 1 for "deny" (and "kill"), 0 for "allow" or "confirm" */
    int alert;      /* action = "alert": the statement runs and the log says that it did */
    int dry_run;    /* dry_run = true: the rule only says what it would have done */
    int kill;       /* action = "kill": refused, and the connection is closed */
    int confirm; /* 1 for "confirm": a DELETE or UPDATE is run, looked at, and confirmed by a person
                  */
    unsigned long long over_rows; /* confirm: only when more rows than this were touched */
    /* action = "limit" about a whole connection rather than a statement: what one result, or one
     * connection, may carry out, and how long a statement may run. 0: no limit of that kind. */
    int conn_limit;
    unsigned long long max_result_rows;
    unsigned long long max_result_bytes;
    unsigned long long max_total_bytes;
    unsigned max_duration_s;
    unsigned max_idle_in_transaction_s; /* a connection left in an open transaction this long is
                                           closed */
    unsigned long long max_connections; /* at once, for the users the rule is about */
    /* action = "limit" with a budget: how much one user may carry out, or change, in a sliding
     * window of time, whatever the number of connections (budget.h). 0: no budget of that kind. */
    int budget;
    unsigned long long budget_rows;       /* rows sent to the client */
    unsigned long long budget_bytes;      /* bytes of those rows */
    unsigned long long budget_changed;    /* rows changed by INSERT, UPDATE, DELETE and MERGE */
    unsigned long long budget_statements; /* round trips to the server */
    unsigned max_transaction_s;           /* a transaction open this long ends the connection */
    unsigned window_s;                    /* the window of the budgets of this rule */
    /* action = "mask": hide values in the rows this user gets (mask.h). */
    int mask;
    char **mask_columns; /* output names of the columns to hide, whatever they hold */
    size_t nmask_columns;
    unsigned mask_detect; /* SL_MASK_* patterns to look for in any text */
    int mask_how;         /* SL_MASK_HASH, ... */
    int limit;   /* action = "limit": a DELETE or UPDATE that touches more than max_rows rows is
                    undone, with no one to ask (it is also `confirm` for the rest of the machinery) */
    int journal; /* confirm and limit, for a DELETE: SL_JOURNAL_* (docs/policy.md, "Undoing a
                    DELETE") */
    int via; /* confirm: who is asked: SL_VIA_DEFAULT (what the operator chose), SL_VIA_SESSION (the
                person who sent the statement) or SL_VIA_OPERATOR (the terminal or command of the
                proxy) */
    int no_side_effects; /* confirm: do not look at what else the statement changed (cascades,
                            triggers) before asking */
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
    char **functions; /* applies when the statement calls one of them (name, schema.name, name*) */
    size_t nfunctions;
    char **fingerprints; /* applies when the statement has one of these shapes */
    size_t nfingerprints;
    char **outside_fingerprints; /* applies when it has none of these shapes: one not seen before */
    size_t noutside_fingerprints;
    /* when the rule applies (UTC): in these windows, outside these windows, from and until */
    sl_window during[SL_MAX_WINDOWS];
    size_t nduring;
    sl_window except_during[SL_MAX_WINDOWS];
    size_t nexcept_during;
    long long valid_from; /* unix seconds; 0: no limit */
    long long valid_until;
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
    int confirm;          /* no statement is denied, and one needs a person's confirmation */
    const sl_rule *rule;  /* the rule that denied or asked to confirm, NULL when allowed */
    const sl_rule *alert; /* the first "alert" rule that matched, whatever else was decided */
    const sl_rule *dry;   /* the first "dry_run" rule that matched: it decided nothing */
    int kill;             /* the denial closes the connection (action = "kill") */
} sl_verdict;

/* What a connection of this user on this database may do: for each kind of limit, the smallest that
 * a rule gives (0: none), and the rule that gives it. */
#define SL_MAX_BUDGETS 8 /* budget rules in a policy: a connection holds the counters of each */

typedef struct {
    char rule[72];
    unsigned window_s;
    unsigned long long rows, bytes, changed, statements;
} sl_budget_spec;

typedef struct {
    unsigned long long result_rows;
    unsigned long long result_bytes;
    unsigned long long total_bytes;
    unsigned duration_s;
    unsigned idle_in_transaction_s;
    unsigned transaction_s;
    unsigned long long connections;
    /* the names of the rules that gave each limit, copied: the policy may be replaced (reloaded)
     * while the connection lives */
    char rule_idle[72];
    char rule_transaction[72];
    char rule_connections[72];
    char rule_rows[72];
    char rule_bytes[72];
    char rule_total[72];
    char rule_duration[72];
    sl_budget_spec budgets[SL_MAX_BUDGETS]; /* the budget rules that apply to this user */
    size_t nbudgets;
} sl_limits;

void sl_policy_limits(const sl_policy *p, const char *user, size_t user_len, const char *database,
                      size_t database_len, sl_limits *out);

/* The mask rules that apply to this user on this database, in file order, as views into the policy
 * (valid until it is freed: sl_mask_new copies them). Returns how many. */
/* Does some rule keep a journal of the rows it deletes? */
int sl_policy_needs_journal(const sl_policy *p);

size_t sl_policy_masks(const sl_policy *p, const char *user, size_t user_len, const char *database,
                       size_t database_len, sl_mask_rule_view out[SL_MASK_MAX_RULES]);

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

/* What a rule would do, as a word: "deny", "kill", "confirm", "limit". */
const char *sl_rule_would(const sl_rule *r);

#endif
