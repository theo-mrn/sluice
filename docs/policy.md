# Policy reference

A policy is a small text file given with `--policy FILE`. Without one, sluice only relays and logs. With
one, every Query and Parse message is judged before it reaches the database.

```bash
sluice --listen 127.0.0.1:5433 --upstream db.internal:5432 --policy policy.toml
```

The policy and the encryption of the database hop (`--upstream-tls`, see the README) are independent:
rules apply the same way with or without TLS.

The file is read at startup. If it cannot be read, or contains anything sluice does not understand,
sluice prints the file and line and exits with status 1. It never starts with a partial or guessed policy.

## Changing the policy while sluice runs

Send `SIGHUP` to sluice (`kill -HUP <pid>`, or `kubectl exec ... kill -HUP 1` in a pod, or a `reload`
of your service manager) and it reads the file again.

- **A valid file replaces the policy at once**, for connections that are already open too: the next message
  of each of them is judged by the new rules. Tightening a policy therefore does not wait for clients to
  reconnect. The log says `policy_reloaded`, with the `mode`, the number of `rules` and `on_uninspectable`.
- **An invalid file changes nothing.** If it is missing, unreadable, or contains anything sluice does not
  understand, the log has a `policy_reload_failed` event with the file, the line and the reason, and the
  policy in force stays in force. Running without rules, or stopping, would both be worse than running on
  the last good ones. At startup it is the opposite on purpose: there is no last good policy then.
- **A policy can be changed, not added or removed.** A sluice started without `--policy` answers
  `policy_reload_ignored` and goes on; one started with a policy keeps having one.
- The options of the command line (`--listen`, `--upstream`, `--upstream-tls`...) are not read again.
- Write the new file in place, or replace it with a rename: both work, the file is opened by its path
  each time.

## Format

A strict subset of [TOML](https://toml.io): comments (`#`), `[[rule]]` tables, `key = "string"` (or
`'literal'`), and one-line lists of strings `["a", "b"]`. Numbers, booleans, inline tables, multi-line
strings and other tables are errors. An unknown key is an error, and so is a key given twice.

## Top level

| Key | Values | Default | Meaning |
|---|---|---|---|
| `mode` | `"audit"`, `"enforce"` | `"audit"` | `audit` logs what the rules would block and changes nothing. `enforce` blocks. |
| `on_uninspectable` | `"deny"`, `"allow"` | `"deny"` | What `enforce` does with a message it cannot read (see below). |
| `confirm_timeout` | `"1s"` to `"1h"` | `"2m"` | How long a person has to answer a confirmation (see "Confirming a DELETE or UPDATE"). |

## Rules

```toml
[[rule]]
name      = "no-unbounded-write"
match     = "update_or_delete_without_where"
action    = "deny"
users     = ["app"]
databases = ["prod"]
message   = "add a WHERE clause"
```

| Key | Required | Meaning |
|---|---|---|
| `name` | yes | Unique. Letters, digits and `_ . : -`, 1 to 64 characters. It is shown in the error and the log. |
| `match` | yes | What the rule is about, from the table below, or `"any"` for every statement. |
| `action` | no | `"deny"` (default), `"allow"`, `"confirm"` (ask a person: see below), `"limit"` (a row cap, with nobody to ask: see below), `"mask"` (hide values in the rows the user gets: see below), `"alert"` (let it through and say so in the log) or `"kill"` (refuse it and close the connection): see [Watching and cutting](#watching-and-cutting-alert-and-kill). |
| `users` | no | The rule only applies to these users (exact, case-sensitive). |
| `except_users` | no | The rule applies to everybody **but** these users (exact, case-sensitive): a role created tomorrow is covered without touching the file. |
| `databases` | no | The rule only applies on these databases. |
| `tables` | no | The rule only applies to statements that touch one of these tables (see [Tables](#tables)). |
| `outside_tables` | no | The rule only applies to statements that touch a table that is **not** in this list. |
| `functions` | no | The rule only applies to statements that call one of these functions (`name`, `schema.name`, or a prefix ending in `*`: `"pg_ls_*"`). See [Roles and dangerous calls](#roles-and-dangerous-calls). |
| `columns`, `detect`, `how` | no | With `mask`: what to hide and how (see [Hiding values](#hiding-values-action--mask)). |
| `journal` | no | With `confirm` or `limit`, `match = "delete"` or `"update"` (PostgreSQL 18): keep the rows for undo, `"on"` or `"required"` (see [Undoing a DELETE](#undoing-a-delete-journal)). |
| `confirm_via` | no | With `confirm`: who is asked, `"session"` or `"operator"` (see [Who is asked](#who-is-asked-confirm_via)). |
| `during`, `except_during`, `valid_from`, `valid_until` | no | When the rule applies, in UTC: only in these weekly windows, never in these, from and until a moment (see [When a rule applies](#when-a-rule-applies)). |
| `fingerprints`, `outside_fingerprints` | no | The rule only applies to statements of these shapes, or of none of these (see [Shapes of statements](#shapes-of-statements-and-learning-them)). |
| `dry_run` | no | `"on"`: the rule says what it **would** have done and decides nothing (see [Trying a rule](#trying-a-rule-dry_run)). |
| `budget_rows`, `budget_bytes`, `budget_changed`, `budget_statements`, `window` | no | With `limit` and `match = "any"`: what a user may take out or change in a window of time (see [Budgets](#budgets-what-one-user-may-take-out-or-change-in-a-window-of-time)). |
| `message` | no | Added to the error the client receives. Printable ASCII, no backslash, 200 characters at most. |

`users` and `databases` are the values the client announced in its startup packet. They are labels, not
proof of identity: the database is still the one that authenticates.

### What a rule can match

| `match` | A statement matches when it is |
|---|---|
| `update_or_delete_without_where` | an `UPDATE` or a `DELETE` with no `WHERE` clause. A `WHERE` inside a sub-select does not count; `WHERE true` does. |
| `delete` | a `DELETE` (also one hidden in a CTE), or a `MERGE` with a `WHEN MATCHED ... THEN DELETE` (or `WHEN NOT MATCHED BY SOURCE`) clause. |
| `update` | an `UPDATE` (likewise), a `MERGE` with a `WHEN MATCHED ... THEN UPDATE` clause, or an `INSERT ... ON CONFLICT DO UPDATE` (an upsert changes rows that are there). A `MERGE` that only inserts, and `ON CONFLICT DO NOTHING`, match neither. |
| `ddl` | anything that changes the schema, the roles or the privileges: `CREATE`, `ALTER`, `DROP`, `TRUNCATE`, `GRANT`, `REVOKE`, `COMMENT`, `ALTER SYSTEM`, `SELECT ... INTO`, `CREATE TABLE AS`. Not `VACUUM`, `ANALYZE`, `REINDEX`, `CLUSTER` or `COPY`. |
| `drop` | any `DROP` (tables, indexes, databases, roles...). `TRUNCATE` is separate. |
| `truncate` | `TRUNCATE`. |
| `not_read_only` | anything that is not on the read-only allowlist below. |
| `procedural` | `DO` and `CALL`: code sluice cannot look into. |
| `multi_statement` | one of several statements sent in a single message (`select 1; select 2`). |
| `set_session` | `SET ROLE`, `SET SESSION AUTHORIZATION` (also `LOCAL`), or a call to `set_config()`. See [Roles and dangerous calls](#roles-and-dangerous-calls). |
| `dangerous` | `COPY` from or to a file of the server or a program, or a call to a function that reads files, runs on another server, sleeps, stops other sessions or takes part in replication (the list is below). |

Statements hidden inside others count as statements of their own: the data-modifying CTE in
`WITH d AS (DELETE FROM t RETURNING *) SELECT ...`, the statement of `EXPLAIN ANALYZE <statement>` (it
really runs), the one of `PREPARE p AS <statement>`, of `DECLARE c CURSOR FOR <query>`, and the query of
`COPY (<query>) TO ...`. `EXPLAIN` without `ANALYZE` does not run anything and is read-only.

**The read-only allowlist.** `SELECT` (without `INTO` and without `FOR UPDATE` / `FOR SHARE`), `SHOW`,
`EXPLAIN` without `ANALYZE`, `EXECUTE`, `DEALLOCATE`, `DISCARD`, `FETCH`, `CLOSE`, transaction control
(`BEGIN`, `COMMIT`, `ROLLBACK`, `SAVEPOINT`, `RELEASE`; not the two-phase `PREPARE TRANSACTION`), and `SET` /
`RESET` of harmless settings: `application_name`, `client_encoding`, `DateStyle`, `IntervalStyle`,
`extra_float_digits`, `TimeZone`, `statement_timeout`, `lock_timeout`, `idle_in_transaction_session_timeout`,
`standard_conforming_strings`, `bytea_output`, `search_path`, `client_min_messages`, transaction
characteristics, and any setting with a dot in its name (`myapp.user_id`). Everything else is not read-only,
including every kind of statement this version does not know.

## When a rule applies

```toml
[[rule]]                       # nobody writes at night or on the week-end
name         = "writes-in-working-hours"
match        = "not_read_only"
users        = ["agent"]
except_during = ["mon-fri 08:00-19:00"]
message      = "writes during working hours only"

[[rule]]                       # the migrator may change the schema, on one evening
name        = "migration-window"
match       = "ddl"
action      = "allow"
users       = ["migrator"]
valid_from  = "2026-12-01T18:00Z"
valid_until = "2026-12-01T20:00Z"
```

- **`during`** (a list): the rule applies only inside one of these windows. **`except_during`**: only outside all of them.
  A window is `"mon-fri 08:00-19:00"`, `"sat,sun 00:00-24:00"` or `"22:00-06:00"` (every day; past midnight, the part after
  midnight belongs to the day that started it). Days are `mon` to `sun`, as a list or a range (`fri-mon` works); hours
  are 24-hour, the end is not included.
- **`valid_from`**, **`valid_until`**: a moment, as `"2026-12-01"` or `"2026-12-01T18:30Z"` (the end is not included). A
  rule that was only needed for an evening stops by itself instead of staying in the file for a year.
- **All of it is UTC.** There is no time zone and no daylight saving: write the hours of your office in UTC.
- The conditions combine with the others of the rule (all must hold). They go with rules about statements, not with limits of
  a connection or `mask`. The time is looked at **when a statement is judged**: a reload is not needed when the hour changes.
- To check a rule at another moment: `sluice --check-policy FILE --at 2026-12-01T18:30Z --sql ...`, or `at` in a test file
  (below).

## Trying a rule: `dry_run`

A new rule that refuses things is easier to trust once it has been seen refusing, without anyone being refused. With
`dry_run = "on"` it is judged like any other, **decides nothing**, and writes a `dry_run` event of its own (rule, what it
would have done: `deny`, `kill`, `confirm` or `limit`, user, database, tables), plus a `dry_run` field in the statement's
event. Read the log for a week, then remove the line.

```toml
[[rule]]
name    = "no-update-without-where"
match   = "update_or_delete_without_where"
dry_run = "on"
```

It goes with a rule that refuses or asks (`deny`, `kill`, `confirm`, a `limit` with `max_rows`), not with `allow`, `alert`,
`mask` or a limit of a connection. `--check-policy` shows `[dry run: rule R would deny]`.

## Policy as code: `--test-policy`

```
sluice --test-policy policy.toml policy.tests
```

`policy.tests` says, a line each, what a statement must get. It is the file to keep next to the policy, and to run in CI:

```
# VERDICT [RULE] [as USER[@DATABASE]] :: SQL        (a comment is a line of its own, or follows `as` and `at`)
as agent                           # who the lines that follow are from
at 2026-11-17T23:30Z               # the moment they are judged at ("at now": the clock)

allow :: select 1
deny no-ddl :: drop table t
deny writes-in-working-hours :: update t set a = 1 where id = 1
kill no-danger as dba :: select pg_read_file('/etc/passwd')
confirm confirm-deletes :: delete from t where id < 100
limit cap :: update t set a = 1 where id < 1000
# an alert rule matched, besides what was decided:
alert honeypot :: select * from internal_secrets
# a rule that is being tried (dry_run) matched:
dry try-ddl :: create table x (a int)
uninspectable :: select (
```

A line that does not get what it says is shown with the line number, what was wanted and what came (`FAIL tests:12 ...`);
the exit status is 1 (0 when all are as wanted, 2 for a wrong command line). The rule's name is optional; when given it
has to be the one that decided. A policy that is not valid is reported and stops the run. `tests/policies/` has one.

## Shapes of statements, and learning them

The log gives each statement a **fingerprint**: 16 hex digits that are the same for the same query whatever its values
(`where id = 1` and `where id = 99` are one shape; `where id = 1 or id = 2` is another). A rule can be about it:

```toml
[[rule]]                       # an application that only ever runs the queries it was seen to run
name                 = "unknown-shapes"
match                = "any"
users                = ["app"]
outside_fingerprints = [
  "3f9a0c61d2b4e7a8",          # 1203x  select * from users where id = $1
  "b7c01e5d9a2f4863",          # 88x    insert into orders (...) values ($1, $2)
]
message              = "this kind of statement has not been seen from this user"
```

`fingerprints` is the same turned round (the rule applies to these shapes), for a shape that is known to be bad.
Lists may run over several lines, with comments between the entries and a comma after the last one.

**`sluice --learn LOG [LOG...] [--user NAME] [--database NAME] [--action deny|confirm|alert]`** reads a log and prints that
rule for you, with the shapes of the statements that went through, how many times, and their normalized text (never the
values, even when the log was written with `--log-sql full`). The way to use it: run a policy in `audit` mode for a while,
learn from the log, read what it printed (a shape in it is a shape you accept), and put it in. With `--action alert` it only
says when something new appears; with `confirm`, the confirmation exists only for a `DELETE`, `UPDATE`, `TRUNCATE` or `DROP`,
so a new `SELECT` under that action is refused.

What it is, and is not: the fingerprint of the whole **message** (a message with two statements has one), computed by the
parser, and it ignores the number of constants in a list (`in (1, 2)` and `in (1, 2, 3)` are the same shape, which is
what a program that builds its lists wants). It is not a security boundary against someone who knows the shapes you accepted
and can write another statement of the same shape. A statement whose shape cannot be had is a new one to `outside_fingerprints`.

## Roles and dangerous calls

Rules are about the **login name**, but a session can change what it is allowed to do without changing that name:
`SET ROLE dba`, `SET SESSION AUTHORIZATION postgres`, `select set_config('role', 'dba', false)`. A rule that
says "the agent may not drop anything" does nothing against an agent that may become a role that can. `match = "set_session"`
catches the three:

```toml
[[rule]]
name    = "no-escalation"
match   = "set_session"
users   = ["agent"]
message = "the role stays what it logged in as"
```

`RESET ROLE` is not matched (it only goes back to the login role). A `SET` of anything else keeps the meaning it had.

`match = "dangerous"` and the `functions` key are about **calls**. `select pg_read_file('/etc/passwd')`,
`select dblink_exec(...)`, `select pg_terminate_backend(pid)` are reads for sluice, and a role that is allowed to run
them can do a lot with them. `dangerous` is, besides `COPY ... PROGRAM` and `COPY` to or from a file of the server:

`pg_read_file`, `pg_read_binary_file`, `pg_stat_file`, `pg_ls_*`, `pg_file_*`, `pg_current_logfile`, `lo_import`,
`lo_export`, `lo_unlink`, `dblink*`, `pg_terminate_backend`, `pg_cancel_backend`, `pg_reload_conf`, `pg_rotate_logfile`,
`pg_switch_wal`, `pg_create_restore_point`, `pg_promote`, `pg_backup_start`, `pg_backup_stop`, `pg_start_backup`,
`pg_stop_backup`, the functions that make, copy or drop a replication slot, `pg_logical_slot_*`,
`pg_logical_emit_message`, `pg_replication_origin_*`, `pg_wal_replay_*`, `pg_sleep*`, and the functions that run the SQL
they are given as text (`query_to_xml*`, `cursor_to_xml*`).

For your own list, `functions` makes any rule depend on the calls of a statement:

```toml
[[rule]]
name      = "no-reports-for-the-app"
match     = "any"
users     = ["app"]
functions = ["monthly_report", "analytics.*", "reporting.rebuild"]
```

How the calls are found: the whole tree of the statement is looked at, so a call in a `RETURNING` list, in the default of a
column, in `DECLARE CURSOR` or in a sub-select counts. Names are compared without regard to case. A call written without a
schema matches whatever schema the entry names (the `search_path` can be changed), a call with one has to agree.
What cannot be seen is what is **inside** a function, a view, a trigger or a `DO` block (use `procedural` for the last).
`set_session` and `dangerous` rules ask sluice to read the calls of every statement, which costs a second parse (the same as
`tables`).

## Watching and cutting: `alert` and `kill`

```toml
[[rule]]            # a table nobody should read: if somebody does, say so
name   = "honeypot"
match  = "any"
action = "alert"
tables = ["internal_secrets", "admin_audit"]

[[rule]]            # and this one ends the session
name   = "no-files"
match  = "dangerous"
action = "kill"
```

- **`alert`** lets the statement through and writes an `alert` event of its own, with the rule, the user, the database and
  the tables, as well as the `alert` field of the statement's event. It does not decide anything: the other rules judge the
  statement as if it was not there, whatever their place in the file. It is for what you want to know about, not stop.
- **`kill`** is `deny` that also ends the connection: the statement is refused with the reason, it is answered, and the
  connection closes; whatever the client had already sent behind it is refused too (`rule X closed this connection`), the
  `statement` event has `kill: true` and `connection_close` says `reason: killed`. In `audit` mode it is only logged.
  It is for the session that has shown what it is.

## Tables

`tables` and `outside_tables` make a rule depend on what a statement touches. Both take a list of
`"table"` or `"schema.table"` (letters, digits, `_`, `$` and `-`). They combine with `match`, `users` and
`databases`: all the conditions of a rule must hold.

```toml
# An agent that may only work with two tables: anything else is refused, whatever it is
[[rule]]
name           = "agent-sales-only"
match          = "any"
users          = ["agent"]
outside_tables = ["orders", "public.products"]
message        = "sales tables only"

# Nobody writes to the ledger
[[rule]]
name   = "no-ledger-write"
match  = "not_read_only"
tables = ["ledger"]
```

- **`tables`**: the rule applies when the statement touches at least one of the tables.
- **`outside_tables`**: the rule applies when the statement touches at least one table that is not in the
  list. A statement that touches no table at all (`select 1`, `begin`, `set application_name = ...`) never
  satisfies it, so an allowlist does not break a driver's own housekeeping.
- **Names**: `"orders"` matches that table in any schema. `"public.products"` matches that schema only. A
  table written **without a schema** in the SQL could be in any schema, because the `search_path` of the
  session decides and a client can change it (`SET search_path = tenant_b`, then `select * from orders`
  reads `tenant_b.orders`). So against an entry that has a schema, sluice does not guess: the answer is
  "unknown", which is treated like tables it cannot see: a `deny` rule applies, an `allow` rule does not.
  In practice: with `outside_tables = ["tenant_a.orders"]`, `select * from tenant_a.orders` goes through and
  `select * from orders` is blocked. Write the schema in the SQL, or leave it out of the rule if any schema
  will do (`"orders"`).
  Names are compared as the parser gives them: lower case unless the SQL quoted them (`"Ledger"` is not
  `ledger`).
  An entry with upper-case letters therefore only matches a table written with double quotes, and sluice
  logs a `warning` (with the rule and the entry) when it loads such a policy, at startup and on reload.
- **Sub-selects, CTEs, joins, `UNION`, `EXPLAIN ANALYZE`, `PREPARE`, `COPY (query)`**: every table in them
  counts, wherever it appears.
- **Several statements in one message**: each statement has its own tables, so `select * from orders;
  select * from secret` is judged as two statements, and the second one is refused.
- **Hidden statements share their tables**: the `DELETE` of a data-modifying CTE is not told apart from the
  statement that holds it, so it counts as touching all of that statement's tables. This errs on the side
  of blocking.

**When sluice cannot know the tables of a statement.** The PostgreSQL parser does not report them all.
`MERGE` leaves out its source table (`MERGE INTO orders USING secret ...` reports only `orders`);
`GRANT ... ON ALL TABLES`, `DROP SCHEMA ... CASCADE`, `VACUUM` without a target, `COMMENT`, `CREATE FUNCTION`
and `CREATE TRIGGER` reach tables without naming them; and `DO` and `CALL` hide everything. For such
statements sluice assumes the worst, so that a rule cannot be walked around:

- a **`deny`** rule with a table condition **applies** to them;
- an **`allow`** rule with a table condition **does not apply** to them.

In practice an allowlist like the one above refuses `MERGE`, `DO`, `CALL` and `VACUUM` for the agent, and a
ledger rule refuses `MERGE` and `GRANT ... ON ALL TABLES` for everyone. That is deliberate. What it cannot do
is look into a function, a view or a trigger: a `select my_function()` is a statement without tables.

## How rules are applied

1. The message is split into its statements (including the hidden ones above).
2. **Each statement is judged on its own.** The rules are read in file order. The first rule that applies
   to the statement (its `match` fits, and so do `users` and `databases`) decides: `deny` blocks, `allow`
   lets this statement through. No rule applies: allowed.
3. The message is blocked as soon as one of its statements is denied, since a message cannot be forwarded
   in part.

That is why order matters, and why an `allow` only covers the statements it matches:

```toml
[[rule]]                       # the migration job may change the schema...
name = "migrations"
match = "ddl"
action = "allow"
users = ["migrator"]

[[rule]]                       # ...nobody else may
name = "no-ddl"
match = "ddl"

[[rule]]                       # and nobody may write without a WHERE, the migration job included
name = "no-unbounded-write"
match = "update_or_delete_without_where"
```

`create table x (i int); delete from t` sent by `migrator` is blocked: the `CREATE` is allowed by the first
rule, the `DELETE` falls through to the third.

## Applications on one side, people and agents on the other

The same database is reached by an application, that must not be slowed down or asked anything, and by
people at a terminal, scripts and agents, that should be. sluice tells them apart by **the database role**
they log in with, because that is what the database itself checks. So the recommendation is one role per use
(`app`, `migrator`, then a role for each person or agent), and rules written the other way round: not "these
users are watched" (a role nobody listed escapes) but "everybody except these".

```toml
mode = "enforce"
confirm_timeout = "2m"

# ---- the application and the migrations are left alone, except for what nobody should do ----
[[rule]]
name         = "nobody-drops-by-mistake"
match        = "drop"
except_users = ["migrator"]
message      = "Dropping goes through a migration."

# ---- everybody else: people, agents, scripts, and any role created later ----
[[rule]]
name         = "no-schema-changes"
match        = "ddl"
except_users = ["app", "migrator"]
message      = "Schema changes go through migrations."

[[rule]]
name         = "no-unbounded-write"
match        = "update_or_delete_without_where"
except_users = ["app", "migrator"]
message      = "Add a WHERE clause."

[[rule]]
name         = "confirm-deletes"
match        = "delete"
action       = "confirm"
over_rows    = "50"
except_users = ["app", "migrator"]
message      = "A person has to confirm this."

[[rule]]
name         = "confirm-updates"
match        = "update"
action       = "confirm"
over_rows    = "50"
except_users = ["app", "migrator"]
```

What this does at the terminal (`psql`, a script, an agent): schema changes and `DELETE`/`UPDATE` without
`WHERE` are refused; a `DELETE` or `UPDATE` that touches up to 50 rows goes through, and more than that asks a
person (see "Confirming a DELETE or UPDATE"). The application keeps working as before, whatever protocol it
speaks (its prepared statements are not affected by the `confirm` rules, which do not apply to it). Rules are
tried in file order and the first that applies decides, so the specific refusals come before the questions.

- **Separate roles are the real protection.** Do not give a person or an agent the role of the application.
  Nothing in sluice can tell two clients of the same role apart.
- **Whoever has the application's password can be the application.** sluice relays the login and keeps no secret of
  its own, so a rule that excludes `app` excludes anybody who connects as `app`. That is accepted (design.md,
  section 4); keep the application's credentials away from people and agents, and give each their own role.
- **The client's `application_name` is not used** to tell them apart, on purpose: it is whatever the client says
  (`PGAPPNAME=app psql ...`), so a rule on it would only stop honest mistakes.
- **Another way is to run two sluice processes**, on two ports, with two policy files: the applications
  connect to the first, the terminals to the second. Useful when the same role is shared, as long as the
  database only accepts connections from sluice.
- **If the roles are the same for everyone**, a rule has nothing to hold on to: say so rather than hope.

## Capping the rows of a DELETE or UPDATE

When nobody is there to ask (an agent that runs unattended, a job), a rule can simply cap what one statement may
touch:

```toml
[[rule]]
name     = "cap-deletes"
match    = "delete"
action   = "limit"
max_rows = "1000"                 # a string, like over_rows
message  = "Delete in smaller batches."
```

sluice runs the statement as for a confirmation (in a transaction, counting the rows it touched). Up to `max_rows`
rows it is committed at once and the client notices nothing. More than that, it is **undone**, and the client gets
an error that says so: `sluice: refused (rule cap-deletes): it touched 3500 rows, more than the limit of 1000.
Delete in smaller batches. Nothing was changed.` It works with simple queries and prepared statements, with the
same limits as a confirmation (one `DELETE` or `UPDATE` per message), and the `confirm` event of the log records
the outcome `limit`. A limit applies to `DELETE` and `UPDATE`; `TRUNCATE` and `DROP` have no rows to count (use
`confirm` or `deny`). The statement does its work before it is undone, so a statement that touches millions of
rows costs that, and holds its locks for that long: a limit is a safety net against a mistake, not a way to make
an expensive statement cheap.

## Limits on what a connection receives, and on how long a statement runs

A rule with `action = "limit"` and `match = "any"` can also be about the **connection** instead of a kind of
statement. This is the guard against data leaving in bulk (an agent that `select`s a whole table) and against
statements that run for ever:

```toml
[[rule]]
name              = "agent-limits"
match             = "any"
action            = "limit"
users             = ["agent"]
max_result_rows   = "10000"     # one result (one statement's answer, or one Execute)
max_result_bytes  = "10MB"      # ... in bytes of data rows ("500K", "10MB", "2G"; 1024 to the K)
max_total_bytes   = "1GB"       # everything the connection receives; spent, it is closed
max_duration      = "30s"       # a statement that runs longer is cancelled ("1s" to "1h")
max_idle_in_transaction = "2m"  # a transaction left open this long is rolled back and the connection closed
max_connections   = "2"         # at most this many connections at once for the users the rule is about
```

Any of the four, in a rule of their own or together (not with `max_rows`, which is about a `DELETE` or `UPDATE`:
use two rules); `users`, `except_users` and `databases` choose who is concerned, `tables` do not make sense here.
When several rules apply to a connection, the smallest of each limit wins.

- **A result over `max_result_rows` or `max_result_bytes`** is cut: the rows up to the limit were sent, the rest is
  **dropped** as it arrives, and the end of the result is an error (SQLSTATE `54000`, "sluice: result limit (rule R):
  more than N rows; the rest was not sent"). The next statement is answered as usual. `COPY ... TO STDOUT` is counted
  too (each piece of data is a row). A statement that returns exactly the limit is not cut.
- **`max_total_bytes`**: when the connection has received that much, the answer that crosses it is cut with a `FATAL`
  error and the connection is closed. It counts the data rows and `COPY` data of everything on the connection.
- **`max_idle_in_transaction`**: an agent that does `BEGIN`, then thinks (or dies) holds locks and a snapshot for as
  long as it likes. When a connection has been in a transaction (`T`, or aborted `E`) and sent nothing for that long,
  it gets a `FATAL` error (`25P03`) and is closed, and the server rolls the transaction back. The time a confirmation
  waits for a person does not count. The session can lift `idle_in_transaction_session_timeout` with a `SET`; it cannot
  lift this.
- **`max_transaction`**: a transaction (`T` or aborted `E`) that has been open this long, **whatever it did in between**, ends
  the connection with `25P03`: the server rolls it back. It is checked between two statements (a statement that is running
  has `max_duration`), so a transaction that keeps issuing queries every second is ended all the same. The counting starts
  at the answer that says the transaction is open.
- **`max_connections`**: an agent that opens fifty connections to go faster is refused from the third on (`53300`, "too
  many connections for this user", with the rule). It counts the connections of the same user that are open through
  this sluice when the new one logs in, so write the rule with `users` for the roles you want to bound (without it,
  the limit applies to each user separately).
- **`max_duration`**: when the server has been working for the client for that long, sluice opens a connection of its
  own to the database and sends the `CancelRequest` with the session's key (the one the server gave at login),
  after a warning to the client. The server stops the statement and answers with its own error (`57014`,
  "canceling statement due to user request"), which the client sees. The time does not count while a confirmation
  waits for a person. It is the way to enforce a time that the client cannot lift: `statement_timeout` can be
  changed by the session with a `SET`, this cannot.

What these do not do, said plainly:

- The server **keeps producing** the rows that are dropped (it does not know): a limit on results protects what
  leaves, not the work. Combine it with `max_duration` for that.
- `max_result_rows` counts one answer. A client that reads a cursor or a portal a thousand rows at a time makes many
  small answers: `max_total_bytes` is what bounds the whole. And a client that **opens another
  connection** starts again from zero: the totals are per connection. A [budget](#budgets-what-one-user-may-take-out-or-change-in-a-window-of-time)
  is per user and per window, whatever the connections.
- The limits are read when the connection starts: a reload of the policy applies to the connections that open after it.
- The cancel is a request: a statement that is in a state where the server does not look for it (some extensions, a
  lock wait is fine) may take a moment. It is sent in clear text, as the cancel of any client is.
- A client's own `RETURNING` that is held for a confirmation is given back whole when it is confirmed: results are
  not cut there.

## Budgets: what one user may take out or change in a window of time

The limits above are about one result or one connection, so an agent that opens a new connection for each query,
or asks for 10,000 rows a hundred times, is not stopped by them. A **budget** is counted per rule and per **user**,
across all connections, over a sliding window:

```toml
[[rule]]
name           = "agent-budget"
match          = "any"
action         = "limit"
users          = ["agent"]
budget_rows    = "100000"       # rows sent to the client in the window
budget_bytes   = "200MB"        # ... in bytes of data rows
budget_changed = "5000"         # rows changed by INSERT, UPDATE, DELETE and MERGE in the window
window         = "1h"           # from "1m" to "7d" (default "1h")
```

Any of the three, alone or together; `users`, `except_users` and `databases` choose whose use is counted (each user
has their own count). It is a `limit` rule about the connection, so `match = "any"` and no `tables`. At most 8 rules
may carry a budget.

- **`budget_rows` and `budget_bytes`** are enforced on the stream, like `max_result_rows`: the rows that would go
  past the budget are dropped, the end of the result is an error (SQLSTATE `53400`, "sluice: budget (rule R): N rows in
  1h are used up; the rest was not sent, more is possible in about Ts"), and the next statement that returns rows
  starts the same way until the window frees some. A statement that returns no row is not affected.
- **`budget_changed`** is counted from what the database says (the number in the tag of `INSERT 0 n`, `UPDATE n`,
  `DELETE n`, `MERGE n`) and from the rows of a confirmed `DELETE` or `UPDATE`. Once the budget is used up, every
  statement that can write is refused ("sluice: budget of changed rows used up (rule R: N rows in 1h); writes are
  possible again in about Ts") until the window frees some. Reads keep working.
- **`budget_statements`** counts **round trips**: each answer the server ends with a ReadyForQuery, which is one per
  `Query` and one per `Sync` (the cycle of a prepared statement). It is what a loop is made of, whatever it asks: an agent
  that runs ten thousand small `SELECT`s passes every budget of rows. When it runs out the connection is **ended with
  the answer that spent it** (`connection_close` says `statement_budget`), because a statement that was prepared before can
  be executed again without a new `Parse` and could not be refused one at a time; the next statement of that user, on any
  connection, is refused ("sluice: budget of round trips used up (rule R: N in 1h); statements are possible again in
  about Ts"). Statements run for a confirmation are not counted.
- The window slides in twelve slices (a slice is forgotten as a whole when it leaves the window, so the count is
  exact to within a twelfth of the window). The time to wait that the message gives is worked out from them.
- The count is kept in memory, per rule and user: it is **lost when sluice restarts**, and is not shared between two
  sluices. The budgets of a user are held while a connection of theirs is open and are forgotten once the window is
  empty.

What a budget does not do, said plainly:

- `budget_changed` is checked **before** a statement, not during it: a single `UPDATE` can go well past the budget.
  Put a `max_rows` rule (above) next to it to bound one statement. The check is made when a statement is **sent or
  prepared**: a statement that was prepared before the budget ran out is not stopped when it is executed later.
- A statement that cannot be inspected counts as a write once the budget of changed rows is used up.
- Budgets apply in `audit` mode too, like the other limits of a connection.
- The rules are read when the connection starts (the budgets of an open connection do not change on a reload).

## Hiding values: `action = "mask"`

An agent that reads a table reads what is in it. A `mask` rule hides values in the **rows that go to the client**,
so that personal data stays out of what the agent reads, and out of the transcripts, logs and prompts that follow:

```toml
[[rule]]
name    = "pii"
match   = "any"
action  = "mask"
users   = ["agent"]
columns = ["email", "phone", "ssn"]      # by the name the client sees for the column
detect  = ["email", "card", "iban"]      # by the look of the value, in any text, whatever the column is called
how     = "hash"                         # hash (default) | partial | null | redact
```

Two ways to find what to hide, which complement each other:

- **`columns`**: the *output name* of the column, compared without regard to case (`select email as e` is a column
  called `e`: this is why the patterns exist). The whole value is replaced.
  A name may be qualified, `users.email` or `public.users.email`: it then hides the column only when the rows come
  from that table (below).
- **`detect`**: an **e-mail address**, a **payment card number** (13 to 19 digits that pass the Luhn check, in groups
  separated by a space or a hyphen) or an **IBAN** (two capitals, two check digits, up to 30 more characters, check
  digits right), found *inside* any value of type `text`, `varchar`, `bpchar`, `name`, `"char"`, `json`, `jsonb` or `xml`.
  Only the part found is replaced. The scans are written by hand and linear: no regular expression, so no value makes
  them slow. A number of 13 to 19 digits that is not a card passes the check about one time in ten: such a value in
  free text may be hidden by mistake.

Four ways to hide (`how`):

| `how` | A value becomes | Notes |
|---|---|---|
| `hash` | `~` and 16 hexadecimal digits: an HMAC-SHA256 of the value, cut | The same value gives the same token, so counts, `GROUP BY` and joins on that column still work. Needs a key: `--mask-key-file` (16 to 1024 bytes of anything secret) makes the tokens the same from one run to the next; without it a key is made at startup, the tokens change when sluice restarts, and sluice says so in its log. |
| `partial` | `a***@e***.com`, `****1111`, `FR****0189`, or the first and last character | Keeps enough to be recognised. By design this tells more than the others. |
| `null` | NULL | Inside a text there is no NULL to give: a pattern found in a text becomes `[masked]`. |
| `redact` | `[masked]` | |

**Types.** A column picked by name is replaced by text only when the client expects text (the five types above, in
text or binary format: the same bytes). Any other type (a number, a `uuid`, `citext`, an enum, an array) becomes
**NULL**, whatever `how` says. NULLs and empty strings are left as they are. Patterns are not looked for in other types
(a card number stored in a `bigint`, in a `text[]` or in a composite is not found).

**Several rules.** All the `mask` rules that apply to a user (`users`, `except_users`, `databases` work as for any rule)
are in force together, at most 8: a column takes the `how` of the first rule that names it, and a pattern the `how` of
the first rule that looks for it. A mask rule never decides about a statement and takes no `tables`: it is about what the
user *gets*, so write `match = "any"`.

**Where it applies**, besides the rows of ordinary results:

- the **error and notice messages** of the server, which quote values: the patterns are looked for in the message,
  hint and context, the values of `Key (email)=(a@b.com) already exists.` are hidden when a column of `columns` is among
  the key's, and the whole `Failing row contains (...)` when any column is listed;
- the **rows shown to the person asked** in a confirmation, and the client's own `RETURNING` given back after a yes;
- both protocols. In the extended protocol sluice puts a `Describe` of the portal in front of each `Execute` to learn
  the columns, whether or not the client described, and the client never sees its answer. That costs a few bytes per
  statement. A client with more than 1024 messages in flight with no Sync is cut off rather than let through unmasked.

**What is refused rather than risked**, with an error that says why: `COPY ... TO STDOUT` (no way to tell where a value
starts); a row over 1 MiB (it cannot be held to be read); a row that does not match its description; a fast-path
function call; an `Execute` of a portal whose name is too long to follow. If sluice can no longer follow the session
(a frame that cannot be read), the connection is closed with an error: masking is never silently dropped.

**This is a guard-rail, not a security boundary.** Say it to whoever asks:

- A client that can run SQL can compute around it: `select md5(email)`, `select split_part(email, '@', 2)`,
  `select left(email, 3)`, a comparison in a `WHERE` clause (`where email = 'a@b.com'` is an oracle), a `LIKE` on a
  prefix. Those are values the rules did not describe, and a card number split in two columns is not a card number.
  The boundary is the privileges of the database: `GRANT SELECT (id, name) ON users TO agent`, row-level security,
  views. Use a mask for what privileges cannot say, and as a second line.
- Names are *output* names: `users.email` is not a thing here, and an alias hides the name (the patterns still find
  an address, a card or an IBAN, not a Social Security number under a new name).
- `LISTEN`/`NOTIFY` payloads, `ParameterStatus` values and the text of statements in `pg_stat_activity` are not looked
  into, except that `pg_stat_activity.query` is a `text` column and so is scanned for patterns like any other.
- `hash` tokens are the same for the same value: whoever sees many of them can count and correlate. With a short or
  guessable value (a four-digit code) and **the key**, they can be reversed; keep the key file private.
- The rules are read when the connection starts: a reload of the policy applies to the connections that open after it.
- The log keeps what a client *sends* (`--log-sql`), not what it receives: no value of a row is ever logged. The
  `connection_close` event says how many values were hidden (`masked`).

### Qualified names: `table.column`

```toml
columns = ["email", "users.email", "public.users.email"]   # any email | the table users | that table in that schema
```

The RowDescription says which table each column comes from (an OID, not a name), so a connection that has a qualified
name asks the server **once, right after the login**, for the OIDs and names of its tables (a query of its own on
`pg_class`, whose answer the client never sees; it shows once in the server's own log and statistics). From then on
`users.email` hides `email` when the rows come from `users`, and not when the server said they come from another table.

It is wrong on the side of hiding, never the other: the column is hidden **as if the name were not qualified** when

- the column comes from no table (a computed value, a function's result), or a table made **after** the login (the list was
  read once; a table dropped and made again has a new OID: it is hidden until the client reconnects);
- the list could not be had (the user may not read the catalog; the `mask_catalog` event says so), was cut at 20,000
  tables, or the client spoke before sluice could ask (it is asked once, at the start, and only when nothing is in flight).

A **view is a table of its own**: `select email from v_users` is not `users.email`; write `v_users.email` as well, or leave
the name unqualified. A name with a dot in the name of a column itself cannot be written (the dot separates the parts).
The schema, when given, is compared as the server names it; without it, a table of that name in any schema.

## Undoing a DELETE: `journal`

A `DELETE` that was confirmed (or small enough to go through without a question) is gone. With `journal`, the rows it
removes are written to a file **before** the `COMMIT`, and `sluice --undo` prints the SQL that puts them back:

```toml
[[rule]]
name      = "confirm-deletes"
match     = "delete"                  # a DELETE only: see below
action    = "confirm"                 # or "limit" with max_rows
over_rows = "100"
journal   = "required"                # "on": record when it can; "required": do not apply the DELETE when it cannot
```

```
sluice --listen 127.0.0.1:5433 --upstream db:5432 --policy policy.toml --undo-journal /var/lib/sluice/undo.jsonl
sluice --undo /var/lib/sluice/undo.jsonl                       # the entries: who, when, which table, how many rows
sluice --undo /var/lib/sluice/undo.jsonl --id 3f9a0c61d2b4e7a8 # the SQL that puts the rows of one back
```

The script is for a person to read and to run (`psql -f`); `sluice --undo` connects to nothing and needs no credentials.
It looks like this:

```sql
-- sluice undo of entry 3f9a0c61d2b4e7a8: DELETE 3, 3 rows, by agent on mydb at 2026-11-18T12:00:12Z
-- rule: confirm-deletes
-- statement: delete from users where id < 5
-- WARNING: it also changed public.orders (0 inserted, 0 updated, 100 deleted): those rows are NOT in this script
BEGIN;
SET LOCAL standard_conforming_strings = on;
INSERT INTO "users" ("id", "email") OVERRIDING SYSTEM VALUE VALUES
  ('18', 'ana@example.com'),
  ('52', NULL);
COMMIT;
```

- **`required` is a promise**: if the rows cannot all be written (the journal is full or cannot be written, the statement has
  a `RETURNING` of its own, more than 10,000 rows or 8 MiB, a value that is not valid text) the `DELETE` is **not applied**,
  with a message that says why, and the person who said yes is told. With `on` it is applied and the log says that it was
  not recorded (`journal` event, `outcome: failed`; the entry that is written says `complete: false` and why).
- **What is kept is what the server gave back** (`RETURNING *`), as text: the values come back as they were, whatever the
  type (`bytea`, `jsonb`, arrays, timestamps, `infinity`), each written as a literal that the column's type reads. An
  identity column gets its old value (`OVERRIDING SYSTEM VALUE`).
- **It is written before the `COMMIT`** and made durable (`fsync`): a statement that is applied is always in the journal. If
  the `COMMIT` then fails (a deferred constraint), the entry exists for a `DELETE` that did not happen: running the script
  would fail on the keys that are there, and do no harm.
- **A `DELETE`, or an `UPDATE` on PostgreSQL 18** (below). `journal` goes with `match = "delete"` or `match = "update"`,
  not with `any`. A `MERGE` that deletes is matched by a `delete` rule and, with `required`, refused ("only the rows of a
  DELETE or an UPDATE can be recorded"); with `on` it is applied and not recorded. `TRUNCATE` and `DROP` keep nothing:
  `confirm` is their protection.

What the script does **not** put back, said plainly, and that the entry says too:

- **What the delete took with it:** rows removed by `ON DELETE CASCADE`, changed by a trigger, or deleted by a rule are not
  in `RETURNING`. When the confirmation looked at them (`side_effects`, the default) the entry lists them with their counts
  and the script says so; when it did not (`side_effects = "off"`, or a `limit` rule) the entry says that it does not know.
  Put back the parent rows alone and the children are still gone.
- **Order and keys:** the rows are inserted as they were, with their old keys. If something else took a key since, the script
  fails and nothing is changed (it runs in a transaction). Generated columns must be taken out by hand.
- **The name of the table is as it was written** in the statement (`users`, `public.users`): run the script with the same
  `search_path`.
- **Sequences, triggers, the other columns of rows that changed since:** it puts back what was deleted, no more.

### An `UPDATE`: the old values (PostgreSQL 18)

An `UPDATE` only gives back the rows as they are now. PostgreSQL 18 can also give the rows as they were (`RETURNING OLD.*,
NEW.*`), so a rule with `match = "update"` and `journal` makes sluice ask for both: the person is shown the new rows as
before, and the journal keeps the old and the new row of each.

```toml
[[rule]]
name    = "confirm-updates"
match   = "update"
action  = "confirm"
journal = "required"     # PostgreSQL 18 or later
```

The script puts each row back to its old values **where it still has the values the `UPDATE` gave it**, matched on every
column (there is no key to rely on: sluice does not read the catalog), and **stops without changing anything** if a row
does not match exactly one row: it changed since, or two rows look alike now. It runs in one transaction:

```sql
-- sluice undo of entry 3f9a0c61d2b4e7a8: UPDATE 2, 2 rows, by agent on mydb at 2026-11-18T12:00:12Z
BEGIN;
SET LOCAL standard_conforming_strings = on;
DO '#variable_conflict use_column
DECLARE sluice_undo_rows bigint;
BEGIN
UPDATE "users" SET "email" = ''ana@example.com'' WHERE "id" IS NOT DISTINCT FROM ''18'' AND "email" IS NOT DISTINCT FROM ''ana@changed.org'';
GET DIAGNOSTICS sluice_undo_rows = ROW_COUNT;
IF sluice_undo_rows <> 1 THEN RAISE EXCEPTION ''row 1 of the entry matched % rows, not 1: nothing was changed'', sluice_undo_rows; END IF;
END
';
COMMIT;
```

Only the columns that changed are set (an identity column the `UPDATE` did not touch is not written); a row the `UPDATE`
left as it was is skipped. Before PostgreSQL 18 the server does not know `OLD`: a simple-protocol statement is run without
the old rows and `required` refuses it ("RETURNING OLD needs PostgreSQL 18"), `on` applies it and logs that it was not
recorded; a prepared statement fails at `Parse` with a syntax error from the server. Do not give a `journal` to an `update`
rule on an older server. A generated column cannot be set and makes the script stop. The same limits apply as for a `DELETE`
(10,000 rows, 8 MiB, a `RETURNING` of the statement's own, cascades and triggers listed but not undone).

**The journal holds data.** It is the rows themselves, including what a [mask](#hiding-values-action--mask) hides from the
user: it is for the operator. sluice creates it readable by its owner only and warns when it is not; keep it where its data
would be kept (the same protection as a backup), and archive it by renaming it and sending `SIGHUP` (the next entry starts a new file, like a log) (`--undo-journal-max`, 256 MB by default: when it is
full `on` stops recording, `required` stops applying). The statement text is written to it whatever `--log-sql` says. It grows
with the deletes that a rule keeps, nothing else. A policy that has a `journal` rule needs `--undo-journal`: sluice does not
start without it, and a reload that would add one is refused. Writing is synchronous (a `write` and an `fsync` on a
statement that is about to delete rows): a slow disk makes those statements slow.

## The outcome of each statement in the log

With `--log-results on` the log has, besides the `statement` event (what was asked), a `result` event (what came of
it): `kind` (`ok`, `error`, `empty`, `suspended`), the command `tag` (`SELECT 30`, `INSERT 0 1`), the number of
`rows` and `bytes` of data it returned, the `duration_ms` and, for an error, its `sqlstate`. It is the thing that a
proxy can say and the database's own log cannot (it does not know how much went to the client). The text of an
error is never in it, since it can quote the values (`Key (email)=(a@b.c) already exists`). It is off by default:
it doubles the lines of the log. It is not written for the statements held for a confirmation (the `confirm` event
says what came of those).

## A log that shows when it was changed

```
sluice ... --log-chain-key-file /etc/sluice/chain.key        # 16 to 1024 bytes of anything secret
sluice --verify-log sluice.log --log-chain-key-file /etc/sluice/chain.key
```

With the key, each line of the log ends with `"seq":N,"chain":"<32 hex>"`: the count of the line in this run and an HMAC of the
previous line's chain value and this line. The first line of a run is a `chain_start` event, and a clean shutdown ends with
`chain_end`. `--verify-log` reads a log and says which line does not check out, what is wrong (`changed`, `taken out or moved`,
`not chained`, `another key`) and exits with 1; a log that is whole but whose last run has no `chain_end` (a crash, `kill -9`, or the
end was cut off) exits with 3; one that checks out exits with 0. A file can hold many runs (each restart begins at 1).

It is evidence for a log that an agent, or someone with the same access as the agent, could have edited; it is not a way to keep
them from doing it. Two limits, stated: **the key has to be out of reach of whoever could edit the log** (anyone with the key can
write a log that checks out), and **the end of a log can be cut off** without the lines before it changing: keep the last chain
value that `--verify-log` prints for a run (every day, say, in another place) and a cut shows. A line that cannot be chained
(out of memory) is not written.

## Tagging the application name

`--tag-application-name on` makes the database see each connection's `application_name` followed by ` [sluice N]`, where N
is the `id` of the connection in sluice's log. A line of the database's own log, a row of `pg_stat_activity` or `pg_locks`
can then be found in the audit, and the other way round. The name the client gave stays in front (cut to leave room: the
server keeps 63 bytes). Off by default, since it changes what the database sees; a client that sends `SET application_name`
later replaces the tag (that is its right, and the audit still has the connection).

## Checking a policy without a server

```bash
sluice --check-policy policy.toml --user agent \
       --sql "delete from t" --sql "update t set a = 1 where b = 2" --sql "drop table t"
```

reads the file (the same checks as at startup) and says, for each `--sql`, what the rules would do with it as that
user and database: allowed, refused (with the rule and its message), held for a confirmation or capped. The exit
status is 0 when everything is allowed, 1 for an invalid policy, 2 for wrong arguments, 3 when something is
refused, 4 when nothing is refused but something would be asked about: a CI can run it on the file that is deployed.

## Confirming a DELETE or UPDATE

`action = "confirm"` asks a person before a `DELETE` or an `UPDATE` becomes final. The rule says which
statements (`match = "delete"` or `"update"`, optionally `users`, `databases` and `tables`) and how many rows are
worth a question:

```toml
confirm_timeout = "2m"           # how long a person has to answer (1s to 1h; default 2 minutes)

[[rule]]
name      = "confirm-deletes"
match     = "delete"
action    = "confirm"
over_rows = "100"                # only ask when more rows than this were touched (default "0": always)
side_effects = "on"              # also show what the statement changed in other tables (default "on")
message   = "A person has to confirm this."
```

`MERGE` and `INSERT ... ON CONFLICT DO UPDATE` are confirmed like the others, when the message holds that one statement
(the count is the one of the tag, `MERGE 20` or `INSERT 0 20`: an upsert counts the rows it inserted as well as those
it updated). The rows are shown when the server can give them: `RETURNING` on a `MERGE` exists from PostgreSQL 17; on an
older server the statement is run again as written and only the count is known. Before version 0.21 sluice did not
see these two as an `UPDATE` or a `DELETE`: a rule with `match = "delete"` did not apply to a `MERGE ... THEN DELETE`,
and a policy written for those versions should be read again with that in mind.

What happens (the reasons are in docs/design.md, sections 20 to 23): sluice runs the statement inside a
transaction that it does not commit, with `RETURNING *` added when the statement has none, so that the database
says how many rows it touched and which. Up to `over_rows` rows it commits at once and the client notices
nothing. Above that, **the person who sent the statement is asked, in their own session** (nobody is usually
at the proxy). In `psql` it looks like this:

```
mydb=> delete from customers where id <= 20;
ERROR:  sluice: DELETE 20 waiting for you (rule confirm-deletes): type  yes;  to apply,  no;  to undo,  show;  for more
DETAIL:  deleted 20 rows, the first 5:
  id  email
  1   user1@example.com
  2   user2@example.com
  ...
  ... and 15 more
also changed: orders 100 deleted, customers 20 deleted, audit 20 inserted
HINT:  Not final until you answer; undone after 5m.
mydb=*> yes;
DELETE 20
```

`yes;` commits, and the answer is the one the statement would have given (`DELETE 20`); `no;` undoes it (`ROLLBACK`); `show;` (or `more;`) asks the question again
with more rows (up to 50 are kept; the first message shows 5) and the same two ways to answer. `y` and `n` do too, in any case, with or
without the semicolon (psql waits for it), and so do `select sluice_confirm();` and `select sluice_cancel();`, for a
client that insists on something that parses. None of them is SQL: they are recognised only while a statement waits.
While the statement waits, everything else the client sends is refused (it would run inside the open
transaction) without the database hearing of it; a prepared statement works the same way (the question is the
answer of its `Execute`, and the confirmation is a cycle of its own). If nobody answers within
`confirm_timeout` the statement is undone and the client gets a warning. These answers are intercepted by
sluice, they are not statements of the database. **The person is whoever is on that connection**: an agent
there can answer too, so write the rule's `message` for it ("Do not confirm without the user's agreement"); to
ask somewhere an agent cannot reach, name a terminal or a command (`--confirm-tty`, `--confirm-command`, below),
and the question is put there instead.

With a terminal (`--confirm-tty`, `/dev/tty` for the terminal of sluice itself) the person is asked there:

```
agent@mydb   rule: confirm-deletes
  DELETE FROM users WHERE created_at < '2020-01-01'
  deleted 41234 rows (not committed yet); the first 10:
    id   email             created_at
    18   ana@example.com   2019-03-02 10:11
    ...  and 41224 more
  tables changed in this transaction (cascades and triggers included):
    public.orders        12 deleted
    public.audit_log     3 inserted
commit? [y/N]
```

The last block is what the statement did **besides** its own rows: rows removed by a cascading foreign key, rows
a trigger inserted or changed. sluice reads the statistics of the transaction that PostgreSQL keeps per table
(`pg_stat_xact_user_tables`) just before the statement and just after it, in the same exchange with the server,
and shows the difference. It needs nothing from the role beyond what any role has. Set `side_effects = "off"`
in a rule for a server that does not have those statistics (a PostgreSQL-compatible database, say): with it on,
such a server answers with an error to the first look, and sluice runs the statement again without looking
(simple queries) or tells the client what happened (prepared statements), with the way to turn it off.

`y` (or anything starting with y) commits, and the client receives the statement's own answer. Anything else
rolls back, and the client receives an error (`42501`, "sluice: not confirmed (rule ...): ... Nothing was
changed.", followed by the rule's `message`) and a normal `ReadyForQuery`. The terminal is `/dev/tty`, or
the file given with `--confirm-tty`; it is never stdout, which is the JSON log. Values are shown on the terminal
only, never in the log, and control characters in them are replaced so that the data cannot write on the screen.

**Asking something other than a terminal.** With `--confirm-command CMD` sluice runs `CMD` (through `sh -c`) for
each question instead: the question, exactly as it would be shown on the terminal, is the command's standard
input, and its **exit status is the answer** (0 is yes; anything else, a command that cannot be run, or one still
running when `confirm_timeout` is over, is no and is killed with whatever it started). That is how a chat message,
a ticket or another program can approve a statement:

```bash
sluice --listen 127.0.0.1:5433 --upstream db.internal:5432 --policy policy.toml \
       --confirm-command '/usr/local/bin/ask-on-slack'     # reads the question, exits 0 to approve
```

Its standard output is discarded (it is not sluice's: that is the JSON log), its standard error is sluice's,
it inherits none of sluice's sockets, and questions are put to it one at a time, in turn. It is given the
statement and the rows (which are data of the database): it is the operator's own command, run with sluice's
rights. `--confirm-command` and `--confirm-tty` exclude each other.

- **Nothing is committed unless a person said yes.** No answer within `confirm_timeout`, no terminal (when one was
  named and cannot be opened), a client that leaves, a sluice that stops: the transaction is rolled back (or,
  for a dropped connection, never committed). While it waits in the session the rows stay locked.
- **Inside the client's own transaction** a savepoint is used instead of `BEGIN`, so the transaction goes on, and
  after a refusal it is still usable.
- **A role that may delete but not read** cannot have `RETURNING`: sluice runs the statement as written, and the
  person is shown the count only, with a note that the rows could not be read.
- **A statement that fails** fails for the client as it would have; it is run twice only when the failure may
  have come from the added `RETURNING`.
- **Costs.** The rows stay locked while the person decides (the timeout bounds it); a big delete does its work
  before being asked about and undoes it on a no; triggers run even when the transaction is rolled back (one that
  acts outside the database has already acted); rows removed by a cascade in other tables are not listed.
- **Both protocols.** A simple query (psql, scripts) is run, shown and committed as described above. A prepared
  statement (Parse/Bind/Execute, which most drivers and ORMs use) is recognised when it is prepared, and asked
  about **each time it is executed**: the answer of the Execute is kept, the person sees the rows, and the
  `Sync` that commits waits for the answer. See "Prepared statements" below. A message with several
  statements, or a data-changing CTE, that matches a `confirm` rule is **refused with a reason**, not let
  through. In `audit` mode the verdict is logged (`confirm`) and the statement goes through untouched.
- A `deny` anywhere in the message wins over a `confirm`. `confirm` rules about tables assume the worst about
  tables that cannot be seen, like `deny` rules.
- Events: `statement` with `verdict: "confirm"` and `action: "held"`, then `confirm` with `outcome` (`yes`, `auto`,
  `no`, `timeout`, `no_terminal`, `error`, `too_large`), `rows`, whether the rows could be shown, and how long the
  person took.

### Who is asked: `confirm_via`

Without anything else, the person who sent the statement is asked, in their own session; with `--confirm-tty` or
`--confirm-command` the operator of the proxy is asked instead (see below). A rule can choose, which is the way to put
the questions that matter most out of the reach of whoever sits in the session (an agent that can type `yes;` is
a person for the session):

```toml
[[rule]]
name        = "confirm-drops"
match       = "drop"
action      = "confirm"
confirm_via = "operator"        # the terminal of the proxy, or the --confirm-command

[[rule]]
name        = "confirm-deletes"
match       = "delete"
action      = "confirm"
over_rows   = "100"
confirm_via = "session"         # even when a command is set for the rest
```

`"session"` or `"operator"`; without the key, what the operator chose with `--confirm-tty` / `--confirm-command`
(the session when neither is given). `"operator"` needs something to ask: `--confirm-command`, `--confirm-tty`, or a
terminal of the process (`/dev/tty`); with none, the statement is refused ("no terminal"). The channel of each
question is in the `confirm` event of the log (`session`, `terminal` or `command`).

### TRUNCATE and DROP

`match = "truncate"` and `match = "drop"` take `action = "confirm"` too:

```toml
[[rule]]
name    = "confirm-truncate"
match   = "truncate"
action  = "confirm"
message = "Not without the user."

[[rule]]
name   = "confirm-drop"
match  = "drop"
action = "confirm"
```

PostgreSQL runs `TRUNCATE` and `DROP TABLE` (or `VIEW`, `INDEX`, ...) inside a transaction, and undoes them on a
rollback, so the same mechanism applies: the statement is run as written, not committed, and the person answers
`yes;`, `no;` or `show;`. Differences from a `DELETE`: there are no rows to count, so **it is always asked about**
(`over_rows` does not apply) and the question shows the statement itself and its tag; nothing is added to it
(no `RETURNING`); no look at the side effects (a `TRUNCATE` leaves no counters).

- **The table is locked until you answer**, and for these statements the lock is exclusive: any other session that
  reads the table waits for it. Keep `confirm_timeout` short for such rules (it defaults to 2 minutes).
- `DROP DATABASE`, `DROP ROLE` and the like are not confirmable (a database cannot be dropped inside a
  transaction, and a role or a database is not undone by a rollback): a rule that matches them refuses them, with
  the reason.
- `DROP INDEX CONCURRENTLY` and other statements PostgreSQL refuses inside a transaction fail with its own error.

### Applications and drivers

An application does not ask a person: when its statement is held for confirmation, what it sees is an error. A
driver then usually rolls back (`ROLLBACK`), and that is understood as a **no**: the waiting statement goes with
it. A `COMMIT` before the answer is refused (it would apply what was not confirmed). A driver that sends a row
limit with every `DELETE` (pgjdbc sends 1) is run without the limit. For an application, name a terminal or a
command (`--confirm-tty`, `--confirm-command`) rather than the session: that is where a person can answer.

### Prepared statements

What the client's driver sends is the extended protocol: `Parse` (once, with a name or without), `Bind`
(with the arguments), `Execute`, `Sync`. sluice follows it so that the person sees the same thing as for a
simple query:

- At `Parse`, a `DELETE` or `UPDATE` that a `confirm` rule matches is recorded and sent with ` RETURNING *`
  added (unless the statement has its own). The client is told, when it describes the statement, that it
  returns no rows, as for any `DELETE`; its own `RETURNING` is left as it wrote it.
- At `Execute` of such a statement, sluice runs it (with a `Describe` of its own before it, for the names of
  the columns, and a `Flush` after it), keeps the answer, and asks. A **yes** gives the client its answer and
  lets its `Sync` go on, which commits. A **no** gives the client an error (SQLSTATE `42501`) and makes the
  server fail the cycle, so the statement is undone: the `Sync` then rolls the implicit transaction back.
- **Inside a transaction of the client's** (`BEGIN` ... `COMMIT`) a no aborts the transaction, exactly as any
  statement that fails does: the client has to roll back. (A simple query uses a savepoint instead and leaves
  the transaction usable; a prepared statement has none, because the protocol gives sluice no clean place to
  put one.)
- A statement prepared **before a policy reload** keeps the rule it was prepared under.
- Refused, with a reason: an `Execute` with a row limit (`max_rows` other than 0), more than 256 confirmable
  statements or portals on one connection, and statement or portal names longer than 63 bytes on a connection
  that has one (the server keeps only the first 63 bytes, so the names cannot be compared the way it does).
- The rows are shown as text. A client that asked for **binary** results for a statement with its own
  `RETURNING` will see the raw bytes in the question (cleaned of control characters): the answer it gets is
  unchanged.
- Pipelining works: several statements sent without waiting are matched to their answers, and an error before
  the confirmed one means nothing is asked (the server skips it).

## Uninspectable messages

Some messages cannot be judged: SQL the parser rejects (syntax error, or syntax newer than the parser),
a Query or Parse over 1 MiB, a malformed message, a nesting too deep to analyse, the fast-path function
call (`F`), which runs a function without any SQL, and SQL whose strings the server may cut elsewhere than
sluice does (see below).

- `on_uninspectable = "deny"` (default): in `enforce` mode they are blocked, with the reason in the error,
  for example `sluice: cannot inspect this statement (syntax error at or near "selec")`.
- `on_uninspectable = "allow"`: they are relayed, and logged as uninspectable.

In `audit` mode they are always relayed and logged.

### Strings read two ways

A client can change how the server reads the quotes in the middle of a session: `SET
standard_conforming_strings = off` (or `select set_config(...)`), or a multi-byte `client_encoding` such as
SJIS, BIG5 or GBK. sluice reads the SQL with the default settings, so a string like `'x\'` newline `'; delete
from t; --'` is one harmless `select` to it and a `select` followed by a `DELETE` to such a server. A rule
cannot judge a statement that is read two ways, so these are uninspectable:

| In the SQL | Verdict |
|---|---|
| a quote preceded by an odd number of backslashes inside a plain string (`'a\'`, `'a\\\'`) | uninspectable |
| a quote right after any number of backslashes, in any kind of string (plain, `E'...'`, `U&'...'`) that also holds a byte above 0x7f | uninspectable |
| `'\d+'`, `'C:\\'`, `E'it\'s'`, `$$it\'s$$`, a backslash in a comment or in `"an identifier"` | normal |

The error says `a backslash inside a quoted string is read differently depending on
standard_conforming_strings and client_encoding`. Use a bind parameter, or `E'...'` for a quote inside a
string, or double the quote (`''`). With `on_uninspectable = "allow"` these statements go through like the
others: the setting means that what sluice cannot read is not its business.

## What a blocked client sees

sluice does not answer in place of the database. In `enforce` mode it sends the database a replacement
message that fails, and the database replies as it would to any error. The client gets:

```
ERROR:  invalid input syntax for type integer: "sluice: blocked by rule no-unbounded-write: add a WHERE clause"
```

- the connection stays open and usable;
- a transaction in progress is aborted, so a later `COMMIT` is a `ROLLBACK`: a blocked statement never
  leaves a half-applied transaction behind;
- in the extended protocol the rest of the batch is skipped up to `Sync`, as for any error;
- the SQLSTATE is `22P02`, not `42501`.

The reasoning is in [design.md](design.md), section 11.

## Metrics, answering over HTTP, and telling somebody

Three things for the people who run sluice, all off unless asked for.

### `--admin HOST:PORT`: the counters, and the questions

```
sluice ... --admin 127.0.0.1:9100 --admin-token-file /etc/sluice/admin.token
```

A small HTTP listener in the same loop as everything else. **Plain HTTP, no TLS**: keep it on a loopback address or a private
network, or put a reverse proxy in front. `--admin-token-file` (a token of 16 to 1024 bytes; a newline at the end is not
part of it) makes every route but `/healthz` need `Authorization: Bearer TOKEN`. The token is **required** when the address
is not a loopback one and whenever confirmations are answered here (the questions hold rows); without one, sluice warns.

| Route | |
|---|---|
| `GET /healthz` | `ok`, no token (for a load balancer) |
| `GET /metrics` | the counters, in the Prometheus text format (below) |
| `GET /pending` | the confirmations waiting for an answer, as JSON: `id`, `age_s`, `user`, `database`, `rule`, `tag`, `rows`, `expires_in_s` |
| `GET /pending/ID` | the question of one, as text: what a person would have been shown, **with the rows** |
| `POST /confirm/ID/yes` and `/no` | answers it. **Only POST**: a GET is what a chat client or a browser fetches by itself to show a preview, and it must never decide |

It serves at most 8 connections at once, one request each, 4 KiB of request and 5 seconds to send it; it never blocks the
proxy.

**The counters** (they are lost when sluice restarts, which Prometheus sees as a reset):

| Series | Labels |
|---|---|
| `sluice_connections_total`, `sluice_connections_closed_total` | `reason` (`client_closed`, `killed`, `statement_budget`, ...) |
| `sluice_statements_total` | `verdict` (`allow`, `deny`, `confirm`, `uninspectable`, `none`), `action` (`relayed`, `blocked`, `held`) |
| `sluice_rule_hits_total` | `rule`, `verdict`: which rules decide |
| `sluice_confirmations_total` | `outcome` (`yes`, `no`, `timeout`, `auto`...), `channel` (`session`, `terminal`, `command`, `admin`) |
| `sluice_limits_total` | `kind` (`budget_rows`, `transaction`, `statement_budget`, ...) |
| `sluice_bytes_total` | `direction` |
| `sluice_masked_values_total` | |
| `sluice_log_events_total` | `event`: every line of the log, by name (`alert`, `kill`, `dry_run`, `journal`, ...) |
| `sluice_event_commands_total` | `outcome` (`started`, `ok`, `failed`, `timeout`, `dropped`) |
| `sluice_admin_requests_total` | `path`, `status` |
| `sluice_policy_reloads_total` | `outcome` |
| gauges | `sluice_connections_active`, `sluice_pending_confirmations`, `sluice_policy_rules`, `sluice_uptime_seconds`, `sluice_build_info{version}` |

The label values are words sluice chooses, a rule's name or an event's name: never what a client sent. The number of series is
bounded (1,500); beyond it they are counted in `sluice_metrics_dropped_series_total`. A scrape and an alert:

```yaml
scrape_configs:
  - job_name: sluice
    authorization: { credentials_file: /etc/prometheus/sluice.token }
    static_configs: [{ targets: ["sluice:9100"] }]
# alert on:  increase(sluice_statements_total{action="blocked"}[5m]) > 20      increase(sluice_log_events_total{event="kill"}[1h]) > 0
#            sluice_pending_confirmations > 0 for 10m     rate(sluice_event_commands_total{outcome=~"failed|timeout|dropped"}[10m]) > 0
```

### `--confirm-admin on`: answering a confirmation over HTTP

The operator's way to be asked (like `--confirm-tty` and `--confirm-command`, and exclusive with them) that needs no terminal
and no script that waits: the statement is run and held as for any confirmation, a `confirm_pending` event is logged (rule,
user, database, tag, rows, `question`: the id, and when it expires), and it waits until somebody `POST`s the answer, the client
leaves, or `confirm_timeout` passes (then it is undone, as always). Any number wait at once. The rows are in the question
(`GET /pending/ID`, with the token), **never in the log**.

With this the default for a confirmation is the admin listener, not the session of the client; a rule can still choose
`confirm_via = "session"`.

### `--event-command CMD`: sending an event somewhere

```
sluice ... --event-command 'WEBHOOK_URL=https://hooks.example.com/T00/B00/xyz WEBHOOK_FORMAT=slack sh /etc/sluice/webhook.sh' \
           --event-filter alert,kill,confirm_pending
```

For each line of the log whose event is in `--event-filter` (default `alert,kill,confirm_pending,admin_denied,policy_reload_failed`),
the shell runs `CMD` with the line (one JSON object, as it is in the log) on its standard input and the name of the event in
`$SLUICE_EVENT`. Its output is discarded. sluice never waits for it: at most 4 run at once, at most 64 lines wait, and a line that
finds the queue full is dropped and counted (`dropped`); a command that has not ended in 15 seconds is killed with whatever it
started; on a clean shutdown the last ones get 5 seconds. Any event can be asked for (`statement` too, but that is every statement).

`tools/webhook.sh` is the command for the common case: it posts to a URL, as the line itself (`json`), as `{"text": ...}` for
Slack and Mattermost, or `{"content": ...}` for Discord, signs the body when `WEBHOOK_SECRET` is set
(`X-Sluice-Signature: sha256=<hmac>`), and for `confirm_pending` puts the question in the message (`WEBHOOK_ADMIN` and
`WEBHOOK_TOKEN_FILE`) with the two lines that answer it. It needs `curl` (and `openssl` for the signature): the image of sluice
has neither, so use a derived one, or run sluice where they are.

The approval chain that this makes: `--confirm-admin on` holds the statement and logs `confirm_pending`; the event command posts
it with the question; the person's answer is a `POST /confirm/ID/yes` made by whatever receives their click (a bot, a small
service, a `curl` in a terminal). sluice does not receive chat callbacks itself: that is a service of yours that holds the token.

## What goes in the log

Without a policy a `statement` event holds `kind` (`query`, `parse`), the SQL and its length. With a policy
it also holds:

| Field | Meaning |
|---|---|
| `verdict` | `allow`, `deny`, or `uninspectable` |
| `rule` | the rule that decided (for `deny`) |
| `fingerprint`, `sql_redacted` | with `--log-sql normalized` or `none`: a hash of the shape of the query, and whether the text was withheld (see the README). |
| `tables` | the tables of the message, as `table` or `schema.table`, once each (at most 32; `"tables_truncated":true` when there were more). Only when a rule is about tables. |
| `detail` | why it could not be inspected |
| `action` | `relayed` or `blocked`. In `audit` mode it is always `relayed`, even for `deny`. |

The `connection_close` event counts `statements` and `blocked`, and `listening` states the `policy`, its
`mode`, the number of `rules` and `on_uninspectable`.

## Replication and the like

In `enforce` mode, a connection that asks for replication (`replication=true`, `on`, `yes`, `1` or
`database` in its startup packet) is refused with a `FATAL` error: it speaks another protocol, and
`replication=database` runs ordinary SQL through it. An impossible message header closes the connection.

## Examples

**Guardrails for people and scripts on a production database**

```toml
mode = "enforce"

[[rule]]
name    = "no-unbounded-write"
match   = "update_or_delete_without_where"
message = "add a WHERE clause"

[[rule]]
name    = "no-drop"
match   = "drop"
message = "drops go through migrations"

[[rule]]
name  = "no-truncate"
match = "truncate"
```

**An AI agent that may only read**

```toml
mode = "enforce"

[[rule]]
name  = "agent-read-only"
match = "not_read_only"
users = ["agent"]
```

**An AI agent that may only touch some tables**

```toml
mode = "enforce"

[[rule]]
name           = "agent-sales-only"
match          = "any"
users          = ["agent"]
outside_tables = ["orders", "products"]
message        = "sales tables only"
```

Add the `agent-read-only` rule above to make it read-only as well. Both are needed for a fully locked-down
agent: this one decides *where* it may look, the other *what* it may do.

Run it first with `mode = "audit"`, read the `deny` and `uninspectable` lines in the log for a day (the
`tables` field shows what the workload really touches), then switch to `enforce`.

## What a policy cannot do

sluice judges statements, not their effects. A `DO` block, a function or a trigger runs code it never
sees (use `procedural` to refuse `DO` and `CALL`); `select some_function_with_side_effects()` is a read;
`WHERE true` is a `WHERE`. Keep `GRANT` and row-level security as the real protection. The full list is in
[design.md](design.md), section 12.
