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
| `action` | no | `"deny"` (default) or `"allow"`. |
| `users` | no | The rule only applies to these users (exact, case-sensitive). |
| `except_users` | no | The rule applies to everybody **but** these users (exact, case-sensitive): a role created tomorrow is covered without touching the file. |
| `databases` | no | The rule only applies on these databases. |
| `tables` | no | The rule only applies to statements that touch one of these tables (see [Tables](#tables)). |
| `outside_tables` | no | The rule only applies to statements that touch a table that is **not** in this list. |
| `message` | no | Added to the error the client receives. Printable ASCII, no backslash, 200 characters at most. |

`users` and `databases` are the values the client announced in its startup packet. They are labels, not
proof of identity: the database is still the one that authenticates.

### What a rule can match

| `match` | A statement matches when it is |
|---|---|
| `update_or_delete_without_where` | an `UPDATE` or a `DELETE` with no `WHERE` clause. A `WHERE` inside a sub-select does not count; `WHERE true` does. |
| `delete` | a `DELETE` (also one hidden in a CTE). |
| `update` | an `UPDATE` (likewise). |
| `ddl` | anything that changes the schema, the roles or the privileges: `CREATE`, `ALTER`, `DROP`, `TRUNCATE`, `GRANT`, `REVOKE`, `COMMENT`, `ALTER SYSTEM`, `SELECT ... INTO`, `CREATE TABLE AS`. Not `VACUUM`, `ANALYZE`, `REINDEX`, `CLUSTER` or `COPY`. |
| `drop` | any `DROP` (tables, indexes, databases, roles...). `TRUNCATE` is separate. |
| `truncate` | `TRUNCATE`. |
| `not_read_only` | anything that is not on the read-only allowlist below. |
| `procedural` | `DO` and `CALL`: code sluice cannot look into. |
| `multi_statement` | one of several statements sent in a single message (`select 1; select 2`). |

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
message   = "A person has to confirm this."
```

What happens (the reasons are in docs/design.md, section 20): sluice runs the statement inside a transaction
that it does not commit, with `RETURNING *` added when the statement has none, so that the database says how
many rows it touched and which. Up to `over_rows` rows it commits at once and the client notices nothing. Above
that, the person is asked on the terminal:

```
agent@mydb   rule: confirm-deletes
  DELETE FROM users WHERE created_at < '2020-01-01'
  deleted 41234 rows (not committed yet); the first 10:
    id   email             created_at
    18   ana@example.com   2019-03-02 10:11
    ...  and 41224 more
commit? [y/N]
```

`y` (or anything starting with y) commits, and the client receives the statement's own answer. Anything else
rolls back, and the client receives an error (`42501`, "sluice: not confirmed (rule ...): ... Nothing was
changed.", followed by the rule's `message`) and a normal `ReadyForQuery`. The terminal is `/dev/tty`, or
the file given with `--confirm-tty`; it is never stdout, which is the JSON log. Values are shown on the terminal
only, never in the log, and control characters in them are replaced so that the data cannot write on the screen.

- **Nothing is committed unless a person said yes.** No answer within `confirm_timeout`, no terminal (a service,
  a container), a client that leaves, a sluice that stops: the transaction is rolled back (or, for a dropped
  connection, never committed).
- **Inside the client's own transaction** a savepoint is used instead of `BEGIN`, so the transaction goes on, and
  after a refusal it is still usable.
- **A role that may delete but not read** cannot have `RETURNING`: sluice runs the statement as written, and the
  person is shown the count only, with a note that the rows could not be read.
- **A statement that fails** fails for the client as it would have; it is run twice only when the failure may
  have come from the added `RETURNING`.
- **Costs.** The rows stay locked while the person decides (the timeout bounds it); a big delete does its work
  before being asked about and undoes it on a no; triggers run even when the transaction is rolled back (one that
  acts outside the database has already acted); rows removed by a cascade in other tables are not listed.
- **Only the simple query protocol** (psql, scripts, several drivers) for now. A prepared statement
  (Parse/Bind/Execute, which most ORMs use) or a message with several statements that matches a `confirm`
  rule is **refused with a reason**, not let through. In `audit` mode the verdict is logged (`confirm`) and the
  statement goes through untouched.
- A `deny` anywhere in the message wins over a `confirm`. `confirm` rules about tables assume the worst about
  tables that cannot be seen, like `deny` rules.
- Events: `statement` with `verdict: "confirm"` and `action: "held"`, then `confirm` with `outcome` (`yes`, `auto`,
  `no`, `timeout`, `no_terminal`, `error`, `too_large`), `rows`, whether the rows could be shown, and how long the
  person took.

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
