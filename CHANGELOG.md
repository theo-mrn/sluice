# Changelog

All notable changes to sluice. The format follows [Keep a Changelog](https://keepachangelog.com/), and the
version numbers follow [Semantic Versioning](https://semver.org/) **as far as 0.x allows**: while the major
number is 0, a minor version may change the policy format, the events of the log or the names of the metrics.
When it does, the entry says so under **Changed** or **Removed**.

## [Unreleased]

## How to read the entries below

Versions 0.1 to 0.27 were built one after the other before the first public release; their entries are the
description each one had in the roadmap, newest first.

## [0.27.0]

- `--admin` (an HTTP listener: `/metrics` for Prometheus, `/healthz`, `/pending`), `--confirm-admin` (answer a confirmation with a `POST`, from a bot or a chat), `--event-command` (a command run for the events that matter, with `tools/webhook.sh` for Slack, Mattermost, Discord or any URL).
- **Packaging.** Static release binaries (Linux with musl, macOS with OpenSSL inside; `-Dstatic=true`), a source archive that builds
  without a network, two container images (about 10 MB with nothing but the binary, and one with `sh`, `curl`, `openssl` and
  `tini` for `--event-command`), `SHA256SUMS`, build provenance and signed images, all made by `.github/workflows/release.yml`
  from a tag. `sluice --version` says the commit, the OpenSSL and the parser. Two example policies in `examples/policies/`
  (run as tests), `THIRD_PARTY_NOTICES.md`, `SECURITY.md`, `CONTRIBUTING.md`. `--test-policy` accepts a comment after `as` and `at`.
- **Fixed.** The optimized (release) build failed with GCC on a message that could name a 1,023-byte path (`server.c`); a failed start with a
  bad `--admin-token-file` leaked what it had made.


## [0.26.0]

- `dry_run` (a rule that says what it would do), `--test-policy` (expectations as a file), `during` / `except_during` / `valid_from` / `valid_until` (a rule that begins and ends by itself), query shapes (`outside_fingerprints`, `sluice --learn`), `budget_statements`, `max_transaction`, `--tag-application-name`, lists over several lines in the policy.

## [0.25.0]

- `match = "set_session"` (SET ROLE, set_config) and `"dangerous"` (COPY to files or programs, functions that reach out), a `functions` key, `action = "alert"` and `"kill"`, and `--log-chain-key-file` with `sluice --verify-log` (a log that shows when it was changed).

## [0.24.0]

- mask names may be qualified (`users.email`, `public.users.email`): sluice reads the tables' OIDs once after the login and hides a column only when its rows come from that table; anything it cannot tell is hidden.

## [0.23.0]

- `journal` also goes with `match = "update"` on PostgreSQL 18 (`RETURNING OLD.*, NEW.*`): `sluice --undo` prints a script that puts the old values back where the row still has the values the UPDATE gave it, and stops if it does not.

## [0.22.0]

- `journal` on a rule keeps the rows a confirmed `DELETE` removes (`--undo-journal FILE`, written before the `COMMIT`; `required` does not apply a DELETE that cannot be recorded), and `sluice --undo` prints the SQL that puts them back.

## [0.21.0]

- `MERGE` and `INSERT ... ON CONFLICT DO UPDATE` count as DELETEs and UPDATEs for the rules (they did not), and can be confirmed like them.

## [0.20.0]

- `action = "mask"` hides values in what a user reads: by column name and by pattern (e-mail, card number, IBAN), as a stable token, partly, NULL or `[masked]`; in both protocols, in error messages and in confirmations. A guard-rail, not a security boundary (see docs/policy.md).

## [0.19.0]

- a rule says who is asked (`confirm_via = "session"` or `"operator"`), and a **budget** bounds what one user takes out or changes over a window of time whatever the number of connections (`budget_rows`, `budget_bytes`, `budget_changed`, `window`).

## [0.18.0]

- a transaction left open is ended (`max_idle_in_transaction`), connections per user are bounded (`max_connections`), `--log-results` writes how each statement ended (tag, rows, bytes, time, error code); tests that throw garbage at the proxy, compare it with a direct connection, and run 64 clients at once.

## [0.17.0]

- limits on a connection (`action = "limit"` with `max_result_rows`, `max_result_bytes`, `max_total_bytes`, `max_duration`): rows past the limit are dropped and the result ends in an error, a connection that has received too much is closed, a statement that runs too long is cancelled on the server.

## [0.16.0]

- `action = "limit"` (an unattended row cap: more than `max_rows` rows is undone, with the reason) and `sluice --check-policy` (what a policy does with given statements, without a server; usable in a CI).

## [0.15.0]

- `TRUNCATE` and `DROP` of tables, views and indexes can be confirmed too; the confirmation was tried with psycopg, asyncpg, SQLAlchemy and JDBC (`tests/drivers.py`), which found and fixed two defects (a driver's `ROLLBACK` while a statement waits, and the row limit pgjdbc sends).

## [0.14.0]

- the question is asked in the client's own session by default (you answer `yes;` or `no;`), for simple queries and prepared statements; a terminal or a command is for an operator who wants it elsewhere.

## [0.13.0]

- the question also shows what the statement changed besides its own rows (cascades, triggers, as exact counts), and can be put to a command instead of a terminal (`--confirm-command`).

## [0.12.0]

- confirmations for prepared statements (the extended protocol: `Parse`, `Bind`, `Execute`), tested against the real server and against `pgbench -M prepared`.

## [0.11.0]

- TLS towards the clients (`--listen-tls self-signed`, or `--listen-tls-cert` and `--listen-tls-key`), so that `sslmode=require` works and sluice can listen beyond the machine.

## [0.10.0]

- confirming a `DELETE` or `UPDATE` (`action = "confirm"`): sluice runs it in a transaction that it does not commit, shows a person the count and the first rows on the terminal, and commits or rolls back. Simple query protocol only for now.

## [0.9.0]

- hardening found by reading and by testing on a real server: strings that the server may read differently, `search_path` and table rules, reconnecting to every address of a name, TCP keepalive, Linux and musl builds, a test against a real PostgreSQL.

## [0.8.0]

- a client certificate towards the database (`--upstream-cert`, `--upstream-key`).

## [0.7.0]

- `--log-sql normalized` and `none`, to keep the values of the SQL out of the log.

## [0.6.0]

- reload the policy on `SIGHUP`; the message scanner split out of the connection code and fuzzed against an independent model.

## [0.5.0]

- rules by table (`tables`, `outside_tables`, `match = "any"`), with the worst case assumed for statements whose tables the parser does not report.

## [0.4.0]

- TLS towards the database (`require`, `verify-full`), fuzzing of the parsers.

## [0.3.0]

- policy file and rules (writes without `WHERE`, DDL, read-only), `audit` and `enforce` modes, SQL read with libpg_query.

## [0.2.0]

- parse the query messages (simple and extended protocol), one JSON log line per statement.

## [0.1.0]

- TCP passthrough between client and Postgres, parse the startup message, JSON log of each connection.
