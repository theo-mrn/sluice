# sluice

A small guard proxy for PostgreSQL, written in C. It sits between a client and the database, reads every
query, decides whether it goes through, and logs it either way.

> **Status: pre-alpha (v0.11).** sluice relays PostgreSQL connections, reads the SQL they carry with the
> PostgreSQL parser itself, applies rules to it, logs every verdict as JSON, and can encrypt and verify the
> hop to the database. In `audit` mode it only says what it would block; in `enforce` mode it blocks. It is
> tested automatically against fake servers and, with Docker, against a real PostgreSQL 17 (SCRAM login,
> rules, the quoting and `search_path` attacks it was hardened against, reload, the log, TLS with a client
> certificate, `psql` with `sslmode=require`). It builds and passes its tests on macOS and Linux (glibc and
> musl). The connection from the client to sluice is in clear text unless `--listen-tls` is given. See the
> [roadmap](#roadmap) and the [limits](#limits-today).

## What it is for

Postgres can say "this user may `DELETE` from this table". It cannot say "but not without a `WHERE`", or
"no `DROP` in production, even for the owner". sluice adds that layer:

- **Mistakes.** `UPDATE users SET email = ...` run by hand on the wrong terminal.
- **Tools and AI agents with SQL access.** Read-only, whatever the model decides to write.
- **Audit.** Who ran which statement, and what the rules thought of it, as JSON, ready for a log
  collector or a SIEM.

It works with any PostgreSQL, managed ones included: no server extension, no change to the database. The
only change on the client side is its connection string.

## How it is used

One binary, one policy file. You run it **next to the client** and point the client at it instead of the
database.

```bash
sluice --listen 127.0.0.1:5433 --upstream db.internal:5432 \
       --upstream-tls verify-full --upstream-ca db-ca.pem --policy policy.toml
psql -h 127.0.0.1 -p 5433 -U app mydb
```

The same binary covers every setup:

| Where it runs | What the client uses |
|---|---|
| On a laptop, next to a tool or an AI agent | `DATABASE_URL=postgres://app@127.0.0.1:5433/mydb` |
| As a Kubernetes sidecar (second container in the pod) | `postgres://app@localhost:5433/mydb`; policy from a ConfigMap; JSON log on stdout |
| In CI, as a background process or service container | same as the laptop case |

"Sidecar" is a way to run it, not a separate mode: there is no Kubernetes dependency, no operator, no CRD.

### The connection to the database

`--upstream-tls` chooses how sluice talks to PostgreSQL:

| Value | Meaning |
|---|---|
| `off` (default) | plain text. Fine for a database on the same machine; sluice logs a warning at startup when the upstream is anywhere else. |
| `require` | encrypted, but the server's certificate is not checked. Protects against listening, not against impersonation, and warns about it. |
| `verify-full` | encrypted, and the certificate chain and the host name (or IP address) are verified. `--upstream-ca FILE` gives the CA to trust; without it the system store is used. |

With `--upstream-cert` and `--upstream-key`, sluice also shows a client certificate (see the limits below).

There is no `prefer`: when TLS is asked for and cannot be had, the client gets an error and the connection
ends. sluice never falls back to plain text.

### The connection from the client

By default the clients talk to sluice in clear text, which is fine on loopback or inside a pod. For a client
that insists on `sslmode=require` (most connection strings of managed providers), or to listen on another
machine, sluice can be a TLS server too:

| Option | Meaning |
|---|---|
| `--listen-tls self-signed` | a certificate made at startup and kept in memory. Enough for `sslmode=require`; a client that checks who sluice is (`verify-full`) cannot trust it, and sluice warns about it. |
| `--listen-tls-cert FILE --listen-tls-key FILE` | your own certificate (PEM, key not encrypted), for `verify-ca` and `verify-full`. |

With either, TLS becomes **mandatory**: a client that starts in clear text (`sslmode=disable`, or `prefer`
that did not ask) is refused with "this server requires TLS", and nothing may follow the TLS request in clear
(it would be taken for encrypted input). A `CancelRequest` is still accepted in clear, as PostgreSQL does.
sluice does not ask clients for a certificate. This does not change the connection to the database, which is
chosen by `--upstream-tls`.

### The policy

```toml
mode = "audit"                  # "audit" logs what would be blocked, "enforce" blocks it

[[rule]]
name    = "no-unbounded-write"
match   = "update_or_delete_without_where"
message = "add a WHERE clause"

[[rule]]
name  = "agent-read-only"
match = "not_read_only"
users = ["agent"]

[[rule]]                          # and it only looks at two tables
name           = "agent-sales-only"
match          = "any"
users          = ["agent"]
outside_tables = ["orders", "public.products"]
```

Rules can also be about tables: `tables = [...]` (the statement touches one of them) and `outside_tables =
[...]` (it touches one that is not in the list). Sub-selects, joins, CTEs and every statement of a message
count. A name in a rule is `table` (any schema) or `schema.table`; a table written without a schema in the SQL
is not trusted against `schema.table`, since a client can change its `search_path`. The parser does not report
the tables of every statement (`MERGE` leaves out its source, `DO` hides
everything), so for those a `deny` rule assumes the worst: an agent limited to some tables cannot get round
it with `MERGE ... USING secret`.

A rule can also ask a person before a `DELETE` or `UPDATE` becomes final (`action = "confirm"`): sluice runs
the statement inside a transaction it does not commit, then shows on the terminal how many rows it touched
and which, and waits for a `y`. Without an answer (or a terminal), nothing is committed. See
[docs/policy.md](docs/policy.md#confirming-a-delete-or-update); it needs the simple query protocol (psql, scripts,
several drivers) for now, and refuses what it cannot confirm instead of letting it through.

To leave the application alone and watch only people, scripts and agents, write the rules with
`except_users = ["app"]` (everybody but the application): see
[docs/policy.md](docs/policy.md#applications-on-one-side-people-and-agents-on-the-other).

Start in `audit` to see what your workload actually runs, then switch to `enforce`. In `enforce` mode a
blocked client gets a normal PostgreSQL error and keeps its connection:

```
ERROR:  invalid input syntax for type integer: "sluice: blocked by rule no-unbounded-write: add a WHERE clause"
```

(sluice makes the *server* raise this error, which keeps the order of replies, the extended protocol and
open transactions exactly right. The price is the SQLSTATE: `22P02`, not `42501`.)

Everything the file can say is in [docs/policy.md](docs/policy.md).

## What you get

Events go to stdout, one JSON object per line, ready for a log collector:

```json
{"ts":"2026-11-16T10:00:00.123Z","event":"connection_open","id":1,"client":"127.0.0.1:53341"}
{"ts":"2026-11-16T10:00:00.124Z","event":"startup","id":1,"user":"app","database":"mydb","application_name":"psql","protocol":"3.0"}
{"ts":"2026-11-16T10:00:00.130Z","event":"upstream_connected","id":1,"upstream":"db.internal:5432","tls":"TLSv1.3 TLS_AES_256_GCM_SHA384"}
{"ts":"2026-11-16T10:00:00.140Z","event":"statement","id":1,"user":"app","database":"mydb","kind":"query","sql":"select 1;","sql_len":9,"verdict":"allow","action":"relayed"}
{"ts":"2026-11-16T10:00:00.141Z","event":"statement","id":1,"user":"app","database":"mydb","kind":"query","sql":"delete from t;","sql_len":14,"verdict":"deny","rule":"no-unbounded-write","action":"blocked"}
{"ts":"2026-11-16T10:00:00.150Z","event":"connection_close","id":1,"reason":"client_closed","statements":2,"blocked":1,"bytes_from_client":314,"bytes_from_upstream":676,"duration_ms":27}
```

### When the database connection fails

The `upstream_error` event says why the database hop failed, and `connection_close` follows with its own
`reason`. Filter and alert on `code`, which is stable; `error` is the explanation for a person, written by
OpenSSL or the system, and changes from one version to the next.

```json
{"event":"upstream_error","id":1,"code":"tls_peer_alert","tls_alert":48,"error":"error:0A000418:SSL routines::tlsv1 alert unknown ca"}
```

| `code` | Meaning |
|---|---|
| `connect_failed` | the TCP connection to the database could not be made |
| `tls_not_supported` | the database answered that it does not do TLS |
| `tls_request_failed` | the TLS request could not be sent, or the database hung up on it |
| `tls_handshake_failed` | the handshake failed, for instance on an untrusted or mismatched certificate |
| `tls_setup_failed` | sluice could not even start a TLS session (out of memory, bad host name) |
| `tls_peer_alert` | the database sent a TLS alert once connected; `tls_alert` is its number in RFC 8446 (48 `unknown_ca`, 42 `bad_certificate`, 116 `certificate_required`: the usual refusals of a client certificate) |
| `tls_error` | any other TLS failure while relaying |
| `io_error` | the socket failed while relaying |

## What the log keeps of the SQL

`--log-sql full|normalized|none` (default `full`) chooses it.

| Mode | `sql` | other fields |
|---|---|---|
| `full` | the SQL as sent (first 8 KiB) | `sql_len` |
| `normalized` | the SQL with its values replaced by `$1`, `$2`... | `fingerprint`, `sql_len` |
| `none` | not logged (`"sql_redacted":true`) | `fingerprint`, `sql_len` |

The `fingerprint` is 16 hex digits and identifies the *shape* of a query: the same for `where id = 1` and
`where id = 987`, different for another query. Statements that do not parse have none.

**`normalized` withholds the text whenever it cannot vouch for it.** The PostgreSQL normalizer masks the values
of ordinary statements (and of `ALTER ROLE ... PASSWORD`, `SET`, function bodies), but leaves them in
`CREATE SERVER ... OPTIONS (password '...')`, `COPY ... FROM PROGRAM '...'`, `COMMENT ON`, `PREPARE`, column
defaults, and in every comment. So its output is only logged after the PostgreSQL lexer has found no constant
and no comment left in it; otherwise the event has `"sql_redacted":true` and the fingerprint alone. The message
of a parse error is cut before the part that quotes the SQL (`syntax error`, not `syntax error at or near
"..."`). The client still gets the full message.

What these modes do not hide: the names of tables and columns, the names of prepared statements, the user and
the database, and what a *failed* statement told the database. They make the log safe to keep, not the
traffic safe to publish.

`kind` is `query` for a simple query and `parse` for a prepared statement of the extended protocol (the
usual path of drivers). Without a policy the `verdict` and `action` fields are absent and the bytes are
never changed. With `--upstream-tls`, the `upstream_connected` event says which protocol and cipher the
database hop uses.

## Limits today

So that nothing surprises you:

- **sluice judges statements, not their effects.** A `DO` block, a function body or a trigger runs code it
  never sees, a plain `SELECT` can have side effects, and `WHERE true` is a `WHERE`. See
  [what it is not](#what-it-is-not).
- **Cost.** One measure, `pgbench` with 8 clients against PostgreSQL 17 in Docker on a laptop (one run of 8
  seconds each, so read it as an order of magnitude): about 0.1 ms more per query, and 10 to 15 % less
  throughput than going straight to the database, with or without rules (read-only 10.4k to 9.2k and 9.0k
  transactions per second; TPC-B writes 1.45k to 1.24k). sluice uses one thread, so it is for a team or a
  workload, not for the whole traffic of a large service.
- **By default the log contains your SQL, as sent.** A literal typed into a simple query appears in clear in
  `sql`, so treat the log like the data it describes. Passwords (the login ones), bind parameters and `COPY`
  data are never read, so they never reach the log. `--log-sql normalized` keeps the values out: `where
  email = 'a@b.c'` is logged as `where email = $1`, with a `fingerprint` that is the same for every value
  of the same query. `--log-sql none` logs the fingerprint only. See [what the log keeps](#what-the-log-keeps-of-the-sql).
- **The client side is in clear text unless `--listen-tls` is given.** Without it `sslmode=prefer` (the default)
  and `disable` work and `sslmode=require` fails with "server does not support SSL": the client side is meant
  to be loopback or pod-local. With it, only TLS clients are served and no client certificate is asked for.
  A self-signed certificate protects against listening, not against someone impersonating sluice.
- **No channel binding.** With TLS to a database that uses SCRAM, the server offers `SCRAM-SHA-256-PLUS`
  (login bound to its TLS session). That binding cannot cross a proxy, and a client in clear refuses the
  offer, so sluice takes it out of the server's offer; clients log in with plain `SCRAM-SHA-256`. A client
  that insists on channel binding (`channel_binding=require`) fails to connect.
- **Client certificate for the database**: `--upstream-cert FILE --upstream-key FILE` (PEM) make sluice show a
  certificate to a database that asks for one (`clientcert=verify-full`, or the `cert` method). The key must not
  be encrypted: sluice never asks for a passphrase, and a key that needs one stops it at startup. These two
  files are the certificate of **sluice**, not of the clients, who still authenticate to the database in the usual
  way through it. The files are read once at startup (a `SIGHUP` does not reload them).
- **Confirmations** (`action = "confirm"`) work with the simple query protocol only: a prepared statement
  (what most ORMs send) or a message with several statements that matches such a rule is refused, with the
  reason in the error. The rows stay locked while the person decides, rows removed by a cascade in other tables
  are not listed, and a trigger that acts outside the database has acted even if the answer is no.
- **Messages sluice cannot read** (syntax error, over 1 MiB, malformed, fast-path function call, and a quote
  after a backslash inside a string, which the server may read differently once a session changes
  `standard_conforming_strings` or `client_encoding`) are blocked in `enforce` mode unless the policy says
  `on_uninspectable = "allow"`. See [Strings read two ways](docs/policy.md#strings-read-two-ways).
- One `statement` event is one message. A simple query holding several statements is a single event, but
  each statement is judged on its own.
- `sql` is cut at 8 KiB in the log (`"truncated":true`, `sql_len` keeps the real length).
- The policy is read at startup and again on `SIGHUP` (`kill -HUP <pid>`): the change applies at once, to
  connections that are already open as well. A file that cannot be read or understood is reported and the
  previous policy stays in force. A policy cannot be added or removed by a reload: sluice started without
  `--policy` has nothing to reload.
- **Warnings at startup.** sluice says so, as a `warning` event, when it listens on an address that is not
  this machine only and `--listen-tls` is not used, when `--listen-tls self-signed` is used (the clients cannot
  check who they talk to), when `--upstream` is not local and not encrypted, when a private key is readable by
  others, and when a table entry of the policy has upper-case letters (it
  would only match a table written with quotes, so the rule probably never applies).
- **The database name can have several addresses.** They are tried one after the other, so `--upstream
  localhost:5432` reaches a database that only listens on `127.0.0.1` although `localhost` also means `::1`.
  An address that does not answer at all (packets dropped) is waited for until the 10 second connection
  timeout; the next one is tried only when an address refuses or is unreachable.
- Connections to the clients and to the database use TCP keepalive (probe after 60 s of silence, every 10 s,
  give up after 6): a peer that disappeared without closing is noticed in about two minutes and its slot is
  given back. There is no timeout on a connection that is merely idle.
- In `enforce` mode, replication connections are refused and an impossible message header closes the
  connection.
- An error before the relay starts (upstream down, TLS impossible, invalid first packet) reaches the client
  as a normal PostgreSQL `FATAL` message.

## What it is not

- **Not a security boundary against a determined attacker.** Code that runs inside the server is out of its
  sight, and so are the effects of a function. `GRANT` and row-level security stay the real protection.
  sluice is a safety net for mistakes, plus an audit trail. The full list is in
  [docs/design.md](docs/design.md#12-what-sluice-cannot-see).
- Not a connection pooler (use pgbouncer), not a load balancer, no caching.
- No dashboard, no control plane, no multi-tenant server, no MySQL.

The reasoning behind these choices is in [docs/design.md](docs/design.md).

## Build

Needs a C11 compiler, [Meson](https://mesonbuild.com) (with Ninja) and **OpenSSL 3 or newer** with its
development files, found through pkg-config (on macOS: `brew install openssl`; on Debian: `libssl-dev`;
LibreSSL is not supported). It is built and tested on macOS (Apple clang) and on Linux (Debian 12, GCC 12,
OpenSSL 3.0), both normally and with the sanitizers; the warnings are errors, so a compiler that warns about
more than the other one stops the build.
Python 3 (and `ps`) is used by the integration test, and the `openssl` tool by its TLS scenarios, which are skipped
when it cannot make a certificate. The map of the code is in [docs/architecture.md](docs/architecture.md).

```bash
meson setup build
meson compile -C build
meson test -C build
```

The first `meson setup` downloads the source of [libpg_query](https://github.com/pganalyze/libpg_query)
18.1.0 (a 4.6 MB tarball from GitHub, checked against the SHA-256 pinned in `subprojects/libpg_query.wrap`)
into `subprojects/`. It then compiles in about ten seconds. Without network access, put the tarball in
`subprojects/packagecache/` first.

With sanitizers:

```bash
meson setup build-asan -Db_sanitize=address,undefined
meson test -C build-asan
```

A report of the undefined-behaviour sanitizer fails the test (`-fno-sanitize-recover`): with GCC it would
otherwise only be printed. Run this on Linux as well as on macOS: glibc declares more pointers as never null
than the macOS headers do.

Platforms tried: macOS (Apple clang), Debian 12 (GCC 12, clang 16 with the sanitizers) and Alpine 3.20 (GCC 13,
musl). **clang 14 does not build on aarch64**: the PostgreSQL parser it compiles asks for SVE support that
clang 14 lacks (use GCC or clang 16 or newer). Everything above was built with warnings as errors.

Against a real PostgreSQL (in a throwaway Docker container, off by default; it checks what the server does with
what sluice lets through: logins, rules, the strings and `search_path` attacks, reload, the log, TLS with a
client certificate):

```bash
SLUICE_REAL_PG=1 meson test -C build realpg
```

Code coverage of the tests (GCC, needs `gcovr`): `meson setup build-cov -Db_coverage=true && meson test -C
build-cov && ninja -C build-cov coverage-text`. About 92 % of the lines of `src/` are run; what is left is
mostly out-of-memory and system-call failure branches that a test cannot provoke.

Style: `tools/format.sh` rewrites the sources with clang-format (`tools/format.sh check` only reports), following
`.clang-format`. It uses `uvx clang-format` when no clang-format is installed.

Fuzzing: `meson test` runs a short fuzz pass. A longer one, with a seed so it can be repeated:

```bash
build-asan/fuzz/fuzz_driver -t 600 -s 7 fuzz/corpus
```

Eleven targets cover the protocol parsers, the policy file, the JSON escaper, the SQL classifier, the byte
queue and the message scanner (the part that decides which bytes reach the database, checked against an
independent model with the stream cut in every way), with checks of invariants and not only of crashes. Details, and what it does and does not prove, in
[docs/design.md](docs/design.md#14-fuzzing).

## Roadmap

- **v0.1** (done): TCP passthrough between client and Postgres, parse the startup message, JSON log of each connection.
- **v0.2** (done): parse the query messages (simple and extended protocol), one JSON log line per statement.
- **v0.3** (done): policy file and rules (writes without `WHERE`, DDL, read-only), `audit` and `enforce` modes, SQL read with libpg_query.
- **v0.4** (done): TLS towards the database (`require`, `verify-full`), fuzzing of the parsers.
- **v0.5** (done): rules by table (`tables`, `outside_tables`, `match = "any"`), with the worst case assumed for statements whose tables the parser does not report.
- **v0.6** (done): reload the policy on `SIGHUP`; the message scanner split out of the connection code and fuzzed against an independent model.
- **v0.7** (done): `--log-sql normalized` and `none`, to keep the values of the SQL out of the log.
- **v0.8** (done): a client certificate towards the database (`--upstream-cert`, `--upstream-key`).
- **v0.9** (done): hardening found by reading and by testing on a real server: strings that the server may
  read differently, `search_path` and table rules, reconnecting to every address of a name, TCP keepalive,
  Linux and musl builds, a test against a real PostgreSQL.
- **v0.10** (done): confirming a `DELETE` or `UPDATE` (`action = "confirm"`): sluice runs it in a transaction that
  it does not commit, shows a person the count and the first rows on the terminal, and commits or rolls back.
  Simple query protocol only for now.
- **v0.11** (done): TLS towards the clients (`--listen-tls self-signed`, or `--listen-tls-cert` and
  `--listen-tls-key`), so that `sslmode=require` works and sluice can listen beyond the machine.
- **Later**: that real-PostgreSQL test in a CI, row-count and duration limits.

## Third-party code

sluice is MIT. It builds [libpg_query](https://github.com/pganalyze/libpg_query) (BSD-3-Clause), which
embeds the PostgreSQL parser and three small libraries. Their licenses travel with the source tree that
Meson downloads into `subprojects/libpg_query-18.1.0/`: `LICENSE` (libpg_query), `src/postgres/COPYRIGHT`
(the PostgreSQL parser), `vendor/upb/LICENSE` and `vendor/upb/third_party/utf8_range/LICENSE` (upb and its
UTF-8 validator), and the notice in the header of `vendor/xxhash/xxhash.c` (xxHash, BSD 2-Clause). The
`.wrap` file and the Meson build description are all that is kept in this repository.

It links against the OpenSSL of the system; OpenSSL is not bundled.

## License

MIT
