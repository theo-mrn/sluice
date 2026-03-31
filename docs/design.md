# Design decisions

Written before the code, so that the project does not drift while it is being built. If a decision here
changes, change it here first.

## 1. One binary, deployed next to the client

sluice is a single process: it accepts client connections on one address and forwards them to one upstream
Postgres. Everything else (laptop, Kubernetes sidecar, CI service) is only a way to launch that process.

Why next to the client and not next to the database:

- The client-to-sluice hop is loopback or pod-local, so it needs no TLS (see 3).
- One policy per workload: the agent gets a read-only policy, the migration job gets another.
- The failure domain is one workload. A crashed sluice breaks one client, not every client of the database.

A shared central deployment is possible with the same binary but is not designed for in v1.

## 2. Scope of v1

In: wire protocol relay, startup message parsing, simple and extended query parsing, JSON log, a rule file,
`audit` and `enforce` modes.

Out: pooling, load balancing, query rewriting for the client's benefit, caching, a UI, a Kubernetes
operator, a control plane, support for other databases. Each of these is a project of its own and each is a
way to never ship. The only message sluice ever writes is the replacement of a blocked one (see 11).

## 3. TLS

To read queries, sluice must see them in clear text, so it terminates the client side.

- **Client to sluice**: plain text by default, on loopback or inside the pod: sluice then answers `N` to the
  client's `SSLRequest` and `GSSENCRequest`, so clients must use `sslmode=disable` or `prefer`. With
  `--listen-tls` it is TLS, with sluice as the server (v0.11, below). `GSSENCRequest` is always declined.
- **sluice to Postgres**: TLS, with sluice as the TLS client, through OpenSSL (v0.4). The option is
  `--upstream-tls off|require|verify-full`:
  - `off` (default): plain text. Fine for a database on the same machine; sluice logs a `warning` at startup
    when the upstream is anywhere else.
  - `require`: encrypted, but the certificate is not checked, so it protects against listening, not against
    someone impersonating the server. It warns for that reason.
  - `verify-full`: the certificate chain is checked (the system store, or the PEM file of `--upstream-ca`)
    and so is the name, against the subject alternative names: a DNS name, or an IP address when the
    upstream is given as one.
  There is no `prefer`: a mode that falls back to clear text when anything goes wrong protects against
  nothing. When TLS is asked for and cannot be had (no TLS on the server, bad certificate, handshake
  failure) the client gets a `FATAL` error and the connection ends. TLS 1.2 or newer.
- **The negotiation is PostgreSQL's own**: sluice sends an `SSLRequest`, the server answers one byte, and on
  `S` the handshake follows on the same socket. Exactly that one byte is read before the handshake, so
  bytes a hostile server sends in clear right after it cannot be taken for TLS data.
- **Read-ahead is on**, deliberately. OpenSSL then pulls several records out of the socket at once, and some
  of them wait inside the library while the socket is quiet. `conn.c` handles that (`sl_tls_pending`, and a
  zero timeout in the poll loop), but with OpenSSL's default of reading record by record that path almost
  never runs, so it would be untested code waiting for another version of the library. Turning read-ahead
  on makes it the normal path, and `scenario_tls_many_small_records` fails without the handling.
- **SCRAM channel binding cannot work through sluice, and the failure is not subtle.** A PostgreSQL server on
  TLS offers `SCRAM-SHA-256-PLUS` (login bound to its TLS session) next to `SCRAM-SHA-256`. The client talks
  to sluice in clear, and libpq refuses an offer of PLUS on a connection that is not on TLS: with a TLS
  upstream and the default authentication of PostgreSQL, nobody could log in. This was not visible with a
  fake server; it showed up on the first run against a real one. So, when the TLS to the upstream is up,
  sluice reads the server's first authentication message and sends it on without `SCRAM-SHA-256-PLUS`
  (it keeps the other mechanisms, in order; if PLUS is the only one it leaves the message alone). Nothing
  else of the server's stream is looked at. The client picks `SCRAM-SHA-256`, which the server accepts on
  TLS. A client that insists on channel binding (`channel_binding=require`) gets "channel binding required,
  but SSL not in use": the right answer, since the binding it asked for does not exist.
- **A client certificate towards the server** (`--upstream-cert`, `--upstream-key`, both or neither, and only with
  TLS on). A server can ask for one (`clientcert=verify-full` in `pg_hba.conf`, or the `cert` method). Decisions:
  - *The key is never decrypted by asking.* OpenSSL's default for an encrypted PEM key is to prompt on the
    terminal of the process, which in a daemon is either nobody, or a hang at startup. sluice installs a
    passphrase callback that always says no, so an encrypted key stops it at startup with a message instead.
    This is tested on a real pseudo-terminal, because without a terminal OpenSSL's prompt fails the same way as
    the refusal and the difference cannot be seen.
  - *Everything is checked at startup.* The certificate and the key are loaded, and that they match is checked
    (OpenSSL notices the mismatch when loading the key; the message says so rather than blaming encryption).
    The files are not reloaded on `SIGHUP`.
  - *The key's permissions are only warned about.* A key readable by group or others gets a `warning` event, not
    a refusal, because an orchestrator often mounts secrets with group access chosen by the operator.
  - *It is sluice's identity, not the clients'.* Every client connection through sluice presents the same
    certificate to the database. Telling clients apart is still the database's own authentication, through the
    proxy.
- **TLS towards the clients** (v0.11; the proposal of section 19 A, as built). `--listen-tls self-signed`, or
  `--listen-tls-cert` with `--listen-tls-key` (both or neither, not together with `self-signed`; everything is
  loaded at startup and a failure stops sluice). Decisions:
  - *TLS is mandatory once configured.* An optional TLS toward the client would let a client that forgot
    `sslmode=require` send its queries, and its password, in clear. A startup in clear text is refused with
    SQLSTATE 28000 "this server requires TLS" (close reason `tls_required`). A `CancelRequest` in clear is
    still forwarded: PostgreSQL's cancel key travels in clear in any case, and drivers send it on a new
    connection without TLS.
  - *Nothing may follow the `SSLRequest` in clear.* sluice answers `S` only when the request is the only thing
    received (checked on the buffer, the same bytes-after-the-answer rule as for the upstream, mirrored). Bytes
    queued behind it would otherwise be taken for the start of the encrypted stream, the classic "STARTTLS
    injection". A second `SSLRequest` under TLS is refused too (08P01). Mutation-tested.
  - *The self-signed certificate* is an EC P-256 key generated at startup, valid ten years, random serial,
    never written to disk. It is enough for `sslmode=require`; sluice warns that a client cannot check who it
    talks to.
  - *No client certificate is asked for.* Who is connecting is still PostgreSQL's own authentication, passed
    through. The key's permissions are warned about, as for `--upstream-key`.
  - *TLS 1.2 or newer*, the same non-blocking handling as the upstream side (`WANT_READ`/`WANT_WRITE`, bytes
    held inside the library: `sl_conn_has_pending` looks at both sides). The tests move 4 MB and 1 MB through
    it and run the real `psql` of the PostgreSQL image with `sslmode=require` and `disable`.
  - *No SCRAM-PLUS concern here.* Channel binding is between the client and the server it believes it talks
    to; with TLS on the client side the binding would be to sluice's session, which the upstream does not
    share, so sluice keeps removing `SCRAM-SHA-256-PLUS` from the server's offer (section 3 above).

## 4. Authentication

Pass-through. sluice relays the authentication exchange and never reads, stores or checks passwords. The
database stays the only authority on who is who.

**An accepted risk.** Because sluice relays the login, whoever knows the password of a role can use that role,
and a rule that leaves the role alone (the application's) leaves them alone too. Someone, or an agent, that takes
the application's credentials instead of using their own escapes the rules that are written for people. That is
the price of not keeping any secret in sluice, and it was chosen: the alternative (sluice holding the database
credentials, section 19 B) is not built and not planned. What reduces the risk is outside sluice: a role of their
own for each person and agent, and the application's credentials kept out of their reach.

## 5. Identity

Taken from the startup message (`user`, `database`, `application_name`) and written on every log line.
Rules can match on user and database. This is a label supplied by the client, not proof of identity.

## 6. Failure behaviour

- A denied statement gets a normal Postgres `ErrorResponse` followed by `ReadyForQuery`, produced by the
  server itself (see 11); the connection stays usable.
- A message sluice cannot understand (syntax error, over 1 MiB, malformed, fast-path function call) is
  *uninspectable*. In `enforce` mode it is blocked unless the policy says `on_uninspectable = "allow"`; in
  `audit` mode it is logged and relayed. Failing closed is the default because an inspector that waves
  through what it cannot read is easy to get around.
- A message header that cannot be valid: in `enforce` mode the connection is closed, since nothing after it
  can be trusted to mean what it looks like; in `audit` mode inspection stops and the stream is relayed.
- Replication connections (`replication=...` in the startup packet) are refused in `enforce` mode: they
  speak another protocol, and `replication=database` runs ordinary SQL through it.
- Policy errors at startup are fatal: sluice refuses to start rather than run without its rules. Unknown
  keys and values are errors too, so that a typo cannot silently weaken a policy.

## 7. Safe adoption

`audit` is the default mode. Run it first, read what the workload really does, then switch to `enforce`.

## 8. Language and dependencies

C11, no allocator tricks, few dependencies:

- **libpg_query** (BSD-3-Clause) for SQL: it is the PostgreSQL parser itself extracted as a library, so the
  answer follows the real grammar instead of a guess from keywords. It is a Meson subproject pinned by the
  SHA-256 of its release tarball (`subprojects/libpg_query.wrap`); the upstream Makefile is replaced by a
  short `meson.build` that compiles the same files with the same flags. It is always built optimised and
  without sanitizers, whatever the build type. Version 18.x (the PostgreSQL 18 grammar) was chosen on
  purpose: a parser newer than the server only accepts more, which is harmless, while an older one would
  refuse valid syntax of a newer server.
- **No TOML library.** The policy needs a handful of constructs, so sluice reads a strict subset itself
  (about 300 lines, fully tested). Everything outside the subset is an error, never a silent fallback.
- **OpenSSL 3 or newer** for upstream TLS, the one of the system, found through pkg-config and not bundled
  (built and tested against 4.1). LibreSSL is not supported.

The build runs with sanitizers (`address,undefined`) and the parsers are fuzzed (see 14).

## 9. Concurrency model

One thread, one `poll()` loop, non-blocking sockets. No threads, and no `epoll` or `kqueue` in v1.

- The target is one workload per process: tens of connections, not tens of thousands. `poll()` behaves the
  same on macOS and Linux, and its cost is invisible at that scale.
- No locks and no shared state: the whole proxy reads as one sequential program. That matters more than
  raw throughput for something that sits in the path of every query.
- If a profile ever shows the loop is the bottleneck, `poll()` can be replaced inside `server.c`; no other
  module knows about it.
- Known cost: `getaddrinfo()` blocks the loop while it resolves the upstream name.
- Descriptors and sockets: each connection uses two; keepalive is on for both sockets; `accept()` is paused
  for 500 ms after a failure that does not go away by itself (see architecture.md).
- Limits: 1024 connections by default, lowered automatically if the process cannot get enough file
  descriptors (each connection uses two). Beyond the limit, clients get a PostgreSQL `FATAL` (53300).

## 10. What is logged, and what never is

- **Logged**: connection events, the startup parameters (`user`, `database`, `application_name`), and the
  SQL text of simple Query and Parse messages (the first 8 KiB, the full length is kept).
- **Never read, so never logged**: passwords and every other `p` message, Bind parameters, `COPY` data,
  anything the server sends back.
- The SQL text can itself hold secrets (literals in a simple query). The log has to be handled like the
  data it describes. `full` is the default because an audit trail that cannot say what was run is of little
  use; `--log-sql normalized` and `none` exist for when it can say less (see 17).
- Every value that comes from the client is untrusted and goes through the JSON escaper, which guarantees
  one valid line per event whatever the bytes are: control characters are escaped, invalid UTF-8 is
  replaced, cuts never split a character.
- A message with several statements is one event; the verdict is computed per statement (see 12).
- Without a policy, and in `audit` mode, the stream is never changed. If sluice cannot make sense of the
  bytes it stops reading them and keeps relaying them, so a bug in the scanner can lose a log line but
  cannot corrupt a query. Only in `enforce` mode does a message get replaced, and only to block it.
- With a policy, each `statement` event also carries `verdict` (`allow`, `deny`, `uninspectable`), the
  `rule` that decided, a `detail` for uninspectable messages and `action` (`relayed` or `blocked`).

## 11. How a statement is blocked

Three ways were considered:

1. **Answer in place of the server.** sluice would write an `ErrorResponse` and a `ReadyForQuery` into the
   server's stream. To do that correctly it would have to frame the server's messages (to write between
   two of them), count `ReadyForQuery` messages to order its answer after the replies to earlier pipelined
   requests, reproduce the "ignore everything until Sync" behaviour of the extended protocol, and keep the
   transaction status it does not own. Every one of those is a place to get the protocol subtly wrong.
2. **Close the connection.** Safe and trivial, but a typo in a `psql` session then costs the session.
3. **Replace the message by one that fails on the server.** Chosen.

The replacement keeps the kind of message and the statement name, and carries `select '<reason>'::int`: an
unknown literal that is not an integer, which PostgreSQL rejects while analysing the statement, with any
role, in any database, at `Parse` time in the extended protocol. For a message too big to be held, only
its 5 byte header is replaced and the body is thrown away as it arrives.

What this gets for free, because the server itself does it:

- the `ErrorResponse` and `ReadyForQuery` come in the right place, in the right order, whatever the client
  has pipelined;
- in the extended protocol the server skips the rest of the batch up to `Sync`, as it would for any error;
- an open transaction really is aborted: a `COMMIT` afterwards is a `ROLLBACK`, so a blocked statement
  cannot leave a half-applied transaction behind. This was checked on PostgreSQL 17;
- the blocked statement never reaches the server at all.

What it costs: the client sees the server's own error, SQLSTATE `22P02` (`invalid input syntax for type
integer`) with the reason as the value, for example `"sluice: blocked by rule no-ddl: schema changes go
through migrations"`. It is not `42501`. An application that classifies errors by SQLSTATE will see an
"invalid text representation" error. The log has the real reason, and the text is meant to be read by a
person.

The reason is made safe before it goes into the literal: quotes are doubled, backslashes, control
characters and non-ASCII bytes become spaces or `?`, the length is capped, and rule names and messages are
restricted to plain ASCII when the policy is loaded. The result cannot leave the string literal whatever
`standard_conforming_strings` or `client_encoding` say. The parser's own error text goes through the same
function.

## 12. What sluice cannot see

sluice judges statements, not their effects. It is a safety net, not a boundary:

- **Code that runs inside the server**: the body of a `DO` block, a function, a procedure, a trigger or a
  rule is not parsed. `DO` and `CALL` have a match of their own (`procedural`) so they can be refused.
- **Side effects of a plain `SELECT`**: `select pg_terminate_backend(...)` or `select nextval(...)` are
  reads for sluice. "Read-only" means "only statements of read-only kinds", not "cannot change anything".
- **The content of a `WHERE`**: `where true` is a `WHERE`. The rule asks for a clause, not for a good one.
- **Locks in sub-selects**: `FOR UPDATE` is seen on the statement itself and on the arms of a `UNION`, not
  inside a sub-select.
- **Statements held by name**: `PREPARE p AS <statement>` is judged at `PREPARE` time on the statement
  inside it, and `EXECUTE p` is let through, because whatever it can run was judged when it was prepared.
- **What goes around sluice**: a connection that does not go through it.

One thing is not a limit but was a hole, found with a real server and closed (section 18): sluice and the
server could read the same bytes as different statements.

Reading the SQL has a cost too, measured on a laptop: an ordinary statement takes 6 to 32 microseconds to
classify, which is invisible. A 1 MiB statement takes about 0.2 second (a huge `INSERT ... VALUES` or a
script of 100 000 tiny statements), during which the single thread serves nobody else. That is acceptable
for one workload per process and is another reason for the 1 MiB limit. Pathological nesting is refused
cleanly instead of crashing: an expression of a million `+ 1` ends in "stack depth limit exceeded", which
counts as uninspectable.

`SET` and `RESET` are on the read-only allowlist only for harmless settings (`application_name`,
`client_encoding`, `DateStyle`, `TimeZone`, `search_path`, timeouts, `standard_conforming_strings`,
`bytea_output`, `client_min_messages`, `transaction`, session characteristics) and for custom settings
(names with a dot, such as `myapp.user_id`). `SET ROLE` and `SET SESSION AUTHORIZATION` are not.

## 13. Judging a message

The SQL of a message is split into the statements that would run: those written in it, plus the ones
hidden inside (data-modifying CTEs, `EXPLAIN ANALYZE <statement>`, `PREPARE ... AS <statement>`,
`DECLARE ... CURSOR FOR <query>`, `COPY (<query>) TO ...`). Each gets a set of flags (see `sql_check.h`)
and is judged on its own against the rules, in file order; the first rule that applies decides. A message
is blocked as soon as one statement is denied, because a message cannot be forwarded in part.

Judging each statement separately matters: with "allow `ddl` for the migrator" followed by "deny unbounded
writes", a message holding a `CREATE TABLE` and a `DELETE` without `WHERE` must still be blocked for the
`DELETE`. A union of flags over the whole message would have let it through.

A statement kind this version does not know is never read-only, so a statement added by a future
PostgreSQL is refused by a read-only policy until sluice learns about it.

## 15. Rules about tables

A rule can depend on the tables a statement touches (`tables`, `outside_tables`, and `match = "any"` to
talk about every statement). The tables come from the parser's own summary (`pg_query_summary`), not from a
walk through the parse tree that sluice would have to keep in step with PostgreSQL.

**The parser does not report every table, and the first design assumed it did.** Looking at its output for
about forty kinds of statement showed gaps: `MERGE` omits its source table, and a number of statements
(`DROP SCHEMA ... CASCADE`, `GRANT ... ON ALL TABLES`, `COMMENT`, `VACUUM`, `CREATE FUNCTION`, `CREATE
TRIGGER`, `DO`, `CALL`) touch tables without naming them. With "allowed tables only" as the main use, each
gap is a way round: `MERGE INTO orders USING secret` would have passed an allowlist of `orders`.

So every statement kind is either on a list of those whose tables are known to be reported (checked one by
one in `tests/test_sql_check.c`, plus those that touch no table at all), or it is flagged
`SL_SQL_TABLES_UNSEEN`. For an unseen statement a table condition is decided by the worst case: a `deny` rule
applies, an `allow` rule does not. A statement kind that PostgreSQL adds later is unseen until someone checks
it, so the failure mode of a new version is a refusal, not a leak. `DROP` and `ALTER TABLE` are known only
when they work on a table; `DROP INDEX`, `DROP SCHEMA`, `ALTER INDEX` are not.

**Granularity: the statement of the message, not the effective statement.** The tables are worked out for
each statement of a message (the message is cut at the boundaries the parser gives, and each part is
summarised on its own). The statements hidden inside one (a data-modifying CTE, the statement of `EXPLAIN
ANALYZE`) share its tables. The alternative, an exact table list for each hidden statement, needs a walk
through the whole parse tree. The shared list can only make a rule apply more often, never less, which is
the right direction for a guard; the exception is `allow` rules, which can then apply to a hidden statement
that touches other tables than the one they name. Writing allow rules narrowly is the remedy.

**Matching.** Names are those of the parser (lower case unless quoted). A rule entry without a schema matches
the table in any schema; an entry with a schema matches that schema only. A table written without a schema is
the problem: its schema is the first one of the `search_path` that has it, and a client sets that freely
(`SET search_path = tenant_b`), or through `set_config()`, so nothing in sluice can know it. It was once
taken to be in the schema of the entry; found on a real server, that let `select * from orders` read
`tenant_b.orders` through a rule that kept a client in `tenant_a`. Now the comparison has three answers:
yes, no, and unknown for an unqualified table against a qualified entry. Unknown is handled like the tables
that cannot be seen (`TABLES_UNSEEN`): a deny rule applies, an allow rule does not. The price is that a
policy with qualified entries asks the SQL to qualify its tables.
`outside_tables` never matches a statement that touches no table, so session housekeeping (`begin`,
`set application_name`, `select 1`) needs no entry in an allowlist.

**Cost.** The tables take one more parse per statement, so they are only worked out when some rule is about
tables (`sl_policy_needs_tables`). Policies without such rules cost what they cost before.

**Not covered**: tables reached through a function, a view or a trigger, and everything in a `DO` block.

## 17. Keeping the values out of the log

`--log-sql normalized` logs the SQL with its literals replaced by `$1`, `$2`..., and a fingerprint of the
query; `none` logs the fingerprint only. Both come from the PostgreSQL normalizer and fingerprint.

**The normalizer was not trusted as it comes.** Its output was looked at for about eighteen kinds of
statement, and it keeps values in several: `CREATE SERVER ... OPTIONS (password '...')`, `COPY ... FROM
PROGRAM '...'`, `COMMENT ON`, `PREPARE ... AS`, column defaults, and every comment (`-- hunter2` survives).
Logging it blindly would have looked like redaction and still published secrets. So the text is accepted only
after the PostgreSQL lexer has run over it and found no string, number, bit or hex constant and no comment.
Otherwise the text is withheld (`sql_redacted`) and the fingerprint, which is computed from the parse tree
and carries no value, is all that is logged. The cost is that some harmless statements lose their text (an
`ALTER TABLE ... DEFAULT 5`, anything with a trailing comment such as the ones some ORMs add). Withholding a
harmless text is the right way to be wrong here.

**Error messages quote SQL.** `syntax error at or near "hunter2"` is the parser's way to say where it stopped.
In the log the message is cut before ` at or near`. The client's error is not touched: it is its own SQL.

**Not hidden**: identifiers (tables, columns, prepared statement names), the user, the database, and the
`tables` field of the log. These are the schema, not the data; if the schema is the secret, the answer is
not to log at all.

**The normalized text is for reading, not for replaying.** `do $$ ... $$` becomes `do $1`, which is not SQL.
When it does parse, normalizing it again changes nothing (checked by the fuzzer).

## 16. Reloading the policy

On `SIGHUP` the policy file is read again. The decisions behind it:

- **Fail towards the last good policy.** At startup a bad file stops sluice (§6): there is nothing better to
  fall back on. On a reload there is: the policy in force. Dropping to "no rules" would turn a typo into an
  open door, and exiting would turn it into an outage, so the old rules stay and the failure is logged
  (`policy_reload_failed`, with the line).
- **At once, for open connections too.** The reason to reload is usually to tighten something, and a
  guard whose new rules only reach new connections is not one: a long-lived client (an agent session, a
  pooled connection) would keep the old rules for hours. Connections do not hold the policy: they read the
  current one through a pointer each time they judge a message.
- **Atomic.** The server keeps two slots. The file is read into the free one, and only a fully valid policy
  is switched to, after which the old slot is freed. The switch happens between two events of the
  single-threaded loop, never during one, so no handler ever sees the policy change under it and a
  pointer to a rule is good for as long as the handler runs.
- **No policy cannot become a policy, nor the reverse.** Whether a connection asks about fast-path calls
  and whether messages are judged at all is decided when it is opened; that is only sound if having a
  policy is a property of the process. Starting a guard without rules and adding some later is a different
  deployment.
- **Only the policy file.** Addresses, TLS options and the rest of the command line are read once.

## 14. Fuzzing

Everything that reads bytes sluice does not control has a fuzz target, in `fuzz/targets.c`, behind the
libFuzzer entry point `LLVMFuzzerTestOneInput`: the first byte of an input picks the target.

| Target | What it checks besides "does not crash" |
|---|---|
| startup packet | lengths and offsets stay inside the input; parameter values point into the packet |
| message framing | a complete message agrees with its header; only a bad header makes a complete message fail |
| Query / Parse | no NUL in the text, every pointer inside the payload |
| blocking message | the reason cannot leave its string literal: every quote is doubled, nothing else can break out |
| JSON string | the output is always one valid JSON string of valid UTF-8, whatever the input |
| host and port | the parts are bounded, numeric, free of brackets |
| policy file | an error always names the source; a success holds unique names and one flag per rule |
| SQL classification | the PostgreSQL parser, on inputs up to 2 KiB |
| byte queue | the buffer against a plain array, after every append, consume, replace and reserve |
| SASL offer | the rewritten offer is the old one minus PLUS, in order, and rewriting it again changes nothing |
| message scanner | the same bytes and verdicts whether the stream arrives in one read, in irregular reads or one byte at a time; and exactly the output of an independent model that reads the whole stream at once (see below) |

`fuzz/make_corpus.py` writes the 61 seed inputs (valid ones and edge cases). `fuzz/driver.c` replays them
and mutates them at random with a seed, so a run can be repeated; before each input it writes the input to
a file, so after a crash that file is the culprit. A short run is part of `meson test`; longer ones:

```bash
build-asan/fuzz/fuzz_driver -t 600 -s 7 fuzz/corpus
```

What this is and is not:

- The driver is a **blind mutation fuzzer**: it does not see coverage, so it is weaker than libFuzzer. It is
  there because Apple's clang ships no libFuzzer. The same targets build with libFuzzer on a machine that has
  it (`-Dfuzzer=enabled`); that build could not be tried on the machine this was written on.
- About 1.4 million inputs per 3 minutes of run on a laptop, under ASan and UBSan, found no crash. It did
  find one defect, through an invariant: the host of `HOST:PORT` accepted anything without a colon,
  newlines and quotes included. It is now checked.
- Injected defects (a missing length check, a quote not doubled, a wrong `memmove`...) are found within
  seconds. That is how the harness is known to be able to fail.
- **The message scanner needed an oracle, not only invariants.** The first version of its target checked
  that cutting the stream differently changes nothing, and that nothing is lost when nothing is blocked.
  Injected defects such as a byte too many when releasing a message, a blocked body that is not thrown away,
  or a size limit off by one slipped through half a million inputs, because a scanner that is wrong in the
  same way for every cut, and still sends every byte in the end, satisfies both. The target now also runs
  a deliberately simple second implementation (`fz_model` in `fuzz/targets.c`), which reads the whole stream
  at once with no state, and requires the same output and the same verdicts. With it, those defects are
  found within seconds. The scanner itself lives in `src/scanner.c` for this reason: it used to sit in
  `conn.c`, between two sockets, where nothing could drive it.
- **Not fuzzed**: the rest of the connection state machine in `conn.c` (timeouts, the TLS negotiation, the
  flow control between the two sockets), which needs sockets. The integration tests cover it with scripted
  peers.

## 18. Reading the SQL the way the server does

A proxy that judges SQL has a problem a database does not have: it must cut the text into statements exactly
where the server will. Where it cuts elsewhere, the rule is applied to one statement and another one runs.
This was found, not foreseen: with `no-unbounded-write` in `enforce` mode, `SET standard_conforming_strings =
off` followed by one message was judged `allow` and emptied the table; the same with `SET client_encoding =
'SJIS'` and the bytes `E'` 0x95 0x5c `'; delete from t; --'`, where 0x95 0x5c is a single character for the
server and `\'` an escaped quote for the parser. Both were reproduced on PostgreSQL 17 on a bare server. The first was also run through sluice before the
change, where it emptied the table; both are blocked now.

Only two settings of a session change where a string ends, and only around a quote that follows a backslash
(a quote is never the second byte of a multi-byte character, and `$$...$$` has no escape). So sluice does not
try to follow the settings, which a client can also change with `set_config()`, in a function, or through a
role's own defaults. It looks at the text: a string where the two readings can differ is uninspectable
(`sl_sql_classify` refuses it; the rules for what counts are in the comment of `sql_check.c`). It costs
nothing for SQL without a backslash (one `memchr`), and the usual backslashes (`'\d+'`, `'C:\\'`) are not
affected.

What this does not cover: other ways for the server to read bytes differently from the parser, if there are
any. The versions of the grammar differ too (sluice parses with PostgreSQL 18's grammar; a statement that an
older server reads differently would be a second way). The test that would find the next one compares both
readings on a real server; it is a candidate for the CI that does not exist yet.


## 19. Guarding an AI agent (proposal, not decided)

Status: a proposal. Part A was built in v0.11 (section 3); B is not planned; C was built in another form
(section 20). It changes three earlier decisions on purpose (sections 1, 3 and 4), which are named below.

**Who it is for.** A developer who lets an agent (Cursor, Claude Code, a script with a model behind it) run SQL
against a managed Postgres (Supabase, Neon, RDS...) or one in Docker. The threat is a mistake, or a prompt
that steers the agent, not a person who holds the real credentials and wants to get round the tool. What
success looks like: the agent cannot silently lose data, a human sees what it asks for and decides, and
setting it up takes minutes.

**Honest limit.** sluice only guards what goes through it. An agent that can read the real database password
(a `.env`, a shell variable) or run `docker exec` into the database container can go round it. Part B below
removes the first; the second is not sluice's to close (`pg_hba.conf`, who may use Docker). The strongest
protection stays a database role with minimal rights and, where possible, a copy instead of production.

Three pieces, in this order, each useful on its own.

### A. TLS towards the client (changes section 3)

Why: the connection strings of managed providers say `sslmode=require`, and many drivers refuse a server that
does not do TLS. Today sluice answers `N`, so those clients fail.

- `--listen-tls-cert FILE --listen-tls-key FILE`: sluice answers `S` to the `SSLRequest` and does the TLS
  handshake as a server (OpenSSL, the same module as the client side, with a server context).
- For the loopback case, `--listen-tls self-signed`: a certificate made at startup, kept in memory. A client
  with `sslmode=require` accepts it; one with `verify-full` needs the certificate given to it.
- Client certificates are not asked for in v1.
- A key readable by others gets the same warning as the upstream key.

### B. sluice holds the database credentials (changes section 4)

*Status: not planned. The risk it removes was accepted instead (section 4); kept here as the option that was weighed.*

Why: if the agent does not know the real password, it cannot connect to the database directly. It receives
an address of sluice and nothing secret.

- A second authentication mode, next to today's pass-through (which stays the default): sluice logs in to the
  database itself, with its own role, then tells the client the login succeeded.
- The credentials come from `--upstream-url-env VAR` or `--upstream-url-file PATH` (a `postgres://user:pass@host/db`
  URL). Never from the command line, where `ps` shows them. The file must not be readable by others.
- sluice is the SCRAM-SHA-256 *client* (PBKDF2, HMAC and SHA-256 come from OpenSSL). `trust` is accepted.
  Cleartext and MD5 are refused, with a message that says why.
- Order of events: the client's startup packet arrives; sluice connects and logs in upstream with the configured
  role and database; only then does it answer the client `AuthenticationOk`, forwards the server's
  `ParameterStatus` and `BackendKeyData`, and the `ReadyForQuery`. After that the relay is opaque as before.
  This needs a *bounded* reading of the server's messages (types R, S, K, Z, E, N, up to the first
  `ReadyForQuery`), not the full reading that a row-count preview would need.
- Cancellation keeps working: the key the server gave is the key the client gets, so a `CancelRequest` is
  relayed unchanged.
- Who may connect to sluice: `--client-auth trust` (the default, accepted only when listening on loopback) or
  `password`, a cleartext password checked against a value from the environment or a file, allowed only
  over the TLS of part A.
- One upstream role per sluice process in v1. The client's `user` is logged as `client_user`, the role used
  upstream as `upstream_user`; rules match on `client_user`. The client's `database` is ignored in favour of
  the configured one, and a mismatch is logged.
- The URL stays in memory for the life of the process (every connection needs a login). It is never logged.
  Core dumps are turned off. If it sits in a file, anything running as the same user can read it: say so in the
  documentation, and recommend a separate user or the system keychain.

### C. `action = "ask"` (a third action next to `allow` and `deny`)

Why: the rules that are too strict to always allow and too useful to always deny (`DELETE` without `WHERE`,
DDL, `not_read_only`) get a human in the loop.

```toml
[[rule]]
name    = "mass-write"
match   = "update_or_delete_without_where"
action  = "ask"
message = "Do not retry. Ask the user."
```

- Only in `enforce` mode. In `audit` mode an `ask` rule is logged as a verdict and relayed.
- The statement is held (its bytes stay unreleased, as an incomplete message is today). sluice prints a prompt
  on the terminal, `/dev/tty`, never stdout (that is the JSON log):

  ```
  agent@mydb  14:02:31   rule: mass-write
    DELETE FROM users WHERE created_at < '2020-01-01'
    allow? [y]es once / [N]o / [a]lways for this query shape in this run
  ```

- Answers: `y` releases the statement, `n` or Enter replaces it with the failing statement that exists today
  (the agent sees the rule's `message`), `a` remembers the fingerprint until sluice stops.
- No answer within `ask_timeout` (default two minutes) is `n`. No terminal at all (`/dev/tty` cannot be
  opened) makes `ask` behave as `deny`, once logged as `ask_unavailable`: it fails closed.
- Several held statements wait in a queue, one prompt at a time. A client that disconnects withdraws its
  statement.
- The extended protocol is judged at `Parse`. So an approval covers that prepared statement's executions on
  this connection. That is coarser than asking at each `Execute` and is a known limit of v1.
- A held statement inside a transaction leaves the transaction open and holding its locks until the answer or
  the timeout: the timeout is what bounds it.
- A `CancelRequest` for a connection that is waiting does nothing in v1: the server has no statement to cancel.
- Events: `ask` (rule, wait) and `ask_answer` (`y`, `n`, `a`, `timeout`, `no_tty`, and how long it took).
- Policy syntax: the strict TOML subset has no numbers, so durations are strings (`ask_timeout = "2m"`),
  read by the same parser.

Part C above is superseded for `DELETE` and `UPDATE` by section 20, which also shows the rows; a bare `ask` that
shows only the statement is not built.

### Not in this proposal

- A count of the rows a statement would touch (needs the full reading of the server's messages, section 12).
- A separate terminal tool talking to sluice over a socket, and an MCP mode for agents that do not use a
  wire connection. Both are worth doing once A, B and C have been used.
- Several upstream roles, or approvals by someone other than the person at the terminal.

### Order, effort and tests

A takes a few days, B one to two weeks (the SCRAM client and the bounded reading of the server's messages are
the delicate parts), C about a week. Tests: A and B against the real PostgreSQL of `tests/realpg.py` (a login
without the real password, `sslmode=require` clients), plus the fake upstream for the failure cases; C on a
pseudo-terminal, as the passphrase test already does.

Questions to settle before building: one upstream role or a mapping (v1: one); `trust` on loopback (v1: yes);
asking at `Parse` or at `Execute` (v1: `Parse`); `ask` also as a one-flag quick mode (`--ask-writes`).

## 20. Validating deletes: run, look, then confirm (built in v0.10)

Status: built, with the choices below. It replaces part C of section 19 for statements that change rows (a static "ask" cannot say
how many rows are concerned), and it makes the reading of the server's messages (section 12) a prerequisite.

**The need, in one sentence.** Whatever tool sends `DELETE FROM users WHERE ...` (psql, an ORM, pgAdmin, an
agent), someone sees "this deleted 41,234 rows", and which ones, and says yes or no *before* it is final.

**The idea.** Do not guess the count in advance (that needs a rewritten `SELECT count(*)`, parameters, a second
parse, and it can be wrong by the time the statement runs). Let the database do it, inside a transaction that
sluice has not committed yet:

1. The client sends `DELETE ...`. A rule says this kind of statement is to be confirmed.
2. sluice sends `BEGIN`, then the client's statement, and swallows the server's answer to `BEGIN`. When the
   statement is a `DELETE` or an `UPDATE` without a `RETURNING`, sluice adds `RETURNING *` first (the lexer finds where the
   statement really ends, and the text is added there, so that parameters, comments and the rest of the
   statement are untouched), so that the server hands back the rows.
3. The server answers with the rows, then `DELETE 41234` and `ReadyForQuery`. sluice keeps the first rows
   (ten by default) for the human, counts the others and throws them away, and **holds** the final messages.
4. If the count is not above the threshold (`over_rows`), sluice sends `COMMIT` and gives the client its
   messages: the client noticed nothing but a few more microseconds. One row deleted by hand does not ask.
5. If it is above, sluice shows the human the statement, the count and the first rows, and waits: `y` sends `COMMIT`, then the
   held answer goes to the client; `n`, a timeout or a disconnect sends `ROLLBACK` and the client gets an error.

This gives the exact count (cascades and triggers included in the work done), the same snapshot as the
statement, parameters and the extended protocol without any rewriting, and a safe default: anything that goes
wrong (the human does not answer, sluice crashes, the terminal closes) ends in a rollback, because an
uncommitted transaction is rolled back by the server when the connection drops.

```toml
[[rule]]
name      = "confirm-deletes"
match     = "delete"          # new matchers: delete, update (the statement kinds)
action    = "confirm"         # a fourth action: allow, deny, ask (always), confirm (after looking)
over_rows = "100"             # a string, as the policy format has no numbers; default "0": always ask
message   = "A person has to confirm this."
```

```
agent@mydb  14:02:31   rule: confirm-deletes
  DELETE FROM users WHERE created_at < '2020-01-01'
  deleted 41234 rows (not committed yet); the first 2:
    id     email                  created_at           plan
    18     ana@example.com        2019-03-02 10:11     free
    52     bob@example.com        2019-07-21 08:40     free
    ...    (and 41232 more)
  commit? [y]es / [N]o  (rolls back in 2 min)
```

**The detail.**
- The rows are what the statement really deleted: the same snapshot, so nothing to guess. For an `UPDATE`
  they are the new rows (PostgreSQL 18 can also return the old ones with `RETURNING OLD.*`).
- Only the first rows are kept (memory stays bounded, whatever the size of the delete), and each value is cut
  to a width that fits a terminal. A statement that already has a `RETURNING` keeps its own: the client's rows
  are held until the answer, up to a limit (64 MiB), beyond which the statement is rolled back with an error
  that says the result was too large to confirm.
- The values are shown on the terminal and nowhere else: never in the JSON log, whatever `--log-sql` says.
- **A fallback, because `RETURNING` needs more rights than `DELETE`.** A role that may delete but not read
  (no `SELECT` on the table, or row-level security that hides the rows) fails with the added `RETURNING`. On
  any error of the modified statement, sluice rolls back to the savepoint and runs the original statement
  as the client wrote it: if that works, the human gets the count and a note that the detail is unavailable; if
  it fails too, that error goes to the client.
- **What the detail does not show:** rows that a cascade (`ON DELETE CASCADE`) or a trigger removed from
  *other* tables. The count and the rows are those of the statement itself. A later version could warn that
  foreign keys cascade from this table.

**If the client is already in a transaction** (`ReadyForQuery` said `T`): sluice uses `SAVEPOINT` instead of
`BEGIN`, and `ROLLBACK TO SAVEPOINT` instead of `ROLLBACK`.

**What the client sees.** On `y`, the server's own answer, with the `ReadyForQuery` status byte put back to what
the client expects (our `BEGIN` made it `T`). On `n`, an error that sluice writes (SQLSTATE and the rule's
message), then a `ReadyForQuery`. If our own `COMMIT` fails (a deferred constraint checked at commit time), the
server's error goes to the client, as it would have.

**What it costs, said plainly.**
- The rows stay locked while the human decides: others that touch them wait. The timeout bounds it.
- A big delete does all its work, and the work is undone on `n`. Expensive for millions of rows.
- Triggers run even when the transaction is rolled back. One that acts outside the database (a call to a
  service) has already acted. Rare, and not something sluice can see.
- Adding `RETURNING *` makes the server send the deleted rows, a little more work than the count alone. It
  also depends on the deparse handling the statement; if it cannot, the human gets the count and a note.
- It needs a terminal, or another channel, for the answer: with none, it rolls back and logs why.
- A statement that cannot run inside a transaction block is not wrapped (a `DELETE` always can).

**What it needs first (stage 0): reading the server's messages.** Up to now sluice reads what the client sends
and relays what the server answers without reading it. Here it must read the framing of the server's stream,
the command tag of `CommandComplete` (`DELETE 41234`), the `ErrorResponse` and the status byte of
`ReadyForQuery`, hold messages, swallow the answers to the statements it injected, and write an error. This is
the large and delicate part, and it is a good thing in itself: the log can then say whether a statement
succeeded and how many rows it touched, which an audit needs and the log lacks today.

**Stages.**
0. Read the server's stream (framing, tags, status), log `rows` and the outcome of each statement.
1. `confirm` for `DELETE` and `UPDATE` in the simple query protocol (psql, agents, pgAdmin with some drivers):
   count and first rows, terminal prompt, rollback by default, the fallback without `RETURNING`.
2. The extended protocol (ORMs and most drivers): hold the answers of `Execute` until `Sync`.
3. Other channels for the answer (a command, a webhook), a warning about cascading foreign keys, `TRUNCATE` and
   `DROP` (no count and no rows: always asked, with the statement alone).

**Questions.** Is holding locks while a person decides acceptable (v1: yes, with a timeout)? How many rows
to show (v1: ten, values cut to the width of the terminal)? Where does the answer come from when there is no terminal (v1: nowhere, so rollback)?

### As built: what was decided

- **Simple query protocol only.** A `confirm` rule that meets a prepared statement (Parse) or a message with
  several statements or a data-changing CTE refuses it, with the reason in the error, instead of letting it
  through. The extended protocol is stage 2 (it needs the answers of `Describe` rewritten too, since the
  `RETURNING` added changes the shape of the result).
- **`RETURNING *` is added by text**, at the end of the last significant token (found with the lexer, so a
  trailing comment or `;` is skipped), not through the parser's deparse. Simpler, and the statement is
  otherwise byte for byte the client's.
- **The statement waits for a quiet server.** Whatever the client sent before it has to be answered first
  (`SL_SCAN_WAIT`), counted with the `ReadyForQuery` of the server's stream; what the client sent behind it waits
  until the confirmation ends (`SL_SCAN_GUARD` pauses the scanner). A statement that waits is never let through
  because the client hung up.
- **A refusal leaves the client's transaction usable** (`T`), whereas the real database would have left it
  aborted (`E`): the savepoint was rolled back, nothing is wrong, and the client was told it was not done.
- **The error is ours**: SQLSTATE `42501`, severity `ERROR`, with the rule's `message`.
- **Defaults:** ten rows shown, values cut to 24 characters, `over_rows` 0 (always ask), `confirm_timeout` two
  minutes, at most 64 MiB held for a client's own `RETURNING`.
- **The terminal is `/dev/tty`**, or `--confirm-tty FILE` (the tests give it a pseudo-terminal). It is opened
  when the first question comes. Questions queue, one at a time; leftover typed input is thrown away before each.
- **The log never holds the values of the rows.** The `confirm` event has the rule, the count, the outcome and
  the time.

