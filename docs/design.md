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

**Who it is for.** A developer who lets an agent (an IDE assistant, a coding agent, a script with a model behind it) run SQL
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
2. The extended protocol (ORMs and most drivers): hold the answers of `Execute` until `Sync` (built in v0.12,
   section 21).
3. Other channels for the answer (a command, a webhook), a warning about cascading foreign keys, `TRUNCATE` and
   `DROP` (no count and no rows: always asked, with the statement alone).

**Questions.** Is holding locks while a person decides acceptable (v1: yes, with a timeout)? How many rows
to show (v1: ten, values cut to the width of the terminal)? Where does the answer come from when there is no terminal (v1: nowhere, so rollback)?

### As built: what was decided

- **Simple query first.** A `confirm` rule that meets a message with several statements or a data-changing CTE
  refuses it, with the reason in the error, instead of letting it through. The extended protocol came in v0.12
  (section 21).
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

## 21. Confirming prepared statements (built in v0.12)

Most drivers and ORMs never send a simple query: they send `Parse`, `Bind`, `Execute` and `Sync`, often
several statements at a time without waiting for the answers, and often a statement prepared once and run many
times. The mechanism of section 20 (run it, look, then commit or undo) is kept; what changes is where the
transaction comes from, and that sluice now has to know, for every answer of the server, which message of the
client it belongs to.

**The transaction is the protocol's own.** In the extended protocol an implicit transaction lasts from the first
message of a cycle to its `Sync`, which commits it. So sluice does not inject `BEGIN` (which would also have
disturbed the client's unnamed statement and portal): it runs the guarded `Execute` and **holds the `Sync`**.
Until the person has answered, the statement is done but not committed. Checked against a real PostgreSQL 17
(see `tests/realpg.py`): rows deleted before the `Sync` are invisible to other sessions, and a failing message
before the `Sync` rolls the cycle back.

1. **At `Parse`**, the statement goes through the same judgement as a simple query. When a `confirm` rule
   matches a lone `DELETE` or `UPDATE` (and the session is followed), it is recorded under its name (the
   unnamed statement counts, replaced by each `Parse`) with its text, the rule, the threshold, and whether
   sluice added a `RETURNING`. It is sent with ` RETURNING *` spliced in at the same place as for a simple query
   (the lexer finds where the statement ends), unless it has its own.
2. **At `Bind`**, the portal takes the guard of its statement.
3. **At `Describe`**, the answer of a rewritten statement (a RowDescription, since it now returns rows) is
   changed into `NoData`, which is what the client expects for a `DELETE`.
4. **At `Execute`** of a guarded portal, sluice sends `Describe(portal)` (for the names of the columns, as the
   client may not have asked), the client's `Execute`, and a `Flush` (the server keeps its answers until a
   `Flush` or a `Sync`: without it nothing would come back before the `Sync`). What the client sent after the
   `Execute`, its `Sync` included, waits. The rows are kept (the first ten, and the count), the tag is held.
5. Not above the threshold: the tag is given to the client and the `Sync` goes. **Yes**: the same, after the
   prompt. **No** (or no terminal, or a timeout): the client gets our error (SQLSTATE `42501`), and a `Parse`
   that fails (`select '...'::int`, the mechanism that blocks statements) is sent: the server enters its error
   state and ignores everything up to the `Sync`, which then rolls the cycle back. The server's own error for
   that message is consumed.

**Matching answers to messages.** The server answers in order, but only some messages bring a distinguishable
answer. `extstate.c` keeps a queue of what is owed: a `Describe` brings a RowDescription (and, for a
statement, a ParameterDescription first), an `Execute` brings rows and one terminal message, a `Sync` or a
`Query` brings a `ReadyForQuery` and ends the cycle. A ParseComplete or BindComplete needs no slot (nothing
depends on them). Four decisions make it safe:

- *After an ErrorResponse the queue stops matching until the next `ReadyForQuery`*, because the server ignores
  what follows. If a guarded `Execute` was waiting behind the error it will not run, and the confirmation is
  cancelled (event `confirm` with `outcome: "skipped"`); the client's stream goes on.
- *`Sync` and `Query` are barriers*, so a `ReadyForQuery` settles one cycle and not the next one's answers, and
  pipelined cycles stay matched.
- *The queue is run-length encoded* (a batch of 3,000 plain `Execute`s is one entry), with a hard limit; when it
  overflows sluice stops following the connection and refuses what would need it, rather than guess.
- *Names are compared the way the server does.* It keeps 63 bytes of a name, so a longer one cannot be
  compared and is refused on a connection that holds a confirmable statement. A name that is already taken
  keeps the guard it first had (the server refuses to define a name twice).

**What is not the same as for a simple query**, and why: a no inside the client's own transaction aborts it
(the protocol offers no clean place for a savepoint; the failure is what undoes the statement, and a failure
aborts the transaction); an `Execute` with a row limit is refused (a half-run statement cannot be confirmed);
the rows of a client's own `RETURNING` shown for a binary-format result are raw bytes; the statement text shown
is cut at 4 KiB; and there is no fallback to the statement without `RETURNING` when the role may not read the
rows (the statement is refused with the server's error, since the rewritten statement is already prepared).

**Tested** with a fake server that behaves like the real one on the points that matter (answers kept until
`Flush` or `Sync`, ignored messages after an error, commit at `Sync`), with mutation checks (a guarded `Execute`
that is not guarded, a `Describe` answer that is not rewritten, a scanner that does not wait, a `Flush` that is
not sent, a cancelled confirmation that is not cancelled), with the scanner and queue fuzzed (the scanner
against an independent model, with the new hook), and against real PostgreSQL 17 with a hand-written client
(pipelines, a prepared statement re-run, the client's own transaction, own `RETURNING`) and with `pgbench -M
prepared`.

## 22. What else a statement changed, and who is asked (built in v0.13)

**Cascades and triggers.** Section 20 listed as a limit that the rows shown are those of the statement itself: a
`DELETE FROM customers` that cascades to `orders` and `order_lines` shows the customers only. v0.13 shows the rest.

*How.* PostgreSQL keeps per-table counters of rows inserted, updated and deleted for the current transaction
(`pg_stat_xact_user_tables`), cascades and triggers included, and any role can read them. Two findings from the
real server decided the design:

- The view is **not only about the current transaction**. The counters of earlier transactions of the session
  that have not been reported yet are in it too (a first version that just read the view after the statement
  showed twice the real numbers on the second try, and the inserts of the test's setup). So a number only means
  something as a **difference**: one look just before the statement, one just after.
- A look can lose its meaning if the backend reports its statistics in between (it does so when it goes idle,
  which a `ReadyForQuery` is). So the two looks and the statement go in **one exchange with nothing idle in
  between**: for a simple query, one message `BEGIN; <look>; <statement>; <look>`; for the extended protocol, the
  Describe, the first look (a statement and a portal of sluice's own, with names the client will not use:
  `sluice_side`), the client's Execute, the second look, the closing of what the looks used, and a `Flush`. The
  difference is computed in `confirm.c` (a table with no change is dropped, the biggest deletions come first,
  eight are shown, and when the transaction is the client's own the text says the numbers count what it did
  before).

*When a look fails.* A server that lacks the view (a PostgreSQL-compatible database) answers the first look
with an error. In a simple query that is recoverable: the exchange is rolled back and the statement is run
again without looks, so the person is asked as in v0.10. In the extended protocol it is not (after an error the
server ignores everything up to the `Sync`, and an implicit transaction that failed is rolled back at it), so the
client gets an error of sluice's saying that nothing was committed and how to turn the looks off
(`side_effects = "off"` in the rule), rather than a statement that seems done and is not. That is the one case
where turning a feature on can make a statement fail, and it is why the rule has the switch.

*Cost.* Two catalog queries per confirmed statement, in the same round trip. A `confirm` that is not above its
threshold still runs them, since the number of rows is known only afterwards; set `side_effects = "off"` where
that matters.

**Who is asked.** The prompt on a terminal (section 20) assumes a person at a terminal, which is rarely the case
for an agent on a server, a CI job or a container. `--confirm-command CMD` (and not `--confirm-tty`) puts the
same question, as text on the standard input, to a command run by the shell; **its exit status is the answer**.
Decisions:

- *Exit status, not output.* A command that prints "yes" and fails is a no; a command that cannot be found is a
  no (127). The only way to approve is to succeed, so every failure is a refusal.
- *The command is the operator's.* It comes from sluice's own command line, never from a client or the policy
  file. Its input is the statement and the rows, which are data; they are never in its arguments or
  environment, so a value cannot be turned into a command.
- *Nothing of sluice's is inherited.* Every descriptor above 2 is closed in the child, its standard output is
  `/dev/null` (sluice's own is the JSON log), `SIGPIPE` and `SIGCHLD` are back to their defaults, and the command
  runs in its own process group.
- *End by signal, not by pipe.* The end of the command is noticed through `SIGCHLD`, handled by writing a byte to
  a pipe that is in the poll set (all a handler can safely do for a single-threaded loop). A first version
  waited for a pipe to close, which a command that starts something in the background and exits would have kept
  open; the test for exactly that (`(sleep 3 &); exit 0`) is answered at once.
- *Time out and withdrawal kill the group.* `confirm_timeout` applies as for a terminal, and a command still
  running then (or when the client leaves) is killed with whatever it started.
- *One at a time.* Questions are put in turn, as on a terminal.

**Tested** with unit tests of the difference and the failures in both protocols, integration scenarios with fake
servers for both, real PostgreSQL 17 with a foreign key that cascades and a trigger that inserts (the counts shown
are the true ones, in both protocols, and inside the client's own transaction), and for the command: exit statuses,
a command that is not found, one that is killed on timeout, descriptors not inherited, a background child.

## 23. Asking the person in their own session (built in v0.14)

Section 20 asked on a terminal, which assumes someone is looking at the terminal of sluice. Nobody is: sluice is a
process in a container or a service that no one opens. The person who has to agree is the one who sent the
statement, so the question goes to them, in their connection, by the only means the protocol has: the answer to
their statement.

**The shape.** The statement runs as before (section 20 or 21: a transaction that is not committed, the rows and the
cascades counted). Then, instead of a prompt:

1. The client gets an **error** as the answer of its statement: the message says what is waiting, the rows
   and cascades are the DETAIL, and how to answer is the HINT (with the rule's `message`). psql shows all three.
   In the simple protocol a `ReadyForQuery` in a transaction follows; in the extended protocol the error takes the
   place of the command tag and the cycle's `Sync` is answered by sluice (the server is left in the middle of the
   cycle, with its transaction open, which is what the server does between a Flush and a Sync).
2. The transaction **stays open on the server**. From now on every message of the client goes through a filter
   (`pend_*` in `conn.c`). Two answers are recognised, whatever the case, spacing or semicolon:
   `yes` (or `y`), `no` (or `n`), `show` (or `more`: the question again with up to 50 of the rows that were kept, not
   answered by the server), and, for a client that wants something that parses, `select sluice_confirm()`
   and `select sluice_cancel()`. None of them is SQL, which is why accepting them while a statement waits (and
   only then) cannot change the meaning of a statement. They are **not** forwarded as they are: the call is
   *replaced* by the statement that ends the transaction, so that the server's own answer is the client's
   answer (the tag, rewritten) and nothing has to be invented. For a simple exchange that is `COMMIT` or
   `ROLLBACK` (`RELEASE SAVEPOINT` or `ROLLBACK TO SAVEPOINT` inside the client's own transaction). For a prepared
   statement it is a harmless `SELECT 'confirmed' AS sluice` (the `Sync` that follows commits) or a message that
   fails (which makes the cycle roll back). `ROLLBACK` is not used there: outside a transaction block it only warns,
   and the implicit transaction would be committed by the next `Sync`: this was found by reading the server's
   behaviour, and it is the one place where a cancel could have silently done nothing.
3. **Everything else is refused without the server hearing of it**, because running it inside the open transaction
   would give it a view and a fate of its own (and an error would abort the pending statement). New in the
   scanner for this: `SL_SCAN_ANSWER`, a message that is thrown away because the caller has answered the client itself.
   After an extended message is refused, the rest of its cycle is ignored up to the `Sync`, which sluice answers,
   as a server would.
4. After a yes the client gets the tag of the statement it had sent (`DELETE 20`): the server's `CommandComplete` for
   the statement that ended the transaction (`COMMIT`, or `SET sluice.confirmed = 'on'` for a prepared statement, chosen because it
   returns no rows and says nothing, which `SET LOCAL` outside a transaction block does not) is rewritten on its way back. After a no it is the server's own: `ROLLBACK`, or an error.
5. **Time out** (`confirm_timeout`): sluice sends the rollback itself, throws the answer away (a counter of
   `ReadyForQuery` to swallow, so the client, which did not ask for it, does not see them), and tells the client by
   a warning, which is an asynchronous message and may come at any time.
6. The client that leaves without answering never commits: the server rolls back an unfinished transaction.

**Who answers, and the limit that follows.** The person is whoever is on that connection, and an AI agent on it
can run `select sluice_confirm()` as easily as a human. That fits the threat of the tool (a mistake, not a person
who wants to get round it: section 19) and it is why the rule's `message` is shown with the hint, to be written for
the reader (an agent) as well as for the person ("do not confirm without the user's agreement"). Where an agent
must not be able to answer, the operator names another channel (`--confirm-tty`, `--confirm-command`): then the
question is not put to the session at all. The choice is per sluice, not per rule: what the option names, answers.

**What it costs.** The rows stay locked while the statement waits (up to `confirm_timeout`). A client that never
looks at its connection holds them for that long. The statement of a simple exchange is committed by a `COMMIT` that
the client "sent" (`select sluice_confirm()`), so a driver that wraps its statements may be surprised by an error
for a statement it believed done: that is the point.

**Tested** with fake servers (both protocols, case and spacing of the call, a refused statement, the client's own
transaction, the time running out and the answer that must not reach the client, the client leaving), with the real
PostgreSQL 17 (the simple and extended cycles, the cancel, the client's own transaction, the timeout, and no
transaction left open), and under the sanitizers.

## 24. Real drivers, TRUNCATE and DROP (built in v0.15)

**What real drivers showed.** Everything up to section 23 was tested with `psql`, `pgbench` and clients written for
the tests. `tests/drivers.py` runs psycopg 3, asyncpg, SQLAlchemy and JDBC (pgjdbc, from Maven Central, checked
against its published checksum) against a real server through sluice, and found two defects at once:

- *An application rolls back when something raises.* While a statement waited, the driver's `ROLLBACK` was refused
  like any other message, so the application could not even clean up. Now a `ROLLBACK` or `ABORT` while a statement
  waits is a **no**, and a `COMMIT` or `END` is refused (it would apply what was not confirmed, and the client was
  told the statement had not run). For a prepared statement the rollback needs care: its transaction is the implicit
  one of its cycle, outside a transaction block `ROLLBACK` only warns, and the next `Sync` would commit. So a
  message that fails is sent first, its answers thrown away (the same counter as for the time-out), and the client's
  own `ROLLBACK` follows and gets its own answer.
- *pgjdbc sends `Execute` with a limit of 1 for every DELETE*, to notice a statement that returns rows. A statement
  that sluice gave a `RETURNING` would have suspended its portal after the first row. It is now run without the
  limit (the client never sees the rows, so the limit means nothing to it); a client's own `RETURNING` fetched a few
  rows at a time is still refused, since it cannot be held and confirmed.
- (and a smaller one, found while fixing the first: when the `Parse` of the answer replaced a guarded statement of
  the same name, the guard stayed on the name, and the `Execute` that followed was asked about again.)

**TRUNCATE and DROP.** They are transactional in PostgreSQL, so section 20's mechanism applies unchanged: run, hold,
commit or undo. What is different follows from there being no rows. `sql_check` reports their kind (`'T'`,
`'R'`) and says there is nothing to add to them; `confirm.c` runs them as written (a `plain` exchange), never
compares them with `over_rows` (nothing to count), does not look at the counters (a `TRUNCATE` leaves none), and shows
the statement and its tag instead of rows. `DROP` means `DROP TABLE`, `VIEW`, `INDEX`, `SEQUENCE`, `SCHEMA`... (a
`DropStmt`); `DROP DATABASE`, `ROLE` and `TABLESPACE` are not confirmable: a database cannot be dropped inside a
transaction block, and none of them is undone by a rollback, so a rule that matches them refuses them with the reason
instead of promising an undo it cannot give. The cost is the lock: `TRUNCATE` and `DROP` take an exclusive lock on the
table, held while the person decides, which blocks every reader (a `DELETE` blocks only writers of the same rows).
This is why the documentation recommends a short `confirm_timeout` for these rules.

**Not done.** Only the drivers listed were tried (not Hibernate, Prisma, pgx, node-postgres, Rust or Go drivers,
nor PgBouncer in front). A client that rolls back and retries in a loop will ask again each time.

## 25. A row cap without anyone to ask, and a policy checker (built in v0.16)

**`action = "limit"`.** Sections 20 to 23 ask a person, but the typical user of this tool runs agents and jobs that
nobody watches: for them the question is "what is the most one statement may do", answered without a human. A
limit is the confirmation with a fixed answer: the statement runs in a transaction, the rows are counted by the
database (cascades and triggers do not count: it is the statement's own count, the one the threshold of a
confirmation uses), and then
`rows <= max_rows` commits and anything above rolls back with an error of sluice's (`refused (rule R): it touched N
rows, more than the limit of M`). The two protocols share the machinery of the confirmation, so everything built for
it holds: the statement is held until the count is known, a client's own `RETURNING` is held up to 64 MiB, a
prepared statement is rewritten with a `RETURNING *` and its `Describe` answer corrected, the client's own
transaction gets a savepoint, and the refusal leaves it usable. What a limit does **not** have: any question (the
channel is irrelevant), the look at the side effects (nobody would read it), and a meaning for `TRUNCATE` and `DROP`
(no rows: a rule that matches them refuses them with the reason, rather than quietly never limiting anything). It is
parsed as `action = "limit"` with `max_rows`; `over_rows` and `side_effects` are errors there, so a rule cannot
say two things.

*The cost, said plainly:* the statement runs before it is undone, so a runaway `DELETE` of ten million rows does
ten million rows of work, and holds its locks meanwhile, before it is refused. A limit protects the data, not the
server's time.

**`sluice --check-policy`.** A policy that is wrong in a way the parser accepts (a rule that never applies, an order
in which an `allow` hides a `deny`) is found today by the incident. The command loads the file with the checks of
startup, prints the rules, and for each `--sql` prints the verdict as the given `--user` and `--database` would
get it, through the same functions the proxy calls (`sl_policy_evaluate`, `sl_sql_classify_with_tables`), so it
cannot disagree with the proxy about a statement. The exit status separates "valid and allowed" from "refused" and
"held" (0, 3, 4) so a CI can assert on it: a refusal outranks a question. It reads no server and opens no socket.
It does not run what a rule would *do* to rows (limits and confirmations depend on the data): it says that the
statement would be counted or asked about.

## 26. Limits on volume and duration (built in v0.17)

This is the "parked" idea of section 19 (data leaving in bulk), cut to what can be enforced without guessing. A
rule is about the connection when it carries `max_result_rows`, `max_result_bytes`, `max_total_bytes` or
`max_duration` (`conn_limit` in `policy.c`): it needs `match = "any"` and no tables (it is not about a statement),
statement evaluation skips it, and `sl_policy_limits` gives, for a user and a database, the smallest of each limit
and the rule that gave it. It is computed once, when the connection reaches the relay.

**Rows and bytes.** The server's stream is already followed (`srvscan.c`). A DataRow (or CopyData) is announced
by its header before it is released, so the decision is made on the header: when the result has had its rows, or the
row would take it past the byte limit or the connection past its total, the row is **skipped** unread (a new
`skipped` hook in the scanner says so once, and which limit it was). That is why the first row over the limit is not
the one that slips out: counting after the fact would have sent it. The terminal message of the result (`CommandComplete`,
`EmptyQueryResponse`, `PortalSuspended`) is then read and replaced by an `ErrorResponse` (`54000`); an error of the
server's own takes its place if it comes first. For the volume of the connection the error is `FATAL`, and the
connection ends after the `ReadyForQuery` that the client is owed (the protocol is respected to the end). COPY is
counted because it is the other way out of a table; the client sees the copy end and then the error, so a truncated
copy is never taken for a complete one.

**Duration.** sluice records the process id and secret of the session (`BackendKeyData`, read from the login), and
the moment the server became busy for the client: a statement or a `Sync` was released and the answers (counted
with the `ReadyForQuery` owed) are not all in. A deadline is added to the connection's own (the poll loop already
wakes up for deadlines): when it passes, a non-blocking connection to the database is made, the 16 bytes of a
`CancelRequest` sent, and the client warned. This is the one place where the loop waits (at most 250 ms, and only for
a statement that ran too long); a fork or a second state machine would have cost more than the wait. Not counted as
busy: the time a confirmation waits for a person. Why not `statement_timeout`, which would be one line in the
startup packet: the session can change it with a `SET` or `set_config()`, and the policy allows `SET statement_timeout`
(it is harmless otherwise). A timer outside the session cannot be lifted by it.

**Not done, deliberately.** Windows (a volume per hour, per user, across connections) would need state that outlives a
connection and a rule about what to do on a restart; the per-connection total is what is honest today. Counting the
rows a statement *touches* before it runs (a planner estimate) was rejected: it is wrong in both directions.

## 27. More that only a proxy can do, and how the tests were made harder (built in v0.18)

**What a proxy can enforce that a session can lift.** `idle_in_transaction_session_timeout`, `statement_timeout` and a
role's `CONNECTION LIMIT` are settings of the database that the session (or a role with the right) can change or
that apply to everyone alike; a rule of sluice's is written per user and cannot be reached from the connection.
`max_idle_in_transaction` is measured the way the duration is: the server is idle for the client (everything sent
was answered), the last `ReadyForQuery` said `T` or `E`, no confirmation is waiting (that is a person's time):
the connection is ended by a `FATAL` of ours (`25P03`) and closed, and the server rolls the transaction back as it
does for any client that goes away. `max_connections` is counted when a connection logs in: the server loop gives
each connection a way to ask how many others are open for the same user (`sl_conn_is_user`), so no connection
needs to know of the others. Both are `conn_limit` rules, the family of section 26.

*A bug this found.* A `FATAL` of ours while relaying (the first one there ever was) was appended to the buffer of
the server's stream but not released: the scanner of that stream only lets out what it has judged, and the error
was never sent, nor the connection closed. `fatal()` now releases it.

**The outcome of each statement.** Section 20's "stage 0" promised that reading the server's stream would let the log say
how a statement ended; it was never written. `--log-results on` does it: the terminal messages of every result are read
(they are small; the rows still stream unread), the rows and bytes counted on the way, and the time taken as the time since
the previous result ended, or since the server became busy, since the statements of a message run one after the
other. No text of an error: it can quote values, and `log_sql normalized` exists so that values stay out of the log.

**Tests made harder.** What was missing was not more of the same: it was another kind.

- *Equivalence* (`tests/drivers.py`, `scenario_equivalence`): one workload of about thirty varied operations with psycopg
  (prepared statements by name, parameters, binary results, a 3 MB `bytea`, 200,000 rows, `COPY` in and out, savepoints,
  server-side cursors, `LISTEN`/`NOTIFY`, a pipeline, errors of five kinds, descriptions) is run direct, through sluice,
  and through sluice with TLS and result logging on, and what the driver saw is compared. The claim of a proxy is that it
  is invisible; this is what checks it.
- *Garbage* (`scenario_survives_garbage`): 300 sessions that log in and then send valid messages damaged eight ways
  (flipped bits, lying lengths, cut, repeated, noise, a megabyte of statement), under a policy with confirmations; the
  proxy must live, release its descriptors, and serve a good client at the end. It complements the fuzzers, which
  attack the parsers, with an attack on the whole.
- *Soak* (`scenario_soak`): up to 64 clients at once, 300 operations each (inserts, selects, deletes held for
  confirmation that are answered yes, no, rolled back, or abandoned by closing the connection, cut connections, long
  results). Each client keeps a model of its table; at the end each table must be what its model says, no transaction
  may be open on the server, and sluice must hold the descriptors it held before. Run under the sanitizers.
- *Coverage* (`gcovr`, 91% of the lines of `src/` by the unit and integration tests alone) showed which defensive
  branches nothing exercised: the bounds of the prepared-statement bookkeeping, a cancel that cannot reach the
  database. Testing them found that, once the queue of answers had overflowed, **every** `Bind` was refused on a
  connection that held any confirmable statement, plain ones included: only what needs the queue (a guarded
  statement) is refused now. The remaining uncovered lines are mostly out-of-memory exits, which need fault
  injection to reach.
- *The CI*: the workflow is checked with `actionlint`, and its Linux jobs were run in the image of the runner
  (Ubuntu 24.04: Meson 1.3, OpenSSL 3.0) and its macOS job with Homebrew's Meson. The job that needs Docker on a Linux
  host could not be reproduced on a macOS machine and is the one that will be seen for the first time on the first push.

## 28. Who is asked, and how much a user may take in a day (built in v0.19)

**`confirm_via`.** The in-session confirmation of section 23 fixed the channel for the whole proxy: a flag. But the
people who are asked differ by the damage: a `DELETE` of a hundred rows is the business of whoever sent it, a `DROP` is
not. A rule now says `confirm_via = "session"` or `"operator"`; a guard remembers it (`c->g_via`, and in the table of
prepared statements, `sl_ext_entry.via`, so that the Execute of a statement parsed long before is asked the way its
rule says), and `session_channel()` decides per guard rather than per proxy. Nothing else of the confirmation changes:
the same prompt and queue serve every rule that asks the operator.

*A latent bug found on the way.* `sl_limits` held pointers to the names of the rules that gave each limit, and the
policy is freed when it is reloaded: a connection that outlived a `SIGHUP` would have read freed memory the next time
it logged a limit. The names are copied now (`scenario_budgets_survive_a_reload`).

**Budgets** (`src/budget.[ch]`). The limits of section 26 are per connection; an agent gets around them by
reconnecting. A budget is a counter per (rule, user), shared by the connections of the user, over a window of one
minute to seven days, with no clock of its own (the caller gives the time, as for the scanner) so that it is tested
by moving time:

- *Sliding window.* Twelve slices of window/12, each tagged with the number of the slice it holds (time divided by
  the width); a slot whose tag is out of the last twelve is empty. Adding is O(1), reading is twelve additions; there
  is no timer, nothing to expire. The wait that the error message gives is found by taking slices away from the oldest
  until the use is under the budget.
- *Who holds what.* A connection takes the counters of the budgets that apply to its user when it logs in
  (`hold_budgets`) and gives them back when it ends. A counter that is not held and has nothing in its window is
  forgotten, but only when the table is nearly full: a user who comes back finds their use. The table is bounded
  (4096 pairs); when all are held a new login is refused rather than left uncounted. Counters are made after the
  startup packet and before authentication, so their number is bounded by the number of open connections, not by names
  an unauthenticated client may invent.
- *Rows and bytes* ride on the machinery of section 26: a row that would go past a budget is classified `skip`, the
  hook that marks the cut learns two more reasons (4 and 5), and the end of the result becomes an error. The only
  new work per row is twelve additions per budget.
- *Rows changed* are read from the CommandComplete tag (`INSERT 0 n`, `UPDATE n`, `DELETE n`, `MERGE n`): such a tag
  is read instead of passed when a budget counts rows changed. A statement held for a confirmation is counted when it
  is committed, from the rows the confirmation counted (`yes` and `auto`). The check is made on the way in
  (`judge`): a statement that can write is refused once the budget is used up, whatever the protocol. It is the
  weakest of the three: it is made when a statement is parsed or sent, not when a prepared one is executed, and
  one statement can overshoot. The first is the price of not remembering every prepared statement (section 21 keeps
  only guarded ones); the second is what `max_rows` is for.

*The tests.* `tests/test_budget.c` moves time by hand (slices leaving the window, a slot reused after a full turn,
saturation instead of overflow, a bounded table that forgets idle pairs only, a counted pair that is not lost);
`scenario_budgets` runs the three kinds of budget through the proxy with several connections and two users, a
confirmed `DELETE` counting, and the reload; `scenario_confirm_via` puts the questions of two rules in two places with
a command and a terminal. The fake database had to learn two things: to take more than one connection, and to fail a
refused statement the way the real one does.

## 29. Hiding values in what a user reads (built in v0.20)

**What was asked for, and what it is not.** An agent that reads a table puts what it reads in a prompt, a transcript, a
log. Masking in the proxy is a guard-rail for that, and the design says so because it is easy to oversell: the proxy
sees the rows the client could read anyway, names the columns by the name the *client* gave them, and the client can
compute (`md5`, `substr`, a `WHERE` that guesses). The boundary is the privileges of the database; this is what they
cannot say ("this agent may read the table, but not the e-mail addresses in the notes") and a second line.

**Which bricks.** Nothing new is added to the build. The tokens are HMAC-SHA256 from OpenSSL, which sluice links already
for TLS and SCRAM. PostgreSQL Anonymizer (the extension) was looked at and not chosen: it needs the extension on the
server, which many managed databases do not offer, plus a role the session can change; sluice is for the case where
the database is not the operator's to change. A regular-expression library was looked at and not chosen either: a
pattern engine over client-controlled data (a text column of any size) is a way to be made slow, and three patterns do
not need one. The scans (`find_email`, `find_card`, `find_iban`) are a few lines each and linear in the length of the
text, whatever it holds; the matches of the next one are found once and kept, so a text with thousands of matches is
also walked once per pattern, not once per match (`test_many_matches`: 5000 addresses in one value).

**The model.** A `mask` rule gives, per user, a set of names and patterns and a way to hide (`src/mask.[ch]`). It is
the fourth kind of rule that is about a user rather than a statement (with `limit` on a connection, budgets, and
`confirm_via`): it is skipped when statements are judged, and `sl_policy_masks` hands the rules of a user to the
connection, which copies them (a reloaded policy frees the old one: see section 28). Everything in `mask.c` is a pure
function of bytes: a RowDescription says which columns there are and of which type, a DataRow is rewritten into a new
payload, an ErrorResponse likewise. It is fuzzed (`t_mask`: any bytes as description, row and error; a description and
a row built to fit, with the property that what was hidden by pattern is not found again in what is sent).

**Following the stream.** A DataRow has no column names: they come with the RowDescription that opened the result. In
the simple protocol the two arrive together. In the extended protocol they may not: a client that prepared a statement
once and runs it again sends `Bind`, `Execute` and never `Describe` (drivers that cache prepared statements do; the
tests run pgx, node-postgres, pgjdbc, psycopg and asyncpg that way), so the description of its rows was sent long before, for a statement and not for a portal, and in text format
even when the portal asks for binary. Tracking which statement a portal came from, and with which result formats, for
*every* statement and portal, would be a second prepared-statement table and the room for a mismatch is where a value
leaks. The design instead puts a `Describe` of the portal in front of **every** `Execute` while a user has a mask
(`mask_execute`): the answer is exactly the description of the rows that follow, formats included, and it is
sluice's own: a new kind of answer in the queue of section 21 (`SL_EXT_EXEC_M`: "a RowDescription or NoData that is
ours, then as for an Execute"; the first one is flagged `SL_EXT_OURS` and dropped, the client's own, if it described,
is kept). It reuses the queue that already tells which answers are whose, which is why that queue grew from 256 to 1024
entries (a run-length entry holds many executes; a pipeline of alternating kinds needs two per Execute). The Execute of a
**guarded** portal (a confirmation) is not touched here: the confirmation puts its own Describe in front, and masks.

**Where it must not leak, and how that is enforced rather than hoped:**

- *The classification.* A DataRow is read when the current description has something to hide in it, and streams
  untouched otherwise (a user with a rule for `email` reading a table without one pays nothing). A row that cannot
  be read (over 1 MiB, or no description is known) is **skipped, not passed**, and the end of the result becomes an
  error: the same mechanism as the row limits of section 26 (`cut` 6). `CopyData` is skipped the same way (`cut` 7):
  there is no way to tell where a value starts.
- *The description itself.* An oversized or malformed RowDescription leaves no description, so the rows after it are
  refused, not guessed.
- *When following is lost.* If the framing of either stream cannot be followed, if the queue of answers overflows, or an
  `Execute` cannot be read, masking would silently stop: `mask_check` ends the connection with a `FATAL` instead.
- *Not only rows.* The server's own errors and notices quote values (a unique violation prints the key; a check
  violation prints the whole row); they are read and scrubbed by `sl_mask_message`. So are the errors and rows of the
  confirmation (`confirm.c` takes the mask: the rows shown to the person asked and the client's own `RETURNING` go through
  the same function), and fast-path function calls, whose answer is a bare value with no description, are refused.

**Types, decided once.** To replace a value by text the client has to expect text: `text`, `varchar`, `bpchar`, `name`
and `"char"`, whose binary format is the same bytes. For anything else, a column the rule names becomes NULL, whatever the
`how` says: a token in an `int4` or a `uuid` would break the client, a bogus number would lie. `citext` and enums (their
OIDs are not fixed) go that way too; domains do not, since the server reports the base type. The patterns are looked for
in text-like types and in `json`, `jsonb` and `xml`, where the replaced part (a token of `~` and hex, `[masked]`, `***`)
is made of characters that keep a JSON string valid.

**Cost.** Measured on the debug build (`-O0`), 500,000 rows of three columns through sluice with a rule by name and
three patterns: about 1.0 s against 0.44 s without a mask, which is the time of the client reading them. Rows streamed
with nothing to hide cost nothing. The extra `Describe` per `Execute` is one round of the server's own work.

**Tests.** `tests/test_mask.c`: the patterns and their near misses (timestamps, UUIDs, phone numbers, 12 and 20 digits,
a bad check digit), every cut of a row and description, the four `how`, types, many matches, errors. `scenario_masking_*`
(integration): both protocols with and without the client's own `Describe`, pipelines of 300, errors in the middle,
binary results, a name too long to follow, fast-path, confirmations, a user with no rule streaming a 3 MB row. Against the
real server (`realpg`): the same, with the real error text. Against the drivers: psycopg (text, binary, prepared,
server-side cursor, pipeline), asyncpg (binary protocol, prepared, cursor), SQLAlchemy, and with `SLUICE_DRIVERS=docker`
pgjdbc (a portal fetched four rows at a time), node-postgres (a named statement run twice) and pgx (statement cache,
batch).

## 30. MERGE and upserts are UPDATEs and DELETEs (found and fixed in v0.21)

While looking at what could not be confirmed, a plainer thing showed: `sql_check` gave `MERGE` and `INSERT ... ON
CONFLICT DO UPDATE` only the flag "not read only". A rule with `match = "delete"` (to refuse or to confirm) did not
apply to `MERGE INTO t USING s ON ... WHEN MATCHED THEN DELETE`, nor `match = "update"` to an upsert that overwrites
fifty rows: the confirmation, the row caps and the `update`/`delete` denials were all one statement away from not
applying. They are now what their clauses do (`MergeWhenClause.command_type`; `OnConflictClause.action`), a `MERGE`
with both an update and a delete has both flags, one that only inserts has neither.

They are also confirmable (kinds `M` and `I`, next to `D`, `U`, `T`, `R`): nothing in the machinery of sections 20 to 22
depended on the kind except TRUNCATE and DROP being "plain". The count is the tag's, `RETURNING *` is spliced at the end
as for a DELETE, and the verb in the question is "changed" for anything that is not a DELETE. `MERGE ... RETURNING`
exists from PostgreSQL 17; below that the existing fallback (the statement failed with the RETURNING added: undo, run it
as written) gives the count without the rows. Tables stay "unseen" for a MERGE (its source), so rules with table
conditions treat it as before (section 15).

*Tests.* The classification of each form (both flags, none, a second statement); a policy that denies deletes and updates
refuses each form and lets `DO NOTHING` through; a confirmation of each form with its rows and its tag (fake server);
and the real server: a `MERGE` confirmed, undone, confirmed as a prepared statement, an upsert of 40 rows, and the refusal.

## 31. Undoing a DELETE (built in v0.22; UPDATE in v0.23, see the end)

**What was asked, and the choice that made it small.** "Keep the rows a confirmed DELETE touched, to put them back."
The shape that looks natural, a table in the database that sluice writes to, needs a schema, privileges that the agent's
role would have to be given (and could then use to rewrite the journal), and a rewrite of the statement into a CTE that
inserts into it. A file on the proxy host needs none of that and keeps the data where the operator, not the agent, can
reach it. It costs a limit that is the whole design: the proxy only has what the server sends back.

**Why only DELETE.** The confirmation already runs the statement inside a transaction with `RETURNING *` and reads the
rows (section 20). For a `DELETE` those are the rows as they were. For an `UPDATE` they are the rows as they are now; the old
values would need `RETURNING OLD.*`, which is PostgreSQL 18, or a `SELECT ... FOR UPDATE` of the same rows beforehand, which
cannot be derived from an arbitrary `UPDATE ... FROM ... WHERE`. A journal of new values would be worse than none: it looks like
a way back and is not. So `journal` goes only with `match = "delete"` (checked when the policy is read), and a `MERGE` that
deletes, which that rule also matches since v0.21, is refused under `required` and not recorded under `on`.

**What is kept, and how it reads back.** Each row exactly as the server wrote it, in text format, with the column names of
the RowDescription; no type is needed: the script gives each value as an untyped literal in an `INSERT ... VALUES`, which
PostgreSQL reads as the type of the column it goes in (this is what makes `bytea`, `jsonb`, arrays and `infinity` come back
without the proxy knowing any of them; `scenario_undo_journal` runs the script on the real server and compares the
table by its JSON). `OVERRIDING SYSTEM VALUE` lets identity columns take their old value. The target table is the one the
statement names (`sl_sql_info.top_schema/top_table`, from the parse tree: the first, `FROM`, relation of the `DELETE`).

**When it is written.** The confirmation has three places where it commits: the answer yes, a `DELETE` under `over_rows`, and the
person's yes in their own session (section 23), where the proxy sends the `COMMIT` itself. `journal_gate` stands in front of
all of them (`sl_confirm_journal_gate` for the last, which the confirmation does not see), writes the entry, makes it durable,
and only then lets the commit through. If it must not (`required`), the statement is rolled back instead, with a message, and
nothing is written: an entry for a `DELETE` that did not happen would put back rows that were never gone. Held rows live in the
confirmation (at most 10,000 rows and 8 MiB, `SL_CONFIRM_JOURNAL_ROWS/BYTES`); more is "not whole".

**What it says it cannot do.** Cascades and triggers are not in `RETURNING`. The confirmation's looks at the statistics of the
transaction (section 22) already count them, so the entry carries them (`side`), and says when it did not look
(`side_known: false`). Rather than a flag `--force` there is the smaller thing: the script prints each of them as a
`WARNING` comment, and an entry that is not whole is refused by `sluice --undo` unless `--partial` is given.

**The format** is a line of JSON per entry, written by the same escaper as the log (and refused, not repaired, when a value is
not valid UTF-8: replacing bytes would be writing a different value), and read by a small strict parser of our own
(`undo.c`, depth-limited, no allocation by claimed size) so that reading needs nothing installed. It is fuzzed both ways
(`t_undo`: any line is read without a crash; any description and rows written give a line that reads back).

**A bug the real server found, in the first version of the script.** A literal's length was written by hand in the append
(`52` for a 51-byte string): the NUL after the string was written into the script, and `psql` read the rest as another statement.
All the literals of `journal.c` and `undo.c` are now appended by `strlen` (a helper), and `test_journal` checks that neither the
line nor the script holds a NUL. AddressSanitizer would have said so at once; the plain build did not.

**An UPDATE, in v0.23.** PostgreSQL 18 has `RETURNING OLD.*, NEW.*`, so the objection above is gone for that version. A
rule with `journal` on an `update` match makes the rewrite (`added_returning` in `conn.c`, both protocols) ask for both rows;
each DataRow then has twice the columns, the old half first. Two things follow. What the person and the mask see is the new
half only (`view`, `half_desc`, `half_row` in `confirm.c`), so the question reads as it always did and masking works on the
same columns; the journal gets the raw rows. And the entry has `kind: "update"`, `columns` (one name each), `data` (before)
and `new` (after). The script cannot use a key, because nothing here reads the catalog (the same reason qualified mask names
were not built until v0.24), so each row is found by **all** its new values (`IS NOT DISTINCT FROM`, null-safe) and must match exactly
one row, checked in the `DO` block: a row that changed since, or rows that came to look alike (`update t set b = 0`), stop it,
and since it is one transaction nothing is half undone. Failing closed is the whole design: guessing which of two identical
rows was which would be worse than doing nothing. The real server found two mistakes in the first script: a PL/pgSQL variable
named like a column (`n`) is ambiguous (now `sluice_undo_rows` and `#variable_conflict use_column`), and `RAISE` takes `%`, not
`%s`. A third was already there: the entry listed the statement's own table among "what else it changed"; it is taken out now.
On a server before 18 the `Parse` of a prepared statement fails on `OLD` (a loud failure, documented), and a simple statement
falls back to running without the old rows, which `required` refuses with the reason.

**Not done.** Journals for `UPDATE` before PostgreSQL 18; putting the cascade rows back (it would take a journal of every other
table the transaction touched); running the script (it is for a person: key conflicts and generated columns want a decision);
rotating the file itself.

## 32. Qualified names for masks (built in v0.24)

**What was refused in v0.21, and what changed.** `columns = ["users.email"]` needs to know, for each column of a result, which
table it comes from. The RowDescription gives an OID. Turning it into a name needs the catalog, and sluice holds no
credentials (section 4), so the question has to be asked in the client's own session. The two objections were: an injected
query is dangerous in a stream we follow message by message, and an OID goes stale (a table dropped and made again has a new
one), so a lookup that said "not users" for an OID it does not know would stop masking without anyone knowing.

**The answer to the second objection is the whole design: unknown means hidden.** A qualified name hides the column when the
table is one the list says is the named one, when the column has no table (OID 0), when the connection never had a list, and
when the OID is not in the list. It lets a column through only when the server said it belongs to another table it listed.
So a stale or missing list can only hide too much (`table_ok` in `mask.c`; `test_qualified_names`, and the real server in
`scenario_masking_qualified_names`). Over-hiding is reported by nothing and fixed by reconnecting; that is the price of never
under-hiding.

**The answer to the first is where the query goes.** Not mid-stream: once, after the login's ReadyForQuery, before the client
has said anything. At that moment nothing is in flight (`scan.owed <= z_seen`, no guard, no swallow, status idle), so the
query is injected at the release point, its answers are read by `probe_answer` and thrown away by the `swallow` that
confirmations already use, and the client's first message is queued behind it. A client that spoke first (it did not wait for
its login to end) skips the probe for that connection and gets the unqualified behaviour. One try, no retries, no query
in the middle of someone's pipeline: an extended-protocol cycle that is open would lose its unnamed statement to a simple
Query, which is why a later refresh was not done. A policy reload makes a new mask object, which starts without a list.

**What it costs.** One catalog query per connection that has a qualified name (at most 20,000 tables, 4 bytes each kept
besides the matches), nothing for the others. A view is a table of its own (its OID is the view's, as the server reports it
for a column that comes from a view), documented rather than resolved: following views would take `pg_depend`.

**Not done.** Refreshing the list while the connection lives; resolving views to their base tables; schema names that depend on
`search_path` (without a schema, a table of that name in any schema matches).

## 33. Roles, calls, alerts and a chained log (built in v0.25)

**Rules are about a name, and a name is not what a session can do.** `users = ["agent"]` is the login. `SET ROLE`,
`SET SESSION AUTHORIZATION` and `set_config('role', ...)` change what the session may do and leave that name alone, so a
rule against DDL for the agent is walked around by an agent that may become a role with the privilege. `set_session` is a
flag of the parser (`SET` of those two names, `kind` not `RESET`); `set_config` is only a call, which is why the calls had
to be known.

**Calls come from the tree, not from the summary.** The first version took the list of functions from libpg_query's summary
and a probe found what it leaves out: a `RETURNING` list (`delete from t returning pg_read_file(...)`), `DECLARE CURSOR`,
the defaults of a column. The summary is a walker written by hand for the usual places; the tree is complete. So the calls are
read from the JSON of the whole tree: every `FuncCall` begins with its name as a list of strings, and `collect_functions`
takes those (`tests/test_sql_check.c`, `test_functions`; the probe list of contexts is in the history of this section). A
string literal that looks like a call cannot make one up, since its quotes are escaped in the JSON; and a false one could only
add a name to the list. Not seen: bodies of functions, views, triggers, `DO` blocks. The list of "dangerous" functions is
closed, in `policy.c`, and prefix patterns (`pg_ls_*`) are used so that a function added in the next version is caught;
it is a list of what is known to reach out of the database, not a promise.

**`alert` does not decide.** An alert rule is looked at in a pass of its own, before the rules that decide, so its place in the
file does not matter and a `deny` after it, or before it, does not hide it. It writes a second event so that it can be found
without reading every statement.

**`kill` ends the connection after the answer.** The statement is blocked as `deny` does (a failing message takes its place,
so that the client gets an error and its answers stay in step) and `close_after_z` ends the connection at the ReadyForQuery that
answers it, the way the volume limit does. What the client had already put on the wire behind it is judged by a flag
(`killed`) that refuses every statement: Parse and Query are the messages that carry SQL, and those are the ones judged.

**The log with a chain.** `--log-chain-key-file` makes every line end with `"seq":N,"chain":"..."`, HMAC-SHA256 under that key of
the previous chain value and the line, cut to 16 bytes. A line changed, taken out, added or moved breaks the chain at that
line (`sluice --verify-log`), and a restart begins a new chain (`chain_start`, counted from 1) so that one file can hold many
runs. What it cannot show: a log **cut at its end** looks like a run that crashed (it says "not closed", exit status 3), and
whoever has the key can write a log that checks out, so the key belongs somewhere that the one who edits the log cannot read.
The last chain value of a run, which `--verify-log` prints, is what to keep elsewhere to catch a cut. The chain is made at
the moment the line is written (one HMAC of the line, on the single thread): a line that cannot be chained is not written,
rather than written without.

**Not done.** Calls inside views and functions; a policy for who may run `SET` of other settings; shipping the chain value to
a remote place (it is the operator's to do); `alert` through a channel other than the log.

## 34. Trying, testing, timing and counting (built in v0.26)

**Rules are easy to write and hard to trust.** The additions of this version are about the life of a policy: `dry_run` to see a
rule act without effect, `--test-policy` to keep the expectations as a file, windows of time to let a rule begin and end by
itself, shapes (fingerprints) with `--learn` to start from what really runs, and two limits (`budget_statements`,
`max_transaction`) for what an agent does by repeating.

**`dry_run` is `alert` for refusals.** It is looked at in a pass of its own (like alerts, before the rules that decide) and the
deciding loop skips it, so it is invisible to the verdict. It only goes with a rule that refuses or asks, because "this allow rule
would have allowed" says nothing. The `would` of the event is `sl_rule_would`.

**Time is an argument of the policy, not of the clock.** `time_fits` reads `now_unix()`, which a test can set
(`sl_policy_set_time`): `--test-policy`'s `at` and `--check-policy --at` use it. Windows are weekly, in UTC, with a window that
runs past midnight owned by the day it began. The first draft of `parse_instant` used `timegm`, which glibc hides under
`-D_POSIX_C_SOURCE`; the civil-date arithmetic is a few lines of its own (`days_from_civil`).

**Shapes.** The fingerprint is libpg_query's, of the message as the client sent it (before any `RETURNING` sluice adds), the one the
log already carries; it is now also in the log when `--log-sql full` is used, so that `--learn` can read any log. `--learn` is a
line scanner for the few fields it needs (a tolerant reader: its input is sluice's own log and a malformed line is skipped), and
it passes the text it shows through the normalizer so that a log with values cannot leak them into a policy file.
Two things came with it. The policy parser reads lists over several lines (comments, trailing comma): the learned rule has
hundreds of entries and one per line is how it is read; `join_list_lines` joins them in place before the existing parser sees one
line. And `SEEN_` became 64-bit macros: there were no bits left.

**Counting round trips instead of statements.** A statement count that works for the extended protocol would have had to follow
`Execute`, which only exists on connections that have the queue of answers (confirm or mask). The ReadyForQuery count needs
nothing: one per `Query`, one per `Sync`. The price is that it is not "statements" (a pipeline of fifty `Execute`s and one `Sync`
is one trip) and that a prepared statement run again cannot be refused one at a time, which is why spending the budget ends
the connection and later statements are refused at `Parse`/`Query`.

**`max_transaction` is checked when the connection is between two statements**, never in the middle of one: `fatal()` writes a
message into the stream and that is only safe when nothing is in flight. A transaction that is busy for longer than the limit
is `max_duration`'s business.

**`--tag-application-name`** rewrites the startup packet (`tag_startup`): the parameters are copied except the name, which is put
last with the tag and cut at a character boundary to leave the tag whole inside 63 bytes.

**Not done.** A refresh of fingerprints while the policy runs (learn offline, deploy by reload); `--learn` over rotated and
compressed logs; counting `Execute`s.

## 35. Metrics, answering over HTTP, and event commands (built in v0.27)

**Metrics from the places that know, not from the log.** The log could have been parsed back into counters, but a line that is
built for a person has the fields a person wants; a counter wants a small closed set of labels. So the places that already log
(`log_statement`, the close of a connection, `log_limit`, the confirmation outcome) also add to a counter, with labels that are
words sluice chose. Only one counter is generic, `sluice_log_events_total{event}`, fed by a **tap** in `sl_log_end` that sees every
line: that is also what the event command hangs on, so that any event can be sent anywhere without a site of its own. The registry
(`metrics.c`) is a fixed table with a hash index, bounded at 1,536 series, the last slots reserved for the counter that says
series were dropped; labels are cut at 72 bytes. A label that came from a client would be a way to grow memory: none does.

**One more listener in the same loop.** `admin.c` is a small non-blocking HTTP/1.1 server (8 connections, 4 KiB of request, one
request each, 5 s to send it), polled with the rest (`is_upstream == 3` in the slots). It has no TLS, no keep-alive, no body
parsing: it was cheaper to write the three things needed than to link an HTTP library into a proxy whose point is a small
attack surface. The token is compared with `CRYPTO_memcmp`. **Only POST answers**: link previews fetch URLs, so an approve link
that works on GET would be approved by Slack itself. Without a token it is open on a loopback address (metrics only; the
server refuses `--confirm-admin` and a non-loopback address without one), because a counter of how many statements were blocked
is worth less than the cost of distributing a token to a local Prometheus.

**The admin channel of the prompt.** Confirmations asked a terminal or a command, one at a time. The admin channel is a table in
the same module: a question gets a random id (16 hex digits), waits with any others, and `sl_prompt_admin_answer` calls the
reply of its owner, the same one a terminal answer calls, so the rest of the confirmation (the held answers, the commit or
rollback, the journal, the timeout, the client that leaves) is exactly what it was. `confirm_pending` is logged with the id, the
rule, the tag and the row count and **not the rows**; the question, which has them, is only behind the token.

**Event commands do not wait.** Forking a command from a single-threaded proxy is safe only if nothing waits for it: four at once,
64 queued, a dropped line is a counter, a late command is killed with its process group, and `fork` closes every descriptor above
2 so that a command inherits no socket. A webhook client inside the proxy would have meant DNS, TLS and timeouts on the thread
that moves the bytes; a `curl` in a child costs a process and takes all that out. `tools/webhook.sh` is the example, with the
JSON escaping done by `sed` and `awk` (the first version used a `sed` script that macOS and GNU read differently: the test posts a
multi-line question and checks that it parses).

**Not done.** TLS on the listener; a bearer token per route (read-only for Prometheus, answering for the bot); a callback
receiver for Slack's interactive messages (it would hold the token, so it is a service of its own); histograms (durations of
statements and confirmations).

## 36. Packaging (v0.27)

**One file is the promise, so the file has to be one file.** The README says "one binary"; with OpenSSL linked as a shared
library it was one binary plus a version of libssl that the machine may not have, and on macOS plus a path in Homebrew. The
release binaries are therefore static where static makes sense: on Linux with musl (a fully static program: `-Dstatic=true`
adds `-static` and links OpenSSL's archives), on macOS with OpenSSL's archives and nothing but `libSystem`, which cannot be
static. glibc is not used for this: its name lookups load libraries at run time, which a static glibc program does not do
reliably, and `getaddrinfo` is the first thing sluice does. Alpine has built sluice and passed every test since v0.9, so musl costs nothing
new. The static musl binary resolves Docker's names (tested against a
container reached by name on a user network).

**The release build found what the debug build hid.** `-O3` makes GCC see the `snprintf` of a 1,023-byte path into a 240-byte
message, and with `-Werror` the first optimized Linux build failed. The debug builds of every CI job never ran that path.
The CI now has a job that builds the release binary exactly as the release workflow does (`tools/build-static.sh`: Alpine,
optimized, tests run on the very binary that is shipped, then `strip`: Meson's `--strip` only acts at install time and the first
image carried 22 MB of debug information).

**Two images, because the small one cannot run a command.** `FROM scratch` with the binary and the CA certificates is 10 MB and has
no shell, no `curl`, nothing to exploit; it also has no `sh`, which `--event-command` and `--confirm-command` need. So a second
image on Alpine has `sh`, `curl`, `openssl`, `tini` and `webhook.sh`. `tini` is PID 1 there because a command that backgrounds
something leaves a child that nobody reaps, and sluice does not wait for its children of children. The user is a number
(`65532`): Kubernetes' `runAsNonRoot` cannot verify a name in an image with no `/etc/passwd`.

**The release is made once.** The release workflow builds and tests the four binaries (`linux` and `macos`, `amd64` and `arm64`),
packs them (`tools/package.sh`, which runs the packed binary and the example policies first), makes the source archive with
libpg_query inside (`meson dist --include-subprojects`) and **builds from it with downloads forbidden**, writes `SHA256SUMS`,
attests the provenance of every file, and makes the images from the *same* static binaries (`Dockerfile.release`) so that
nothing is compiled twice and the image holds what was released. Images are signed with cosign's keyless flow (the identity is
the workflow). A tag must equal the version in `meson.build` and have an entry in `CHANGELOG.md`, or nothing is built. A manual run
builds everything and publishes nothing.

**Notices travel with the binary.** A static binary contains libpg_query (BSD-3), the PostgreSQL parser (PostgreSQL License), upb,
utf8_range, xxHash and OpenSSL (Apache-2.0): `THIRD_PARTY_NOTICES.md` is generated from the licence files of the sources and is
in every archive. `sluice --version` says the commit, the OpenSSL, the parser and whether the build is static, which is what a
bug report needs.

**Not done.** `.deb` and `.rpm` (with a hardened systemd unit and manual pages), a Homebrew tap, a Helm chart, Windows (WSL
works), reproducible builds (the archive and the Alpine image are pinned by version, not by digest), a signature of the binaries
by a key (the attestation says who built them; a key would say who released them).
