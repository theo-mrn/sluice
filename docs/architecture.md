# Architecture

How the code is organised and where the next versions plug in. Decisions and their reasons live in
[design.md](design.md); this file is the map.

## Overview

sluice is a single-threaded TCP proxy built on `poll()`. Each accepted client connection becomes one
`sl_conn`, which owns two sockets (client and upstream) and two byte queues.

```
                      ┌──────────────────── sluice process ────────────────────┐
                      │                                                        │
  client ──TCP──►  listener ──accept──► sl_conn ──connect──► upstream Postgres │
 (psql, app,          │                  │  ▲                                  │
  agent)              │            c2u queue│u2c queue                          │
                      │                  ▼  │                                  │
                      │             state machine                              │
                      │   STARTUP → CONNECTING → RELAY → DONE                  │
                      └────────────────────────────────────────────────────────┘
                                          │
                                          └──► JSON lines on stdout (log)
```

`c2u` holds bytes read from the client that are not yet written to the upstream. `u2c` is the opposite
direction. Reading from a side stops when the opposite queue is above a high-water mark, so a slow peer
slows the other one down instead of filling memory.

## Modules

| File | Role | Depends on |
|---|---|---|
| `main.c` | Entry point: `--help`, `--version`, parse the command line, run the server | config, server |
| `config.c` | Command-line parsing, `HOST:PORT` parsing and validation | |
| `server.c` | Listener, `poll()` loop, connection table, signals, connection limit | conn, net, log |
| `conn.c` | One connection: state machine, I/O handlers, deadlines, the message scanners, verdicts and blocking, the TLS negotiation, the glue of confirmations | net, tls, pg_proto, policy, sql_check, buf, json, log |
| `policy.c` | The policy file (strict subset of TOML), the rules, and their evaluation. Pure | sql_check |
| `sql_check.c` | What a piece of SQL does, through libpg_query: one set of flags per statement, and on request the tables of each statement of the message. No network | libpg_query |
| `net.c` | Sockets only: listen, non-blocking connect, tuning, address strings | |
| `pg_proto.c` | PostgreSQL wire protocol: framing, SQL extraction, message building, the SASL offer. Pure functions, no I/O | |
| `scanner.c` | Walks the client's bytes message by message and decides what may be sent; pure, driven by callbacks | pg_proto, buf |
| `srvscan.c` | Walks the server's bytes message by message: relays, reads or throws away each one; pure, driven by callbacks | pg_proto, buf |
| `confirm.c` | The state machine of one confirmation (a DELETE or UPDATE run in a transaction not yet committed, shown, then committed or rolled back). Messages in, messages out; no socket, no terminal | pg_proto, srvscan, buf |
| `prompt.c` | A yes / no question on a terminal (`/dev/tty` or `--confirm-tty`), one at a time, in a queue | |
| `tls.c` | TLS towards the upstream, and as a server towards the clients (certificate files or one made at startup): a thin wrapper of OpenSSL with non-blocking calls that say what they wait for | OpenSSL |
| `buf.c` | Growable byte queue | |
| `json.c` | JSON string escaping, valid UTF-8 guaranteed | buf |
| `log.c` | One JSON object per line | buf, json |
| `clock.h` | Monotonic milliseconds | |

The split is chosen so that everything that touches bytes from the network (`pg_proto`, `json`, `buf`,
`config`) is pure: no sockets, no globals, easy to unit test and to fuzz. Everything that touches the
operating system is in `net.c`, `conn.c` and `server.c`.

## Connection life cycle

```
STARTUP ──startup packet complete──► CONNECTING ──socket writable, no error──► RELAY ──► DONE
   │  ▲                                  │                                       │
   │  └── SSLRequest / GSSENCRequest:    └── connect failed ──► FATAL to client ─┴──► DONE
   │      reply 'N', stay in STARTUP
   └── invalid packet ──► FATAL to client ──► DONE
```

- **STARTUP**: read the client's first packet. `SSLRequest` and `GSSENCRequest` get a single `N`; the
  client then sends its real startup packet in plain text. A `CancelRequest` or a startup packet moves on
  to CONNECTING, and the packet is kept in `c2u` so that it is the first thing sent upstream.
  With `--listen-tls`, an `SSLRequest` that is alone in the buffer gets `S` and the TLS handshake with the
  client (still in STARTUP, driven by `cltls_step`; from then on `cl_read` / `cl_write` carry the client's
  bytes, as `up_read` / `up_write` do for the upstream); a startup in clear is refused (28000), a
  `CancelRequest` in clear is still forwarded.
- **CONNECTING**: non-blocking `connect()` to the upstream. Nothing is read from the client meanwhile.
- **TLS** (only with `--upstream-tls`): between CONNECTING and RELAY. Three steps, each driven by what the
  socket allows: send the `SSLRequest`; read the server's one byte answer (`S`, or anything else is a
  failure); run the handshake. The same 10 second deadline covers CONNECTING and TLS. From then on every
  read and write on the upstream socket goes through `up_read` / `up_write`, which turn the library's
  "I need the socket readable / writable first" into the right `poll()` events. Bytes the library has
  already decrypted are served by `sl_conn_service_pending`, called from the server loop, which also
  shortens its `poll()` timeout to zero while some wait.
- **RELAY**: bytes flow both ways, unchanged. Towards the upstream they pass through the scanner, which
  reads Query and Parse messages and logs their SQL (next section).
- **DONE**: the server frees the connection on its next sweep and logs `connection_close` with the reason.

A connection that has not reached RELAY after 10 seconds is closed (`startup_timeout`,
`upstream_timeout`). Once in RELAY there is no timeout of sluice's own: Postgres enforces its own.

Errors before RELAY are reported to the client as a real PostgreSQL `ErrorResponse` (severity `FATAL`),
so `psql` and drivers print a readable message instead of a bare disconnect. After RELAY begins sluice
never writes into the stream towards the client: it could land in the middle of a message, and the replies
of earlier pipelined requests would be out of order. To block a statement it changes what the server
receives instead, so that the server writes the error itself (docs/design.md, section 11).

## The client to upstream scanner

`c2u` is a byte queue with a watermark, `released`. The first `released` bytes may be written to the
upstream; what follows is received but not cleared yet.

```
 c2u:  [ released: waiting for the upstream socket ][ held: an incomplete message ][ not scanned yet ]
         ^ flush_c2u writes this part                 ^ scan_c2u decides about this part
```

The walk itself is `sl_scan_run` in `src/scanner.c`: a state machine over a byte queue that knows nothing
about sockets, logs or policy, and asks `conn.c` three questions through callbacks (`on_statement`,
`on_unreadable`, `on_frame_error`): judge this message, say what replaces it if it is blocked, say whether
a broken stream ends the connection. The same bytes and the same answers come out however the stream is cut
into reads, which is what lets it be tested and fuzzed on its own. `scan_c2u` in `conn.c` is only the call
to it. It walks the unscanned bytes message by message (`sl_pg_parse_header`) and applies these rules:

- **Query (`Q`) and Parse (`P`)**, up to 1 MiB: held until the message is complete, then read
  (`sl_pg_statement_from_query` / `_from_parse`), judged (`judge`: classify the SQL, evaluate the rules),
  logged as a `statement` event, and released. If the verdict is "blocked" (enforce mode), the message is
  first replaced in place by `sl_buf_replace` with the one that fails (`sl_pg_append_failing_query` /
  `_failing_parse`), and the replacement is what gets released.
- **Every other message** is released as it arrives, header and body, without being read. Passwords (`p`),
  bind parameters (`B`) and `COPY` data (`d`) are therefore never looked at, let alone logged.
- **Query or Parse over 1 MiB** is logged as `oversized` and streamed unread. This is what bounds the
  memory held per connection: at most one message of 1 MiB plus the high-water mark. When it is blocked
  (an *uninspectable* message in enforce mode), only its 5 byte header is replaced by the failing message
  and `skip_remaining` throws the body away as it arrives.
- **Fast-path function call (`F`)**: runs a function without any SQL, so with a policy it is treated like
  a message that cannot be read.
- **An impossible header** (length below 4 or above the protocol maximum) logs `frame_error` once. In audit
  mode, and without a policy, inspection is turned off for that connection and everything is relayed as is:
  PostgreSQL answers the garbage itself. In enforce mode the connection is closed.
- **End of the client's stream**: whatever is still held is released, so the upstream sees exactly what the
  client sent, even a message cut short.
- **Backpressure** counts `released` (bytes the upstream has not taken yet), not held bytes. Otherwise a
  large message being held could stop the very reads that would complete it.

Without a policy, and in audit mode, every complete message is released right after it is logged:
behaviour on the wire is unchanged. Only enforce mode ever changes a byte, and only to block.

## Where the next versions plug in

- **Later.** A real PostgreSQL in the tests of a CI.

## Conventions

- Prefix `sl_` for everything public. Functions return `0` on success and `-1` on failure unless they
  return a count, a pointer or a three-way status (`SL_PG_OK`, `SL_PG_NEED_MORE`, `SL_PG_ERROR`).
- Parsers never read past the length they are given, never allocate, and treat every byte as hostile.
- Ownership: `sl_conn_new` takes the client socket on success (the caller keeps it on `NULL`).
  `sl_conn_free` closes both sockets and frees everything. Buffers are owned by the structure holding them.
- The only global state is the log sink and the "stop" flag set by the signal handler.
- `-Werror` with `warning_level=3`; CI builds also run with `address,undefined` sanitizers.
- Third-party code comes only through Meson subprojects pinned by hash, and is compiled apart from our own
  flags (no `-Werror`, no sanitizers).

## Tests

- `tests/test_*.c`: unit tests of the pure modules, run by `meson test`. `test_sql_check.c` runs the real
  PostgreSQL parser over about 130 statements (what each one counts as, hidden statements, refusals, very
  long and very deep SQL); `test_policy.c` covers the file format, every error with its line, and the
  evaluation order.
- `tests/integration.py`: starts the real binary against a fake PostgreSQL upstream and checks the bytes
  that cross the proxy, the error paths, the JSON log and the shutdown. No database needed.
  The TLS scenarios use a fake server that speaks PostgreSQL's TLS negotiation with Python's `ssl` module,
  with certificates made by the `openssl` tool at test time (they are skipped, and say so, when it cannot).
  They cover both modes, a wrong name, an unknown CA, a server without TLS, 5 MB each way, many small records
  at once, and the SCRAM offer arriving whole or byte by byte.
- `fuzz/`: eleven fuzz targets (the scanner one against an independent model), a seed corpus and a mutation driver (docs/design.md, section 14). A short run
  is part of `meson test`.
- Not automated, done by hand against throwaway PostgreSQL 17 containers: SCRAM login, simple and extended
  protocol, `COPY`, transactions, a 12 MB result compared byte for byte, and TLS (the server confirms it
  through `pg_stat_ssl`). A real PostgreSQL in CI is still to do.

## Known limits

- sluice judges statements, not their effects: `DO` blocks, function bodies and side effects of a `SELECT`
  are out of its sight (docs/design.md, section 12).
- Reading a very large statement is CPU work done on the only thread.
- A blocked statement shows up to the client as SQLSTATE `22P02`, not `42501` (section 11 of the design).
- `getaddrinfo()` is blocking: a slow DNS answer for the upstream stalls every connection for its
  duration. Acceptable for one workload per process; to revisit if it hurts.
- The addresses of the upstream are tried in turn (`net.c`, `sl_net_target_*`), and the list lives in the
  connection until one of them answers. A refused or unreachable address moves on to the next; one that
  stays silent is waited for until the connection timeout.
- When `accept()` fails for lack of descriptors, the listening socket is left out of the poll for 500 ms (or
  until a connection closes): on Linux the pending connection would otherwise keep it readable, and the loop
  would spin and fill the log. macOS drops that connection, which is why only Linux shows it.
- Upstream traffic is plain text unless `--upstream-tls` is given. The client side is plain text unless `--listen-tls` is given.
- Channel binding (`SCRAM-SHA-256-PLUS`) cannot work through sluice and is taken out of the server's offer.
- The handshake and connection timeout is fixed at 10 seconds.

## Following the server, and confirming a DELETE or UPDATE

Since a policy can ask for a person's confirmation (`action = "confirm"`), a connection with a policy reads
the server's stream too (`srvscan.c`), not only the client's. Most of it is relayed unread, header by
header, so that a result of any size still streams. What is read is the `ReadyForQuery` that ends each
answer: the status byte says whether a transaction is open, and counting them against the Query, Sync and
fast-path messages the client sent (`sl_scan.owed`) says whether the server is quiet.

When a statement matches a `confirm` rule and the server is quiet, the client's scanner swaps it for a
message of ours and **pauses** (`SL_SCAN_GUARD`): what the client sends behind it waits. The state machine of
`confirm.c` then runs the exchange: the server's answers are consumed, not forwarded; it asks for messages to
send to the server (they are put ahead of the held bytes with `sl_scan_inject`); the question goes to
`prompt.c`; and when it is over the client gets its own answer, the scanners resume, and the held bytes go
through the usual judgement. A statement that arrives while the server still owes answers is left in place
(`SL_SCAN_WAIT`) and looked at again when they are in. Whatever goes wrong (no answer, the client leaves,
sluice stops), the transaction is never committed. See design.md, section 20.

