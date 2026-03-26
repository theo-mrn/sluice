#!/usr/bin/env python3
"""End-to-end test of sluice against a fake PostgreSQL upstream.

No real database is involved. The fake upstream speaks just enough of the wire protocol to check that
bytes cross the proxy unchanged in both directions, that errors reach the client as a proper
ErrorResponse, that the JSON log is valid, and that the process shuts down cleanly.

usage: integration.py PATH_TO_SLUICE
"""
import atexit
import hashlib
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

SLUICE = sys.argv[1]
TIMEOUT = 10.0

SSL_REQUEST = struct.pack("!II", 8, 80877103)
GSSENC_REQUEST = struct.pack("!II", 8, 80877104)
CANCEL_REQUEST = struct.pack("!IIII", 16, 80877102, 4242, 0xDEADBEEF)


def check(cond, what):
    if not cond:
        print(f"FAIL: {what}", file=sys.stderr)
        sys.exit(1)


# ---- protocol helpers ----

def startup_packet(**params):
    body = struct.pack("!I", 196608)
    for key, value in params.items():
        body += key.encode() + b"\0" + value.encode() + b"\0"
    body += b"\0"
    return struct.pack("!I", len(body) + 4) + body


def message(kind, payload=b""):
    return kind + struct.pack("!I", len(payload) + 4) + payload


def recv_exact(sock, n):
    chunks = []
    while n:
        data = sock.recv(min(n, 1 << 20))
        if not data:
            raise EOFError(f"connection closed with {n} bytes still expected")
        chunks.append(data)
        n -= len(data)
    return b"".join(chunks)


def read_message(sock):
    head = recv_exact(sock, 5)
    length = struct.unpack("!I", head[1:])[0]
    return head[:1], recv_exact(sock, length - 4)


def read_startup(sock):
    head = recv_exact(sock, 4)
    length = struct.unpack("!I", head)[0]
    return head + recv_exact(sock, length - 4)


def at_eof(sock):
    try:
        return sock.recv(1) == b""
    except ConnectionResetError:
        return True


def error_fields(payload):
    """Splits an ErrorResponse payload into {tag: text}."""
    fields = {}
    for part in payload.split(b"\0"):
        if part:
            fields[chr(part[0])] = part[1:].decode()
    return fields


# ---- the fake PostgreSQL ----

class FakeUpstream:
    """Accepts one connection and runs `script(conn, seen)` on it."""

    def __init__(self, script, tls=None, answer=b"S", tolerate=False, client_ca=None):
        """tls: (certfile, keyfile) to speak PostgreSQL's TLS negotiation, `answer` being the byte sent to
        the SSLRequest. tolerate: the connection is expected to fail, which is not a test error. client_ca: the
        server asks for a client certificate and trusts this one."""
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.seen = {}
        self.error = None
        self.tolerate = tolerate
        self.client_ca = client_ca
        self.thread = threading.Thread(target=self._run, args=(script, tls, answer), daemon=True)
        self.thread.start()

    def _run(self, script, tls, answer):
        try:
            conn, _ = self.sock.accept()
            conn.settimeout(TIMEOUT)
            try:
                if tls is not None:
                    self.seen["ssl_request"] = recv_exact(conn, 8)
                    conn.sendall(answer)
                    if answer != b"S":
                        return
                    import ssl
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ctx.load_cert_chain(*tls)
                    if self.client_ca:
                        ctx.verify_mode = ssl.CERT_REQUIRED
                        ctx.load_verify_locations(self.client_ca)
                    conn = ctx.wrap_socket(conn, server_side=True)
                    self.seen["tls_version"] = conn.version()
                    if self.client_ca:
                        subject = dict(item[0] for item in conn.getpeercert()["subject"])
                        self.seen["client_cn"] = subject.get("commonName")
                script(conn, self.seen)
            finally:
                conn.close()
        except Exception as exc:  # reported by finish()
            if not self.tolerate:
                self.error = exc
        finally:
            self.sock.close()

    def finish(self):
        self.thread.join(TIMEOUT)
        check(not self.thread.is_alive(), "the fake upstream script did not finish")
        check(self.error is None, f"the fake upstream script failed: {self.error!r}")


# ---- the process under test ----

class Sluice:
    def __init__(self, upstream_port, policy=None, extra_args=(), fd_limit=None, held_fds=0,
                 upstream_host="127.0.0.1"):
        """fd_limit: the limit of open descriptors it runs under; held_fds: how many of them are already taken
        when it starts (they are opened under the limit, so that they use the low numbers)."""
        args = [SLUICE, "--listen", "127.0.0.1:0", "--upstream", f"{upstream_host}:{upstream_port}", *extra_args]
        if policy is not None:
            handle = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
            handle.write(policy)
            handle.close()
            atexit.register(lambda path=handle.name: os.path.exists(path) and os.unlink(path))
            args += ["--policy", handle.name]
            self.policy_path = handle.name
        if fd_limit is not None:
            launcher = (
                "import os, resource, sys\n"
                "limit, held = int(sys.argv[1]), int(sys.argv[2])\n"
                "resource.setrlimit(resource.RLIMIT_NOFILE, (limit, limit))\n"
                "for _ in range(held):\n"
                "    os.set_inheritable(os.open(os.devnull, os.O_RDONLY), True)\n"
                "os.execv(sys.argv[3], sys.argv[3:])\n"
            )
            args = [sys.executable, "-I", "-c", launcher, str(fd_limit), str(held_fds), *args]
        self.proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        # a failing check exits the test: never leave a proxy running behind it
        atexit.register(lambda: self.proc.poll() is None and self.proc.kill())
        first = self.proc.stdout.readline()
        if not first:
            self.proc.wait(TIMEOUT)
            print(self.proc.stderr.read(), file=sys.stderr)
            check(False, "sluice exited before listening")
        self.raw = [first]
        self.events = [json.loads(first)]
        check(self.events[0]["event"] == "listening", "first log line is the listening event")
        self.port = self.events[0]["port"]
        self.reader = threading.Thread(target=self._drain, daemon=True)
        self.reader.start()

    def _drain(self):
        for line in self.proc.stdout:
            self.raw.append(line)
            self.events.append(json.loads(line))  # every line must be valid JSON

    def connect(self):
        return socket.create_connection(("127.0.0.1", self.port), timeout=TIMEOUT)

    def raw_text(self):
        time.sleep(0.1)
        return "".join(self.raw)

    def wait_event(self, name, timeout=TIMEOUT, **match):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for ev in list(self.events):
                if ev["event"] == name and all(ev.get(k) == v for k, v in match.items()):
                    return ev
            time.sleep(0.02)
        check(False, f"no '{name}' event {match} in {self.events}")

    def stop(self):
        self.proc.send_signal(signal.SIGTERM)
        code = self.proc.wait(TIMEOUT)
        self.reader.join(TIMEOUT)
        return code


# ---- scenarios ----

def scenario_happy_path():
    """TLS refusal, startup, a query and its answer, terminate: all bytes cross unchanged."""
    def script(conn, seen):
        seen["startup"] = read_startup(conn)
        conn.sendall(message(b"R", struct.pack("!I", 0)) + message(b"Z", b"I"))
        kind, payload = read_message(conn)
        seen["query"] = message(kind, payload)
        conn.sendall(message(b"C", b"SELECT 1\0") + message(b"Z", b"I"))
        kind, payload = read_message(conn)
        seen["terminate"] = message(kind, payload)
        seen["eof"] = at_eof(conn)

    upstream = FakeUpstream(script)
    sluice = Sluice(upstream.port)

    client = sluice.connect()
    client.sendall(SSL_REQUEST)
    check(recv_exact(client, 1) == b"N", "SSLRequest is answered with N")
    client.sendall(GSSENC_REQUEST)
    check(recv_exact(client, 1) == b"N", "GSSENCRequest is answered with N")

    startup = startup_packet(user="alice", database="db1", application_name="itest")
    client.sendall(startup)
    check(read_message(client) == (b"R", struct.pack("!I", 0)), "AuthenticationOk reaches the client")
    check(read_message(client) == (b"Z", b"I"), "ReadyForQuery reaches the client")

    query = message(b"Q", b"SELECT 1\0")
    client.sendall(query)
    check(read_message(client) == (b"C", b"SELECT 1\0"), "CommandComplete reaches the client")
    check(read_message(client) == (b"Z", b"I"), "second ReadyForQuery reaches the client")

    client.sendall(message(b"X"))
    client.close()
    upstream.finish()

    check(upstream.seen["startup"] == startup, "the startup packet reaches the upstream unchanged")
    check(upstream.seen["query"] == query, "the query reaches the upstream unchanged")
    check(upstream.seen["terminate"] == message(b"X"), "Terminate reaches the upstream")
    check(upstream.seen["eof"], "the upstream sees the connection close")

    started = sluice.wait_event("startup", user="alice", database="db1", application_name="itest")
    check(started["protocol"] == "3.0", "the protocol version is logged")
    sluice.wait_event("upstream_connected")
    closed = sluice.wait_event("connection_close", reason="client_closed")
    check(closed["bytes_from_client"] > len(startup), "bytes read from the client are counted")
    check(closed["bytes_from_upstream"] > 0, "bytes read from the upstream are counted")
    check(closed["id"] == started["id"], "events of one connection share an id")

    check(sluice.stop() == 0, "SIGTERM ends sluice with exit code 0")
    sluice.wait_event("shutdown")


def scenario_large_transfer():
    """5 MB each way: exercises partial writes and the high-water mark."""
    size = 5_000_000
    blob = os.urandom(size)
    answer = os.urandom(size)

    def script(conn, seen):
        read_startup(conn)
        conn.sendall(message(b"R", struct.pack("!I", 0)) + message(b"Z", b"I"))
        kind, payload = read_message(conn)
        seen["digest"] = (kind, hashlib.sha256(payload).hexdigest())
        conn.sendall(message(b"D", answer))
        seen["eof"] = at_eof(conn)

    upstream = FakeUpstream(script)
    sluice = Sluice(upstream.port)
    client = sluice.connect()
    client.sendall(startup_packet(user="bulk"))
    read_message(client)
    read_message(client)

    client.sendall(message(b"Q", blob))
    kind, payload = read_message(client)
    check(kind == b"D" and hashlib.sha256(payload).digest() == hashlib.sha256(answer).digest(),
          "a 5 MB answer arrives intact")
    client.close()
    upstream.finish()
    check(upstream.seen["digest"] == (b"Q", hashlib.sha256(blob).hexdigest()),
          "a 5 MB query arrives intact")
    sluice.wait_event("connection_close", reason="client_closed")
    check(sluice.stop() == 0, "clean shutdown after a large transfer")


def scenario_cancel_request():
    """A CancelRequest opens its own connection and is forwarded as is."""
    def script(conn, seen):
        # like a real server: read the request, then hang up
        seen["cancel"] = recv_exact(conn, 16)

    upstream = FakeUpstream(script)
    sluice = Sluice(upstream.port)
    client = sluice.connect()
    client.sendall(CANCEL_REQUEST)
    check(at_eof(client), "the client is disconnected once the upstream closes")
    upstream.finish()
    check(upstream.seen["cancel"] == CANCEL_REQUEST, "the CancelRequest reaches the upstream unchanged")
    sluice.wait_event("cancel_request")
    check(sluice.stop() == 0, "clean shutdown")


def scenario_upstream_down():
    """No upstream listening: the client gets a FATAL ErrorResponse, not a silent disconnect."""
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    dead_port = probe.getsockname()[1]
    probe.close()

    sluice = Sluice(dead_port)
    client = sluice.connect()
    client.sendall(startup_packet(user="alice"))
    kind, payload = read_message(client)
    fields = error_fields(payload)
    check(kind == b"E", "the client receives an ErrorResponse")
    check(fields["S"] == "FATAL" and fields["C"] == "08001", f"FATAL / 08001, got {fields}")
    check("sluice" in fields["M"], "the message says it comes from sluice")
    check(at_eof(client), "the connection is closed after the error")
    err = sluice.wait_event("upstream_error")
    check(err["code"] == "connect_failed" and "tls_alert" not in err, f"a stable code, and no alert: {err}")
    sluice.wait_event("connection_close", reason="upstream_unreachable")
    check(sluice.stop() == 0, "clean shutdown")


def scenario_garbage_startup():
    """Invalid first packets are answered with a protocol-violation error."""
    sluice = Sluice(1)  # never reached
    for junk in (b"\x00\x00\x00\x03abc", b"\xff\xff\xff\xff", b"\x00\x00\x00\x08\x00\x01\x00\x00"):
        client = sluice.connect()
        client.sendall(junk)
        kind, payload = read_message(client)
        fields = error_fields(payload)
        check(kind == b"E" and fields["C"] == "08P01", f"junk {junk!r} gets 08P01, got {fields}")
        check(at_eof(client), "the connection is closed after the error")
    sluice.wait_event("connection_close", reason="protocol_error")

    # a client that connects and leaves without a word is just logged and forgotten
    client = sluice.connect()
    client.close()
    sluice.wait_event("connection_close", reason="client_closed")
    check(sluice.stop() == 0, "clean shutdown")


def scenario_log_is_safe_json():
    """Hostile values in the startup packet must not break the log."""
    def script(conn, seen):
        read_startup(conn)

    upstream = FakeUpstream(script)
    sluice = Sluice(upstream.port)
    client = sluice.connect()
    evil = 'bob"}\n{"event":"forged'
    client.sendall(startup_packet(user=evil, application_name="café"))
    event = sluice.wait_event("startup")
    check(event["user"] == evil, "the user name is logged as a plain string, newline and quote escaped")
    check(event["application_name"] == "café", "UTF-8 is preserved")
    check(not [e for e in sluice.events if e["event"] == "forged"], "no forged event in the log")
    client.close()
    upstream.finish()
    check(sluice.stop() == 0, "clean shutdown")


# ---- v0.2: the SQL of Query and Parse messages is logged, the bytes are never altered ----

def recording_script(conn, seen):
    """Greets the client like a server would, then records everything it receives until EOF."""
    seen["startup"] = read_startup(conn)
    conn.sendall(message(b"R", struct.pack("!I", 0)) + message(b"Z", b"I"))
    chunks = []
    while True:
        data = conn.recv(1 << 20)
        if not data:
            break
        chunks.append(data)
    seen["stream"] = b"".join(chunks)


def open_session(sluice, **params):
    """Connects and completes the startup exchange, so that closing later cannot reset the connection."""
    client = sluice.connect()
    client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    client.sendall(startup_packet(**params))
    check(read_message(client)[0] == b"R", "authentication request reaches the client")
    check(read_message(client)[0] == b"Z", "ReadyForQuery reaches the client")
    return client


def statements_of(sluice, started):
    sluice.wait_event("connection_close", id=started["id"])
    return [e for e in sluice.events if e["event"] == "statement" and e["id"] == started["id"]]


def scenario_statements_are_logged():
    """Query and Parse are logged; passwords and bind parameters never are; the stream is untouched."""
    hostile = "select 'a\"b\n\\' , 'é'"
    simple = [
        message(b"p", b"s3cret-password\0"),
        message(b"Q", b"SELECT 1\0"),
        message(b"P", b"s1\0select $1::int\0" + struct.pack("!H", 1) + struct.pack("!I", 23)),
        message(b"B", b"\0s1\0" + struct.pack("!HH", 0, 1) + struct.pack("!I", 14) + b"topsecretvalue"
                + struct.pack("!H", 0)),
        message(b"E", b"\0" + struct.pack("!I", 0)),
        message(b"S"),
        message(b"Q", hostile.encode() + b"\0"),
        message(b"Q", b"select '\xff\xfe'\0"),
    ]
    split = message(b"Q", b"select pg_sleep(0)\0")
    coalesced = (message(b"Q", b"select 1\0") + message(b"Q", b"select 2\0") + message(b"S"))
    malformed = message(b"Q", b"select no nul")

    upstream = FakeUpstream(recording_script)
    sluice = Sluice(upstream.port)
    client = open_session(sluice, user="alice", database="db1")

    for msg in simple:
        client.sendall(msg)
    for i in range(len(split)):  # one byte at a time: the message must be reassembled
        client.sendall(split[i:i + 1])
        time.sleep(0.002)
    client.sendall(coalesced)    # three messages in one segment
    client.sendall(malformed)
    client.close()
    upstream.finish()

    sent = b"".join(simple) + split + coalesced + malformed
    check(upstream.seen["stream"] == sent, "every byte reaches the upstream unchanged and in order")

    started = sluice.wait_event("startup", user="alice")
    stmts = statements_of(sluice, started)
    got = [(e["kind"], e.get("name"), e.get("sql"), e.get("malformed", False)) for e in stmts]
    want = [
        ("query", None, "SELECT 1", False),
        ("parse", "s1", "select $1::int", False),
        ("query", None, hostile, False),
        ("query", None, "select '��'", False),
        ("query", None, "select pg_sleep(0)", False),
        ("query", None, "select 1", False),
        ("query", None, "select 2", False),
        ("query", None, None, True),
    ]
    check(got == want, f"statements logged in order.\n got:  {got}\n want: {want}")
    check(all(e["user"] == "alice" and e["database"] == "db1" for e in stmts),
          "each statement carries the user and the database")
    check(stmts[0]["sql_len"] == len("SELECT 1"), "sql_len is the length of the SQL")

    log_text = "".join(sluice.raw)
    check("s3cret-password" not in log_text, "a password never reaches the log")
    check("topsecretvalue" not in log_text, "bind parameters never reach the log")

    closed = sluice.wait_event("connection_close", id=started["id"])
    check(closed["statements"] == len(want), "the close event counts the statements")
    check(sluice.stop() == 0, "clean shutdown")


def scenario_long_and_oversized_statements():
    """Long SQL is cut on a character boundary; a message over 1 MiB streams through unread."""
    long_sql = "select '" + "é" * 10000 + "'"          # 20 010 bytes of UTF-8
    long_msg = message(b"Q", long_sql.encode() + b"\0")
    huge_msg = message(b"Q", b"select '" + b"y" * (2 * 1024 * 1024) + b"'\0")
    after = message(b"Q", b"select 3\0")

    upstream = FakeUpstream(recording_script)
    sluice = Sluice(upstream.port)
    client = open_session(sluice, user="bob", database="db2")
    client.sendall(long_msg)
    client.sendall(huge_msg)
    client.sendall(after)
    client.close()
    upstream.finish()
    check(upstream.seen["stream"] == long_msg + huge_msg + after, "long and huge messages arrive intact")

    started = sluice.wait_event("startup", user="bob")
    stmts = statements_of(sluice, started)
    check(len(stmts) == 3, f"three statements logged, got {len(stmts)}")

    first = stmts[0]
    check(first["truncated"] is True, "a long statement is marked truncated")
    check(first["sql_len"] == len(long_sql.encode()), "the full length is still reported")
    check(len(first["sql"].encode()) <= 8192, "the logged text is capped at 8 KiB")
    check("�" not in first["sql"], "the cut does not split a UTF-8 character")
    check(long_sql.startswith(first["sql"]), "the logged text is a prefix of the real one")

    check(stmts[1].get("oversized") is True and "sql" not in stmts[1], "a huge statement is flagged, not read")
    check(stmts[1]["message_len"] > 2 * 1024 * 1024, "its size is reported")
    check(stmts[2]["sql"] == "select 3", "inspection resumes right after a huge message")
    check(sluice.stop() == 0, "clean shutdown")


def scenario_frame_error_keeps_relaying():
    """An invalid header ends inspection, not the connection: sluice stays transparent."""
    good = message(b"Q", b"select 1\0")
    garbage = b"Z\x00\x00\x00\x02not a message at all"
    later = message(b"Q", b"select 2\0")

    upstream = FakeUpstream(recording_script)
    sluice = Sluice(upstream.port)
    client = open_session(sluice, user="carol", database="db3")
    client.sendall(good)
    client.sendall(garbage)
    client.sendall(later)
    client.close()
    upstream.finish()
    check(upstream.seen["stream"] == good + garbage + later, "everything is relayed, garbage included")

    started = sluice.wait_event("startup", user="carol")
    stmts = statements_of(sluice, started)
    check([e["sql"] for e in stmts] == ["select 1"], "nothing is logged after the framing error")
    sluice.wait_event("frame_error", id=started["id"])
    check(sluice.stop() == 0, "clean shutdown")


def scenario_client_leaves_mid_message():
    """A message cut short by a disconnect is passed on as it is, and nothing hangs."""
    cut = b"Q" + struct.pack("!I", 104) + b"select"

    upstream = FakeUpstream(recording_script)
    sluice = Sluice(upstream.port)
    client = open_session(sluice, user="dave", database="db4")
    client.sendall(cut)
    client.close()
    upstream.finish()
    check(upstream.seen["stream"] == cut, "the truncated message reaches the upstream as sent")

    started = sluice.wait_event("startup", user="dave")
    check(statements_of(sluice, started) == [], "an incomplete message is not logged as a statement")
    sluice.wait_event("connection_close", id=started["id"], reason="client_closed")
    check(sluice.stop() == 0, "clean shutdown")


# ---- v0.3: rules. A blocked message is replaced by one that fails on the server ----

POLICY = """
mode = "enforce"

[[rule]]
name = "migrations"
match = "ddl"
action = "allow"
users = ["migrator"]

[[rule]]
name = "no-ddl"
match = "ddl"
message = "schema changes go through migrations"

[[rule]]
name = "no-unbounded-write"
match = "update_or_delete_without_where"
message = "add a WHERE clause"

[[rule]]
name = "agent-read-only"
match = "not_read_only"
users = ["agent"]
"""

R_UNBOUNDED = "sluice: blocked by rule no-unbounded-write: add a WHERE clause"
R_DDL = "sluice: blocked by rule no-ddl: schema changes go through migrations"
R_AGENT = "sluice: blocked by rule agent-read-only"
R_BIG = "sluice: cannot inspect this statement (message over 1 MiB)"
R_FASTPATH = "sluice: cannot inspect this statement (fast-path function calls cannot be inspected)"


def q(sql):
    return message(b"Q", sql.encode() + b"\0")


def parse_msg(name, sql, oids=()):
    return message(b"P", name + b"\0" + sql.encode() + b"\0" + struct.pack("!H", len(oids))
                   + b"".join(struct.pack("!I", o) for o in oids))


def failing_sql(reason):
    return "select '%s'::int" % reason.replace("'", "''")


def failing_q(reason):
    return q(failing_sql(reason))


def failing_p(name, reason):
    return parse_msg(name, failing_sql(reason))  # no parameters: the original type ids are dropped


def run_session(policy, user, messages, database="db1"):
    """One client, one fake upstream: returns what the upstream received, the statement events, the
    close event and the sluice process."""
    upstream = FakeUpstream(recording_script)
    sluice = Sluice(upstream.port, policy=policy)
    client = open_session(sluice, user=user, database=database)
    for m in messages:
        client.sendall(m)
    client.close()
    upstream.finish()
    started = sluice.wait_event("startup", user=user)
    stmts = statements_of(sluice, started)
    closed = sluice.wait_event("connection_close", id=started["id"])
    check(sluice.stop() == 0, "clean shutdown")
    return upstream.seen["stream"], stmts, closed, sluice


def summary(stmts):
    return [(e["kind"], e.get("verdict"), e.get("rule"), e.get("action")) for e in stmts]


def scenario_enforce_rewrites_blocked_messages():
    """In enforce mode a blocked message never reaches the server: its replacement does, the rest is
    untouched and in order."""
    bind = message(b"B", b"\0s1\0" + struct.pack("!HHH", 0, 0, 0))
    execute = message(b"E", b"\0" + struct.pack("!I", 0))
    sync = message(b"S")
    sent = [
        q("select 1"),
        q("delete from t"),
        parse_msg(b"s1", "delete from t", (23,)),
        bind, execute, sync,
        q("delete from t where id = 1"),
        q("select 1; drop table t"),
        q("with d as (delete from t returning *) select * from d"),
        q("explain analyze delete from t"),
        q("explain delete from t"),
        parse_msg(b"p1", "select $1::int", (23,)),
        message(b"X"),
    ]
    expected = [
        q("select 1"),
        failing_q(R_UNBOUNDED),
        failing_p(b"s1", R_UNBOUNDED),
        bind, execute, sync,
        q("delete from t where id = 1"),
        failing_q(R_DDL),
        failing_q(R_UNBOUNDED),
        failing_q(R_UNBOUNDED),
        q("explain delete from t"),
        parse_msg(b"p1", "select $1::int", (23,)),
        message(b"X"),
    ]
    stream, stmts, closed, _ = run_session(POLICY, "alice", sent)
    check(stream == b"".join(expected), "the server receives the replacements, everything else unchanged")
    check(summary(stmts) == [
        ("query", "allow", None, "relayed"),
        ("query", "deny", "no-unbounded-write", "blocked"),
        ("parse", "deny", "no-unbounded-write", "blocked"),
        ("query", "allow", None, "relayed"),
        ("query", "deny", "no-ddl", "blocked"),
        ("query", "deny", "no-unbounded-write", "blocked"),
        ("query", "deny", "no-unbounded-write", "blocked"),
        ("query", "allow", None, "relayed"),
        ("parse", "allow", None, "relayed"),
    ], f"verdicts are logged: {summary(stmts)}")
    check(stmts[2]["name"] == "s1" and stmts[2]["sql"] == "delete from t",
          "the log shows the original statement, not the replacement")
    check(closed["statements"] == 9 and closed["blocked"] == 5, "the close event counts blocked messages")


R_AMBIGUOUS = ("sluice: cannot inspect this statement (a backslash inside a quoted string is read differently "
               "depending on standard_conforming_strings and client_encoding)")


def qb(sql):
    """A simple query from bytes: the SQL may hold bytes that are not UTF-8."""
    return message(b"Q", sql + b"\0")


def scenario_strings_read_two_ways():
    """A string that the server may cut elsewhere than sluice (standard_conforming_strings, a multi-byte
    client_encoding) is not judged on a reading that may be wrong: found with a real server, where the DELETE
    hidden after the string ran although a rule forbids it."""
    scs = b"select 'x\\'\n'; delete from t; --'"           # standard_conforming_strings = off
    sjis = b"select E'\x95\\'; delete from t; --'"           # client_encoding = SJIS: 0x95 0x5c is one letter
    fine = [q("select 'C:\\\\'"), q(r"select x ~ '^\\d+$' from t"), q("select E'it\\'s'"), q("select $$a\\'b$$")]
    sent = [q("set standard_conforming_strings = off"), qb(scs), qb(sjis), parse_msg(b"s1", scs.decode("latin1")),
            *fine, q("select 1")]
    expected = [q("set standard_conforming_strings = off"), failing_q(R_AMBIGUOUS), failing_q(R_AMBIGUOUS),
                failing_p(b"s1", R_AMBIGUOUS), *fine, q("select 1")]
    stream, stmts, closed, _ = run_session(POLICY, "alice", sent)
    check(stream == b"".join(expected), "the ambiguous messages never reach the server; the others are untouched")
    check([e["verdict"] for e in stmts] == ["allow"] + ["uninspectable"] * 3 + ["allow"] * 5,
          f"verdicts: {[e['verdict'] for e in stmts]}")
    check(all(e["action"] == "blocked" for e in stmts[1:4]), "and they are blocked")
    check("backslash" in stmts[1]["detail"], f"the log says why: {stmts[1]}")
    check(closed["blocked"] == 3, "three messages blocked")

    # audit mode relays them and says what it would have done; on_uninspectable = "allow" lets them through
    stream, stmts, _, _ = run_session(POLICY.replace('"enforce"', '"audit"'), "alice", [qb(scs)])
    check(stream == qb(scs) and stmts[0]["verdict"] == "uninspectable"
          and stmts[0]["action"] == "relayed", "audit relays it and logs the verdict")
    stream, stmts, _, _ = run_session(POLICY.replace('mode = "enforce"', 'mode = "enforce"\non_uninspectable = "allow"'),
                                      "alice", [qb(scs)])
    check(stream == qb(scs) and stmts[0]["action"] == "relayed", "on_uninspectable = allow lets it through")


def cpu_seconds(pid):
    """CPU time used so far by a process, from ps ("1:02.50" or "0:00.12")."""
    out = subprocess.run(["ps", "-o", "time=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
    total = 0.0
    for part in out.split(":"):
        total = total * 60 + float(part)
    return total


def scenario_out_of_descriptors_does_not_spin():
    """When accept() fails for lack of descriptors, the listening socket stays readable: polling it again at
    once would burn a whole CPU and fill the log. sluice leaves it alone for a moment, and recovers."""
    sluice = None
    clients = []
    try:
        sluice = Sluice(1, fd_limit=64, held_fds=40)  # 64 in all: 40 taken, so 24 for sockets, pipes and logs
        for _ in range(40):
            try:
                clients.append(sluice.connect())
            except OSError:
                break
        time.sleep(0.2)
        before = cpu_seconds(sluice.proc.pid)
        count = len([e for e in sluice.events if e["event"] == "accept_error"])
        time.sleep(1.5)
        spent = cpu_seconds(sluice.proc.pid) - before
        errors = len([e for e in sluice.events if e["event"] == "accept_error"]) - count
        check(count > 0, "the test did run sluice out of descriptors")
        check(spent < 0.3, f"it does not spin while out of descriptors: {spent:.2f} s of CPU in 1.5 s")
        check(errors <= 8, f"and does not flood the log: {errors} accept_error events in 1.5 s")

        # room again: it serves new connections
        for c in clients:
            c.close()
        clients = []
        time.sleep(1.0)
        opened = len([e for e in sluice.events if e["event"] == "connection_open"])
        fresh = sluice.connect()
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline and len([e for e in sluice.events if e["event"] == "connection_open"]) <= opened:
            time.sleep(0.05)
        check(len([e for e in sluice.events if e["event"] == "connection_open"]) > opened, "and takes connections again")
        fresh.close()
        check(sluice.stop() == 0, "clean shutdown")
    finally:
        for c in clients:
            c.close()


def scenario_name_with_several_addresses():
    """A name that resolves to several addresses is tried address by address: "localhost" is ::1 and 127.0.0.1
    on most machines, and the database only listens on the second."""
    upstream = FakeUpstream(recording_script)  # IPv4 only, like a database with listen_addresses = '127.0.0.1'
    sluice = Sluice(upstream.port, upstream_host="localhost")
    client = open_session(sluice, user="alice", database="db1")
    client.sendall(q("select 1"))
    client.close()
    upstream.finish()
    check(upstream.seen["stream"] == q("select 1"), "the query reaches the database through 'localhost'")
    sluice.wait_event("upstream_connected")
    check(not [e for e in sluice.events if e["event"] == "upstream_error"], "and nothing is reported as an error")
    check(sluice.stop() == 0, "clean shutdown")

    # nothing listens on any of the addresses: one clear error, with the reason of the last attempt
    sluice = Sluice(1, upstream_host="localhost")
    client = sluice.connect()
    client.sendall(startup_packet(user="alice"))
    kind, payload = read_message(client)
    check(kind == b"E" and error_fields(payload)["C"] == "08001", "the client gets a FATAL 08001")
    err = sluice.wait_event("upstream_error")
    check(err["code"] == "connect_failed" and "localhost:1" in err["error"] and "refused" in err["error"].lower(),
          f"the log says it: {err}")
    check(len([e for e in sluice.events if e["event"] == "upstream_error"]) == 1, "once")
    sluice.wait_event("connection_close", reason="upstream_unreachable")
    check(sluice.stop() == 0, "clean shutdown")


def scenario_search_path_cannot_move_a_table():
    """Found on a real server: with a rule that keeps a client in tenant_a, `SET search_path = tenant_b` then
    `select * from orders` read tenant_b.orders. A table written without a schema is not proof."""
    policy = """
mode = "enforce"

[[rule]]
name = "tenant-a-only"
match = "any"
outside_tables = ["tenant_a.orders"]
message = "tenant A only"
"""
    reason = "sluice: blocked by rule tenant-a-only: tenant A only"
    sent = [q("select * from tenant_a.orders"), q("set search_path = tenant_b"), q("select * from orders"),
            q("select * from tenant_b.orders"), q("select * from tenant_a.orders"), message(b"X")]
    expected = [q("select * from tenant_a.orders"), q("set search_path = tenant_b"), failing_q(reason),
                failing_q(reason), q("select * from tenant_a.orders"), message(b"X")]
    stream, stmts, closed, _ = run_session(policy, "alice", sent)
    check(stream == b"".join(expected), "only what is surely in tenant_a reaches the server")
    check([s["verdict"] for s in stmts] == ["allow", "allow", "deny", "deny", "allow"],
          f"verdicts: {[s['verdict'] for s in stmts]}")
    check(closed["blocked"] == 2, "two messages blocked")


def scenario_warnings_for_a_risky_setup():
    """Two ways to be less protected than it looks, said at startup: an address that others can reach while
    the clients' side is in clear, and a table entry that can never match an unquoted name."""
    port = 1  # nobody connects: only the startup is looked at
    sluice = Sluice(port)
    time.sleep(0.2)
    check(not [e for e in sluice.events if e["event"] == "warning"], "a loopback setup has nothing to warn about")
    check(sluice.stop() == 0, "clean shutdown")

    # a database elsewhere, in clear (an address of the documentation range: nothing connects to it)
    sluice = Sluice(port, upstream_host="192.0.2.1")
    warning = sluice.wait_event("warning")
    check("not encrypted" in warning["detail"] and "not on this machine" in warning["detail"],
          f"upstream in clear: {warning}")
    check(sluice.stop() == 0, "clean shutdown")

    sluice = Sluice(port, extra_args=["--listen", "0.0.0.0:0"])
    warning = sluice.wait_event("warning")
    check("not encrypted" in warning["detail"] and "0.0.0.0" not in warning["detail"], f"listening wide: {warning}")
    check(sluice.stop() == 0, "clean shutdown")

    policy = ('mode = "enforce"\n[[rule]]\nname = "w"\nmatch = "not_read_only"\ntables = ["Ledger", "audit.log"]\n'
              '[[rule]]\nname = "o"\nmatch = "any"\noutside_tables = ["public.Orders"]\n')
    sluice = Sluice(port, policy=policy)
    time.sleep(0.2)
    found = sorted((e["rule"], e["entry"]) for e in sluice.events if e["event"] == "warning" and "rule" in e)
    check(found == [("o", "public.Orders"), ("w", "Ledger")], f"upper-case entries are named: {found}")

    # the same after a reload
    with open(sluice.policy_path, "w") as f:
        f.write('mode = "enforce"\n[[rule]]\nname = "w2"\nmatch = "any"\ntables = ["Secret"]\n')
    sluice.proc.send_signal(signal.SIGHUP)
    sluice.wait_event("policy_reloaded")
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline and not [e for e in sluice.events if e.get("rule") == "w2"]:
        time.sleep(0.02)
    check([e["entry"] for e in sluice.events if e.get("rule") == "w2"] == ["Secret"], "and after a reload")
    check(sluice.stop() == 0, "clean shutdown")

    sluice = Sluice(port, policy='mode = "enforce"\n[[rule]]\nname = "w"\nmatch = "any"\ntables = ["ledger", "a.b"]\n')
    time.sleep(0.2)
    check(not [e for e in sluice.events if e["event"] == "warning"], "lower-case entries are fine")
    check(sluice.stop() == 0, "clean shutdown")


def hold_open(conn, seen):
    """Takes the connection and reads whatever comes, never answering, until the other side hangs up."""
    seen["received"] = b""
    conn.settimeout(3 * TIMEOUT)  # longer than any deadline of sluice: it is sluice that must give up first
    while True:
        data = conn.recv(65536)
        if not data:
            return
        seen["received"] += data


def abort_connection(sock):
    """Closes with a reset (RST) instead of the usual FIN: what a crashed peer or a firewall does."""
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    sock.close()


def scenario_timeouts():
    """A connection that does not get going is dropped after 10 seconds, at whichever stage it is stuck at:
    nothing may keep a slot for ever by connecting and going quiet."""
    quiet = FakeUpstream(hold_open, tolerate=True)  # takes the TCP connection, says nothing
    waiting = Sluice(1)                                                   # a client that sends no startup packet
    stuck = Sluice(quiet.port, extra_args=["--upstream-tls", "require"])  # a database that never answers
    idle = waiting.connect()
    client = stuck.connect()
    client.sendall(startup_packet(user="alice"))

    closed = waiting.wait_event("connection_close", timeout=15, reason="startup_timeout")
    check(9500 <= closed["duration_ms"] <= 13000, f"after about 10 seconds: {closed['duration_ms']} ms")
    check(at_eof(idle), "the silent client is disconnected")
    closed = stuck.wait_event("connection_close", timeout=15, reason="upstream_timeout")
    check(9500 <= closed["duration_ms"] <= 13000, f"the same while waiting for the database: {closed}")
    check(at_eof(client), "and that client too")
    check(waiting.stop() == 0 and stuck.stop() == 0, "clean shutdown")
    quiet.finish()


def scenario_connection_limit():
    """Beyond the limit a client gets PostgreSQL's own "too many connections" and the others are unaffected."""
    sluice = Sluice(1, fd_limit=40)  # 12 connections fit in 40 descriptors, two each, with some to spare
    limit = sluice.events[0]["max_connections"]
    check(limit == 12, f"the limit follows the descriptors: {limit}")
    clients = [sluice.connect() for _ in range(limit)]
    for _ in range(limit):
        sluice.wait_event("connection_open", id=_ + 1)
    extra = sluice.connect()
    kind, payload = read_message(extra)
    fields = error_fields(payload)
    check(kind == b"E" and fields["C"] == "53300" and "too many" in fields["M"], f"FATAL 53300: {fields}")
    check(at_eof(extra), "and the connection is closed")
    sluice.wait_event("connection_rejected", reason="too_many_connections")
    clients.pop().close()  # a slot is free again
    sluice.wait_event("connection_close", reason="client_closed")
    again = sluice.connect()
    again.sendall(startup_packet(user="alice"))
    sluice.wait_event("startup", user="alice")
    again.close()
    for c in clients:
        c.close()
    check(sluice.stop() == 0, "clean shutdown")


def scenario_shutdown_with_open_connections():
    """SIGTERM with a session open: the session is closed, said so in the log, and the exit is clean."""
    upstream = FakeUpstream(recording_script)
    sluice = Sluice(upstream.port)
    client = open_session(sluice, user="alice", database="db1")
    check(sluice.stop() == 0, "clean exit")
    check(sluice.wait_event("shutdown")["open_connections"] == 1, "the shutdown event counts the open session")
    sluice.wait_event("connection_close", reason="shutdown")
    check(at_eof(client), "the client is disconnected")
    upstream.finish()


def scenario_startup_failures():
    """What cannot be set up stops sluice with a message and status 1, before it listens: a port that is taken,
    a CA that cannot be read, a policy that is not a file."""
    def run(*args):
        return subprocess.run([SLUICE, *args], capture_output=True, text=True, timeout=TIMEOUT)

    taker = socket.socket()
    taker.bind(("127.0.0.1", 0))
    taker.listen(1)
    proc = run("--listen", f"127.0.0.1:{taker.getsockname()[1]}", "--upstream", "127.0.0.1:1")
    taker.close()
    check(proc.returncode == 1 and "cannot listen" in proc.stderr and proc.stdout == "",
          f"a taken port: {proc.returncode} {proc.stderr!r}")

    proc = run("--listen", "127.0.0.1:0", "--upstream", "127.0.0.1:1", "--upstream-tls", "verify-full",
               "--upstream-ca", "/nonexistent/ca.pem")
    check(proc.returncode == 1 and "cannot read the CA file" in proc.stderr and proc.stdout == "",
          f"an unreadable CA: {proc.returncode} {proc.stderr!r}")

    proc = run("--listen", "127.0.0.1:0", "--upstream", "127.0.0.1:1", "--policy", "/")
    check(proc.returncode == 1 and proc.stderr.startswith("sluice: /:") and proc.stdout == "",
          f"a policy that is a directory: {proc.returncode} {proc.stderr!r}")


def scenario_connections_lost_midway():
    """A peer that disappears with a reset, at each stage, ends the connection with the right reason and
    leaves sluice working."""
    # the client vanishes while the database is still streaming an answer to it
    def stream_a_lot(conn, seen):
        seen["startup"] = read_startup(conn)
        conn.sendall(message(b"R", struct.pack("!I", 0)) + message(b"Z", b"I"))
        recv_exact(conn, 1)
        conn.sendall(b"x" * (64 << 20))

    upstream = FakeUpstream(stream_a_lot, tolerate=True)
    sluice = Sluice(upstream.port)
    client = open_session(sluice, user="alice", database="db1")
    client.sendall(q("select 1"))
    time.sleep(0.2)
    abort_connection(client)
    sluice.wait_event("connection_close", reason="client_error")
    check(sluice.stop() == 0, "the client's reset ends only its own connection")
    upstream.finish()

    # the database vanishes while the client is still sending
    def reset_after_greeting(conn, seen):
        seen["startup"] = read_startup(conn)
        conn.sendall(message(b"R", struct.pack("!I", 0)) + message(b"Z", b"I"))
        recv_exact(conn, 1)
        abort_connection(conn)

    upstream = FakeUpstream(reset_after_greeting, tolerate=True)
    sluice = Sluice(upstream.port)
    client = open_session(sluice, user="alice", database="db1")
    try:
        for _ in range(64):
            client.sendall(q("select " + "1" * 100000))
            time.sleep(0.01)
    except OSError:
        pass  # sluice closed the connection under us: that is the point
    error = sluice.wait_event("upstream_error")
    check(error["code"] == "io_error" and error["error"] != "", f"the log says what happened: {error}")
    sluice.wait_event("connection_close", reason="upstream_error")
    client.close()
    check(sluice.stop() == 0, "clean shutdown")
    upstream.finish()

    # the client vanishes while sluice waits for the database to answer the SSLRequest
    quiet = FakeUpstream(hold_open, tolerate=True)
    sluice = Sluice(quiet.port, extra_args=["--upstream-tls", "require"])
    client = sluice.connect()
    client.sendall(startup_packet(user="alice"))
    sluice.wait_event("startup", user="alice")
    abort_connection(client)
    closed = sluice.wait_event("connection_close", reason="client_error")
    check(closed["duration_ms"] < 2000, f"seen at once, not when the attempt times out: {closed}")
    check(sluice.stop() == 0, "clean shutdown")
    quiet.finish()

    # the same with a normal close, and with bytes already sent after the startup packet
    quiet = FakeUpstream(hold_open, tolerate=True)
    sluice = Sluice(quiet.port, extra_args=["--upstream-tls", "require"])
    client = sluice.connect()
    client.sendall(startup_packet(user="alice") + q("select 1"))
    sluice.wait_event("startup", user="alice")
    client.close()
    closed = sluice.wait_event("connection_close", reason="client_closed")
    check(closed["duration_ms"] < 2000, f"also seen at once: {closed}")
    check(sluice.stop() == 0, "clean shutdown")
    quiet.finish()

    # the database hangs up on the SSLRequest
    gone = FakeUpstream(lambda conn, seen: None, tolerate=True)
    sluice = Sluice(gone.port, extra_args=["--upstream-tls", "require"])
    client = sluice.connect()
    client.sendall(startup_packet(user="alice"))
    kind, payload = read_message(client)
    check(kind == b"E" and error_fields(payload)["C"] == "08001", "the client gets a FATAL 08001")
    error = sluice.wait_event("upstream_error")
    check(error["code"] == "tls_request_failed", f"with its own code: {error}")
    check(sluice.stop() == 0, "clean shutdown")
    gone.finish()


def scenario_tls_ends_cleanly_and_abruptly():
    """The database ends a TLS session with a close_notify (a clean end), or with a reset (an error)."""
    with tempfile.TemporaryDirectory() as d:
        good = make_cert(d, "good", "DNS:localhost,IP:127.0.0.1")
        if good is None:
            print("    (skipped: no openssl tool able to make a certificate)")
            return
        args = ["--upstream-tls", "verify-full", "--upstream-ca", good[0]]

        def close_notify(conn, seen):
            seen["startup"] = read_startup(conn)
            conn.sendall(message(b"R", struct.pack("!I", 0)) + message(b"Z", b"I"))
            recv_exact(conn, 1)
            conn._sslobj.shutdown()  # sends the close_notify alert, without waiting for the answer

        upstream = FakeUpstream(close_notify, tls=good, tolerate=True)
        sluice = Sluice(upstream.port, extra_args=args)
        client = open_session(sluice, user="alice", database="db1")
        client.sendall(q("select 1"))
        sluice.wait_event("connection_close", reason="upstream_closed")
        check(not [e for e in sluice.events if e["event"] == "upstream_error"], "a clean end is not an error")
        client.close()
        check(sluice.stop() == 0, "clean shutdown")
        upstream.finish()

        def reset(conn, seen):
            seen["startup"] = read_startup(conn)
            conn.sendall(message(b"R", struct.pack("!I", 0)) + message(b"Z", b"I"))
            recv_exact(conn, 1)
            abort_connection(conn)

        upstream = FakeUpstream(reset, tls=good, tolerate=True)
        sluice = Sluice(upstream.port, extra_args=args)
        client = open_session(sluice, user="alice", database="db1")
        client.sendall(q("select 1"))
        error = sluice.wait_event("upstream_error")
        check(error["code"] in ("io_error", "tls_error") and error["error"] != "", f"a reset is: {error}")
        sluice.wait_event("connection_close", reason="upstream_error")
        client.close()
        check(sluice.stop() == 0, "clean shutdown")
        upstream.finish()


def scenario_log_limits():
    """What the log shows of a statement has bounds, and says when it cut: the tables of a message, and the
    normalized text of a very long one."""
    names = [f"t{i}" for i in range(40)]
    sent = [q("select * from orders, orders o2"), q("select * from " + ", ".join(names)), message(b"X")]
    stream, stmts, closed, _ = run_session(POLICY_TABLES, "agent", sent)
    check(stmts[0]["tables"] == ["orders"], f"a table used twice is listed once: {stmts[0]['tables']}")
    check(len(stmts[1]["tables"]) <= 32 and stmts[1].get("tables_truncated") is True,
          f"many tables are cut, and it says so: {len(stmts[1]['tables'])} {stmts[1].get('tables_truncated')}")

    upstream = FakeUpstream(recording_script)
    sluice = Sluice(upstream.port, extra_args=["--log-sql", "normalized"])
    client = open_session(sluice, user="alice", database="db1")
    columns = ", ".join(f"col_{i}" for i in range(2500))
    client.sendall(q(f"select {columns} from t"))
    client.close()
    upstream.finish()
    event = sluice.wait_event("statement")
    check(event.get("truncated") is True and 0 < len(event["sql"]) <= 8192,
          f"a long normalized text is cut: {event.get('truncated')} {len(event.get('sql', ''))}")
    check(sluice.stop() == 0, "clean shutdown")


def scenario_bytes_sent_before_the_database_answers():
    """A client that pipelines its first statements behind the startup packet: they wait while the database
    is reached, and are judged like any other once it is, with TLS to the database or without."""
    with tempfile.TemporaryDirectory() as d:
        good = make_cert(d, "good", "DNS:localhost,IP:127.0.0.1")
        modes = [(None, [])]
        if good is not None:
            modes.append((good, ["--upstream-tls", "verify-full", "--upstream-ca", good[0]]))
        for tls, extra in modes:
            upstream = FakeUpstream(tls_greeting_script, tls=tls) if tls else FakeUpstream(recording_script)
            sluice = Sluice(upstream.port, policy=POLICY, extra_args=extra)
            client = sluice.connect()
            client.sendall(startup_packet(user="alice", database="db1") + q("delete from t") + q("select 1"))
            check(read_message(client)[0] == b"R", "the database's greeting reaches the client")
            check(read_message(client)[0] == b"Z", "and ReadyForQuery")
            client.sendall(message(b"X"))
            client.close()
            upstream.finish()
            check(upstream.seen["stream"] == failing_q(R_UNBOUNDED) + q("select 1") + message(b"X"),
                  f"the statement that waited was judged: {upstream.seen['stream'][:80]!r}")
            check(sluice.stop() == 0, "clean shutdown")


# ---- confirming a DELETE or UPDATE (docs/design.md, section 20) ----

POLICY_CONFIRM = """
mode = "enforce"
confirm_timeout = "5s"

[[rule]]
name = "confirm-deletes"
match = "delete"
action = "confirm"
over_rows = "1"
message = "A person has to confirm this."

[[rule]]
name = "confirm-updates"
match = "update"
action = "confirm"
"""


def cc(tag):
    return message(b"C", tag.encode() + b"\0")


def z(status):
    return message(b"Z", status)


def error_msg(sqlstate, text):
    return message(b"E", b"SERROR\0VERROR\0C" + sqlstate.encode() + b"\0M" + text.encode() + b"\0\0")


def row_description(names):
    body = struct.pack("!H", len(names))
    for n in names:
        body += n.encode() + b"\0" + b"\0" * 18
    return message(b"T", body)


def data_row(values):
    body = struct.pack("!H", len(values))
    for v in values:
        if v is None:
            body += struct.pack("!i", -1)
        else:
            body += struct.pack("!I", len(v)) + v.encode()
    return message(b"D", body)


def confirm_db(rows=3, fail_returning=False, fail_always=False, slow=0.0, junk=False):
    """A fake PostgreSQL that answers what sluice sends for a confirmation as the real one would:
    BEGIN; DELETE ... RETURNING * gives rows, then COMMIT or ROLLBACK ends it."""
    def script(conn, seen):
        seen["queries"] = []
        seen["stamps"] = []
        seen["startup"] = read_startup(conn)
        conn.sendall(message(b"R", struct.pack("!I", 0)) + z(b"I"))
        if junk:
            conn.sendall(b"N\x00\x00\x00\x01")  # a header that cannot be one: the stream is not followed any more
        status = b"I"
        while True:
            try:
                kind, payload = read_message(conn)
            except (EOFError, OSError):
                break
            if kind == b"X":
                break
            if kind != b"Q":
                continue
            text = payload[:-1].decode()
            seen["queries"].append(text)
            seen["stamps"].append(time.monotonic())
            out = b""
            if text.startswith("BEGIN; ") or text.startswith("SAVEPOINT sluice_guard; "):
                prelude = "BEGIN" if text.startswith("BEGIN") else "SAVEPOINT"
                stmt = text.split("; ", 1)[1]
                with_returning = stmt.endswith("RETURNING *")
                verb = "DELETE" if stmt.lower().startswith("delete") else "UPDATE"
                if fail_always or (with_returning and fail_returning):
                    out = cc(prelude) + error_msg("42501" if with_returning else "23503", "no good") + z(b"E")
                    status = b"E"
                else:
                    out = cc(prelude)
                    if with_returning:
                        out += row_description(["id", "email"])
                        sample = [("18", "ana@example.com"), ("52", None), ("7", "carl@example.com")]
                        for i in range(rows):
                            out += data_row(sample[i % 3])
                    out += cc(f"{verb} {rows}") + z(b"T")
                    status = b"T"
            elif text == "COMMIT":
                out, status = cc("COMMIT") + z(b"I"), b"I"
            elif text == "RELEASE SAVEPOINT sluice_guard":
                out = cc("RELEASE") + z(b"T")
            elif text == "ROLLBACK":
                out, status = cc("ROLLBACK") + z(b"I"), b"I"
            elif text == "ROLLBACK TO SAVEPOINT sluice_guard; RELEASE SAVEPOINT sluice_guard":
                out, status = cc("ROLLBACK") + cc("RELEASE") + z(b"T"), b"T"
            elif text.lower() == "begin":
                out, status = cc("BEGIN") + z(b"T"), b"T"
            else:
                if text.startswith("select slow"):
                    time.sleep(slow)
                out = cc("SELECT 1") + z(status)
            conn.sendall(out)
    return script


class Tty:
    """The terminal on which a person is asked: a pseudo-terminal, the test being the person."""

    def __init__(self):
        import pty
        self.master, self.slave = pty.openpty()
        self.path = os.ttyname(self.slave)
        os.set_blocking(self.master, False)
        self.text = ""

    def wait_for(self, needle, timeout=TIMEOUT):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data = os.read(self.master, 4096)
                self.text += data.decode("utf-8", "replace")
            except BlockingIOError:
                time.sleep(0.02)
            except OSError:
                break
            if needle in self.text:
                return self.text
        check(False, f"{needle!r} never appeared on the terminal: {self.text!r}")
        return self.text

    def answer(self, line):
        self.text = ""  # the next question is looked for from here on, not in the text of this one
        os.write(self.master, line.encode())

    def close(self):
        os.close(self.master)
        os.close(self.slave)


def confirm_session(db, policy=POLICY_CONFIRM, tty=None, extra=(), user="agent"):
    upstream = FakeUpstream(db, tolerate=True)
    args = list(extra) + (["--confirm-tty", tty.path] if tty else [])
    sluice = Sluice(upstream.port, policy=policy, extra_args=args)
    client = open_session(sluice, user=user, database="mydb")
    return upstream, sluice, client


def read_answer(client):
    """What the client gets for one Query: the messages up to ReadyForQuery."""
    out = []
    while True:
        kind, payload = read_message(client)
        out.append((kind, payload))
        if kind == b"Z":
            return out


def kinds(answer):
    return b"".join(k for k, _ in answer)


def scenario_confirm_yes_and_no():
    """A DELETE over the threshold is run, shown, and committed or rolled back as the person says."""
    tty = Tty()
    try:
        upstream, sluice, client = confirm_session(confirm_db(rows=3), tty=tty)
        client.sendall(q("delete from users where id < 5"))
        text = tty.wait_for("commit? [y/N]")
        check("deleted 3 rows" in text and "agent@mydb" in text and "confirm-deletes" in text, text)
        check("ana@example.com" in text and "NULL" in text, f"the rows are shown: {text!r}")
        check("RETURNING" not in text, "the text added to the statement is not what is shown")
        tty.answer("y\n")
        answer = read_answer(client)
        check(kinds(answer) == b"CZ" and answer[0][1] == b"DELETE 3\0" and answer[1][1] == b"I",
              f"the client sees the statement's own answer and nothing else: {answer}")
        client.sendall(q("select 1"))
        check(kinds(read_answer(client)) == b"CZ", "and the session goes on")
        client.close()
        upstream.finish()
        check(upstream.seen["queries"] == ["BEGIN; delete from users where id < 5 RETURNING *", "COMMIT",
                                           "select 1"], f"what the database was sent: {upstream.seen['queries']}")
        event = sluice.wait_event("confirm")
        check(event["outcome"] == "yes" and event["rows"] == 3 and event["rule"] == "confirm-deletes"
              and event["detail"] is True and event["user"] == "agent", f"the log: {event}")
        statement = [e for e in sluice.events if e["event"] == "statement" and e.get("verdict") == "confirm"]
        check(len(statement) == 1 and statement[0]["action"] == "held" and statement[0]["rule"] == "confirm-deletes",
              f"the statement event: {statement}")
        check("ana@example.com" not in sluice.raw_text(), "the values of the rows are not in the log")
        check(sluice.stop() == 0, "clean shutdown")

        # no
        tty.text = ""
        upstream, sluice, client = confirm_session(confirm_db(rows=3), tty=tty)
        client.sendall(q("delete from users where id < 5"))
        tty.wait_for("commit? [y/N]")
        tty.answer("n\n")
        answer = read_answer(client)
        check(kinds(answer) == b"EZ" and answer[1][1] == b"I", f"an error and ReadyForQuery: {answer}")
        fields = error_fields(answer[0][1])
        check(fields["C"] == "42501" and "not confirmed" in fields["M"] and "A person has to confirm" in fields["M"]
              and "Nothing was changed" in fields["M"], f"the error: {fields}")
        client.sendall(q("select 1"))
        check(kinds(read_answer(client)) == b"CZ", "the session goes on after a no")
        client.close()
        upstream.finish()
        check(upstream.seen["queries"] == ["BEGIN; delete from users where id < 5 RETURNING *", "ROLLBACK",
                                           "select 1"], f"rolled back: {upstream.seen['queries']}")
        check(sluice.wait_event("confirm")["outcome"] == "no", "logged as a no")
        check(sluice.stop() == 0, "clean shutdown")
    finally:
        tty.close()


def scenario_confirm_threshold_and_updates():
    """Few rows are committed without asking; an UPDATE is asked about like a DELETE."""
    tty = Tty()
    try:
        upstream, sluice, client = confirm_session(confirm_db(rows=1), tty=tty)
        client.sendall(q("delete from users where id = 1"))
        answer = read_answer(client)  # nobody was asked: it is answered at once
        check(kinds(answer) == b"CZ" and answer[0][1] == b"DELETE 1\0", f"{answer}")
        check(tty.text == "", "no question was shown")
        client.close()
        upstream.finish()
        check(upstream.seen["queries"] == ["BEGIN; delete from users where id = 1 RETURNING *", "COMMIT"],
              f"{upstream.seen['queries']}")
        check(sluice.wait_event("confirm")["outcome"] == "auto", "logged as automatic")
        check(sluice.stop() == 0, "clean shutdown")

        upstream, sluice, client = confirm_session(confirm_db(rows=4), tty=tty)
        client.sendall(q("update users set plan = 'free'"))
        text = tty.wait_for("commit? [y/N]")
        check("changed 4 rows" in text and "update users set plan" in text, text)
        tty.answer("yes\n")
        answer = read_answer(client)
        check(kinds(answer) == b"CZ" and answer[0][1] == b"UPDATE 4\0", f"{answer}")
        client.close()
        upstream.finish()
        check(upstream.seen["queries"][0] == "BEGIN; update users set plan = 'free' RETURNING *", "UPDATE too")
        check(sluice.stop() == 0, "clean shutdown")
    finally:
        tty.close()


def scenario_confirm_without_an_answer():
    """No answer in time, no terminal at all, or a client that leaves: nothing is committed."""
    tty = Tty()
    try:
        # nobody answers: the timeout (1 second here) rolls it back
        policy = POLICY_CONFIRM.replace('"5s"', '"1s"')
        upstream, sluice, client = confirm_session(confirm_db(rows=3), policy=policy, tty=tty)
        client.sendall(q("delete from users"))
        tty.wait_for("commit? [y/N]")
        started = time.monotonic()
        answer = read_answer(client)
        check(0.8 < time.monotonic() - started < 4, "after the timeout")
        check(kinds(answer) == b"EZ" and "nobody answered" in error_fields(answer[0][1])["M"], f"{answer}")
        client.close()
        upstream.finish()
        check(upstream.seen["queries"] == ["BEGIN; delete from users RETURNING *", "ROLLBACK"], f"{upstream.seen['queries']}")
        check(sluice.wait_event("confirm")["outcome"] == "timeout", "logged as a timeout")
        check(sluice.stop() == 0, "clean shutdown")

        # no terminal to ask on
        upstream, sluice, client = confirm_session(confirm_db(rows=3), extra=["--confirm-tty", "/nonexistent/tty"])
        client.sendall(q("delete from users"))
        answer = read_answer(client)
        check(kinds(answer) == b"EZ" and "no terminal" in error_fields(answer[0][1])["M"], f"{answer}")
        client.close()
        upstream.finish()
        check(upstream.seen["queries"][-1] == "ROLLBACK", "rolled back")
        check(sluice.wait_event("confirm")["outcome"] == "no_terminal", "logged")
        check(sluice.stop() == 0, "clean shutdown")

        # the client leaves while the question is shown: the database sees the connection end, with no COMMIT
        upstream, sluice, client = confirm_session(confirm_db(rows=3), tty=tty)
        client.sendall(q("delete from users"))
        tty.wait_for("commit? [y/N]")
        client.close()
        sluice.wait_event("connection_close", reason="client_closed")
        upstream.finish()
        check("COMMIT" not in upstream.seen["queries"], f"never committed: {upstream.seen['queries']}")
        check(sluice.stop() == 0, "clean shutdown")
    finally:
        tty.close()


def scenario_confirm_in_a_transaction():
    """Inside the client's own transaction a savepoint is used, and the transaction goes on."""
    tty = Tty()
    try:
        upstream, sluice, client = confirm_session(confirm_db(rows=3), tty=tty)
        client.sendall(q("begin"))
        check(read_answer(client)[-1][1] == b"T", "the client is in a transaction")
        client.sendall(q("delete from users where id < 5"))
        tty.wait_for("commit? [y/N]")
        tty.answer("y\n")
        answer = read_answer(client)
        check(kinds(answer) == b"CZ" and answer[1][1] == b"T", f"still in the transaction: {answer}")
        client.sendall(q("delete from users where id < 9"))
        tty.wait_for("commit? [y/N]")
        tty.answer("n\n")
        answer = read_answer(client)
        check(kinds(answer) == b"EZ" and answer[1][1] == b"T", f"refused, the transaction goes on: {answer}")
        client.close()
        upstream.finish()
        check(upstream.seen["queries"] == [
            "begin",
            "SAVEPOINT sluice_guard; delete from users where id < 5 RETURNING *",
            "RELEASE SAVEPOINT sluice_guard",
            "SAVEPOINT sluice_guard; delete from users where id < 9 RETURNING *",
            "ROLLBACK TO SAVEPOINT sluice_guard; RELEASE SAVEPOINT sluice_guard"], f"{upstream.seen['queries']}")
        check(sluice.stop() == 0, "clean shutdown")
    finally:
        tty.close()


def scenario_confirm_fallback_and_errors():
    """A role that may not read cannot have RETURNING: the statement is run as written and only the count is
    shown. A statement that fails fails for the client as it would have."""
    tty = Tty()
    try:
        upstream, sluice, client = confirm_session(confirm_db(rows=3, fail_returning=True), tty=tty)
        client.sendall(q("delete from users where id < 5"))
        text = tty.wait_for("commit? [y/N]")
        check("deleted 3 rows" in text and "could not be read" in text and "ana@example.com" not in text, text)
        tty.answer("y\n")
        answer = read_answer(client)
        check(kinds(answer) == b"CZ" and answer[0][1] == b"DELETE 3\0", f"{answer}")
        client.close()
        upstream.finish()
        check(upstream.seen["queries"] == [
            "BEGIN; delete from users where id < 5 RETURNING *", "ROLLBACK",
            "BEGIN; delete from users where id < 5", "COMMIT"], f"{upstream.seen['queries']}")
        check(sluice.wait_event("confirm")["detail"] is False, "logged without detail")
        check(sluice.stop() == 0, "clean shutdown")

        # a real error: the client gets the database's own error, and a rolled back session
        upstream, sluice, client = confirm_session(confirm_db(fail_always=True), tty=tty)
        client.sendall(q("delete from users where id < 5"))
        answer = read_answer(client)
        check(kinds(answer) == b"EZ" and error_fields(answer[0][1])["C"] == "23503" and answer[1][1] == b"I", f"{answer}")
        client.sendall(q("select 1"))
        check(kinds(read_answer(client)) == b"CZ", "the session is usable")
        client.close()
        upstream.finish()
        check(upstream.seen["queries"][-2] == "ROLLBACK" or upstream.seen["queries"][-1] == "select 1", "rolled back")
        check(sluice.stop() == 0, "clean shutdown")
    finally:
        tty.close()


def scenario_confirm_waits_its_turn():
    """A client that pipelines a DELETE behind a slow query: the guard starts only once the server is quiet."""
    tty = Tty()
    try:
        upstream, sluice, client = confirm_session(confirm_db(rows=3, slow=0.5), tty=tty)
        client.sendall(q("select slow") + q("delete from users where id < 5") + q("select 1"))
        first = read_answer(client)
        check(kinds(first) == b"CZ", "the slow query answers first")
        tty.wait_for("commit? [y/N]")
        tty.answer("y\n")
        check(kinds(read_answer(client)) == b"CZ", "then the DELETE")
        check(kinds(read_answer(client)) == b"CZ", "then what came after it")
        client.close()
        upstream.finish()
        check(upstream.seen["queries"] == ["select slow", "BEGIN; delete from users where id < 5 RETURNING *",
                                           "COMMIT", "select 1"], f"in order: {upstream.seen['queries']}")
        check(upstream.seen["stamps"][1] - upstream.seen["stamps"][0] >= 0.45,
              "the guard was started after the slow answer, not before")
        check(sluice.stop() == 0, "clean shutdown")
    finally:
        tty.close()


def scenario_confirm_what_it_cannot_do():
    """What cannot be confirmed is refused with a reason, not let through: prepared statements, several
    statements, a policy in audit mode."""
    stream, stmts, closed, _ = run_session(POLICY_CONFIRM, "agent", [
        parse_msg(b"s1", "delete from users where id = $1", (23,)),
        q("delete from a where id = 1; delete from b where id = 1"),
        q("with d as (delete from a returning id) delete from b where id in (select id from d)"),
        message(b"S"),
    ])
    check(stream.count(b"asks for a confirmation") == 3, f"three refusals: {stream!r}")
    check(b"simple query protocol" in stream and b"one DELETE or UPDATE" in stream, "with their reasons")
    check([s["action"] for s in stmts] == ["blocked"] * 3 and all(s["verdict"] == "confirm" for s in stmts),
          f"logged: {[(s['verdict'], s['action']) for s in stmts]}")

    # a session that cannot be followed (the server's stream is not framed any more) is not guessed at
    upstream, sluice, client = confirm_session(confirm_db(junk=True))
    client.sendall(q("delete from users"))
    time.sleep(0.3)  # what the client reads back is the junk too: nothing to read, the database is what is looked at
    client.close()
    upstream.finish()
    check(upstream.seen["queries"] and "cannot follow" in upstream.seen["queries"][0]
          and not any(x.startswith("BEGIN;") for x in upstream.seen["queries"]),
          f"refused, and not run: {upstream.seen['queries']}")
    check(sluice.stop() == 0, "clean shutdown")

    # audit mode: the verdict is logged, the statement goes through untouched
    stream, stmts, _, _ = run_session(POLICY_CONFIRM.replace('"enforce"', '"audit"'), "agent",
                                      [q("delete from users"), message(b"X")])
    check(stream == q("delete from users") + message(b"X"), "audit relays it as it is")
    check(stmts[0]["verdict"] == "confirm" and stmts[0]["action"] == "relayed", f"{stmts[0]}")


def scenario_confirm_nothing_leaks_when_the_client_leaves():
    """A statement that waits to be judged is never let through because the client hung up: it has not been
    looked at, and it must not run."""
    for how in ("close", "reset"):
        upstream, sluice, client = confirm_session(confirm_db(rows=3, slow=0.4))
        client.sendall(q("select slow") + q("delete from users") + q("select 1"))
        if how == "close":
            client.close()
        else:
            abort_connection(client)
        sluice.wait_event("connection_close")
        upstream.finish()
        check(upstream.seen["queries"] == ["select slow"], f"{how}: only the first query reached the database: "
              f"{upstream.seen['queries']}")
        check(sluice.stop() == 0, "clean shutdown")

    # the same for the one that is being run when the client leaves: it is never committed
    tty = Tty()
    try:
        upstream, sluice, client = confirm_session(confirm_db(rows=3), tty=tty)
        client.sendall(q("delete from users") + q("select 1"))
        tty.wait_for("commit? [y/N]")
        abort_connection(client)
        sluice.wait_event("connection_close")
        upstream.finish()
        check(upstream.seen["queries"] == ["BEGIN; delete from users RETURNING *"], f"{upstream.seen['queries']}")
        check(sluice.stop() == 0, "clean shutdown")
    finally:
        tty.close()


def policy_from_docs(heading):
    """The first toml block under a heading of docs/policy.md: the documentation's examples are tested as written."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "docs", "policy.md")
    try:
        text = open(path, encoding="utf-8").read()
    except OSError:
        return None
    start = text.find("## " + heading)
    if start < 0:
        return None
    block = text.find("```toml\n", start)
    end = text.find("\n```", block + 8)
    return text[block + 8:end + 1] if block >= 0 and end >= 0 else None


def scenario_apps_and_people():
    """The example of the documentation: the application is left alone, whatever it sends and however it
    sends it; a person at a terminal is held to the rules. A role created tomorrow is held to them too."""
    policy = policy_from_docs("Applications on one side, people and agents on the other")
    if policy is None:
        print("    (skipped: docs/policy.md is not next to the tests)")
        return
    big = [q("delete from users where id < 5000"), q("update users set plan = 'free'"),
           parse_msg(b"s1", "delete from users where id = $1", (23,)),
           q("delete from users"), q("create table x (i int)"), message(b"X")]
    # the application: nothing is refused, nothing is held, not even a prepared DELETE or one without WHERE
    stream, stmts, closed, _ = run_session(policy, "app", big)
    check(stream == b"".join(big), f"the application's messages go through as they are: {stream[:60]!r}")
    check(all(e["action"] == "relayed" for e in stmts) and closed["blocked"] == 0, "none is held or blocked")
    # the migrations may change the schema and delete as they like
    stream, stmts, _, _ = run_session(policy, "migrator", big)
    check(stream == b"".join(big), "the migrations too")
    # DROP is refused for the application and for a person alike, but not for the migrations
    drop = [q("drop table users"), message(b"X")]
    stream, _, _, _ = run_session(policy, "app", drop)
    check(b"nobody-drops-by-mistake" in stream, "nobody drops by mistake, the application included")
    stream, _, _, _ = run_session(policy, "migrator", drop)
    check(stream == b"".join(drop), "except the migrations")
    # a person, or a role nobody had listed: refused, or held
    for user in ("alice", "a-role-created-tomorrow"):
        stream, stmts, _, _ = run_session(policy, user, [q("create table x (i int)"), q("delete from users"),
                                                         q("select 1"), message(b"X")])
        check(b"no-schema-changes" in stream and b"no-unbounded-write" in stream, f"{user}: refused: {stream[:100]!r}")
        check(q("select 1") in stream, f"{user}: what is harmless goes through")
    # and a person's DELETE with a WHERE is asked about, through the terminal
    tty = Tty()
    try:
        upstream, sluice, client = confirm_session(confirm_db(rows=60), policy=policy, tty=tty, user="alice")
        client.sendall(q("delete from users where id < 5000"))
        text = tty.wait_for("commit? [y/N]")
        check("alice@mydb" in text and "confirm-deletes" in text and "deleted 60 rows" in text, text)
        tty.answer("n\n")
        check(kinds(read_answer(client)) == b"EZ", "a no")
        client.close()
        upstream.finish()
        check(sluice.stop() == 0, "clean shutdown")
        upstream, sluice, client = confirm_session(confirm_db(rows=30), policy=policy, tty=tty, user="alice")
        client.sendall(q("delete from users where id < 5000"))
        answer = read_answer(client)  # 30 rows is under the 50 of the example: nobody is asked
        check(kinds(answer) == b"CZ" and answer[0][1] == b"DELETE 30\0", f"{answer}")
        client.close()
        upstream.finish()
        check(sluice.stop() == 0, "clean shutdown")
    finally:
        tty.close()


def scenario_audit_only_logs():
    """The same policy in audit mode: the verdicts are logged but not a single byte changes."""
    sent = [q("select 1"), q("delete from t"), parse_msg(b"s1", "drop table t", (23,)), message(b"S"),
            message(b"X")]
    stream, stmts, closed, sluice = run_session(POLICY.replace('"enforce"', '"audit"'), "alice", sent)
    check(stream == b"".join(sent), "audit mode relays every byte unchanged")
    check(summary(stmts) == [
        ("query", "allow", None, "relayed"),
        ("query", "deny", "no-unbounded-write", "relayed"),
        ("parse", "deny", "no-ddl", "relayed"),
    ], f"what would be blocked is logged: {summary(stmts)}")
    check(closed["blocked"] == 0, "nothing was blocked")
    listening = sluice.events[0]
    check(listening["mode"] == "audit" and listening["rules"] == 4, "the listening event states the policy")


def scenario_rules_follow_user_and_order():
    """Allow rules and user scoping: file order decides, each statement is judged on its own."""
    stream, stmts, _, _ = run_session(POLICY, "migrator", [
        q("create table x (i int)"),
        q("delete from t"),
        q("create table y (i int); delete from t"),
    ])
    check(stream == b"".join([
        q("create table x (i int)"),
        failing_q(R_UNBOUNDED),
        failing_q(R_UNBOUNDED),  # allowed as DDL, but the DELETE next to it is not covered by that allow
    ]), "an allow covers the statements it matches, not the ones next to them")
    check([s["verdict"] for s in stmts] == ["allow", "deny", "deny"], "verdicts of the migrator")

    stream, stmts, _, _ = run_session(POLICY, "agent", [
        q("select 1"),
        q("insert into t values (1)"),
        q("delete from t"),
        q("show all"),
        q("begin"),
    ])
    check(stream == b"".join([
        q("select 1"),
        failing_q(R_AGENT),
        failing_q(R_UNBOUNDED),  # the first rule in the file that applies wins
        q("show all"),
        q("begin"),
    ]), "the read-only agent can read, and nothing else")
    check([s.get("rule") for s in stmts] == [None, "agent-read-only", "no-unbounded-write", None, None],
          "rules named in the log")


def scenario_uninspectable_in_enforce():
    """What cannot be read is blocked by default, and let through when the policy says so."""
    huge = q("select '" + "y" * (2 * 1024 * 1024) + "'")
    sent = [q("select 1"), huge, q("select 2"), q("selec 3"), message(b"F", struct.pack("!IHHH", 1234, 0, 0, 0)),
            q("select 4")]
    stream, stmts, closed, _ = run_session(POLICY, "alice", sent)

    # the syntax error text comes from the PostgreSQL parser: read it back from what the server received
    msgs = []
    rest = stream
    while rest:
        length = struct.unpack("!I", rest[1:5])[0]
        msgs.append(rest[:5 + length - 4])
        rest = rest[5 + length - 4:]
    check(len(msgs) == 6, f"six messages reach the server, got {len(msgs)}")
    check(msgs[0] == q("select 1"), "plain statement untouched")
    check(msgs[1] == failing_q(R_BIG), "a message over 1 MiB is replaced, its body thrown away")
    check(msgs[2] == q("select 2"), "the message after a big one is read normally")
    check(msgs[3].startswith(b"Q") and b"cannot inspect this statement (syntax error at or near" in msgs[3]
          and b'selec' in msgs[3], "a syntax error is blocked with the parser's own words")
    check(msgs[4] == failing_q(R_FASTPATH), "a fast-path call is replaced, its body thrown away")
    check(msgs[5] == q("select 4"), "and the stream goes on")
    kinds = [(e["kind"], e["verdict"], e["action"]) for e in stmts]
    check(kinds == [("query", "allow", "relayed"), ("query", "uninspectable", "blocked"),
                    ("query", "allow", "relayed"), ("query", "uninspectable", "blocked"),
                    ("function", "uninspectable", "blocked"), ("query", "allow", "relayed")],
          f"uninspectable messages are logged: {kinds}")
    check(stmts[1].get("oversized") is True and "sql" not in stmts[1], "the huge statement is flagged, not copied")
    check(closed["blocked"] == 3, "three messages were blocked")

    # on_uninspectable = "allow": the same stream goes through untouched
    relaxed = POLICY.replace('mode = "enforce"', 'mode = "enforce"\non_uninspectable = "allow"')
    stream, stmts, _, _ = run_session(relaxed, "alice", sent)
    check(stream == b"".join(sent), "on_uninspectable = allow relays what it cannot read")
    check(all(e["action"] == "relayed" for e in stmts), "nothing is blocked")


def scenario_enforce_guards_the_connection():
    """Replication connections and broken framing are refused when enforcing."""
    sluice = Sluice(1, policy=POLICY)  # no upstream is needed: sluice must not even try to reach it
    client = sluice.connect()
    client.sendall(startup_packet(user="r", database="db1", replication="database"))
    kind, payload = read_message(client)
    fields = error_fields(payload)
    check(kind == b"E" and fields["S"] == "FATAL" and fields["C"] == "42501", f"replication refused: {fields}")
    check(at_eof(client), "the connection is closed")
    sluice.wait_event("connection_close", reason="replication_denied")

    client = sluice.connect()
    client.sendall(startup_packet(user="r", database="db1", replication="off"))
    kind, payload = read_message(client)
    check(error_fields(payload)["C"] == "08001", "replication=off is a normal connection (the upstream is down)")
    check(sluice.stop() == 0, "clean shutdown")

    # an impossible message header: in enforce mode nothing is relayed after it
    upstream = FakeUpstream(recording_script)
    sluice = Sluice(upstream.port, policy=POLICY)
    client = open_session(sluice, user="alice", database="db1")
    client.sendall(q("select 1") + b"Z\x00\x00\x00\x02junk" + q("delete from t"))
    check(at_eof(client), "the connection is closed on a framing error")
    upstream.finish()
    check(upstream.seen["stream"] in (b"", q("select 1")), "the garbage and what follows never reach the server")
    started = sluice.wait_event("startup", user="alice")
    sluice.wait_event("connection_close", id=started["id"], reason="frame_error")
    check(sluice.stop() == 0, "clean shutdown")


POLICY_TABLES = """
mode = "enforce"

[[rule]]
name = "agent-sales-only"
match = "any"
users = ["agent"]
outside_tables = ["orders", "public.products"]
message = "sales tables only"

[[rule]]
name = "no-ledger-write"
match = "not_read_only"
tables = ["ledger"]
"""

R_SALES = "sluice: blocked by rule agent-sales-only: sales tables only"
R_LEDGER = "sluice: blocked by rule no-ledger-write"


def scenario_rules_about_tables():
    """An agent that may only touch some tables, and a table that nobody writes."""
    sent = [
        q("select * from orders"),
        q("select * from users"),
        q("select o.id from orders o join public.products p on p.id = o.product_id"),
        q("select * from orders; select * from secret"),
        parse_msg(b"p1", "select * from public.products", (23,)),
        parse_msg(b"p2", "select * from secret"),
        q("merge into orders using secret on true when matched then delete"),
        q("do $$ begin perform 1 from secret; end $$"),
        q("begin"),
        q("select 1"),
        message(b"X"),
    ]
    expected = [
        q("select * from orders"),
        failing_q(R_SALES),
        q("select o.id from orders o join public.products p on p.id = o.product_id"),
        failing_q(R_SALES),
        parse_msg(b"p1", "select * from public.products", (23,)),
        failing_p(b"p2", R_SALES),
        failing_q(R_SALES),
        failing_q(R_SALES),
        q("begin"),
        q("select 1"),
        message(b"X"),
    ]
    stream, stmts, closed, _ = run_session(POLICY_TABLES, "agent", sent)
    check(stream == b"".join(expected), "the agent reaches its tables and nothing else")
    check([s["verdict"] for s in stmts] == ["allow", "deny", "allow", "deny", "allow", "deny", "deny", "deny",
                                            "allow", "allow"], f"verdicts: {[s['verdict'] for s in stmts]}")
    check(stmts[0]["tables"] == ["orders"], "the tables of a statement are in the log")
    check(stmts[2]["tables"] == ["orders", "public.products"], "all the tables of a join are")
    check(stmts[3]["tables"] == ["orders", "secret"], "and those of every statement of the message")
    check("tables" not in stmts[8], "a statement without a table has no table list")
    check(closed["blocked"] == 5, "five messages were blocked")

    # the same rules for someone else: the agent's rule is not theirs, the ledger rule is everybody's
    sent = [q("select * from users"), q("select * from ledger"), q("update ledger set a = 1 where id = 1"),
            q("update other set a = 1 where id = 1"), q("merge into other using ledger on true when matched then delete")]
    stream, stmts, closed, _ = run_session(POLICY_TABLES, "alice", sent)
    check(stream == b"".join([
        q("select * from users"),
        q("select * from ledger"),
        failing_q(R_LEDGER),
        q("update other set a = 1 where id = 1"),
        failing_q(R_LEDGER),  # tables not all known: the deny rule assumes the worst
    ]), "everyone may read ledger, nobody writes it")
    check([s.get("rule") for s in stmts] == [None, None, "no-ledger-write", None, "no-ledger-write"],
          "the rule is named in the log")

    # in audit mode the tables are logged and nothing is blocked
    stream, stmts, closed, _ = run_session(POLICY_TABLES.replace('"enforce"', '"audit"'), "agent",
                                           [q("select * from secret")])
    check(stream == q("select * from secret"), "audit mode relays the statement")
    check(stmts[0]["verdict"] == "deny" and stmts[0]["action"] == "relayed" and stmts[0]["tables"] == ["secret"],
          "but says what it would have done")


def scenario_policy_reload():
    """SIGHUP: the file is read again, at once for connections that are already open, and a bad file changes
    nothing."""
    audit = ('mode = "audit"\n[[rule]]\nname = "no-unbounded-write"\nmatch = "update_or_delete_without_where"\n'
             'message = "add a WHERE clause"\n')
    enforce = audit.replace('"audit"', '"enforce"')
    enforce_ddl = enforce + '[[rule]]\nname = "no-ddl"\nmatch = "ddl"\nmessage = "schema changes go through migrations"\n'

    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "policy.toml")

        def write(text):
            with open(path, "w") as f:  # a plain rewrite, as an editor would do
                f.write(text)

        def hup(sluice):
            sluice.proc.send_signal(signal.SIGHUP)

        write(audit)
        upstream = FakeUpstream(recording_script)
        sluice = Sluice(upstream.port, extra_args=["--policy", path])
        client = open_session(sluice, user="alice", database="db1")
        delete = q("delete from t")

        client.sendall(delete)  # audit: it goes through (and is only logged)

        write(enforce)  # tighten: applies to the connection that is already open
        hup(sluice)
        sluice.wait_event("policy_reloaded", mode="enforce")
        client.sendall(delete)

        write("mode = \"enforce\"\n[[rule]]\nname = \"x\"\nmatch = \"dll\"\n")  # broken: unknown match
        hup(sluice)
        failed = sluice.wait_event("policy_reload_failed")
        check(":4: unknown match 'dll'" in failed["error"], f"the error names the line: {failed}")
        check("previous policy stays" in failed["detail"], "and says what is in force")
        client.sendall(delete)  # still enforced: a bad file never loosens anything

        write(audit)  # loosen
        hup(sluice)
        sluice.wait_event("policy_reloaded", mode="audit")
        client.sendall(delete)

        write(enforce_ddl)  # add a rule
        hup(sluice)
        reloaded = sluice.wait_event("policy_reloaded", rules=2)
        check(reloaded["policy"] == path and reloaded["on_uninspectable"] == "deny", "the event states the policy")
        client.sendall(q("drop table t"))
        client.sendall(delete)

        # a file that vanishes or cannot be read is the same story: nothing changes
        os.unlink(path)
        hup(sluice)
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline and len([e for e in sluice.events if e["event"] == "policy_reload_failed"]) < 2:
            time.sleep(0.02)
        check(len([e for e in sluice.events if e["event"] == "policy_reload_failed"]) == 2, "a missing file is reported")
        client.sendall(q("drop table t"))  # the last good policy is still there

        client.close()
        upstream.finish()
        check(upstream.seen["stream"] == b"".join([
            delete,                  # audit
            failing_q(R_UNBOUNDED),  # enforce, same connection
            failing_q(R_UNBOUNDED),  # a bad file: still enforce
            delete,                  # audit again
            failing_q(R_DDL),        # the new rule
            failing_q(R_UNBOUNDED),  # (enforce + ddl policy: delete is blocked as well)
            failing_q(R_DDL),        # the file is gone: the last good policy holds
        ]), "each statement met the policy in force when it was sent")
        check(sluice.stop() == 0, "clean shutdown")


def scenario_sighup_without_policy():
    """Without a policy file there is nothing to reload, and SIGHUP must not kill the process."""
    upstream = FakeUpstream(recording_script)
    sluice = Sluice(upstream.port)
    client = open_session(sluice, user="alice", database="db1")
    sluice.proc.send_signal(signal.SIGHUP)
    ignored = sluice.wait_event("policy_reload_ignored")
    check("nothing to reload" in ignored["detail"], "it says why")
    client.sendall(q("delete from t"))
    client.close()
    upstream.finish()
    check(upstream.seen["stream"] == q("delete from t"), "and the connection goes on")
    check(sluice.stop() == 0, "clean shutdown")


SECRET_SQL = [
    q("select * from users where email = 'a@b.c' and password = 'hunter2'"),
    parse_msg(b"s1", "insert into t values ($1, 'hunter2')", (23,)),
    q("alter role bob password 'hunter2'"),
    q("create server s foreign data wrapper w options (password 'hunter2')"),  # the normalizer leaves this one
    q("select 1 -- hunter2 in a comment"),
    q("select hunter2 from where"),  # does not parse; the parser would quote it in its message
    q("begin"),
]


def raw_log(sluice):
    return "".join(sluice.raw)


def scenario_log_keeps_values_out():
    """--log-sql normalized and none: the values of a statement never reach the log, and the bytes sent to the
    database are the same as ever."""
    for mode in ("normalized", "none"):
        # without a policy: statements are logged but not judged
        upstream = FakeUpstream(recording_script)
        sluice = Sluice(upstream.port, extra_args=["--log-sql", mode])
        client = open_session(sluice, user="alice", database="db1")
        for m in SECRET_SQL:
            client.sendall(m)
        client.close()
        upstream.finish()
        check(upstream.seen["stream"] == b"".join(SECRET_SQL), f"{mode}: the database receives the same bytes")
        started = sluice.wait_event("startup", user="alice")
        stmts = statements_of(sluice, started)
        check(sluice.events[0]["log_sql"] == mode, "the listening event states the mode")
        text = raw_log(sluice)
        for secret in ("hunter2", "a@b.c"):
            check(secret not in text, f"{mode}: {secret!r} is not in the log")
        check(len(stmts) == 7, f"{mode}: every statement is still logged")
        for s in stmts[:6]:
            check(s["sql_len"] > 0 and s["kind"] in ("query", "parse"), "length and kind are kept")
        for s in stmts[:5]:
            check(len(s["fingerprint"]) == 16, f"{mode}: a fingerprint of the shape: {s}")
        check("fingerprint" not in stmts[5] and stmts[5]["sql_redacted"] is True, "no fingerprint for SQL that does not parse")
        check(stmts[1]["name"] == "s1", "the name of a prepared statement is kept")
        if mode == "normalized":
            check(stmts[0]["sql"] == "select * from users where email = $1 and password = $2", f"values replaced: {stmts[0]}")
            check(stmts[1]["sql"] == "insert into t values ($1, $2)", "also in the extended protocol")
            check(stmts[2]["sql"] == "alter role bob password $1", "also in a password change")
            check("sql" not in stmts[3] and stmts[3]["sql_redacted"] is True, "withheld when the normalizer leaves a value")
            check("sql" not in stmts[4] and stmts[4]["sql_redacted"] is True, "withheld when there is a comment")
            check(stmts[6]["sql"] == "begin", "nothing to hide: kept")
        else:
            check(all("sql" not in s and s["sql_redacted"] is True for s in stmts), "none: no SQL at all")
            check(stmts[0]["fingerprint"] != stmts[2]["fingerprint"], "but the fingerprints tell the queries apart")
        check(sluice.stop() == 0, "clean shutdown")

    # the same two statements with other values have the same fingerprint
    upstream = FakeUpstream(recording_script)
    sluice = Sluice(upstream.port, extra_args=["--log-sql", "none"])
    client = open_session(sluice, user="alice", database="db1")
    client.sendall(q("select * from t where id = 1 and n = 'x'"))
    client.sendall(q("select * from t where id = 987 and n = 'something else'"))
    client.sendall(q("select * from t where id = 1 or n = 'x'"))
    client.close()
    upstream.finish()
    stmts = statements_of(sluice, sluice.wait_event("startup", user="alice"))
    check(stmts[0]["fingerprint"] == stmts[1]["fingerprint"] != stmts[2]["fingerprint"], "same shape, same fingerprint")
    check(sluice.stop() == 0, "clean shutdown")


def scenario_log_keeps_values_out_of_verdicts():
    """With a policy, the reason that a statement could not be inspected quotes SQL in the parser's words: the
    client gets it, the log does not."""
    upstream = FakeUpstream(recording_script)
    sluice = Sluice(upstream.port, policy=POLICY, extra_args=["--log-sql", "normalized"])
    client = open_session(sluice, user="alice", database="db1")
    client.sendall(q("select 1 hunter2 hunter2"))  # the error is "syntax error at or near \"hunter2\""
    client.sendall(q("delete from t where password = 'hunter2'"))
    client.sendall(q("delete from t"))
    client.close()
    upstream.finish()
    check(b"hunter2" in upstream.seen["stream"], "the database is told what went wrong, as ever")
    started = sluice.wait_event("startup", user="alice")
    stmts = statements_of(sluice, started)
    check(stmts[0]["verdict"] == "uninspectable" and "hunter2" not in stmts[0]["detail"]
          and stmts[0]["detail"] == "syntax error", f"the detail of the log is cut before the quote: {stmts[0]}")
    check(stmts[1]["verdict"] == "allow" and stmts[1]["sql"] == "delete from t where password = $1", "an allowed statement")
    check(stmts[2]["verdict"] == "deny" and stmts[2]["rule"] == "no-unbounded-write", "a denied one")
    check("hunter2" not in raw_log(sluice), "nothing of the value in the log")
    check(sluice.stop() == 0, "clean shutdown")


def scenario_bad_policy_stops_sluice():
    """A policy that cannot be read is a startup failure, never a silent fallback."""
    cases = [
        ('mode = "enforce"\n\n[[rule]]\nname = "x"\nmatch = "ddl"\nbogus = "1"\n', ":6: unknown key 'bogus'"),
        ('[[rule]]\nname = "x"\nmatch = "dll"\n', ":3: unknown match 'dll'"),
        ('mode = enforce\n', ":1: unsupported value"),
    ]
    for text, fragment in cases:
        handle = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
        handle.write(text)
        handle.close()
        try:
            proc = subprocess.run(
                [SLUICE, "--listen", "127.0.0.1:0", "--upstream", "127.0.0.1:1", "--policy", handle.name],
                capture_output=True, text=True, timeout=TIMEOUT)
        finally:
            os.unlink(handle.name)
        check(proc.returncode == 1, f"exit code 1 for a bad policy, got {proc.returncode}")
        check(fragment in proc.stderr, f"the error names the line: {proc.stderr!r}")
        check(proc.stdout == "", "sluice never started listening")


# ---- v0.4: TLS towards the database ----

def make_cert(directory, name, sans):
    """A self-signed certificate (also usable as its own CA). Returns (cert, key) or None when the
    openssl tool cannot make one: the TLS scenarios are then skipped."""
    cert = os.path.join(directory, name + ".crt")
    key = os.path.join(directory, name + ".key")
    tool = os.environ.get("SLUICE_OPENSSL") or "openssl"
    try:
        subprocess.run(
            [tool, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
             "-keyout", key, "-out", cert, "-days", "2", "-subj", "/CN=" + name, "-addext",
             "subjectAltName=" + sans],
            check=True, capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return cert, key


def tls_greeting_script(conn, seen):
    """Like recording_script, for a TLS connection that may end abruptly."""
    seen["startup"] = read_startup(conn)
    conn.sendall(message(b"R", struct.pack("!I", 0)) + message(b"Z", b"I"))
    chunks = []
    try:
        while True:
            data = conn.recv(1 << 20)
            if not data:
                break
            chunks.append(data)
    except OSError:  # the close of a TLS stream may be reported as an error
        pass
    seen["stream"] = b"".join(chunks)


def scenario_tls_encrypts_the_upstream_hop():
    """require and verify-full: the database side speaks TLS, the bytes still cross unchanged."""
    with tempfile.TemporaryDirectory() as d:
        good = make_cert(d, "good", "DNS:localhost,IP:127.0.0.1")
        if good is None:
            print("    (skipped: no openssl tool able to make a certificate)")
            return
        sent = [q("select 1"), parse_msg(b"s1", "select $1::int", (23,)), message(b"S"), message(b"X")]
        for extra, warns in ((["--upstream-tls", "require"], True),
                             (["--upstream-tls", "verify-full", "--upstream-ca", good[0]], False)):
            upstream = FakeUpstream(tls_greeting_script, tls=good)
            sluice = Sluice(upstream.port, extra_args=extra)
            client = open_session(sluice, user="alice", database="db1")
            for m in sent:
                client.sendall(m)
            client.close()
            upstream.finish()
            check(upstream.seen["ssl_request"] == SSL_REQUEST, "sluice opens with an SSLRequest")
            check(upstream.seen["tls_version"] in ("TLSv1.2", "TLSv1.3"), "a modern TLS version is used")
            check(upstream.seen["stream"] == b"".join(sent), f"bytes cross the TLS hop unchanged ({extra[1]})")
            connected = sluice.wait_event("upstream_connected")
            check(connected["tls"].startswith("TLSv1"), f"the log says how the hop is encrypted: {connected}")
            check(sluice.events[0]["upstream_tls"] == extra[1], "the listening event states the mode")
            sluice.wait_event("connection_close", reason="client_closed")
            check(any(e["event"] == "warning" for e in sluice.events) == warns,
                  "require warns that the server is not authenticated, verify-full does not")
            check(sluice.stop() == 0, "clean shutdown")


def scenario_tls_large_transfer():
    """5 MB each way through TLS: partial writes, WANT_READ / WANT_WRITE and data kept inside the library."""
    with tempfile.TemporaryDirectory() as d:
        good = make_cert(d, "good", "DNS:localhost,IP:127.0.0.1")
        if good is None:
            print("    (skipped: no openssl tool able to make a certificate)")
            return
        size = 5_000_000
        blob = os.urandom(size)
        answer = os.urandom(size)

        def script(conn, seen):
            read_startup(conn)
            conn.sendall(message(b"R", struct.pack("!I", 0)) + message(b"Z", b"I"))
            kind, payload = read_message(conn)
            seen["digest"] = (kind, hashlib.sha256(payload).hexdigest())
            conn.sendall(message(b"D", answer))
            try:
                seen["eof"] = conn.recv(1) == b""
            except OSError:
                seen["eof"] = True

        upstream = FakeUpstream(script, tls=good)
        sluice = Sluice(upstream.port, extra_args=["--upstream-tls", "verify-full", "--upstream-ca", good[0]])
        client = sluice.connect()
        client.sendall(startup_packet(user="bulk"))
        read_message(client)
        read_message(client)
        client.sendall(message(b"Q", blob))
        kind, payload = read_message(client)
        check(kind == b"D" and hashlib.sha256(payload).digest() == hashlib.sha256(answer).digest(),
              "a 5 MB answer arrives intact through TLS")
        client.close()
        upstream.finish()
        check(upstream.seen["digest"] == (b"Q", hashlib.sha256(blob).hexdigest()),
              "a 5 MB query arrives intact through TLS")
        sluice.wait_event("connection_close")
        check(sluice.stop() == 0, "clean shutdown")


def scenario_tls_many_small_records():
    """Several TLS records arrive together: the ones the library has read ahead must not wait for new data."""
    with tempfile.TemporaryDirectory() as d:
        good = make_cert(d, "good", "DNS:localhost,IP:127.0.0.1")
        if good is None:
            print("    (skipped: no openssl tool able to make a certificate)")
            return
        count = 40

        def script(conn, seen):
            read_startup(conn)
            conn.sendall(message(b"R", struct.pack("!I", 0)) + message(b"Z", b"I"))
            kind, _ = read_message(conn)  # the client's query
            for i in range(count):  # one TLS record each
                conn.sendall(message(b"D", b"row-%d" % i))
            conn.sendall(message(b"C", b"SELECT 40\0") + message(b"Z", b"I"))
            seen["eof"] = False
            try:
                seen["eof"] = conn.recv(1) == b""
            except OSError:
                seen["eof"] = True

        upstream = FakeUpstream(script, tls=good)
        sluice = Sluice(upstream.port, extra_args=["--upstream-tls", "verify-full", "--upstream-ca", good[0]])
        client = open_session(sluice, user="alice", database="db1")
        client.sendall(q("select generate_series(1, 40)"))
        rows = [read_message(client) for _ in range(count)]
        check([r[1] for r in rows] == [b"row-%d" % i for i in range(count)],
              "all the small messages arrive, in order, without a second query to wake sluice up")
        check(read_message(client)[0] == b"C" and read_message(client)[0] == b"Z", "and the end of the answer")
        client.close()
        upstream.finish()
        check(sluice.stop() == 0, "clean shutdown")


def scenario_tls_drops_scram_channel_binding():
    """With TLS to the database the server offers SCRAM-SHA-256-PLUS, which a client that talks to sluice in
    clear refuses. sluice takes it out of the offer and touches nothing else."""
    sasl = lambda names: message(b"R", struct.pack("!I", 10) + names)
    both = sasl(b"SCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0\0")
    plain_offer = sasl(b"SCRAM-SHA-256\0\0")
    only_plus = sasl(b"SCRAM-SHA-256-PLUS\0\0")
    cont = message(b"R", struct.pack("!I", 11) + b"r=nonce,s=c2FsdA==,i=4096")
    ok = message(b"R", struct.pack("!I", 0)) + message(b"Z", b"I")
    version = message(b"v", struct.pack("!II", 2, 1) + b"_pq_.x\0")

    def serve(chunks, delay):
        def script(conn, seen):
            read_startup(conn)
            for chunk in chunks:
                conn.sendall(chunk)
                if delay:
                    time.sleep(delay)
            try:
                seen["eof"] = conn.recv(1) == b""
            except OSError:
                seen["eof"] = True
        return script

    def run(stream, expected, delay=0, tls=True, extra=None):
        """The upstream sends `stream` (split in chunks); the client must receive `expected`."""
        with tempfile.TemporaryDirectory() as d:
            good = make_cert(d, "good", "DNS:localhost,IP:127.0.0.1")
            if good is None:
                return None
            chunks = [stream[i:i + 1] for i in range(len(stream))] if delay else [stream]
            upstream = FakeUpstream(serve(chunks, delay), tls=good if tls else None)
            args = ["--upstream-tls", "verify-full", "--upstream-ca", good[0]] if tls else []
            sluice = Sluice(upstream.port, extra_args=args)
            client = sluice.connect()
            client.sendall(startup_packet(user="alice", database="db1"))
            got = recv_exact(client, len(expected))
            client.close()
            upstream.finish()
            adjusted = [e for e in sluice.events if e["event"] == "auth_adjusted"]
            check(sluice.stop() == 0, "clean shutdown")
            return got, adjusted

    if make_cert(tempfile.gettempdir(), "probe", "DNS:localhost") is None:
        print("    (skipped: no openssl tool able to make a certificate)")
        return
    os.unlink(os.path.join(tempfile.gettempdir(), "probe.crt"))
    os.unlink(os.path.join(tempfile.gettempdir(), "probe.key"))

    got, adjusted = run(both + cont, plain_offer + cont)
    check(got == plain_offer + cont, "PLUS is removed, the message after it is untouched")
    check(len(adjusted) == 1, "and the log says so once")

    got, adjusted = run(both + cont, plain_offer + cont, delay=0.001)
    check(got == plain_offer + cont and len(adjusted) == 1, "the same when the message arrives byte by byte")

    got, adjusted = run(version + both + cont, version + plain_offer + cont)
    check(got == version + plain_offer + cont and len(adjusted) == 1, "a NegotiateProtocolVersion may come first")

    got, adjusted = run(ok, ok)
    check(got == ok and not adjusted, "no SCRAM, no change")

    got, adjusted = run(only_plus + cont, only_plus + cont)
    check(got == only_plus + cont and not adjusted, "an offer of PLUS alone is left as it is")

    got, adjusted = run(cont + both, cont + both)
    check(got == cont + both and not adjusted, "only the first authentication message is looked at")

    # without TLS to the database the server does not offer PLUS, and sluice leaves the bytes alone anyway
    got, adjusted = run(both + cont, both + cont, tls=False)
    check(got == both + cont and not adjusted, "plain upstream: the stream is relayed as it comes")


def scenario_tls_client_certificate():
    """A database that asks for a client certificate: sluice shows its own, and fails cleanly without."""
    with tempfile.TemporaryDirectory() as d:
        server = make_cert(d, "server", "DNS:localhost,IP:127.0.0.1")
        mine = make_cert(d, "sluice-client", "DNS:sluice")
        stranger = make_cert(d, "intruder", "DNS:intruder")
        if server is None or mine is None or stranger is None:
            print("    (skipped: no openssl tool able to make a certificate)")
            return
        base = ["--upstream-tls", "verify-full", "--upstream-ca", server[0]]

        # the certificate is shown, and the server sees who it belongs to
        sent = [q("select 1"), message(b"X")]
        upstream = FakeUpstream(tls_greeting_script, tls=server, client_ca=mine[0])
        sluice = Sluice(upstream.port, extra_args=base + ["--upstream-cert", mine[0], "--upstream-key", mine[1]])
        check(sluice.events[0]["upstream_client_cert"] is True, "the listening event says a client certificate is set")
        client = open_session(sluice, user="alice", database="db1")
        for m in sent:
            client.sendall(m)
        client.close()
        upstream.finish()
        check(upstream.seen["client_cn"] == "sluice-client", f"the server read the certificate: {upstream.seen}")
        check(upstream.seen["stream"] == b"".join(sent), "and the bytes cross unchanged")
        check(sluice.stop() == 0, "clean shutdown")

        # a server that wants a certificate, and none, or one it does not trust: no connection, no hang
        for extra in (base, base + ["--upstream-cert", stranger[0], "--upstream-key", stranger[1]]):
            upstream = FakeUpstream(tls_greeting_script, tls=server, client_ca=mine[0], tolerate=True)
            sluice = Sluice(upstream.port, extra_args=extra)
            client = sluice.connect()
            client.sendall(startup_packet(user="alice"))
            try:
                kind, _ = read_message(client)  # TLS 1.2 fails the handshake: a FATAL error comes back
                check(kind == b"E", "an error, not data")
            except (EOFError, ConnectionResetError):
                pass  # TLS 1.3: the server rejects the certificate after the handshake, the connection ends
            closed = sluice.wait_event("connection_close")
            check(closed["reason"] in ("upstream_tls_failed", "upstream_error"), f"the connection ends: {closed}")
            why = [e for e in sluice.events if e.get("event") == "upstream_error"]
            # TLS 1.3 reports the refusal as an alert once the handshake is over. Whether the alert is read, or
            # only the reset that follows it, depends on timing (and on the system): both are failures of
            # the connection, each with its own stable code. The text is OpenSSL's or the system's.
            check(len(why) == 1 and why[0]["error"] != "", f"and the log says why: {why}")
            check(why[0]["code"] in ("tls_peer_alert", "io_error", "tls_error", "tls_handshake_failed"),
                  f"with a stable code: {why}")
            if why[0]["code"] == "tls_peer_alert":
                check(isinstance(why[0]["tls_alert"], int) and 0 <= why[0]["tls_alert"] < 256
                      and "alert" in why[0]["error"].lower(), f"and the number of the alert: {why}")
            check(sluice.stop() == 0, "clean shutdown")


def run_on_terminal(args, timeout=5.0):
    """Runs a command with a terminal of its own, as an operator would. Returns (exit code, output), or
    (None, output) when it is still waiting after `timeout` seconds, which is what a passphrase prompt does."""
    import pty
    import select

    pid, fd = pty.fork()
    if pid == 0:
        os.execv(args[0], args)
    output = b""
    status = None
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and status is None:
        if select.select([fd], [], [], 0.1)[0]:
            try:
                output += os.read(fd, 4096)
            except OSError:
                pass
        done, st = os.waitpid(pid, os.WNOHANG)
        if done:
            status = st
    if status is None:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        os.close(fd)
        return None, output
    try:
        while select.select([fd], [], [], 0.1)[0]:
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            output += chunk
    except OSError:
        pass
    os.close(fd)
    return os.waitstatus_to_exitcode(status), output


def scenario_tls_client_certificate_startup():
    """A client certificate that cannot be used stops sluice at startup, and never asks for a passphrase."""
    tool = os.environ.get("SLUICE_OPENSSL") or "openssl"
    with tempfile.TemporaryDirectory() as d:
        server = make_cert(d, "server", "DNS:localhost,IP:127.0.0.1")
        mine = make_cert(d, "mine", "DNS:sluice")
        other = make_cert(d, "other", "DNS:other")
        if server is None or mine is None or other is None:
            print("    (skipped: no openssl tool able to make a certificate)")
            return
        encrypted = os.path.join(d, "encrypted.key")
        try:
            subprocess.run([tool, "pkey", "-in", mine[1], "-aes256", "-passout", "pass:secret", "-out", encrypted],
                           check=True, capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            encrypted = None
        base = [SLUICE, "--listen", "127.0.0.1:0", "--upstream", "127.0.0.1:1", "--upstream-tls", "verify-full",
                "--upstream-ca", server[0]]
        cases = [
            (["--upstream-cert", mine[0], "--upstream-key", other[1]], 1, "does not match"),
            (["--upstream-cert", os.path.join(d, "missing.crt"), "--upstream-key", mine[1]], 1, "cannot read the client certificate"),
            (["--upstream-cert", mine[0], "--upstream-key", os.path.join(d, "missing.key")], 1, "cannot read the client private key"),
            (["--upstream-cert", mine[0]], 2, "go together"),
        ]
        if encrypted:
            cases.append((["--upstream-cert", mine[0], "--upstream-key", encrypted], 1, "encrypted"))
        for extra, code, fragment in cases:
            # no terminal, and a timeout: a passphrase prompt would hang here instead of failing
            proc = subprocess.run(base + extra, capture_output=True, text=True, timeout=TIMEOUT, stdin=subprocess.DEVNULL)
            check(proc.returncode == code, f"{extra[-1]}: exit {code}, got {proc.returncode}: {proc.stderr!r}")
            check(fragment in proc.stderr, f"{fragment!r} in {proc.stderr!r}")
            check(proc.stdout == "", "sluice never started listening")

        # on a real terminal OpenSSL would ask for the passphrase and wait: sluice must not
        if encrypted:
            code, output = run_on_terminal(base + ["--upstream-cert", mine[0], "--upstream-key", encrypted])
            check(code == 1, f"an encrypted key stops sluice instead of prompting (exit {code}, output {output!r})")
            check(b"pass phrase" not in output.lower() and b"passphrase" not in output.lower().replace(b"does not ask for a passphrase", b""),
                  f"and nothing asks for a passphrase: {output!r}")

        # a key that others can read: it works, with a warning
        os.chmod(mine[1], 0o644)
        upstream = FakeUpstream(tls_greeting_script, tls=server, client_ca=mine[0])
        sluice = Sluice(upstream.port, extra_args=["--upstream-tls", "verify-full", "--upstream-ca", server[0],
                                                   "--upstream-cert", mine[0], "--upstream-key", mine[1]])
        warned = [e for e in sluice.events if e["event"] == "warning" and "readable by other users" in e["detail"]]
        deadline = time.monotonic() + TIMEOUT
        while not warned and time.monotonic() < deadline:
            time.sleep(0.02)
            warned = [e for e in sluice.events if e["event"] == "warning" and "readable by other users" in e["detail"]]
        check(warned, "a world-readable key is warned about")
        os.chmod(mine[1], 0o600)
        upstream.sock.close()
        check(sluice.stop() == 0, "clean shutdown")


def scenario_tls_failures_are_clean():
    """No TLS on the server, a wrong name, an unknown CA: the client gets a FATAL error, never a fallback."""
    with tempfile.TemporaryDirectory() as d:
        good = make_cert(d, "good", "DNS:localhost,IP:127.0.0.1")
        wrong = make_cert(d, "wrong", "DNS:db.other.example")
        if good is None or wrong is None:
            print("    (skipped: no openssl tool able to make a certificate)")
            return
        cases = [
            # (what the fake server does, sluice options, text expected in the log)
            (dict(tls=good, answer=b"N", tolerate=True), ["--upstream-tls", "require"], "does not support TLS"),
            (dict(tls=wrong, tolerate=True), ["--upstream-tls", "verify-full", "--upstream-ca", wrong[0]],
             "mismatch"),
            (dict(tls=good, tolerate=True), ["--upstream-tls", "verify-full", "--upstream-ca", wrong[0]],
             "not trusted"),
            (dict(tls=good, tolerate=True), ["--upstream-tls", "verify-full"], "not trusted"),
        ]
        for server_args, extra, fragment in cases:
            upstream = FakeUpstream(tls_greeting_script, **server_args)
            sluice = Sluice(upstream.port, extra_args=extra)
            client = sluice.connect()
            client.sendall(startup_packet(user="alice"))
            kind, payload = read_message(client)
            fields = error_fields(payload)
            check(kind == b"E" and fields["C"] == "08001" and "TLS" in fields["M"],
                  f"a FATAL 08001 about TLS reaches the client: {fields}")
            check(at_eof(client), "and the connection is closed")
            err = sluice.wait_event("upstream_error")
            check(fragment in err["error"], f"the log says why ({fragment!r}): {err}")
            expected = "tls_not_supported" if fragment == "does not support TLS" else "tls_handshake_failed"
            check(err["code"] == expected, f"and gives a stable code ({expected}): {err}")
            sluice.wait_event("connection_close", reason="upstream_tls_failed")
            check(sluice.stop() == 0, "clean shutdown")


def scenario_tls_options_are_validated():
    """Bad TLS options stop sluice at startup."""
    base = [SLUICE, "--listen", "127.0.0.1:0", "--upstream", "127.0.0.1:1"]
    cases = [
        (["--upstream-tls", "maybe"], 2, "must be off, require or verify-full"),
        (["--upstream-ca", "/x.pem"], 2, "does nothing without"),
        (["--upstream-tls", "require", "--upstream-ca", "/x.pem"], 2, "only used with"),
        (["--upstream-tls", "verify-full", "--upstream-ca", "/nonexistent/ca.pem"], 1, "cannot read the CA file"),
    ]
    for extra, code, fragment in cases:
        proc = subprocess.run(base + extra, capture_output=True, text=True, timeout=TIMEOUT)
        check(proc.returncode == code, f"{extra}: exit {code}, got {proc.returncode}: {proc.stderr!r}")
        check(fragment in proc.stderr, f"{extra}: {fragment!r} in {proc.stderr!r}")
        check(proc.stdout == "", "sluice never started listening")


def tls_client(sluice, cafile=None, start=True, **params):
    """A client that asks for TLS the way libpq does (SSLRequest, 'S', handshake) and starts up under it."""
    import ssl
    raw = sluice.connect()
    raw.sendall(SSL_REQUEST)
    check(recv_exact(raw, 1) == b"S", "sluice agrees to TLS")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if cafile:
        ctx.load_verify_locations(cafile)
        ctx.check_hostname = False
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    client = ctx.wrap_socket(raw, server_hostname="localhost")
    client.settimeout(TIMEOUT)
    if start:
        client.sendall(startup_packet(**params))
    return client


def scenario_clients_speak_tls():
    """sluice as a TLS server: self-signed (sslmode=require) and with a given certificate (verify-ca). The
    upstream hop stays plain, the bytes cross unchanged, 4 MB each way."""
    big = message(b"d", os.urandom(4 << 20))
    with tempfile.TemporaryDirectory() as d:
        good = make_cert(d, "good", "DNS:localhost,IP:127.0.0.1")
        if good is None:
            print("    (skipped: no openssl tool able to make a certificate)")
            return
        for extra, cafile, mode in ((["--listen-tls", "self-signed"], None, "self-signed"),
                                    (["--listen-tls-cert", good[0], "--listen-tls-key", good[1]], good[0],
                                     "certificate")):
            reply = os.urandom(1 << 20)

            def script(conn, seen, reply=reply):
                seen["startup"] = read_startup(conn)
                conn.sendall(message(b"R", struct.pack("!I", 0)) + message(b"Z", b"I"))
                conn.sendall(message(b"d", reply))
                chunks = []
                while True:
                    data = conn.recv(1 << 20)
                    if not data:
                        break
                    chunks.append(data)
                seen["stream"] = b"".join(chunks)

            upstream = FakeUpstream(script)
            sluice = Sluice(upstream.port, extra_args=extra)
            check(sluice.events[0]["listen_tls"] == mode, f"the listening event states the mode: {sluice.events[0]}")
            client = tls_client(sluice, cafile, user="alice", database="db1")
            check(read_message(client)[0] == b"R", "authentication request crosses TLS")
            check(read_message(client)[0] == b"Z", "ReadyForQuery crosses TLS")
            kind, payload = read_message(client)
            check(kind == b"d" and payload == reply, "1 MB from the upstream reaches the client intact")
            sent = [q("select 1"), big, message(b"X")]
            for m in sent:
                client.sendall(m)
            client.close()
            upstream.finish()
            check(upstream.seen["stream"] == b"".join(sent), f"bytes cross unchanged ({mode})")
            check(upstream.seen["startup"] == startup_packet(user="alice", database="db1"),
                  "the startup packet reaches the upstream unchanged")
            started = sluice.wait_event("startup")
            check(started["user"] == "alice", f"the startup event is logged: {started}")
            sluice.wait_event("connection_close", reason="client_closed")
            check(any(e["event"] == "warning" and "signed by nobody" in e["detail"] for e in sluice.events)
                  == (mode == "self-signed"), "a self-signed certificate is warned about, a given one is not")
            check(sluice.stop() == 0, "clean shutdown")


def scenario_clients_must_use_tls():
    """When TLS is on for the clients: clear-text startup is refused, nothing may follow the SSLRequest in
    clear, a second SSLRequest is refused, GSS encryption is declined, and a CancelRequest still goes through."""
    def idle(conn, seen):
        try:
            seen["stream"] = conn.recv(1 << 20)
        except OSError:
            pass

    upstream = FakeUpstream(lambda conn, seen: seen.__setitem__("cancel", recv_exact(conn, 16)))
    sluice = Sluice(upstream.port, extra_args=["--listen-tls", "self-signed"])

    plain = sluice.connect()
    plain.sendall(startup_packet(user="alice", database="db1"))
    kind, payload = read_message(plain)
    fields = error_fields(payload)
    check(kind == b"E" and fields["C"] == "28000" and "requires TLS" in fields["M"], f"plain startup refused: {fields}")
    check(at_eof(plain), "and the connection ends")
    sluice.wait_event("connection_close", reason="tls_required")

    smuggled = sluice.connect()
    smuggled.sendall(SSL_REQUEST + startup_packet(user="alice", database="db1"))
    kind, payload = read_message(smuggled)
    check(kind == b"E" and error_fields(payload)["C"] == "08P01",
          "bytes sent behind the SSLRequest are refused, not taken for encrypted input")
    check(at_eof(smuggled), "and the connection ends")

    again = tls_client(sluice, start=False)  # TLS is up; what the client sends first is another SSLRequest
    again.sendall(SSL_REQUEST)
    kind, payload = read_message(again)
    check(kind == b"E" and error_fields(payload)["C"] == "08P01", "a second SSLRequest under TLS is refused")
    again.close()

    gss = sluice.connect()
    gss.sendall(GSSENC_REQUEST)
    check(recv_exact(gss, 1) == b"N", "GSS encryption is declined")
    gss.close()

    cancel = sluice.connect()
    cancel.sendall(CANCEL_REQUEST)
    check(at_eof(cancel), "the connection ends once the upstream closes")
    upstream.finish()
    check(upstream.seen["cancel"] == CANCEL_REQUEST, "a CancelRequest in clear text is forwarded unchanged")
    check(sluice.stop() == 0, "clean shutdown")


def scenario_tls_to_clients_is_validated():
    """Bad options for the TLS toward clients stop sluice at startup."""
    base = [SLUICE, "--listen", "127.0.0.1:0", "--upstream", "127.0.0.1:1"]
    cases = [
        (["--listen-tls", "maybe"], 2, "must be self-signed or off"),
        (["--listen-tls-cert", "/x.pem"], 2, "go together"),
        (["--listen-tls", "self-signed", "--listen-tls-cert", "/x.pem", "--listen-tls-key", "/y.pem"], 2, "choose one"),
        (["--listen-tls-cert", "/nonexistent/c.pem", "--listen-tls-key", "/nonexistent/k.pem"], 1, "cannot"),
    ]
    for extra, code, fragment in cases:
        proc = subprocess.run(base + extra, capture_output=True, text=True, timeout=TIMEOUT)
        check(proc.returncode == code, f"{extra}: exit {code}, got {proc.returncode}: {proc.stderr!r}")
        check(fragment in proc.stderr, f"{extra}: {fragment!r} in {proc.stderr!r}")
        check(proc.stdout == "", "sluice never started listening")


def main():
    scenarios = [
        scenario_clients_speak_tls,
        scenario_clients_must_use_tls,
        scenario_tls_to_clients_is_validated,
        scenario_tls_encrypts_the_upstream_hop,
        scenario_tls_large_transfer,
        scenario_tls_many_small_records,
        scenario_tls_client_certificate,
        scenario_tls_client_certificate_startup,
        scenario_tls_drops_scram_channel_binding,
        scenario_tls_failures_are_clean,
        scenario_tls_options_are_validated,
        scenario_enforce_rewrites_blocked_messages,
        scenario_strings_read_two_ways,
        scenario_name_with_several_addresses,
        scenario_search_path_cannot_move_a_table,
        scenario_warnings_for_a_risky_setup,
        scenario_audit_only_logs,
        scenario_confirm_yes_and_no,
        scenario_confirm_threshold_and_updates,
        scenario_confirm_without_an_answer,
        scenario_confirm_in_a_transaction,
        scenario_confirm_fallback_and_errors,
        scenario_confirm_waits_its_turn,
        scenario_confirm_what_it_cannot_do,
        scenario_confirm_nothing_leaks_when_the_client_leaves,
        scenario_apps_and_people,
        scenario_bytes_sent_before_the_database_answers,
        scenario_timeouts,
        scenario_connection_limit,
        scenario_shutdown_with_open_connections,
        scenario_startup_failures,
        scenario_connections_lost_midway,
        scenario_tls_ends_cleanly_and_abruptly,
        scenario_log_limits,
        scenario_out_of_descriptors_does_not_spin,
        scenario_rules_follow_user_and_order,
        scenario_uninspectable_in_enforce,
        scenario_enforce_guards_the_connection,
        scenario_rules_about_tables,
        scenario_policy_reload,
        scenario_sighup_without_policy,
        scenario_log_keeps_values_out,
        scenario_log_keeps_values_out_of_verdicts,
        scenario_bad_policy_stops_sluice,
        scenario_statements_are_logged,
        scenario_long_and_oversized_statements,
        scenario_frame_error_keeps_relaying,
        scenario_client_leaves_mid_message,
        scenario_happy_path,
        scenario_large_transfer,
        scenario_cancel_request,
        scenario_upstream_down,
        scenario_garbage_startup,
        scenario_log_is_safe_json,
    ]
    if len(sys.argv) > 2:  # run only the scenarios whose name has one of the given words
        scenarios = [f for f in scenarios if any(w in f.__name__ for w in sys.argv[2:])]
    for scenario in scenarios:
        started = time.monotonic()
        scenario()
        print(f"ok  {scenario.__name__} ({time.monotonic() - started:.2f}s)")


if __name__ == "__main__":
    main()
