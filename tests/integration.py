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

    def __init__(self, script, tls=None, answer=b"S", tolerate=False, client_ca=None, connections=1):
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
        self.connections = connections  # how many connections it takes: each runs the script on its own thread
        self.helpers = []
        self.thread = threading.Thread(target=self._run, args=(script, tls, answer), daemon=True)
        self.thread.start()

    def _run(self, script, tls, answer):
        try:
            for i in range(self.connections):
                conn, _ = self.sock.accept()
                if i < self.connections - 1:
                    helper = threading.Thread(target=self._serve, args=(conn, script, tls, answer), daemon=True)
                    helper.start()
                    self.helpers.append(helper)
                else:
                    self._serve(conn, script, tls, answer)
        except Exception as exc:  # reported by finish()
            if not self.tolerate:
                self.error = exc
        finally:
            self.sock.close()

    def _serve(self, conn, script, tls, answer):
        try:
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

    def finish(self):
        for helper in self.helpers:
            helper.join(TIMEOUT)
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
        while self.events[-1]["event"] in ("chain_start", "admin_listening"):  # a chained log starts with its own line
            line = self.proc.stdout.readline()
            self.raw.append(line)
            self.events.append(json.loads(line))
        check(self.events[-1]["event"] == "listening", "the log goes on with the listening event")
        self.port = self.events[-1]["port"]
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

# These scenarios are about the question and the answer; the look at what else the statement changed has
# scenarios of its own (and is on by default).
POLICY_CONFIRM = """
mode = "enforce"
confirm_timeout = "5s"

[[rule]]
name = "confirm-deletes"
match = "delete"
action = "confirm"
over_rows = "1"
side_effects = "off"
message = "A person has to confirm this."

[[rule]]
name = "confirm-updates"
match = "update"
action = "confirm"
side_effects = "off"
"""

POLICY_CONFIRM_SIDE = POLICY_CONFIRM.replace('side_effects = "off"\n', "")


def cc(tag):
    return message(b"C", tag.encode() + b"\0")


def z(status):
    return message(b"Z", status)


def error_msg(sqlstate, text):
    return message(b"E", b"SERROR\0VERROR\0C" + sqlstate.encode() + b"\0M" + text.encode() + b"\0\0")


def row_description(names, types=None, formats=None, tables=None):
    """names: the columns; types: their type oids (text, 25, when not given); formats: 0 text or 1 binary;
    tables: the oid of the table each column comes from (0 when not given)."""
    body = struct.pack("!H", len(names))
    for i, n in enumerate(names):
        oid = types[i] if types else 25
        fmt = formats[i] if formats else 0
        table = tables[i] if tables else 0
        body += n.encode() + b"\0" + struct.pack("!IhIhih", table, 0, oid, -1, -1, fmt)
    return message(b"T", body)


def data_row(values):
    body = struct.pack("!H", len(values))
    for v in values:
        if v is None:
            body += struct.pack("!i", -1)
        else:
            body += struct.pack("!I", len(v)) + v.encode()
    return message(b"D", body)


def tag_verb(stmt, rows):
    """The command tag the server gives a statement: DELETE n, UPDATE n, MERGE n, INSERT 0 n."""
    low = stmt.lower()
    if low.startswith("delete"):
        return "DELETE"
    if low.startswith("merge"):
        return "MERGE"
    if low.startswith("insert"):
        return "INSERT 0"
    return "UPDATE"


def returned(stmt):
    """What the fake gives back for a statement that ends with a RETURNING sluice added: the columns and the rows.
    RETURNING OLD.*, NEW.* is the old row and the new row side by side (the e-mail changes domain)."""
    sample = [("18", "ana@example.com"), ("52", None), ("7", "carl@example.com")]
    if stmt.endswith("RETURNING OLD.*, NEW.*"):
        new = [(i, e.replace("@example.com", "@changed.org") if e else "filled@changed.org") for i, e in sample]
        return ["id", "email", "id", "email"], [o + n for o, n in zip(sample, new)]
    return ["id", "email"], sample


def confirm_db(rows=3, fail_returning=False, fail_always=False, slow=0.0, junk=False, side_fails=False):
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
            if (text.startswith("BEGIN; ") or text.startswith("SAVEPOINT sluice_guard; ")) \
                    and "pg_stat_xact_user_tables" in text:
                # BEGIN; <look>; <statement>; <look>: the statistics of the session count what earlier
                # transactions did too, so the numbers only mean something as a difference
                prelude = "BEGIN" if text.startswith("BEGIN") else "SAVEPOINT"
                stmt = text.split("; ", 2)[2].rsplit("; select schemaname", 1)[0]
                verb = tag_verb(stmt, rows)
                if side_fails:
                    out, status = cc(prelude) + error_msg("42P01", "relation does not exist") + z(b"E"), b"E"
                else:
                    names, sample = returned(stmt)
                    out = (cc(prelude) + data_row(["public.orders", "100", "0", "50"]) + cc("SELECT 1")
                           + row_description(names))
                    for i in range(rows):
                        out += data_row(sample[i % 3])
                    out += (cc(f"{verb} {rows}") + data_row(["public.orders", "100", "0", "62"])
                            + data_row(["public.audit_log", "3", "0", "0"]) + cc("SELECT 2") + z(b"T"))
                    status = b"T"
            elif text.startswith("BEGIN; ") or text.startswith("SAVEPOINT sluice_guard; "):
                prelude = "BEGIN" if text.startswith("BEGIN") else "SAVEPOINT"
                stmt = text.split("; ", 1)[1]
                with_returning = stmt.endswith(("RETURNING *", "RETURNING OLD.*, NEW.*"))
                verb = tag_verb(stmt, rows)
                if stmt.lower().startswith(("truncate", "drop")):
                    tag = "TRUNCATE TABLE" if stmt.lower().startswith("truncate") else "DROP TABLE"
                    out, status = cc(prelude) + cc(tag) + z(b"T"), b"T"
                elif fail_always or (with_returning and fail_returning):
                    out = cc(prelude) + error_msg("42501" if with_returning else "23503", "no good") + z(b"E")
                    status = b"E"
                else:
                    out = cc(prelude)
                    if with_returning:
                        names, sample = returned(stmt)
                        out += row_description(names)
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
    """What cannot be confirmed is refused with a reason, not let through: several statements, a data-changing
    CTE, a session that cannot be followed; and an audit-mode policy does not touch anything."""
    stream, stmts, closed, _ = run_session(POLICY_CONFIRM, "agent", [
        parse_msg(b"s1", "delete from users where id = $1", (23,)),  # prepared: confirmed when it is run
        q("delete from a where id = 1; delete from b where id = 1"),
        q("with d as (delete from a returning id) delete from b where id in (select id from d)"),
        message(b"S"),
    ])
    check(stream.count(b"asks for a confirmation") == 2, f"two refusals: {stream!r}")
    check(b"one DELETE, UPDATE, TRUNCATE or DROP" in stream, "with their reason")
    check(b"delete from users where id = $1 RETURNING *" in stream, "the prepared one goes on, with a RETURNING")
    check([s["action"] for s in stmts] == ["held", "blocked", "blocked"]
          and all(s["verdict"] == "confirm" for s in stmts),
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


# ---- the extended protocol (docs/design.md, section 21) ----

def bind_msg(portal=b"", stmt=b""):
    return message(b"B", portal + b"\0" + stmt + b"\0" + struct.pack("!HHH", 0, 0, 0))


def describe_msg(kind, name=b""):
    return message(b"D", kind + name + b"\0")


def execute_msg(portal=b"", max_rows=0):
    return message(b"E", portal + b"\0" + struct.pack("!I", max_rows))


def close_msg(kind, name=b""):
    return message(b"C", kind + name + b"\0")


FLUSH = message(b"H")
SYNC = message(b"S")


def ext_db(rows=3, error_on=None, side_fails=False):
    """A fake PostgreSQL for the extended protocol. Like the real one it keeps its answers until a Flush or a
    Sync, ignores messages after an error up to the next Sync, and commits an implicit transaction only at the
    Sync. seen["msgs"] lists what it received: (type, text, whether the answers had been sent before)."""
    def script(conn, seen):
        seen["msgs"] = []
        seen["commits"] = []
        seen["startup"] = read_startup(conn)
        conn.sendall(message(b"R", struct.pack("!I", 0)) + z(b"I"))
        stmts, portals = {}, {}
        out = b""
        skipping = False
        in_tx = False
        failed = False
        cur_stmt = {"": ""}

        def flush():
            nonlocal out
            if out:
                conn.sendall(out)
                out = b""

        def names(p, n):
            parts = p.split(b"\0")
            return parts[:n]

        while True:
            try:
                kind, payload = read_message(conn)
            except (EOFError, OSError):
                break
            text = ""
            if kind == b"P":
                text = payload.split(b"\0")[1].decode()
            elif kind == b"Q":
                text = payload[:-1].decode()
            seen["msgs"].append((kind.decode(), text))
            if kind == b"X":
                break
            if kind == b"H":
                flush()
                continue
            if kind == b"S":
                status = b"I"
                if in_tx:
                    status = b"E" if failed else b"T"
                else:
                    seen["commits"].append("rollback" if failed else "commit")
                out += z(status)
                flush()
                skipping = False
                failed = False if not in_tx else failed
                continue
            if kind == b"Q":
                low = text.lower()
                if low == "begin":
                    in_tx = True
                    failed = False
                    out += cc("BEGIN") + z(b"T")
                elif low in ("rollback", "commit"):
                    seen["commits"].append(low)
                    in_tx = False
                    failed = False
                    out += cc(low.upper()) + z(b"I")
                else:
                    out += cc("SELECT 1") + z(b"E" if failed else (b"T" if in_tx else b"I"))
                flush()
                continue
            if skipping:
                continue
            if kind == b"P":
                name = payload.split(b"\0")[0]
                if "'::int" in text or (error_on and error_on in text):
                    literal = text.split("'", 1)[1].rsplit("'::int", 1)[0].replace("''", "'") if "'::int" in text else ""
                    out += error_msg("22P02", 'invalid input syntax for type integer: "%s"' % literal)
                    flush()
                    skipping = True
                    failed = True
                else:
                    stmts[name] = text
                    out += message(b"1")
            elif kind == b"B":
                portal, stmt = names(payload, 2)
                if stmt not in stmts:
                    out += error_msg("26000", "prepared statement does not exist")
                    flush()
                    skipping = True
                    failed = True
                else:
                    portals[portal] = stmts[stmt]
                    out += message(b"2")
            elif kind == b"D":
                sql = portals.get(payload[1:-1], "") if payload[:1] == b"P" else stmts.get(payload[1:-1], "")
                if payload[:1] == b"S":
                    out += message(b"t", struct.pack("!H", 0))
                out += row_description(["id", "email"]) if "returning" in sql.lower() else message(b"n")
            elif kind == b"E":
                sql = portals.get(payload.split(b"\0")[0], "")
                if sql.startswith("SET "):
                    out += cc("SET")
                elif sql.lower().startswith(("truncate", "drop")):
                    out += cc("TRUNCATE TABLE" if sql.lower().startswith("truncate") else "DROP TABLE")
                elif "boom" in sql:  # fails when it runs, not when it is prepared
                    out += error_msg("22012", "division by zero")
                    flush()
                    skipping = True
                    failed = True
                elif "pg_stat_xact_user_tables" in sql:
                    if side_fails and payload.split(b"\0")[0] == b"sluice_side":
                        out += error_msg("42P01", "relation does not exist")
                        flush()
                        skipping = True
                        failed = True
                    elif payload.split(b"\0")[0] == b"sluice_side":  # the first look
                        out += data_row(["public.orders", "100", "0", "50"]) + cc("SELECT 1")
                    else:  # the second look
                        out += (data_row(["public.orders", "100", "0", "62"])
                                + data_row(["public.audit_log", "3", "0", "0"]) + cc("SELECT 2"))
                elif sql.lower().startswith("delete"):
                    if "returning *" in sql.lower():
                        for i in range(rows):
                            out += data_row([str(i + 1), "user%d@example.com" % i])
                    elif "returning id" in sql.lower():
                        for i in range(rows):
                            out += data_row([str(i + 1)])
                    out += cc(f"DELETE {rows}")
                else:
                    out += data_row(["1"]) + cc("SELECT 1")
            elif kind == b"C":
                (stmts if payload[:1] == b"S" else portals).pop(payload[1:-1], None)
                out += message(b"3")
    return script


def read_until_z(client):
    return read_answer(client)


def ext_session(rows=3, tty=None, policy=POLICY_CONFIRM, error_on=None, side_fails=False, session=False):
    """tty=None: a terminal that does not exist (never the tester's own); session=True: no terminal or
    command at all, so the client itself is asked."""
    upstream = FakeUpstream(ext_db(rows=rows, error_on=error_on, side_fails=side_fails), tolerate=True)
    args = [] if session else ["--confirm-tty", tty.path if tty else "/nonexistent/tty"]
    sluice = Sluice(upstream.port, policy=policy, extra_args=args)
    client = open_session(sluice, user="agent", database="mydb")
    return upstream, sluice, client


DELETE_SQL = "delete from users where id < 5"


def scenario_confirm_shows_side_effects():
    """Before asking, sluice looks at what else the transaction changed (cascades, triggers) and shows it; a server that
    cannot say is not a reason to lose the statement. Both protocols."""
    tty = Tty()
    try:
        # simple protocol
        upstream, sluice, client = confirm_session(confirm_db(rows=3), policy=POLICY_CONFIRM_SIDE, tty=tty)
        client.sendall(q("delete from users where id < 5"))
        text = tty.wait_for("commit? [y/N]")
        check("tables changed in this transaction" in text and "public.orders" in text and "12 deleted" in text
              and "public.audit_log" in text and "3 inserted" in text, f"the side effects are shown: {text!r}")
        check("62" not in text, "as a difference: the counters of the session are not shown")
        check("deleted 3 rows" in text and "ana@example.com" in text, "next to the statement's own rows")
        tty.answer("y\n")
        check(kinds(read_answer(client)) == b"CZ", "the client sees only its own answer")
        client.close()
        upstream.finish()
        queries_sent = upstream.seen["queries"]
        check(len(queries_sent) == 2 and queries_sent[0].startswith("BEGIN; select schemaname")
              and queries_sent[0].count("pg_stat_xact_user_tables") == 2 and queries_sent[1] == "COMMIT",
              f"BEGIN, a look, the statement, a look: in one message: {queries_sent}")
        check(sluice.stop() == 0, "clean shutdown")

        # simple protocol, the look fails: undone, asked without it, committed on a yes
        tty.text = ""
        upstream, sluice, client = confirm_session(confirm_db(rows=3, side_fails=True), policy=POLICY_CONFIRM_SIDE,
                                                   tty=tty)
        client.sendall(q("delete from users where id < 5"))
        text = tty.wait_for("commit? [y/N]")
        check("tables changed" not in text and "deleted 3 rows" in text, f"asked without it: {text!r}")
        tty.answer("y\n")
        check(kinds(read_answer(client)) == b"CZ", "and it goes through")
        client.close()
        upstream.finish()
        sent = upstream.seen["queries"]
        check(len(sent) == 4 and "pg_stat_xact_user_tables" in sent[0] and sent[1] == "ROLLBACK"
              and sent[2] == "BEGIN; delete from users where id < 5 RETURNING *" and sent[3] == "COMMIT",
              f"the look failed: undone, run again without it, committed: {sent}")
        check(sluice.stop() == 0, "clean shutdown")

        # extended protocol
        tty.text = ""
        upstream, sluice, client = ext_session(tty=tty, policy=POLICY_CONFIRM_SIDE)
        client.sendall(parse_msg(b"", DELETE_SQL) + bind_msg() + describe_msg(b"P") + execute_msg() + SYNC)
        text = tty.wait_for("commit? [y/N]")
        check("public.orders" in text and "12 deleted" in text and "user0@example.com" in text, f"{text!r}")
        tty.answer("y\n")
        answer = read_until_z(client)
        check(kinds(answer) == b"12nCZ", f"the client sees what it would have seen without sluice: {kinds(answer)}")
        client.sendall(q("select 1"))
        check(kinds(read_answer(client)) == b"CZ", "and the session goes on")
        client.close()
        upstream.finish()
        sent = [m[0] for m in upstream.seen["msgs"]]
        check(sent[:15] == ["P", "B", "D", "D", "P", "B", "E", "E", "B", "E", "C", "C", "C", "H", "S"],
              f"the statement, our Describe, the first look, the Execute, the second look, closing, Flush, "
              f"then the held Sync: {sent}")
        check(upstream.seen["commits"][0] == "commit", f"{upstream.seen['commits']}")
        check(sluice.stop() == 0, "clean shutdown")

        # extended protocol, the look fails: the client is told, nothing is committed
        tty.text = ""
        upstream, sluice, client = ext_session(tty=tty, policy=POLICY_CONFIRM_SIDE, side_fails=True)
        client.sendall(parse_msg(b"", DELETE_SQL) + bind_msg() + execute_msg() + SYNC)
        answer = read_until_z(client)
        check(kinds(answer) == b"12EZ" and "side_effects" in error_fields(answer[2][1])["M"]
              and "nothing was committed" in error_fields(answer[2][1])["M"],
              f"our error, saying how to turn it off: {kinds(answer)}")
        client.close()
        upstream.finish()
        check(upstream.seen["commits"][0] == "rollback", f"{upstream.seen['commits']}")
        check(sluice.stop() == 0, "clean shutdown")
    finally:
        tty.close()


def scenario_confirm_in_the_session():
    """Nobody is at the proxy: the person who sent the statement is asked, in their own session. The statement has
    run in a transaction that stays open; select sluice_confirm() commits it, select sluice_cancel() undoes it,
    and anything else is refused without the server hearing of it. Simple protocol."""
    upstream, sluice, client = confirm_session(confirm_db(rows=3))
    client.sendall(q("delete from users where id < 5"))
    answer = read_answer(client)
    check(kinds(answer) == b"EZ" and answer[1][1] == b"T", f"an error, then ReadyForQuery in a transaction: {answer}")
    fields = error_fields(answer[0][1])
    check(fields["C"] == "42501" and "DELETE 3 waiting for you" in fields["M"] and "confirm-deletes" in fields["M"]
          and "yes;" in fields["M"] and "no;" in fields["M"], f"the message says what to do: {fields}")
    check("deleted 3 rows" in fields["D"] and "ana@example.com" in fields["D"] and "agent@mydb" not in fields["D"]
          and len(fields["D"].splitlines()) <= 6, f"the rows are the detail, short: {fields['D']!r}")
    check("A person has to confirm this." in fields["H"] and "undone after" in fields["H"], f"{fields['H']!r}")

    # show: the question again, with every row that was kept
    client.sendall(q(" Show ;"))
    answer = read_answer(client)
    shown = error_fields(answer[0][1])
    check(kinds(answer) == b"EZ" and answer[1][1] == b"T" and "waiting for you" in shown["M"]
          and "ana@example.com" in shown["D"] and "carl@example.com" in shown["D"], f"show: {shown}")
    # anything else is refused, and never reaches the database (it would run inside the open transaction)
    client.sendall(q("select 1"))
    answer = read_answer(client)
    check(kinds(answer) == b"EZ" and "waiting for your answer" in error_fields(answer[0][1])["M"],
          f"refused: {answer}")
    # a COMMIT would apply what was not confirmed: refused
    client.sendall(q("commit"))
    answer = read_answer(client)
    check(kinds(answer) == b"EZ" and "COMMIT now would apply" in error_fields(answer[0][1])["M"], f"{answer}")
    # a plain yes: whatever its case, spacing and semicolon
    client.sendall(q("  YES ; "))
    answer = read_answer(client)
    check(kinds(answer) == b"CZ" and answer[0][1] == b"DELETE 3\0" and answer[1][1] == b"I",
          f"the answer is the statement's own, as psql shows it: {answer}")
    client.sendall(q("select 1"))
    check(kinds(read_answer(client)) == b"CZ", "and the session is back to normal")
    client.close()
    upstream.finish()
    check(upstream.seen["queries"] == ["BEGIN; delete from users where id < 5 RETURNING *", "COMMIT", "select 1"],
          f"what the database was sent: {upstream.seen['queries']}")
    event = sluice.wait_event("confirm")
    check(event["outcome"] == "yes" and event["channel"] == "session" and event["rows"] == 3, f"{event}")
    check("ana@example.com" not in sluice.raw_text(), "the values are not in the log")
    check(sluice.stop() == 0, "clean shutdown")

    # cancel
    upstream, sluice, client = confirm_session(confirm_db(rows=3))
    client.sendall(q("delete from users where id < 5"))
    read_answer(client)
    client.sendall(q("no;"))
    answer = read_answer(client)
    check(kinds(answer) == b"CZ" and answer[0][1] == b"ROLLBACK\0", f"{answer}")
    client.close()
    upstream.finish()
    check(upstream.seen["queries"] == ["BEGIN; delete from users where id < 5 RETURNING *", "ROLLBACK"],
          f"{upstream.seen['queries']}")
    check(sluice.wait_event("confirm")["outcome"] == "no", "logged as a no")
    check(sluice.stop() == 0, "clean shutdown")

    # a driver that rolls back because something raised: the waiting statement goes with it
    upstream, sluice, client = confirm_session(confirm_db(rows=3))
    client.sendall(q("delete from users where id < 5"))
    read_answer(client)
    client.sendall(q("ROLLBACK"))
    answer = read_answer(client)
    check(kinds(answer) == b"CZ" and answer[0][1] == b"ROLLBACK\0" and answer[1][1] == b"I", f"{answer}")
    client.close()
    upstream.finish()
    check(upstream.seen["queries"] == ["BEGIN; delete from users where id < 5 RETURNING *", "ROLLBACK"],
          f"the client's own rollback ended it: {upstream.seen['queries']}")
    check(sluice.wait_event("confirm")["outcome"] == "rolled_back", "logged")
    check(sluice.stop() == 0, "clean shutdown")

    # in the client's own transaction a savepoint is used, and the transaction goes on
    upstream, sluice, client = confirm_session(confirm_db(rows=3))
    client.sendall(q("begin"))
    read_answer(client)
    client.sendall(q("delete from users where id < 5"))
    answer = read_answer(client)
    check(kinds(answer) == b"EZ" and answer[1][1] == b"T", f"{answer}")
    client.sendall(q("y"))
    answer = read_answer(client)
    check(kinds(answer) == b"CZ" and answer[0][1] == b"DELETE 3\0" and answer[1][1] == b"T", f"{answer}")
    client.close()
    upstream.finish()
    check(upstream.seen["queries"][1].startswith("SAVEPOINT sluice_guard; ")
          and upstream.seen["queries"][2] == "RELEASE SAVEPOINT sluice_guard", f"{upstream.seen['queries']}")
    check(sluice.stop() == 0, "clean shutdown")

    # the person leaves without answering: nothing is committed
    upstream, sluice, client = confirm_session(confirm_db(rows=3))
    client.sendall(q("delete from users where id < 5"))
    read_answer(client)
    client.close()
    upstream.finish()
    check("COMMIT" not in upstream.seen["queries"], f"{upstream.seen['queries']}")
    check(sluice.stop() == 0, "clean shutdown")


POLICY_PLAIN = """
mode = "enforce"
confirm_timeout = "5s"

[[rule]]
name = "confirm-truncate"
match = "truncate"
action = "confirm"
message = "Not without the user."

[[rule]]
name = "confirm-drop"
match = "drop"
action = "confirm"
"""


def scenario_confirm_truncate_and_drop():
    """TRUNCATE and DROP (tables, views, indexes) are run as they are in a transaction, always asked about (there is no
    row count to measure them against), with the statement shown, in both protocols; DROP DATABASE cannot be undone
    and is refused with a reason."""
    upstream, sluice, client = confirm_session(confirm_db(rows=3), policy=POLICY_PLAIN)
    for sql, tag in (("truncate users", "TRUNCATE TABLE"), ("drop table users", "DROP TABLE")):
        client.sendall(q(sql))
        answer = read_answer(client)
        fields = error_fields(answer[0][1])
        check(kinds(answer) == b"EZ" and f"{tag} waiting for you" in fields["M"], f"{sql}: {fields}")
        check(sql in fields["D"] and "nothing to count" in fields["D"], f"the statement is the detail: {fields['D']!r}")
        check("Not without the user." in fields["H"] or tag == "DROP TABLE", f"the rule's message: {fields['H']!r}")
        client.sendall(q("yes"))
        answer = read_answer(client)
        check(kinds(answer) == b"CZ" and answer[0][1] == tag.encode() + b"\0", f"{sql}: {answer}")
    client.sendall(q("drop database users"))
    read_answer(client)  # (the fake does not make the failing message fail: what it was sent is what counts)
    client.sendall(q("select 1"))
    check(kinds(read_answer(client)) == b"CZ", "and the session goes on")
    client.close()
    upstream.finish()
    check(upstream.seen["queries"][:4] == ["BEGIN; truncate users", "COMMIT", "BEGIN; drop table users", "COMMIT"],
          f"run as written, nothing added: {upstream.seen['queries']}")
    refused = [x for x in upstream.seen["queries"] if "::int" in x]
    check(len(refused) == 1 and "one DELETE, UPDATE, TRUNCATE or DROP" in refused[0] and "drop database" not in refused[0],
          f"DROP DATABASE is replaced by a message that fails, with the reason: {refused}")
    check(sluice.stop() == 0, "clean shutdown")

    # prepared, with the row limit pgjdbc sends for everything
    upstream, sluice, client = ext_session(session=True, policy=POLICY_PLAIN)
    client.sendall(parse_msg(b"", "truncate users") + bind_msg() + execute_msg(b"", 1) + SYNC)
    answer = read_until_z(client)
    check(kinds(answer) == b"12EZ" and "TRUNCATE TABLE waiting for you" in error_fields(answer[2][1])["M"],
          f"{kinds(answer)}")
    client.sendall(parse_msg(b"", "yes") + bind_msg() + execute_msg() + SYNC)
    answer = read_until_z(client)
    check(kinds(answer) == b"12CZ" and answer[2][1] == b"TRUNCATE TABLE\0", f"{answer}")
    client.close()
    upstream.finish()
    check(upstream.seen["msgs"][0] == ("P", "truncate users"), f"not rewritten: {upstream.seen['msgs'][0]}")
    check(upstream.seen["commits"][0] == "commit", f"{upstream.seen['commits']}")
    check(sluice.stop() == 0, "clean shutdown")


POLICY_LIMIT = """
mode = "enforce"

[[rule]]
name = "cap"
match = "delete"
action = "limit"
max_rows = "2"
message = "Delete in smaller batches."
"""


def scenario_limit_without_asking():
    """action = "limit": nobody is asked. A DELETE or UPDATE that touches no more rows than the limit is committed as it
    runs; more than that is undone, and the client is told why, in both protocols."""
    upstream, sluice, client = confirm_session(confirm_db(rows=3), policy=POLICY_LIMIT)
    client.sendall(q("delete from users where id < 5"))
    answer = read_answer(client)
    fields = error_fields(answer[0][1])
    check(kinds(answer) == b"EZ" and answer[1][1] == b"I", f"{answer}")
    check("refused (rule cap)" in fields["M"] and "touched 3 rows, more than the limit of 2" in fields["M"]
          and "Delete in smaller batches." in fields["M"] and "Nothing was changed" in fields["M"], f"{fields}")
    client.sendall(q("select 1"))
    check(kinds(read_answer(client)) == b"CZ", "the session goes on")
    client.close()
    upstream.finish()
    check(upstream.seen["queries"][:2] == ["BEGIN; delete from users where id < 5 RETURNING *", "ROLLBACK"],
          f"{upstream.seen['queries']}")
    event = sluice.wait_event("confirm")
    check(event["outcome"] == "limit" and event["rows"] == 3, f"{event}")
    check(sluice.stop() == 0, "clean shutdown")

    # at the limit: committed, as if nothing had been there
    upstream, sluice, client = confirm_session(confirm_db(rows=2), policy=POLICY_LIMIT)
    client.sendall(q("delete from users where id < 5"))
    answer = read_answer(client)
    check(kinds(answer) == b"CZ" and answer[0][1] == b"DELETE 2\0", f"{answer}")
    client.close()
    upstream.finish()
    check(upstream.seen["queries"] == ["BEGIN; delete from users where id < 5 RETURNING *", "COMMIT"],
          f"{upstream.seen['queries']}")
    check(sluice.wait_event("confirm")["outcome"] == "auto", "logged")
    check(sluice.stop() == 0, "clean shutdown")

    # prepared
    upstream, sluice, client = ext_session(session=True, policy=POLICY_LIMIT, rows=3)
    client.sendall(parse_msg(b"", DELETE_SQL) + bind_msg() + describe_msg(b"P") + execute_msg(b"", 1) + SYNC)
    answer = read_until_z(client)
    check(kinds(answer) == b"12nEZ" and "more than the limit of 2" in error_fields(answer[3][1])["M"], f"{kinds(answer)}")
    client.close()
    upstream.finish()
    check(upstream.seen["commits"][0] == "rollback", f"{upstream.seen['commits']}")
    check(sluice.stop() == 0, "clean shutdown")

    # TRUNCATE has no rows to count: a limit cannot apply, and says so
    policy = POLICY_LIMIT.replace('match = "delete"', 'match = "truncate"')
    upstream, sluice, client = confirm_session(confirm_db(rows=3), policy=policy)
    client.sendall(q("truncate users"))
    read_answer(client)
    client.close()
    upstream.finish()
    refused = [x for x in upstream.seen["queries"] if "::int" in x]
    check(len(refused) == 1 and "a limit counts the rows" in refused[0], f"{refused}")
    check(sluice.stop() == 0, "clean shutdown")


def scenario_check_policy_command():
    """sluice --check-policy: what a policy does with statements, without a server."""
    policy = """
mode = "enforce"
[[rule]]
name = "no-ddl"
match = "ddl"
except_users = ["migrator"]
[[rule]]
name = "cap"
match = "delete"
action = "limit"
max_rows = "1000"
[[rule]]
name = "ask-update"
match = "update"
action = "confirm"
over_rows = "50"
"""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "p.toml")
        with open(path, "w") as f:
            f.write(policy)

        def run(*args):
            return subprocess.run([SLUICE, "--check-policy", path, *args], capture_output=True, text=True, timeout=TIMEOUT)

        r = run("--sql", "select 1")
        check(r.returncode == 0 and "valid. mode enforce, 3 rules" in r.stdout and "allowed" in r.stdout, f"{r}")
        r = run("--user", "agent", "--sql", "drop table t")
        check(r.returncode == 3 and "REFUSED: blocked by rule no-ddl" in r.stdout, f"a refusal is exit 3: {r}")
        r = run("--user", "migrator", "--sql", "drop table t")
        check(r.returncode == 0 and "allowed" in r.stdout, f"except_users: {r}")
        r = run("--sql", "update t set a = 1 where b = 2", "--sql", "delete from t where id = 1")
        check(r.returncode == 4 and "held for a confirmation above 50 rows" in r.stdout
              and "undone beyond" in r.stdout, f"held for an answer is exit 4: {r}")
        r = run("--sql", "update t set a = 1 where b = 2", "--sql", "drop table t")
        check(r.returncode == 3, f"a refusal wins over a question: {r.returncode}")
        r = run("--sql", "selec 1")
        check(r.returncode == 3 and "cannot be inspected" in r.stdout, f"{r}")
        with open(path, "w") as f:
            f.write(policy + "[[rule]]\nname = \"bad\"\nmatch = \"nonsense\"\n")
        r = run()
        check(r.returncode == 1 and "nonsense" in r.stderr, f"an invalid policy is exit 1: {r}")
        r = subprocess.run([SLUICE, "--check-policy"], capture_output=True, text=True, timeout=TIMEOUT)
        check(r.returncode == 2, f"missing file: {r.returncode}")


POLICY_RESULT = """
mode = "enforce"

[[rule]]
name = "cap-result"
match = "any"
action = "limit"
max_result_rows = "100"
"""


def many_rows_db(n=5000, width=20):
    """A fake database that answers 'select many' with n rows, and anything else with SELECT 1."""
    def script(conn, seen):
        status = [b"I"]
        seen["startup"] = read_startup(conn)
        conn.sendall(message(b"R", struct.pack("!I", 0)) + z(b"I"))
        while True:
            try:
                kind, payload = read_message(conn)
            except (EOFError, OSError):
                break
            if kind == b"X":
                break
            if kind != b"Q":
                continue
            if payload.startswith(b"select boom"):
                conn.sendall(error_msg("22012", "division by zero for secret-value-1234") + z(status[0]))
            elif payload.startswith(b"begin"):
                conn.sendall(cc("BEGIN") + z(b"T"))
                status[0] = b"T"
            elif payload.startswith(b"commit") or payload.startswith(b"rollback"):
                conn.sendall(cc("COMMIT") + z(b"I"))
                status[0] = b"I"
            elif payload.startswith(b"select many"):
                body = row_description(["v"]) + b"".join(data_row(["x" * width]) for _ in range(n))
                conn.sendall(body + cc(f"SELECT {n}") + z(status[0]))
            elif b"'::int" in payload:  # what a refused statement is replaced by: it fails, as in the database
                reason = payload.split(b"'", 1)[1].rsplit(b"'::int", 1)[0].replace(b"''", b"'").decode()
                conn.sendall(error_msg("22P02", f'invalid input syntax for type integer: "{reason}"') + z(status[0]))
            elif payload.startswith(b"update"):
                conn.sendall(cc("UPDATE 40") + z(status[0]))
            elif payload.startswith(b"insert"):
                conn.sendall(cc("INSERT 0 3") + z(status[0]))
            else:
                conn.sendall(cc("SELECT 1") + z(status[0]))
    return script


def read_result(client):
    """The messages of one answer, as (kind, payload), up to ReadyForQuery."""
    return read_answer(client)


def scenario_result_limits():
    """What one result, and a whole connection, may carry to the client: the rows over the limit are not sent, the end of
    the result is an error that says so, the next statement is fine; a connection that has spent its volume ends."""
    # rows
    upstream = FakeUpstream(many_rows_db(), tolerate=True)
    sluice = Sluice(upstream.port, policy=POLICY_RESULT)
    client = open_session(sluice, user="agent", database="mydb")
    client.sendall(q("select many"))
    answer = read_result(client)
    check(kinds(answer) == b"T" + b"D" * 100 + b"EZ", f"100 rows, then an error: {kinds(answer)[:5]}...{kinds(answer)[-4:]}")
    fields = error_fields(answer[-2][1])
    check(fields["C"] == "54000" and "result limit (rule cap-result)" in fields["M"] and "more than 100 rows" in fields["M"],
          f"{fields}")
    client.sendall(q("select 1"))
    check(kinds(read_answer(client)) == b"CZ", "the next statement is answered as usual")
    client.sendall(q("select many"))
    check(kinds(read_result(client)) == b"T" + b"D" * 100 + b"EZ", "and the limit applies again")
    client.close()
    upstream.finish()
    event = sluice.wait_event("limit")
    check(event["kind"] == "result_rows" and event["rule"] == "cap-result", f"{event}")
    check(sluice.stop() == 0, "clean shutdown")

    # exactly at the limit: nothing is cut
    upstream = FakeUpstream(many_rows_db(n=100), tolerate=True)
    sluice = Sluice(upstream.port, policy=POLICY_RESULT)
    client = open_session(sluice, user="agent", database="mydb")
    client.sendall(q("select many"))
    check(kinds(read_result(client)) == b"T" + b"D" * 100 + b"CZ", "100 rows are allowed")
    client.close()
    check(sluice.stop() == 0, "clean shutdown")

    # bytes of a result
    policy = POLICY_RESULT.replace('max_result_rows = "100"', 'max_result_bytes = "1K"')
    upstream = FakeUpstream(many_rows_db(width=20), tolerate=True)
    sluice = Sluice(upstream.port, policy=policy)
    client = open_session(sluice, user="agent", database="mydb")
    client.sendall(q("select many"))
    answer = read_result(client)
    rows = kinds(answer).count(b"D")
    # each row is 5 + 2 + 4 + 20 = 31 bytes: 1024 // 31 = 33 fit
    check(rows == 33 and kinds(answer)[-2:] == b"EZ" and "more than 1024 bytes" in error_fields(answer[-2][1])["M"],
          f"{rows} rows: {error_fields(answer[-2][1]) if kinds(answer)[-2:] == b'EZ' else kinds(answer)[-3:]}")
    client.close()
    check(sluice.stop() == 0, "clean shutdown")

    # the volume of the connection: the answer that crosses it is cut and the connection ends
    policy = POLICY_RESULT.replace('max_result_rows = "100"', 'max_total_bytes = "2K"')
    upstream = FakeUpstream(many_rows_db(n=40), tolerate=True)
    sluice = Sluice(upstream.port, policy=policy)
    client = open_session(sluice, user="agent", database="mydb")
    client.sendall(q("select many"))  # 40 rows of 31 bytes: 1240 bytes, under 2 K
    check(kinds(read_result(client))[-2:] == b"CZ", "the first fits")
    client.sendall(q("select many"))  # the second crosses it
    answer = read_result(client)
    fields = error_fields(answer[-2][1])
    check(kinds(answer)[-2:] == b"EZ" and fields["S"] == "FATAL" and "volume limit" in fields["M"], f"{fields}")
    check(at_eof(client), "and the connection is closed")
    check(sluice.wait_event("limit")["kind"] == "total_bytes", "logged")
    check(sluice.stop() == 0, "clean shutdown")

    # a connection without such a rule is not touched
    upstream = FakeUpstream(many_rows_db(n=300), tolerate=True)
    sluice = Sluice(upstream.port, policy=POLICY_RESULT.replace('match = "any"', 'match = "any"\nusers = ["someone-else"]'))
    client = open_session(sluice, user="agent", database="mydb")
    client.sendall(q("select many"))
    check(kinds(read_result(client)) == b"T" + b"D" * 300 + b"CZ", "the rule is for someone else")
    client.close()
    check(sluice.stop() == 0, "clean shutdown")


class CancelAwareUpstream:
    """A fake PostgreSQL that accepts several connections: a session whose 'slow' statement does not end until another
    connection brings a CancelRequest with the process and secret it gave."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.cancel = None
        self.cancelled = threading.Event()
        self.sock.settimeout(TIMEOUT)
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _handle(self, conn):
        conn.settimeout(TIMEOUT)
        try:
            head = recv_exact(conn, 8)
            length, code = struct.unpack("!II", head)
            if code == 80877102:
                rest = recv_exact(conn, length - 8)
                self.cancel = struct.unpack("!II", rest)
                self.cancelled.set()
                return
            recv_exact(conn, length - 8)
            conn.sendall(message(b"R", struct.pack("!I", 0)) + message(b"K", struct.pack("!II", 4242, 0xDEADBEEF)) + z(b"I"))
            while True:
                kind, payload = read_message(conn)
                if kind == b"X":
                    break
                if payload.startswith(b"select slow"):
                    if self.cancelled.wait(15):
                        conn.sendall(error_msg("57014", "canceling statement due to user request") + z(b"I"))
                else:
                    conn.sendall(cc("SELECT 1") + z(b"I"))
        except (EOFError, OSError):
            pass
        finally:
            conn.close()

    def _run(self):
        try:
            while True:
                conn, _ = self.sock.accept()
                threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
        except OSError:
            pass

    def close(self):
        self.sock.close()


POLICY_BUDGET = """
mode = "enforce"

[[rule]]
name = "reads"
match = "any"
action = "limit"
users = ["agent"]
budget_rows = "250"
window = "1h"
"""


def scenario_budgets():
    """What a user may carry out of the database, or change in it, over a window of time, whatever the number of
    connections: the rows over the budget are not sent (the result ends with an error that says when to come back),
    writes are refused once the rows changed have used it up, and another user is not touched."""
    upstream = FakeUpstream(many_rows_db(n=100), tolerate=True, connections=3)
    sluice = Sluice(upstream.port, policy=POLICY_BUDGET)
    client = open_session(sluice, user="agent", database="mydb")
    for _ in range(2):
        client.sendall(q("select many"))
        check(kinds(read_result(client)) == b"T" + b"D" * 100 + b"CZ", "within the budget")
    client.sendall(q("select many"))  # 200 used, 50 left
    answer = read_result(client)
    check(kinds(answer) == b"T" + b"D" * 50 + b"EZ", f"cut at the budget: {kinds(answer)[:3]}...{kinds(answer)[-3:]}")
    fields = error_fields(answer[-2][1])
    check(fields["C"] == "53400" and "budget (rule reads)" in fields["M"] and "250 rows in 1h" in fields["M"]
          and "more is possible in about" in fields["M"], f"{fields}")
    client.sendall(q("select many"))
    check(kinds(read_result(client)) == b"TEZ", "spent: no row at all")
    client.sendall(q("select 1"))
    check(kinds(read_answer(client)) == b"CZ", "a statement that returns no row still works")
    # a new connection is the same user: it shares the budget
    second = open_session(sluice, user="agent", database="mydb")
    second.sendall(q("select many"))
    check(kinds(read_result(second)) == b"TEZ", "another connection of the same user is just as spent")
    second.close()
    # and another user has none to spend
    other = open_session(sluice, user="someone", database="mydb")
    other.sendall(q("select many"))
    check(kinds(read_result(other)) == b"T" + b"D" * 100 + b"CZ", "another user is not touched")
    other.close()
    client.close()
    upstream.finish()
    sluice.wait_event("limit")
    events = [e for e in sluice.events if e["event"] == "limit"]
    check(events and events[0]["kind"] == "budget_rows" and events[0]["rule"] == "reads", f"{events}")
    check(sluice.stop() == 0, "clean shutdown")

    # bytes: rows of 31 bytes, 1 K of budget: 33 rows
    policy = POLICY_BUDGET.replace('budget_rows = "250"', 'budget_bytes = "1K"')
    upstream = FakeUpstream(many_rows_db(n=100), tolerate=True)
    sluice = Sluice(upstream.port, policy=policy)
    client = open_session(sluice, user="agent", database="mydb")
    client.sendall(q("select many"))
    answer = read_result(client)
    check(kinds(answer).count(b"D") == 33 and kinds(answer)[-2:] == b"EZ"
          and "1024 bytes in 1h" in error_fields(answer[-2][1])["M"], f"{kinds(answer)[-3:]}")
    client.close()
    check(sluice.stop() == 0, "clean shutdown")

    # rows changed: counted from what the database says, enforced on the next write
    policy = POLICY_BUDGET.replace('budget_rows = "250"', 'budget_changed = "100"')
    upstream = FakeUpstream(many_rows_db(n=3), tolerate=True, connections=2)
    sluice = Sluice(upstream.port, policy=policy)
    client = open_session(sluice, user="agent", database="mydb")
    for i in range(3):  # 40, 80, 120: the third starts under the budget and ends over it
        client.sendall(q("update t set a = 1"))
        check(kinds(read_answer(client)) == b"CZ", f"write {i} goes through")
    client.sendall(q("update t set a = 1"))
    answer = read_answer(client)
    fields = error_fields(answer[0][1])
    check(kinds(answer) == b"EZ" and "budget of changed rows used up (rule reads: 100 rows in 1h)" in fields["M"],
          f"{fields}")
    client.sendall(q("insert into t values (1)"))
    check(kinds(read_answer(client)) == b"EZ", "an INSERT is a write")
    client.sendall(q("select many"))
    check(kinds(read_result(client)) == b"T" + b"D" * 3 + b"CZ", "reading is not affected")
    second = open_session(sluice, user="agent", database="mydb")
    second.sendall(q("insert into t values (1)"))
    check(kinds(read_answer(second)) == b"EZ", "the budget is the user's, not the connection's")
    second.close()
    client.close()
    upstream.finish()
    check(sluice.stop() == 0, "clean shutdown")

    # a statement that was confirmed counts as well
    policy = POLICY_CONFIRM + """
[[rule]]
name = "writes"
match = "any"
action = "limit"
budget_changed = "5"
"""
    upstream, sluice, client = confirm_session(confirm_db(rows=3), policy=policy)
    for i in range(2):
        client.sendall(q("delete from users where id < 5"))
        read_answer(client)
        client.sendall(q("yes;"))
        check(kinds(read_answer(client)) == b"CZ", f"confirmed delete {i}")
    client.sendall(q("delete from users where id < 5"))  # 6 rows changed, over 5
    read_answer(client)  # (the fake database does not fail a refused statement with its text)
    client.close()
    refused = [e for e in sluice.events if e["event"] == "statement" and e.get("action") == "blocked"]
    check(len(refused) == 1 and refused[0]["rule"] == "writes", f"the third DELETE is refused: {refused}")
    check(sluice.stop() == 0, "clean shutdown")


def scenario_confirm_via():
    """A rule can say who is asked: the person who sent the statement (session) or the operator of the proxy (its
    terminal or its command). What a rule does not say follows what the operator chose with --confirm-command."""
    policy = POLICY_CONFIRM.replace('over_rows = "1"\n', 'over_rows = "1"\nconfirm_via = "session"\n')
    with tempfile.TemporaryDirectory() as d:
        asked = os.path.join(d, "asked")
        script = os.path.join(d, "approver.sh")
        with open(script, "w") as f:
            f.write(f"#!/bin/sh\ncat > {asked}\ntrue\n")
        os.chmod(script, 0o755)
        # the DELETE rule is asked in the session although a command is set; the UPDATE rule goes to the command
        upstream, sluice, client = confirm_session(confirm_db(rows=3), policy=policy,
                                                   extra=["--confirm-command", script])
        client.sendall(q("delete from users where id < 5"))
        answer = read_answer(client)
        check(kinds(answer) == b"EZ" and answer[1][1] == b"T" and "waiting for you" in error_fields(answer[0][1])["M"],
              f"asked in the session: {answer}")
        check(not os.path.exists(asked), "the command was not asked")
        client.sendall(q("yes;"))
        check(kinds(read_answer(client)) == b"CZ", "answered in the session")
        client.sendall(q("update users set plan = 'free'"))
        check(kinds(read_answer(client)) == b"CZ", "the command approved the UPDATE")
        check("changed 3 rows" in open(asked).read(), "and it was the command that was asked")
        client.close()
        upstream.finish()
        channels = [e["channel"] for e in sluice.events if e["event"] == "confirm"]
        check(channels == ["session", "command"], f"{channels}")
        check(sluice.stop() == 0, "clean shutdown")

    # the other way round: the operator's terminal for the rule that says so, the session for the rest
    tty = Tty()
    try:
        policy = POLICY_CONFIRM.replace('side_effects = "off"\nmessage', 'side_effects = "off"\nconfirm_via = "operator"\nmessage')
        upstream, sluice, client = confirm_session(confirm_db(rows=3), policy=policy, tty=tty)
        client.sendall(q("delete from users where id < 5"))
        tty.wait_for("commit? [y/N]")
        tty.answer("y\n")
        check(kinds(read_answer(client)) == b"CZ", "the operator answered the DELETE")
        client.close()
        upstream.finish()
        check(sluice.wait_event("confirm")["channel"] == "terminal", "logged")
        check(sluice.stop() == 0, "clean shutdown")
    finally:
        tty.close()


def scenario_budgets_survive_a_reload():
    """The names of the rules that gave the limits are copied: a reload of the policy frees the old rules while a
    connection that lives on still reports them."""
    upstream = FakeUpstream(many_rows_db(n=100), tolerate=True)
    sluice = Sluice(upstream.port, policy=POLICY_BUDGET)
    client = open_session(sluice, user="agent", database="mydb")
    client.sendall(q("select many"))
    read_result(client)
    with open(sluice.policy_path, "w") as f:
        f.write('mode = "enforce"\n')
    sluice.proc.send_signal(signal.SIGHUP)
    sluice.wait_event("policy_reloaded")
    client.sendall(q("select many"))
    read_result(client)
    client.sendall(q("select many"))
    answer = read_result(client)
    check(kinds(answer)[-2:] == b"EZ" and "rule reads" in error_fields(answer[-2][1])["M"], "still named")
    client.close()
    check(sluice.stop() == 0, "clean shutdown")


POLICY_MASK = """
mode = "enforce"

[[rule]]
name = "pii"
match = "any"
action = "mask"
users = ["agent"]
columns = ["email"]
detect = ["email", "card", "iban"]
how = "redact"
"""

PEOPLE = [
    ["1", "ana@example.com", "call bob@example.org tomorrow", "Ana"],
    ["2", "carl@example.com", "card 4111 1111 1111 1111 on file", "Carl"],
    ["3", None, "nothing here", "Dora"],
]


CATALOG = [("16385", "public", "users"), ("16390", "public", "orders"), ("16400", "billing", "invoices")]


def mask_db(rows=PEOPLE, big=0, catalog=None):
    """A fake PostgreSQL for results that are to be hidden. 'select people' (and a prepared statement whose text
    has 'people') returns the rows; 'select err' fails with a quoted key; 'copy' sends COPY data; 'select big'
    sends one row of `big` bytes; 'update' has no result. Extended messages are answered as the server does, and
    seen["msgs"] records what it received."""
    columns = ["id", "email", "note", "name"]
    types = [23, 25, 25, 1043]

    def people(formats=None, text=""):
        # with a catalog the columns say which table they come from: 'orders' is 16390, the rest 16385
        table = (16390 if "orders" in text else 16385) if catalog else 0
        return row_description(columns, types, formats, [table] * len(columns))

    def script(conn, seen):
        seen["msgs"] = []
        seen["startup"] = read_startup(conn)
        seen.setdefault("startups", []).append(seen["startup"])
        conn.sendall(message(b"R", struct.pack("!I", 0)) + z(b"I"))
        stmts, portals = {}, {}
        out = b""
        skipping = False

        def flush():
            nonlocal out
            if out:
                conn.sendall(out)
                out = b""

        while True:
            try:
                kind, payload = read_message(conn)
            except (EOFError, OSError):
                break
            if kind == b"X":
                break
            text = ""
            if kind == b"Q":
                text = payload[:-1].decode()
            elif kind == b"P":
                text = payload.split(b"\0")[1].decode()
            seen["msgs"].append((kind.decode(), text if kind in (b"Q", b"P") else payload[:12].decode("latin1")))
            if kind == b"Q":
                if "pg_catalog.pg_class" in text:
                    seen["catalog_asked"] = seen.get("catalog_asked", 0) + 1
                    if catalog == "error":
                        out += error_msg("42501", "permission denied for table pg_class") + z(b"I")
                    else:
                        out += (row_description(["oid", "nspname", "relname"]) + b"".join(data_row(list(r)) for r in CATALOG)
                                + cc(f"SELECT {len(CATALOG)}") + z(b"I"))
                elif text.startswith("select people"):
                    out += people(None, text) + b"".join(data_row(r) for r in rows) + cc(f"SELECT {len(rows)}") + z(b"I")
                elif "'::int" in text:  # a refused statement: the reason is in the error, as with the real server
                    reason = text.split("'", 1)[1].rsplit("'::int", 1)[0].replace("''", "'")
                    out += error_msg("22P02", f'invalid input syntax for type integer: "{reason}"') + z(b"I")
                elif text.startswith("select err"):
                    out += message(b"E", b"SERROR\0VERROR\0C23505\0Mduplicate key value violates unique constraint "
                                   b"\"users_email_key\"\0DKey (email)=(ana@example.com) already exists.\0\0") + z(b"I")
                elif text.startswith("select big"):
                    out += (row_description(["blob"]) + message(b"D", struct.pack("!HI", 1, big) + b"x" * big)
                            + cc("SELECT 1") + z(b"I"))
                elif text.startswith("copy"):
                    out += (message(b"H", b"\0\0\1\0\0") + message(b"d", b"1\tana@example.com\n")
                            + message(b"c") + cc("COPY 1") + z(b"I"))
                else:
                    out += cc("SELECT 0") + z(b"I")
                flush()
                continue
            if kind == b"H":
                flush()
                continue
            if kind == b"S":
                out += z(b"I")
                flush()
                skipping = False
                continue
            if skipping:
                continue
            if kind == b"P":
                name = payload.split(b"\0")[0]
                if "boom" in text or "'::int" in text:
                    out += error_msg("42601", "syntax error")
                    flush()
                    skipping = True
                    continue
                stmts[name] = text
                out += message(b"1")
            elif kind == b"B":
                parts = payload.split(b"\0", 2)
                portal, stmt = parts[0], parts[1]
                rest = parts[2]
                nfmt = struct.unpack("!H", rest[:2])[0]
                skip = 2 + 2 * nfmt
                nparams = struct.unpack("!H", rest[skip:skip + 2])[0]
                assert nparams == 0
                rfmt = struct.unpack("!H", rest[skip + 2:skip + 4])[0]
                binary = rfmt >= 1 and struct.unpack("!H", rest[skip + 4:skip + 6])[0] == 1
                portals[portal] = (stmts.get(stmt, ""), binary)
                out += message(b"2")
            elif kind == b"D":
                what, name = payload[:1], payload[1:-1]
                sql, binary = portals.get(name, ("", False)) if what == b"P" else (stmts.get(name, ""), False)
                if what == b"S":
                    out += message(b"t", struct.pack("!H", 0))
                if "people" in sql:
                    out += people([1 if binary else 0] * 4)
                else:
                    out += message(b"n")
            elif kind == b"E":
                name = payload.split(b"\0")[0]
                sql, binary = portals.get(name, ("", False))
                if "people" in sql:
                    out += b"".join(data_row(r) for r in rows) + cc(f"SELECT {len(rows)}")
                else:
                    out += cc("UPDATE 1")
        conn.sendall(out)
    return script


def mask_session(policy=POLICY_MASK, user="agent", rows=PEOPLE, big=0, extra=(), connections=1, catalog=None):
    upstream = FakeUpstream(mask_db(rows=rows, big=big, catalog=catalog), tolerate=True, connections=connections)
    sluice = Sluice(upstream.port, policy=policy, extra_args=list(extra))
    client = open_session(sluice, user=user, database="mydb")
    return upstream, sluice, client


def row_values(message_payload):
    """The text values of a DataRow payload (None for NULL)."""
    count = struct.unpack("!H", message_payload[:2])[0]
    pos, out = 2, []
    for _ in range(count):
        n = struct.unpack("!i", message_payload[pos:pos + 4])[0]
        pos += 4
        if n < 0:
            out.append(None)
        else:
            out.append(message_payload[pos:pos + n].decode())
            pos += n
    return out


def rows_of(answer):
    return [row_values(p) for k, p in answer if k == b"D"]


def scenario_masking_simple_protocol():
    """Values are hidden in the rows an agent reads (by the name of the column and by the look of the value), the
    description is untouched, errors and notices that quote values are scrubbed, COPY and rows that cannot be read
    are refused, and another user's rows are as they are."""
    upstream, sluice, client = mask_session(connections=1)
    client.sendall(q("select people"))
    answer = read_answer(client)
    check(kinds(answer) == b"TDDDCZ", f"the same messages: {kinds(answer)}")
    rows = rows_of(answer)
    check(rows[0] == ["1", "[masked]", "call [masked] tomorrow", "Ana"], f"{rows[0]}")
    check(rows[1] == ["2", "[masked]", "card [masked] on file", "Carl"], f"{rows[1]}")
    check(rows[2] == ["3", None, "nothing here", "Dora"], f"a NULL is a NULL, and nothing is changed where nothing is hidden: {rows[2]}")
    check(answer[0][1] == row_description(["id", "email", "note", "name"], [23, 25, 25, 1043])[5:],
          "the description is the server's own")
    check(answer[-2][1] == b"SELECT 3\0", "and the tag")

    client.sendall(q("select err"))
    answer = read_answer(client)
    fields = error_fields(answer[0][1])
    check(kinds(answer) == b"EZ" and "ana@example.com" not in repr(answer) and "Key (email)=([masked]) already exists" in fields["D"]
          and fields["C"] == "23505", f"the error quotes no value: {fields}")

    client.sendall(q("copy people to stdout"))
    answer = read_answer(client)
    check(b"d" not in kinds(answer) and kinds(answer)[-2:] == b"EZ" and "COPY" in error_fields(answer[-2][1])["M"]
          and "ana@example.com" not in repr(answer), f"COPY data is not given: {kinds(answer)}")
    client.sendall(q("select 1"))
    check(kinds(read_answer(client))[-1:] == b"Z", "and the session goes on")
    client.close()
    upstream.finish()
    close = sluice.wait_event("connection_close")
    check(close["masked"] == 5, f"counted in the log: {close}")
    check("ana@example.com" not in sluice.raw_text(), "no value in the log")
    check(sluice.stop() == 0, "clean shutdown")

    # a row too large to be read is not sent, and says why; the next one is fine
    upstream, sluice, client = mask_session(big=2 * 1024 * 1024)
    client.sendall(q("select big"))
    answer = read_answer(client)
    check(b"D" not in kinds(answer) and kinds(answer)[-2:] == b"EZ" and "could not be read" in error_fields(answer[-2][1])["M"],
          f"{kinds(answer)}")
    client.sendall(q("select people"))
    check(rows_of(read_answer(client))[0][1] == "[masked]", "and the next result is masked")
    client.close()
    check(sluice.stop() == 0, "clean shutdown")

    # another user reads what is there
    upstream, sluice, client = mask_session(user="someone")
    client.sendall(q("select people"))
    rows = rows_of(read_answer(client))
    check(rows[0][1] == "ana@example.com" and rows[0][2] == "call bob@example.org tomorrow", f"{rows[0]}")
    client.close()
    check(sluice.stop() == 0, "clean shutdown")


POLICY_GUARDS = """
mode = "enforce"

[[rule]]
name = "no-escalation"
match = "set_session"
users = ["agent"]
message = "the role stays"

[[rule]]
name = "no-danger"
match = "dangerous"
action = "kill"

[[rule]]
name = "honey"
match = "any"
action = "alert"
tables = ["honeypot"]
"""


def scenario_session_and_dangerous_guards():
    """SET ROLE and set_config() are refused for the user a rule names; a dangerous function or a COPY to a
    program refuses the statement AND ends the connection (what was already sent after it is refused too); an alert
    rule lets the statement through and writes an `alert` event of its own."""
    upstream, sluice, client = mask_session(policy=POLICY_GUARDS, user="agent")
    client.sendall(q("set role admin"))
    answer = read_answer(client)
    check(b"E" in kinds(answer) and "role stays" in repr(answer) or "no-escalation" in repr(answer), f"{answer}")
    client.sendall(q("select set_config('role', 'admin', false)"))
    check(b"E" in kinds(read_answer(client)), "the function that sets the session too")
    client.sendall(q("select people"))
    check(kinds(read_answer(client)) == b"TDDDCZ", "an ordinary statement goes through")
    client.sendall(q("set time zone 'UTC'"))
    check(b"E" not in kinds(read_answer(client)), "and a harmless SET")

    # an alert: the statement runs, the log says so
    client.sendall(q("select people from honeypot"))
    check(kinds(read_answer(client)) == b"TDDDCZ", "an alert does not refuse")
    alert = sluice.wait_event("alert")
    check(alert["rule"] == "honey" and alert["user"] == "agent" and alert["action"] == "relayed"
          and "honeypot" in alert["tables"], f"{alert}")

    # kill: refused with the reason, then nothing more, then the connection ends. A second statement sent
    # right behind the first is refused as well (it never reaches the server).
    client.sendall(q("select pg_read_file('/etc/passwd')") + q("select people"))
    data = b""
    client.settimeout(5)
    try:
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            data += chunk
    except OSError:
        pass
    check(b"no-danger" in data and b"this connection is closed" in data, f"the reason is given: {data[:200]}")
    check(data.count(b"Z") >= 1 and b"ana@example.com" not in data, "and the second statement got nothing")
    client.close()
    upstream.finish()
    seen = [t for k, t in upstream.seen["msgs"] if k == "Q"]
    check("select people" not in seen[-1:] and not any("pg_read_file" in t for t in seen if not t.startswith("sluice")),
          f"neither reached the server as written: {seen}")
    sluice.wait_event("statement", kill=True)  # logged as a kill
    check(sluice.wait_event("connection_close")["reason"] == "killed", "the connection ended because of it")
    check(sluice.stop() == 0, "clean shutdown")


def verify_log(path, key):
    return subprocess.run([SLUICE, "--verify-log", path, "--log-chain-key-file", key], capture_output=True,
                          text=True, timeout=TIMEOUT)


def startup_params(packet):
    """{key: value} of a StartupMessage as the upstream received it (length and version cut off)."""
    parts = packet[8:].split(b"\0")
    return {parts[i].decode(): parts[i + 1].decode() for i in range(0, len(parts) - 2, 2)}


def scenario_application_name_is_tagged():
    """With --tag-application-name on, the database sees the client's application_name followed by the id the
    connection has in sluice's log; nothing else of the startup packet changes; off, it is left alone."""
    for mode in ("on", "off"):
        upstream = FakeUpstream(mask_db(), tolerate=True)
        sluice = Sluice(upstream.port, policy='mode = "audit"\n', extra_args=["--tag-application-name", mode])
        client = open_session(sluice, user="agent", database="mydb", application_name="my agent", options="-c x=1")
        client.sendall(q("select 1"))
        read_answer(client)
        client.close()
        upstream.finish()
        opened = sluice.wait_event("connection_open")
        got = startup_params(upstream.seen["startup"])
        if mode == "on":
            check(got["application_name"] == f"my agent [sluice {opened['id']}]" and got["user"] == "agent"
                  and got["database"] == "mydb" and got["options"] == "-c x=1", f"{got}")
        else:
            check(got["application_name"] == "my agent", f"{got}")
        check(sluice.stop() == 0, "clean shutdown")
    # no name at all, and a very long one: the tag stays whole, inside the 63 bytes the server keeps
    upstream = FakeUpstream(mask_db(), tolerate=True, connections=2)
    sluice = Sluice(upstream.port, policy='mode = "audit"\n', extra_args=["--tag-application-name", "on"])
    client = open_session(sluice, user="agent", database="mydb")
    client.close()
    long_client = open_session(sluice, user="agent", database="mydb", application_name="é" * 60)
    long_client.close()
    upstream.finish()
    names = [startup_params(x)["application_name"] for x in upstream.seen["startups"]]
    check(names[0].startswith(" [sluice ") or names[0].startswith("[sluice ") or "[sluice " in names[0], f"{names}")
    check(all(len(n.encode()) <= 63 and n.endswith("]") and "[sluice " in n for n in names) and "\ufffd" not in names[1],
          f"{names}")
    check(sluice.stop() == 0, "clean shutdown")


def scenario_round_trip_budget_and_transaction_limit():
    """budget_statements counts round trips (a Query, or the Sync of a prepared statement's cycle) per user, across
    connections: the one that spends it is ended with its answer, and a new statement is refused while it is spent.
    max_transaction ends a connection whose transaction has been open too long, between two statements."""
    policy = POLICY_BUDGET.replace('budget_rows = "250"', 'budget_statements = "4"')
    upstream = FakeUpstream(many_rows_db(n=1), tolerate=True, connections=2)
    sluice = Sluice(upstream.port, policy=policy)
    client = open_session(sluice, user="agent", database="mydb")
    for i in range(3):
        client.sendall(q("select 1"))
        check(kinds(read_answer(client)) == b"CZ", f"round trip {i + 1} of 4")
    client.sendall(q("select 1"))
    check(kinds(read_answer(client)) == b"CZ", "the fourth is answered")
    client.settimeout(5)
    check(client.recv(1) == b"", "and the connection ends with it")
    client.close()
    second = open_session(sluice, user="agent", database="mydb")
    second.sendall(q("select 1"))
    answer = read_answer(second)
    check(b"E" in kinds(answer) and "round trips used up" in repr(answer) and "rule reads" in repr(answer),
          f"a new connection of the same user is refused: {answer}")
    second.close()
    upstream.finish()
    sluice.wait_event("limit", kind="statement_budget")  # logged
    check(sluice.stop() == 0, "clean shutdown")

    policy = POLICY_BUDGET.replace('budget_rows = "250"', 'max_transaction = "1s"').replace('window = "1h"\n', "")
    upstream = FakeUpstream(many_rows_db(n=1), tolerate=True, connections=2)
    sluice = Sluice(upstream.port, policy=policy)
    client = open_session(sluice, user="agent", database="mydb")
    client.sendall(q("begin"))
    check(kinds(read_answer(client)) == b"CZ", "a transaction is open")
    time.sleep(1.6)
    client.settimeout(5)
    data = b""
    while True:
        chunk = client.recv(4096)
        if not chunk:
            break
        data += chunk
    check(b"25P03" in data and b"more than 1s" in data and b"rule reads" in data, f"{data[:150]}")
    client.close()
    # a transaction that ends in time is left alone
    other = open_session(sluice, user="agent", database="mydb")
    other.sendall(q("begin"))
    read_answer(other)
    other.sendall(q("commit"))
    read_answer(other)
    time.sleep(1.6)
    other.sendall(q("select 1"))
    check(kinds(read_answer(other)) == b"CZ", "no transaction, no limit")
    other.close()
    upstream.finish()
    sluice.wait_event("limit", kind="transaction")  # logged
    check(sluice.stop() == 0, "clean shutdown")


def scenario_learn_and_policy_tests():
    """A session in audit mode, `sluice --learn` turns its log into a rule that lets those shapes through (values
    do not matter) and refuses the others, and `--test-policy` checks it, including a rule that is only being tried
    and a rule that applies only at some hours."""
    with tempfile.TemporaryDirectory() as d:
        upstream, sluice, client = mask_session(policy='mode = "audit"\n', user="agent", extra=["--log-sql", "full"])
        client.sendall(q("select people from t where id = 41 and note = 'secret-value'"))
        read_answer(client)
        client.sendall(q("select 1"))
        read_answer(client)
        client.sendall(q("select people from t where id = 7 and note = 'another'"))  # the same shape as the first
        read_answer(client)
        client.close()
        upstream.finish()
        sluice.wait_event("connection_close")
        check(sluice.stop() == 0, "clean shutdown")
        log = os.path.join(d, "audit.log")
        open(log, "w").write(sluice.raw_text())
        out = subprocess.run([SLUICE, "--learn", log, "--user", "agent"], capture_output=True, text=True, timeout=TIMEOUT)
        check(out.returncode == 0 and "outside_fingerprints" in out.stdout and "secret-value" not in out.stdout
              and "another" not in out.stdout and "2 shapes in 3 statements" in out.stdout and "3x" not in out.stdout
              and "2x" in out.stdout and "id = $1" in out.stdout, f"{out.stdout} {out.stderr}")
        check(subprocess.run([SLUICE, "--learn", log, "--user", "nobody"], capture_output=True, text=True,
                             timeout=TIMEOUT).returncode == 1, "nothing learned for somebody else")
        policy = os.path.join(d, "learned.toml")
        open(policy, "w").write('mode = "enforce"\n' + out.stdout)
        tests = os.path.join(d, "learned.tests")
        open(tests, "w").write(
            "as agent\n"
            "allow :: select 1\n"
            "allow :: select people from t where id = 999 and note = 'new values, same shape'\n"
            "deny unknown-shapes :: select people from t where id = 1 or note = 'x'\n"
            "deny unknown-shapes :: drop table t\n")
        run = subprocess.run([SLUICE, "--test-policy", policy, tests], capture_output=True, text=True, timeout=TIMEOUT)
        check(run.returncode == 0 and "4 tests, 0 failed" in run.stdout, f"{run.stdout} {run.stderr}")
        # and the other way: a wrong expectation is reported with its line and exits 1
        open(tests, "w").write("as agent\nallow :: drop table t\ndeny nope :: select 1\n")
        run = subprocess.run([SLUICE, "--test-policy", policy, tests], capture_output=True, text=True, timeout=TIMEOUT)
        check(run.returncode == 1 and run.stdout.count("FAIL") == 2 and "2 failed" in run.stdout and ":2:" in run.stdout,
              f"{run.stdout}")


def http(port, method, path, token=None, timeout=5):
    """(status, body) of one request to the admin listener."""
    import http.client
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    conn.request(method, path, headers=headers)
    response = conn.getresponse()
    body = response.read().decode()
    conn.close()
    return response.status, body


def metric(text, name, **labels):
    """The value of one series in a Prometheus text, or None."""
    want = ",".join(f'{k}="{v}"' for k, v in labels.items())
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        series, _, value = line.rpartition(" ")
        if (want and series == f"{name}{{{want}}}") or (not want and series == name):
            return int(value)
    return None


def scenario_admin_metrics():
    """--admin serves the counters in the Prometheus format: /healthz open, the rest behind the token; what was
    judged, blocked, held and closed shows in them, and the gauges follow the connections."""
    with tempfile.TemporaryDirectory() as d:
        tokfile = os.path.join(d, "admin.token")
        token = "admin-token-" + os.urandom(8).hex()
        open(tokfile, "w").write(token + "\n")  # a newline at the end is not part of it
        upstream, sluice, client = mask_session(policy=POLICY_GUARDS, user="agent",
                                                extra=["--admin", "127.0.0.1:0", "--admin-token-file", tokfile])
        port = sluice.wait_event("admin_listening")["port"]
        client.sendall(q("select people"))
        read_answer(client)
        client.sendall(q("set role admin"))  # refused by no-escalation
        read_answer(client)
        client.sendall(q("select people from honeypot"))  # an alert
        read_answer(client)
        check(http(port, "GET", "/healthz") == (200, "ok\n"), "healthz needs no token")
        check(http(port, "GET", "/metrics")[0] == 401 and http(port, "GET", "/metrics", token="wrong")[0] == 401,
              "the counters need the token")
        status, text = http(port, "GET", "/metrics", token=token)
        check(status == 200 and metric(text, "sluice_connections_total") == 1
              and metric(text, "sluice_connections_active") == 1
              and metric(text, "sluice_statements_total", verdict="allow", action="relayed") == 2
              and metric(text, "sluice_statements_total", verdict="deny", action="blocked") == 1
              and metric(text, "sluice_rule_hits_total", rule="no-escalation", verdict="deny") == 1
              and metric(text, "sluice_log_events_total", event="alert") == 1
              and metric(text, "sluice_policy_rules") == 3 and metric(text, "sluice_pending_confirmations") == 0
              and metric(text, "sluice_admin_requests_total", path="/metrics", status="401") == 2,
              f"{text}")
        check("# TYPE sluice_statements_total counter" in text and 'sluice_build_info{version="' in text, "typed")
        client.close()
        upstream.finish()
        sluice.wait_event("connection_close")
        status, text = http(port, "GET", "/metrics", token=token)
        check(metric(text, "sluice_connections_closed_total", reason="client_closed") == 1
              and metric(text, "sluice_connections_active") == 0
              and (metric(text, "sluice_bytes_total", direction="client_to_upstream") or 0) > 0, f"{text}")
        check(sluice.wait_event("admin_denied", method="GET")["path"] == "/metrics", "refusals are in the log")
        check(sluice.stop() == 0, "clean shutdown")
        # beyond this machine, or for confirmations, a token is not optional
        for args in (["--admin", "0.0.0.0:0"], ["--admin", "127.0.0.1:0", "--confirm-admin", "on"],
                     ["--admin-token-file", tokfile], ["--confirm-admin", "on"], ["--event-filter", "alert"]):
            run = subprocess.run([SLUICE, "--listen", "127.0.0.1:0", "--upstream", "127.0.0.1:1", *args],
                                 capture_output=True, text=True, timeout=TIMEOUT)
            check(run.returncode == 2 and "admin" in run.stderr.lower() or "event-filter" in run.stderr, f"{args}: {run.stderr}")
        short = os.path.join(d, "short")
        open(short, "w").write("tiny")
        run = subprocess.run([SLUICE, "--listen", "127.0.0.1:0", "--upstream", "127.0.0.1:1", "--admin", "127.0.0.1:0",
                              "--admin-token-file", short], capture_output=True, text=True, timeout=TIMEOUT)
        check(run.returncode == 1 and "16 to 1024" in run.stderr, f"{run.returncode} {run.stderr}")


def scenario_confirm_by_admin_and_event_command():
    """--confirm-admin: nobody is asked at a terminal or in the session; the statement waits, `confirm_pending` goes
    to the event command (with the id, never the rows), the question is fetched and answered over HTTP with the
    token, and a GET cannot answer."""
    with tempfile.TemporaryDirectory() as d:
        tokfile = os.path.join(d, "admin.token")
        token = "admin-token-" + os.urandom(8).hex()
        open(tokfile, "w").write(token)
        sink = os.path.join(d, "hook.out")
        command = f'{{ echo "$SLUICE_EVENT"; cat; }} >> {sink}'
        upstream, sluice, client = confirm_session(
            confirm_db(rows=3), policy=POLICY_CONFIRM,
            extra=["--admin", "127.0.0.1:0", "--admin-token-file", tokfile, "--confirm-admin", "on",
                   "--event-command", command, "--event-filter", "confirm_pending,confirm"])
        port = sluice.wait_event("admin_listening")["port"]
        client.sendall(q("delete from users where id < 5"))
        pending = sluice.wait_event("confirm_pending")
        check(pending["rule"] == "confirm-deletes" and pending["rows"] == 3 and pending["tag"] == "DELETE 3"
              and len(pending["question"]) == 16 and "ana@example.com" not in repr(pending), f"{pending}")
        qid = pending["question"]
        status, body = http(port, "GET", "/pending", token=token)
        listed = json.loads(body)
        check(status == 200 and len(listed) == 1 and listed[0]["id"] == qid and listed[0]["rule"] == "confirm-deletes"
              and listed[0]["rows"] == 3 and listed[0]["user"] == "agent", f"{body}")
        status, text = http(port, "GET", f"/pending/{qid}", token=token)
        check(status == 200 and "ana@example.com" in text, f"the question holds the rows: {text}")
        check(http(port, "GET", "/pending")[0] == 401, "and it needs the token")
        check(http(port, "GET", f"/confirm/{qid}/yes", token=token)[0] == 404, "a GET answers nothing")
        check(http(port, "POST", f"/confirm/{qid}/yes")[0] == 401, "a POST without the token neither")
        check(http(port, "GET", "/metrics", token=token)[1].count("sluice_pending_confirmations 1") == 1, "one waits")
        check(not client_readable(client), "the client has been told nothing: it is waiting")
        status, body = http(port, "POST", f"/confirm/{qid}/yes", token=token)
        check(status == 200 and "yes" in body, f"{status} {body}")
        check(kinds(read_answer(client)) == b"CZ", "applied")
        check(http(port, "POST", f"/confirm/{qid}/yes", token=token)[0] == 404, "an answer is given once")
        done = sluice.wait_event("confirm", outcome="yes")
        check(done["channel"] == "admin", f"{done}")

        # and a no
        client.sendall(q("delete from users where id < 5"))
        second = [e for e in sluice.events if e["event"] == "confirm_pending"]
        deadline = time.monotonic() + TIMEOUT
        while len(second) < 2 and time.monotonic() < deadline:
            time.sleep(0.02)
            second = [e for e in sluice.events if e["event"] == "confirm_pending"]
        check(len(second) == 2, "a second question")
        check(http(port, "POST", f"/confirm/{second[1]['question']}/no", token=token)[0] == 200, "no")
        answer = read_answer(client)
        check(b"E" in kinds(answer), f"refused: {kinds(answer)}")
        client.close()
        upstream.finish()
        check(sluice.stop() == 0, "clean shutdown")
        deadline = time.monotonic() + TIMEOUT  # the commands run beside sluice: wait for what they write
        while time.monotonic() < deadline:
            out = open(sink).read() if os.path.exists(sink) else ""
            if out.count("confirm_pending\n{") >= 2 and out.count("\nconfirm\n{") >= 1:
                break
            time.sleep(0.05)
        out = open(sink).read()
        check(out.count("confirm_pending\n{") == 2 and out.count("\nconfirm\n{") >= 1 and "ana@example.com" not in out
              and qid in out, f"the command got each event, named, with its line: {out[:400]}")
        check(sluice.raw_text().count("ana@example.com") == 0, "no value in the log")


def client_readable(sock, wait=0.3):
    """Is there anything to read on the socket within `wait` seconds?"""
    import select
    return bool(select.select([sock], [], [], wait)[0])


def scenario_webhook_script():
    """tools/webhook.sh as an event command: a kill is posted as a chat message, signed; a pending confirmation
    carries its question (fetched from the admin listener with the token). Skipped without curl and openssl."""
    import hashlib
    import hmac as hmac_mod
    import shutil
    from http.server import BaseHTTPRequestHandler, HTTPServer
    if not shutil.which("curl") or not shutil.which("openssl") or not shutil.which("sh"):
        print("    (skipped: curl and openssl are needed)")
        return
    received = []

    class Receiver(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            received.append((self.headers.get("X-Sluice-Event"), self.headers.get("X-Sluice-Signature"), body))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Receiver)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_port}/hook"
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools", "webhook.sh")
    secret = "hook-secret-" + os.urandom(6).hex()
    with tempfile.TemporaryDirectory() as d:
        tokfile = os.path.join(d, "t")
        token = "admin-token-" + os.urandom(8).hex()
        open(tokfile, "w").write(token)
        # a kill, as a slack message, signed
        command = f"WEBHOOK_URL={url} WEBHOOK_FORMAT=slack WEBHOOK_SECRET={secret} sh {script}"
        upstream, sluice, client = mask_session(policy=POLICY_GUARDS, user="agent",
                                                extra=["--event-command", command, "--event-filter", "kill"])
        client.sendall(q("select pg_read_file('/etc/passwd')"))
        data = b""
        client.settimeout(5)
        try:
            while True:
                chunk = client.recv(65536)
                if not chunk:
                    break
                data += chunk
        except OSError:
            pass
        client.close()
        upstream.finish()
        check(sluice.stop() == 0, "clean shutdown")  # waits for the command to say it
        deadline = time.monotonic() + TIMEOUT
        while not received and time.monotonic() < deadline:
            time.sleep(0.05)
        check(len(received) == 1, f"{received}")
        event, signature, body = received[0]
        check(event == "kill" and json.loads(body)["text"] == "sluice: kill, rule no-danger, user agent", f"{body}")
        want = "sha256=" + hmac_mod.new(secret.encode(), body, hashlib.sha256).hexdigest()
        check(signature == want, f"the body is signed: {signature} {want}")

        # a pending confirmation, with its question
        received.clear()
        upstream = FakeUpstream(confirm_db(rows=3), tolerate=True)
        # the admin port is chosen by the system; a fixed free one lets the command know it
        free = socket.socket()
        free.bind(("127.0.0.1", 0))
        admin_port = free.getsockname()[1]
        free.close()
        sluice = Sluice(upstream.port, policy=POLICY_CONFIRM, extra_args=[
            "--admin", f"127.0.0.1:{admin_port}", "--admin-token-file", tokfile, "--confirm-admin", "on",
            "--event-filter", "confirm_pending", "--event-command",
            f"WEBHOOK_URL={url} WEBHOOK_FORMAT=slack WEBHOOK_ADMIN=http://127.0.0.1:{admin_port} "
            f"WEBHOOK_TOKEN_FILE={tokfile} sh {script}"])
        client = open_session(sluice, user="agent", database="mydb")
        client.sendall(q("delete from users where id < 5"))
        pending = sluice.wait_event("confirm_pending")
        deadline = time.monotonic() + TIMEOUT
        while not received and time.monotonic() < deadline:
            time.sleep(0.05)
        check(len(received) == 1, f"{received}")
        text = json.loads(received[0][2])["text"]
        check("DELETE 3 waits for an answer" in text and pending["question"] in text and "ana@example.com" in text
              and f"/confirm/{pending['question']}/yes" in text, f"{text}")
        check(http(admin_port, "POST", f"/confirm/{pending['question']}/no", token=token)[0] == 200, "answered")
        read_answer(client)
        client.close()
        upstream.finish()
        check(sluice.stop() == 0, "clean shutdown")
    server.shutdown()


def scenario_log_chain():
    """With --log-chain-key-file every line of the log carries a count and a chain value: `sluice --verify-log`
    accepts the log as it was written, and finds a line changed, taken out, added, moved, a wrong key, and (as a
    different answer) a run that did not end cleanly."""
    with tempfile.TemporaryDirectory() as d:
        key = os.path.join(d, "chain.key")
        other = os.path.join(d, "other.key")
        open(key, "wb").write(os.urandom(32))
        open(other, "wb").write(os.urandom(32))
        upstream, sluice, client = mask_session(policy=POLICY_GUARDS, user="agent", extra=["--log-chain-key-file", key])
        client.sendall(q("select people"))
        read_answer(client)
        client.sendall(q("set role admin"))
        read_answer(client)
        client.close()
        upstream.finish()
        sluice.wait_event("connection_close")
        check(sluice.stop() == 0, "clean shutdown")
        lines = sluice.raw_text().splitlines()
        check(len(lines) >= 6 and json.loads(lines[0])["event"] == "chain_start" and json.loads(lines[-1])["event"] == "chain_end",
              f"a chain starts and ends: {lines[0][:80]} ... {lines[-1][:80]}")
        parsed = [json.loads(x) for x in lines]
        check([x["seq"] for x in parsed] == list(range(1, len(parsed) + 1)) and all(len(x["chain"]) == 32 for x in parsed),
              "every line is counted and chained")
        good = os.path.join(d, "good.log")
        open(good, "w").write("\n".join(lines) + "\n")
        run = verify_log(good, key)
        check(run.returncode == 0 and "closed" in run.stdout and "check out" in run.stdout, f"{run.stdout} {run.stderr}")
        check(verify_log(good, other).returncode == 1, "another key does not check out")

        def tampered(name, new_lines):
            path = os.path.join(d, name)
            open(path, "w").write("\n".join(new_lines) + "\n")
            return verify_log(path, key)

        i = next(n for n, x in enumerate(parsed) if x["event"] == "statement")
        run = tampered("changed.log", lines[:i] + [lines[i].replace("allow", "deny", 1) if "allow" in lines[i]
                                                    else lines[i].replace("\"user\"", "\"usex\"", 1)] + lines[i + 1:])
        check(run.returncode == 1 and f"line {i + 1}:" in run.stderr, f"a changed line: {run.stderr}")
        run = tampered("removed.log", lines[:i] + lines[i + 1:])
        check(run.returncode == 1 and "taken out" in run.stderr and f"line {i + 1}:" in run.stderr, f"a line taken out: {run.stderr}")
        run = tampered("added.log", lines[:i] + [lines[i - 1]] + lines[i:])
        check(run.returncode == 1, f"a line added: {run.stderr}")
        run = tampered("moved.log", lines[:2] + [lines[3], lines[2]] + lines[4:])
        check(run.returncode == 1, "two lines swapped")
        run = tampered("plain.log", lines[:i] + [lines[i].rsplit(",\"seq\"", 1)[0] + "}"] + lines[i + 1:])
        check(run.returncode == 1 and "not chained" in run.stderr, f"a line without a chain: {run.stderr}")
        run = tampered("cut.log", lines[:-3])
        check(run.returncode == 3 and "NOT closed" in run.stdout, f"a log cut at its end is not an error of the lines: {run.stdout}")
        run = tampered("headless.log", lines[2:])
        check(run.returncode == 1 and "start of the log was cut" in run.stderr, f"{run.stderr}")
        # two runs in one file
        run = tampered("twice.log", lines + lines)
        check(run.returncode == 0 and "2 runs" in run.stdout, f"a restart starts a new chain: {run.stdout}")

        # a key that cannot be used stops sluice at the start
        short = os.path.join(d, "short.key")
        open(short, "wb").write(b"abc")
        proc = subprocess.run([SLUICE, "--listen", "127.0.0.1:0", "--upstream", "127.0.0.1:1", "--log-chain-key-file", short],
                              capture_output=True, text=True, timeout=TIMEOUT)
        check(proc.returncode == 1 and "16 to" in proc.stderr, f"{proc.returncode} {proc.stderr}")


def scenario_masking_qualified_names():
    """A name written table.column hides the column only when the rows come from that table: sluice asks the server
    for its tables once, after the login, and the client never sees the question. Anything it cannot tell (the list
    could not be had, a column that comes from no table) is hidden, as if the name were not qualified."""
    qualified = POLICY_MASK.replace('columns = ["email"]', 'columns = ["users.email"]').replace('detect = ["email", "card", "iban"]\n', "")
    check(qualified != POLICY_MASK, "the policy was changed")
    upstream, sluice, client = mask_session(policy=qualified, catalog="ok")
    client.sendall(q("select people from users"))
    answer = read_answer(client)
    check(kinds(answer) == b"TDDDCZ" and rows_of(answer)[0][1] == "[masked]", f"users.email is hidden: {rows_of(answer)}")
    client.sendall(q("select people from orders"))
    answer = read_answer(client)
    check(kinds(answer) == b"TDDDCZ" and rows_of(answer)[0][1] == "ana@example.com",
          f"orders.email is not, the server said it is another table: {rows_of(answer)}")
    client.close()
    upstream.finish()
    queries = [t for k, t in upstream.seen["msgs"] if k == "Q"]
    check(upstream.seen.get("catalog_asked") == 1 and queries[0].startswith("select c.oid::bigint")
          and queries[1:] == ["select people from users", "select people from orders"], f"asked once, before the client: {queries}")
    check(sluice.stop() == 0, "clean shutdown")

    # the server refuses the question: every connection falls back to hiding by name, and the log says so
    upstream, sluice, client = mask_session(policy=qualified, catalog="error")
    client.sendall(q("select people from orders"))
    answer = read_answer(client)
    check(kinds(answer) == b"TDDDCZ" and rows_of(answer)[0][1] == "[masked]", f"hidden whatever the table: {rows_of(answer)}")
    client.close()
    upstream.finish()
    sluice.wait_event("mask_catalog", outcome="failed")  # logged
    check(sluice.stop() == 0, "clean shutdown")

    # a name that is not qualified asks nothing
    upstream, sluice, client = mask_session(catalog="ok")
    client.sendall(q("select people from orders"))
    answer = read_answer(client)
    check(rows_of(answer)[0][1] == "[masked]", "email is email")
    client.close()
    upstream.finish()
    check(upstream.seen.get("catalog_asked") is None, "the server was not asked for its tables")
    check(sluice.stop() == 0, "clean shutdown")


def scenario_masking_hash_is_stable():
    """The token of a hash mask is the same for the same value and the same key, differs for another value, and
    does not hold the value; a key file makes it the same after a restart; a key that is too short is refused."""
    policy = POLICY_MASK.replace('how = "redact"', 'how = "hash"')
    tokens = []
    with tempfile.TemporaryDirectory() as d:
        keyfile = os.path.join(d, "key")
        with open(keyfile, "wb") as f:
            f.write(os.urandom(32))
        for run in range(2):
            upstream, sluice, client = mask_session(policy=policy, extra=["--mask-key-file", keyfile])
            client.sendall(q("select people"))
            rows = rows_of(read_answer(client))
            tokens.append((rows[0][1], rows[1][1]))
            client.close()
            check(sluice.stop() == 0, "clean shutdown")
        check(tokens[0] == tokens[1] and tokens[0][0] != tokens[0][1], f"stable with a key file: {tokens}")
        check(tokens[0][0].startswith("~") and len(tokens[0][0]) == 17 and "ana" not in tokens[0][0], f"{tokens[0]}")
        # without one a key is made at startup, and the log says what it means
        upstream, sluice, client = mask_session(policy=policy)
        client.sendall(q("select people"))
        token = rows_of(read_answer(client))[0][1]
        client.close()
        warnings = [e for e in sluice.events if e["event"] == "warning" and "mask-key-file" in e.get("detail", "")]
        check(token != tokens[0][0] and warnings, f"another key, and a warning: {warnings}")
        check(sluice.stop() == 0, "clean shutdown")
        with open(keyfile, "wb") as f:
            f.write(b"short")
        proc = subprocess.run([SLUICE, "--listen", "127.0.0.1:0", "--upstream", "127.0.0.1:1", "--policy",
                               os.path.join(d, "p.toml"), "--mask-key-file", keyfile], capture_output=True, text=True,
                              timeout=TIMEOUT)
        check(proc.returncode != 0, "a short key, or no policy file, stops sluice")
        with open(os.path.join(d, "p.toml"), "w") as f:
            f.write(policy)
        proc = subprocess.run([SLUICE, "--listen", "127.0.0.1:0", "--upstream", "127.0.0.1:1", "--policy",
                               os.path.join(d, "p.toml"), "--mask-key-file", keyfile], capture_output=True, text=True,
                              timeout=TIMEOUT)
        check(proc.returncode != 0 and "16 to" in proc.stderr, f"{proc.returncode} {proc.stderr!r}")


def scenario_masking_extended_protocol():
    """The extended protocol: sluice puts a Describe of the portal in front of each Execute to learn the columns, and
    the client never sees its answer, whether it asked to describe or not, alone or in a pipeline, in text or binary,
    with errors in between."""
    upstream, sluice, client = mask_session()
    # the client describes the portal itself
    client.sendall(parse_msg(b"", "select people") + bind_msg() + describe_msg(b"P") + execute_msg() + SYNC)
    answer = read_until_z(client)
    check(kinds(answer) == b"12TDDDCZ", f"exactly what it asked for: {kinds(answer)}")
    check(rows_of(answer)[0] == ["1", "[masked]", "call [masked] tomorrow", "Ana"], f"{rows_of(answer)[0]}")
    # it does not describe: the description it uses is the one from before
    client.sendall(parse_msg(b"s1", "select people") + describe_msg(b"S", b"s1") + SYNC)
    first = read_until_z(client)
    check(kinds(first) == b"1tTZ", f"{kinds(first)}")
    client.sendall(bind_msg(b"", b"s1") + execute_msg() + SYNC)
    answer = read_until_z(client)
    check(kinds(answer) == b"2DDDCZ" and rows_of(answer)[1][1] == "[masked]", f"no description, rows masked: {kinds(answer)}")
    # a pipeline: rows, a statement with no result, rows again, in one go
    client.sendall(parse_msg(b"u1", "update t set a = 1") + bind_msg(b"pu", b"u1") + execute_msg(b"pu")
                   + bind_msg(b"", b"s1") + execute_msg() + bind_msg(b"", b"s1") + describe_msg(b"P") + execute_msg() + SYNC)
    answer = read_until_z(client)
    check(kinds(answer) == b"1" + b"2C" + b"2DDDC" + b"2TDDDC" + b"Z", f"{kinds(answer)}")
    check(all(r[1] in ("[masked]", None) for r in rows_of(answer)), f"{rows_of(answer)}")
    # many executes at once, past what a short queue would hold
    batch = b"".join(bind_msg(b"", b"s1") + execute_msg() for _ in range(300)) + SYNC
    client.sendall(batch)
    answer = read_until_z(client)
    check(kinds(answer) == b"2DDDC" * 300 + b"Z" and all(r[1] in ("[masked]", None) for r in rows_of(answer)),
          f"300 pipelined: {len(answer)} messages")
    # an error in the middle: the rest of the cycle is skipped, and the next cycle is clean
    client.sendall(bind_msg(b"", b"s1") + execute_msg() + parse_msg(b"", "boom") + bind_msg(b"", b"s1") + execute_msg() + SYNC)
    answer = read_until_z(client)
    check(kinds(answer) == b"2DDDCEZ", f"{kinds(answer)}")
    client.sendall(bind_msg(b"", b"s1") + execute_msg() + SYNC)
    answer = read_until_z(client)
    check(kinds(answer) == b"2DDDCZ" and rows_of(answer)[0][1] == "[masked]", f"clean again: {kinds(answer)}")
    client.close()
    upstream.finish()
    msgs = upstream.seen["msgs"]
    kinds_seen = "".join(k for k, _ in msgs)
    check(kinds_seen.count("E") >= 305 and kinds_seen.count("D") >= kinds_seen.count("E") - 3,
          f"a Describe in front of every Execute that reaches the database: {kinds_seen[:60]}")
    check(sluice.stop() == 0, "clean shutdown")

    # binary results of text columns are hidden the same way; a named column of another type becomes NULL
    upstream, sluice, client = mask_session()
    binary_bind = message(b"B", b"\0\0" + struct.pack("!HHH", 0, 0, 1) + struct.pack("!HH", 1, 1))
    client.sendall(parse_msg(b"", "select people") + binary_bind + describe_msg(b"P") + execute_msg() + SYNC)
    answer = read_until_z(client)
    check(kinds(answer) == b"12TDDDCZ" and rows_of(answer)[0][1] == "[masked]", f"{kinds(answer)}")
    client.close()
    check(sluice.stop() == 0, "clean shutdown")


def scenario_masking_cannot_be_got_around_by_the_session():
    """Hiding keeps working when the client does odd things with the protocol: an Execute with a name too long to
    follow, fast-path calls, and a stream that cannot be followed any more end in a refusal, never in rows."""
    upstream, sluice, client = mask_session()
    long_name = b"p" * 100
    client.sendall(parse_msg(b"s1", "select people") + bind_msg(long_name, b"s1") + execute_msg(long_name) + SYNC)
    answer = read_until_z(client)
    check(kinds(answer) == b"12EZ", f"refused, no rows: {kinds(answer)}")
    # a fast-path function call has no description to hide its answer by
    client.sendall(message(b"F", struct.pack("!IHHH", 1234, 0, 0, 0) + struct.pack("!H", 0)))
    answer = read_until_z(client)
    check(kinds(answer) == b"EZ" and "fast-path" in error_fields(answer[0][1])["M"], f"{answer}")
    client.close()
    check(sluice.stop() == 0, "clean shutdown")


def scenario_masking_in_a_confirmation():
    """The rows shown to the person who is asked, and the client's own RETURNING, go through the same mask."""
    policy = POLICY_CONFIRM + """
[[rule]]
name = "pii"
match = "any"
action = "mask"
columns = ["email"]
how = "redact"
"""
    upstream, sluice, client = confirm_session(confirm_db(rows=3), policy=policy)
    client.sendall(q("delete from users where id < 5"))
    answer = read_answer(client)
    fields = error_fields(answer[0][1])
    check("waiting for you" in fields["M"] and "ana@example.com" not in repr(answer) and "carl@example.com" not in repr(answer)
          and "[masked]" in fields["D"], f"the rows shown are masked: {fields['D']!r}")
    client.sendall(q("show;"))
    shown = read_answer(client)
    check("@example.com" not in repr(shown) and "[masked]" in error_fields(shown[0][1])["D"], "and so is show;")
    client.sendall(q("yes;"))
    check(kinds(read_answer(client)) == b"CZ", "answered")
    client.close()
    check(sluice.stop() == 0, "clean shutdown")


def scenario_masking_leaves_others_alone():
    """No rule for the user: nothing is read or changed, however large the rows (they stream)."""
    upstream, sluice, client = mask_session(policy='mode = "enforce"\n', big=3 * 1024 * 1024)
    client.sendall(q("select big"))
    answer = read_answer(client)
    check(kinds(answer) == b"TDCZ" and len(answer[1][1]) == 3 * 1024 * 1024 + 6, f"{kinds(answer)}")
    client.close()
    check(sluice.stop() == 0, "clean shutdown")


def scenario_merge_and_upsert_are_updates_and_deletes():
    """MERGE with a WHEN MATCHED ... DELETE or UPDATE, and INSERT ... ON CONFLICT DO UPDATE, are DELETEs and UPDATEs
    for the rules (they used to pass `match = "delete"` and `"update"` unseen): refused when a rule says so, and held
    for a confirmation like any other, with the rows shown and the count of the tag."""
    deny = """
mode = "enforce"
[[rule]]
name = "no-deletes"
match = "delete"
[[rule]]
name = "no-updates"
match = "update"
"""
    upstream = FakeUpstream(confirm_db(rows=3), tolerate=True)
    sluice = Sluice(upstream.port, policy=deny)
    client = open_session(sluice, user="agent", database="mydb")
    for sql, rule in (("merge into t using s on t.id = s.id when matched then delete", "no-deletes"),
                      ("merge into t using s on t.id = s.id when matched then update set a = 1", "no-updates"),
                      ("insert into t values (1) on conflict (id) do update set a = 2", "no-updates")):
        client.sendall(q(sql))
        read_answer(client)
        blocked = [e for e in sluice.events if e["event"] == "statement" and e.get("action") == "blocked"]
        check(blocked and blocked[-1]["rule"] == rule, f"{sql}: {blocked[-1:]}")
    client.sendall(q("insert into t values (1) on conflict do nothing"))
    read_answer(client)
    check(sluice.events[-1].get("action") == "relayed", "DO NOTHING and a plain MERGE insert are not updates")
    client.close()
    check(sluice.stop() == 0, "clean shutdown")

    for sql, tag in (("merge into t using s on t.id = s.id when matched then delete when not matched then insert values (1)",
                      b"MERGE 3\0"),
                     ("insert into t select * from s on conflict (id) do update set a = excluded.a", b"INSERT 0 3\0")):
        upstream, sluice, client = confirm_session(confirm_db(rows=3), policy=POLICY_CONFIRM)
        client.sendall(q(sql))
        answer = read_answer(client)
        fields = error_fields(answer[0][1])
        check("waiting for you" in fields["M"] and "changed 3 rows" in fields["D"] and "ana@example.com" in fields["D"],
              f"{sql}: {fields}")
        client.sendall(q("yes;"))
        answer = read_answer(client)
        check(kinds(answer) == b"CZ" and answer[0][1] == tag, f"{sql}: {answer}")
        client.close()
        upstream.finish()
        check(upstream.seen["queries"][0].endswith(" RETURNING *"), f"{upstream.seen['queries'][0]}")
        check(sluice.stop() == 0, "clean shutdown")


def undo_run(*args):
    return subprocess.run([SLUICE, "--undo", *args], capture_output=True, text=True, timeout=TIMEOUT)


def journal_entries(path):
    return [json.loads(line) for line in open(path)] if os.path.exists(path) else []


def scenario_undo_journal():
    """A DELETE that a rule keeps for undo: its rows are written to the journal just before the COMMIT (a yes, or
    under the threshold), never when it is refused; `required` does not apply a DELETE whose rows cannot be kept (the
    journal is full, the statement has its own RETURNING, it is a MERGE); `sluice --undo` prints the SQL that puts
    them back, and refuses an entry that is not whole unless asked."""
    policy = POLICY_CONFIRM.replace('message = "A person has to confirm this."', 'journal = "required"\nmessage = "A person has to confirm this."')
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "undo.jsonl")
        upstream, sluice, client = confirm_session(confirm_db(rows=3), policy=policy,
                                                   extra=["--undo-journal", path])
        # a no leaves nothing; a yes writes the rows before the COMMIT
        client.sendall(q("delete from users where id < 5"))
        read_answer(client)
        client.sendall(q("no;"))
        read_answer(client)
        check(journal_entries(path) == [], "a refused DELETE is not recorded")
        client.sendall(q("delete from users where id < 5"))
        read_answer(client)
        client.sendall(q("yes;"))
        check(kinds(read_answer(client)) == b"CZ", "applied")
        entries = journal_entries(path)
        check(len(entries) == 1, f"{entries}")
        e = entries[0]
        check(e["complete"] is True and e["rows"] == 3 and e["table"] == "users" and e["schema"] == ""
              and e["columns"] == ["id", "email"] and e["data"] == [["18", "ana@example.com"], ["52", None], ["7", "carl@example.com"]]
              and e["user"] == "agent" and e["rule"] == "confirm-deletes" and e["side_known"] is False or e["side_known"],
              f"{e}")
        check(oct(os.stat(path).st_mode & 0o777) == "0o600", "the file is the owner's alone")
        event = [x for x in sluice.events if x["event"] == "journal"]
        check(event and event[0]["outcome"] == "written" and event[0]["entry"] == e["id"] and "ana@example.com" not in repr(event),
              f"{event}")
        # the commit came after the entry: the order of the log
        names = [x["event"] for x in sluice.events]
        check(names.index("journal") < len(names) - 1 - names[::-1].index("confirm"), f"{names}")
        # a DELETE of a few rows goes through without a question, and is recorded too
        client.close()
        upstream.finish()
        check(sluice.stop() == 0, "clean shutdown")

        listing = undo_run(path)
        check(listing.returncode == 0 and e["id"] in listing.stdout and "users" in listing.stdout and "yes" in listing.stdout,
              f"{listing.stdout} {listing.stderr}")
        script = undo_run(path, "--id", e["id"])
        check(script.returncode == 0 and "INSERT INTO \"users\" (\"id\", \"email\") OVERRIDING SYSTEM VALUE VALUES" in script.stdout
              and "('18', 'ana@example.com')," in script.stdout and "('52', NULL)," in script.stdout
              and script.stdout.rstrip().endswith("COMMIT;"), script.stdout)
        check(undo_run(path, "--id", "nope").returncode == 1 and undo_run().returncode == 2, "wrong ids and arguments")

        # a journal that is full: `required` does not apply the DELETE, and says why
        upstream, sluice, client = confirm_session(confirm_db(rows=3), policy=policy,
                                                   extra=["--undo-journal", path, "--undo-journal-max", "500"])
        client.sendall(q("delete from users where id < 5"))
        read_answer(client)
        client.sendall(q("yes;"))
        answer = read_answer(client)
        fields = error_fields(answer[0][1])
        check(kinds(answer) == b"NCZ" and "was NOT applied" in fields["M"] and "recorded for undo" in fields["M"]
              and answer[1][1] == b"ROLLBACK\0", f"{fields} {kinds(answer)}")
        client.close()
        upstream.finish()
        check("ROLLBACK" in upstream.seen["queries"] and "COMMIT" not in upstream.seen["queries"],
              f"it was rolled back: {upstream.seen['queries']}")
        check(len(journal_entries(path)) == 1, "nothing was added")
        sluice.wait_event("journal", outcome="failed")  # logged
        check(sluice.stop() == 0, "clean shutdown")

        # best effort ("on"): the DELETE goes ahead, and the log says that it was not recorded
        soft = policy.replace('journal = "required"', 'journal = "on"')
        upstream, sluice, client = confirm_session(confirm_db(rows=3), policy=soft,
                                                   extra=["--undo-journal", path, "--undo-journal-max", "500"])
        client.sendall(q("delete from users where id < 5"))
        read_answer(client)
        client.sendall(q("yes;"))
        check(kinds(read_answer(client)) == b"CZ", "applied all the same")
        client.close()
        sluice.wait_event("journal", outcome="failed")  # and it says so
        check(sluice.stop() == 0, "clean shutdown")

    # not whole: a RETURNING of its own, a table that cannot be named; `required` refuses, `on` writes what it can
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "undo.jsonl")
        upstream, sluice, client = confirm_session(confirm_db(rows=3), policy=policy, extra=["--undo-journal", path])
        client.sendall(q("delete from users where id < 5 returning id"))
        read_answer(client)
        client.sendall(q("yes;"))
        answer = read_answer(client)
        check(kinds(answer) == b"NCZ" and "cannot all be recorded" in error_fields(answer[0][1])["M"], f"{answer}")
        client.sendall(q("merge into users using s on users.id = s.id when matched then delete"))
        answer = read_answer(client)
        check(b"E" in kinds(answer), "a MERGE is held like a DELETE")
        client.sendall(q("yes;"))
        answer = read_answer(client)
        check(kinds(answer) == b"NCZ" and "only the rows of a DELETE" in error_fields(answer[0][1])["M"], f"{answer}")
        client.close()
        check(journal_entries(path) == [], "nothing recorded")
        check(sluice.stop() == 0, "clean shutdown")
        soft = policy.replace('journal = "required"', 'journal = "on"')
        upstream, sluice, client = confirm_session(confirm_db(rows=3), policy=soft, extra=["--undo-journal", path])
        client.sendall(q("delete from users where id < 5 returning id"))
        read_answer(client)
        client.sendall(q("yes;"))
        check(kinds(read_answer(client))[-1:] == b"Z", "applied")
        client.close()
        check(sluice.stop() == 0, "clean shutdown")
        e = journal_entries(path)[0]
        check(e["complete"] is False and "RETURNING of its own" in e["incomplete"] and e["data"] == [], f"{e}")
        check(undo_run(path, "--id", e["id"]).returncode == 1 and "nothing to put back" in undo_run(path, "--id", e["id"]).stderr,
              "an entry with no rows has nothing to put back, even with --partial")
        check(undo_run(path, "--id", e["id"], "--partial").returncode == 1, "...even partly")

        # the extended protocol, a few rows under the threshold, and the rows are the server's own
        policy_ext = policy.replace('over_rows = "1"', 'over_rows = "5"')
        upstream = FakeUpstream(ext_db(rows=3), tolerate=True)
        sluice = Sluice(upstream.port, policy=policy_ext, extra_args=["--undo-journal", path])
        client = open_session(sluice, user="agent", database="mydb")
        client.sendall(parse_msg(b"", DELETE_SQL) + bind_msg() + execute_msg() + SYNC)
        answer = read_until_z(client)
        check(kinds(answer) == b"12CZ", f"{kinds(answer)}")
        client.close()
        upstream.finish()
        e = journal_entries(path)[-1]
        check(e["protocol"] == "extended" and e["complete"] and e["rows"] == 3 and e["data"][0] == ["1", "user0@example.com"],
              f"{e}")
        check(sluice.stop() == 0, "clean shutdown")

        # the same, asked in the client's own session (the proxy sends the COMMIT itself)
        upstream = FakeUpstream(ext_db(rows=3), tolerate=True)
        sluice = Sluice(upstream.port, policy=policy, extra_args=["--undo-journal", path])
        client = open_session(sluice, user="agent", database="mydb")
        before = len(journal_entries(path))
        client.sendall(parse_msg(b"", DELETE_SQL) + bind_msg() + describe_msg(b"P") + execute_msg() + SYNC)
        check(kinds(read_until_z(client)) == b"12nEZ", "the question")
        check(len(journal_entries(path)) == before, "nothing is written while it waits")
        client.sendall(parse_msg(b"", "yes") + bind_msg() + describe_msg(b"P") + execute_msg() + SYNC)
        check(kinds(read_until_z(client)) == b"12nCZ", "answered")
        client.close()
        entries = journal_entries(path)
        check(len(entries) == before + 1 and entries[-1]["protocol"] == "extended" and entries[-1]["rows"] == 3, f"{entries[-1]}")
        check(sluice.stop() == 0, "clean shutdown")

    # sluice does not start (or reload) a policy that asks for a journal it has none of
    with tempfile.TemporaryDirectory() as d:
        pol = os.path.join(d, "p.toml")
        with open(pol, "w") as f:
            f.write(policy)
        proc = subprocess.run([SLUICE, "--listen", "127.0.0.1:0", "--upstream", "127.0.0.1:1", "--policy", pol],
                              capture_output=True, text=True, timeout=TIMEOUT)
        check(proc.returncode != 0 and "--undo-journal" in proc.stderr, f"{proc.returncode} {proc.stderr!r}")
        upstream = FakeUpstream(confirm_db(rows=3), tolerate=True)
        with open(pol, "w") as f:
            f.write('mode = "audit"\n')
        sluice = Sluice(upstream.port, policy=None, extra_args=["--policy", pol])
        with open(pol, "w") as f:
            f.write(policy)
        sluice.proc.send_signal(signal.SIGHUP)
        event = sluice.wait_event("policy_reload_failed")
        check("--undo-journal" in event["error"], f"{event}")
        check(sluice.stop() == 0, "clean shutdown")


def scenario_undo_journal_update():
    """The old values of an UPDATE kept for undo: sluice asks for the old and the new row (RETURNING OLD.*, NEW.*),
    the person is shown the new one, the journal keeps both, and `sluice --undo` prints a script that puts the old
    values back where the row still has the new ones. `required` refuses an UPDATE whose old rows cannot be had."""
    base = POLICY_CONFIRM.replace('name = "confirm-updates"\nmatch = "update"\naction = "confirm"\n',
                                  'name = "confirm-updates"\nmatch = "update"\naction = "confirm"\njournal = "required"\n')
    check(base != POLICY_CONFIRM, "the policy was changed")
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "undo.jsonl")
        upstream, sluice, client = confirm_session(confirm_db(rows=3), policy=base, extra=["--undo-journal", path])
        client.sendall(q("update users set email = replace(email, 'example.com', 'changed.org') where id < 5"))
        read_answer(client)
        check(any(x.endswith("RETURNING OLD.*, NEW.*") for x in upstream.seen["queries"]),
              f"both rows are asked for: {upstream.seen['queries']}")
        client.sendall(q("show;"))
        shown = error_fields(read_answer(client)[0][1])
        shown = shown.get("D", "") + shown["M"]
        check("ana@changed.org" in shown and "ana@example.com" not in shown,
              f"the person is shown the new rows, once: {shown}")
        client.sendall(q("yes;"))
        check(kinds(read_answer(client)) == b"CZ", "applied")
        entries = journal_entries(path)
        check(len(entries) == 1, f"{entries}")
        e = entries[0]
        check(e["kind"] == "update" and e["complete"] is True and e["rows"] == 3 and e["table"] == "users"
              and e["columns"] == ["id", "email"] and e["protocol"] == "simple"
              and e["data"] == [["18", "ana@example.com"], ["52", None], ["7", "carl@example.com"]]
              and e["new"] == [["18", "ana@changed.org"], ["52", "filled@changed.org"], ["7", "carl@changed.org"]],
              f"{e}")
        client.close()
        upstream.finish()
        check(sluice.stop() == 0, "clean shutdown")
        script = undo_run(path, "--id", e["id"])
        check(script.returncode == 0 and "UPDATE \"users\" SET \"email\" = ''ana@example.com''" in script.stdout
              and "WHERE \"id\" IS NOT DISTINCT FROM ''18'' AND \"email\" IS NOT DISTINCT FROM ''ana@changed.org''"
              in script.stdout and "SET \"email\" = NULL" in script.stdout and "INSERT INTO" not in script.stdout
              and script.stdout.rstrip().endswith("COMMIT;"), script.stdout)
        listing = undo_run(path)
        check(listing.returncode == 0 and e["id"] in listing.stdout and "update" in listing.stdout.lower(),
              f"{listing.stdout} {listing.stderr}")

        # a statement with a RETURNING of its own: the old rows cannot be had, `required` refuses
        upstream, sluice, client = confirm_session(confirm_db(rows=3), policy=base, extra=["--undo-journal", path])
        client.sendall(q("update users set email = 'x' where id < 5 returning id"))
        read_answer(client)
        client.sendall(q("yes;"))
        answer = read_answer(client)
        check(kinds(answer) == b"NCZ" and "cannot all be recorded" in error_fields(answer[0][1])["M"], f"{answer}")
        client.close()
        upstream.finish()
        check(len(journal_entries(path)) == 1, "nothing was added")
        check(sluice.stop() == 0, "clean shutdown")

        # before PostgreSQL 18 the server does not know OLD: the statement is run as it was written, there are
        # no old rows, `required` refuses with the reason
        upstream, sluice, client = confirm_session(confirm_db(rows=3, fail_returning=True), policy=base,
                                                   extra=["--undo-journal", path])
        client.sendall(q("update users set email = 'x' where id < 5"))
        answer = read_answer(client)
        client.sendall(q("yes;"))
        answer = read_answer(client)
        check(kinds(answer) == b"NCZ" and "PostgreSQL 18" in error_fields(answer[0][1])["M"], f"{answer}")
        client.close()
        upstream.finish()
        check(len(journal_entries(path)) == 1, "nothing was added")
        check(sluice.stop() == 0, "clean shutdown")

        # a statement that changed no row leaves nothing to put back, and no entry
        upstream, sluice, client = confirm_session(confirm_db(rows=0), policy=base, extra=["--undo-journal", path])
        client.sendall(q("update users set email = 'x' where id < 0"))
        check(kinds(read_answer(client)) == b"CZ", "it went through")
        client.close()
        upstream.finish()
        check(len(journal_entries(path)) == 1, "no entry for no rows")
        check(sluice.stop() == 0, "clean shutdown")


def scenario_undo_journal_keeps_what_a_mask_hides():
    """The journal is the operator's: it keeps the rows as the server gave them, while the person asked, and the
    client, see them masked."""
    policy = POLICY_CONFIRM.replace('message = "A person has to confirm this."', 'journal = "on"\nmessage = "A person has to confirm this."') + """
[[rule]]
name = "pii"
match = "any"
action = "mask"
columns = ["email"]
how = "redact"
"""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "undo.jsonl")
        upstream, sluice, client = confirm_session(confirm_db(rows=3), policy=policy, extra=["--undo-journal", path])
        client.sendall(q("delete from users where id < 5"))
        answer = read_answer(client)
        check("ana@example.com" not in repr(answer), "masked for the person asked")
        client.sendall(q("yes;"))
        read_answer(client)
        client.close()
        e = journal_entries(path)[0]
        check(e["data"][0] == ["18", "ana@example.com"], f"raw in the journal: {e['data']}")
        check(sluice.stop() == 0, "clean shutdown")


def scenario_undo_journal_rotation():
    """The journal is archived like a log: renamed, then SIGHUP; the next entry starts a new file."""
    policy = POLICY_CONFIRM.replace('message = "A person has to confirm this."', 'journal = "required"\nmessage = "A person has to confirm this."')
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "undo.jsonl")
        upstream, sluice, client = confirm_session(confirm_db(rows=3), policy=policy, extra=["--undo-journal", path])
        client.sendall(q("delete from users where id < 5"))
        read_answer(client)
        client.sendall(q("yes;"))
        read_answer(client)
        check(len(journal_entries(path)) == 1, "one entry")
        os.rename(path, path + ".1")
        sluice.proc.send_signal(signal.SIGHUP)
        sluice.wait_event("journal_reopened")
        client.sendall(q("delete from users where id < 5"))
        read_answer(client)
        client.sendall(q("yes;"))
        read_answer(client)
        check(len(journal_entries(path)) == 1 and len(journal_entries(path + ".1")) == 1, "one in each")
        check(oct(os.stat(path).st_mode & 0o777) == "0o600", "owner only")
        client.close()
        check(sluice.stop() == 0, "clean shutdown")


def scenario_duration_limit():
    """A statement that runs longer than the policy allows is cancelled: sluice opens a connection of its own to the
    database and sends the CancelRequest with the process and secret the server gave at login."""
    policy = """
mode = "enforce"
[[rule]]
name = "short"
match = "any"
action = "limit"
max_duration = "1s"
"""
    upstream = CancelAwareUpstream()
    sluice = Sluice(upstream.port, policy=policy)
    client = sluice.connect()
    client.sendall(startup_packet(user="agent", database="mydb"))
    check([read_message(client)[0] for _ in range(3)] == [b"R", b"K", b"Z"], "the login, with the key of the session")
    started = time.monotonic()
    client.sendall(q("select slow"))
    answer = read_answer(client)
    took = time.monotonic() - started
    check(kinds(answer) == b"NEZ", f"a warning of sluice's, then the server's own error: {kinds(answer)}")
    check("ran for more than 1s (rule short)" in error_fields(answer[0][1])["M"], f"{error_fields(answer[0][1])}")
    check(error_fields(answer[1][1])["C"] == "57014", "the server's error is passed on")
    check(1.0 <= took < 8.0, f"after about a second: {took:.1f}s")
    check(upstream.cancel == (4242, 0xDEADBEEF), f"the cancel carries the session's key: {upstream.cancel}")
    client.sendall(q("select 1"))
    check(kinds(read_answer(client)) == b"CZ", "the session works")
    # a statement that is quick is not cancelled
    client.sendall(q("select 2"))
    check(kinds(read_answer(client)) == b"CZ", "")
    client.close()
    event = sluice.wait_event("limit")
    check(event["kind"] == "duration" and event["rule"] == "short", f"{event}")
    check(sluice.stop() == 0, "clean shutdown")
    upstream.close()

    # the database cannot be reached for the cancel: the warning still goes, nothing waits for long, nothing breaks
    upstream = CancelAwareUpstream()
    sluice = Sluice(upstream.port, policy=policy)
    client = sluice.connect()
    client.sendall(startup_packet(user="agent", database="mydb"))
    [read_message(client) for _ in range(3)]
    upstream.close()  # nobody listens any more
    client.sendall(q("select slow"))
    started = time.monotonic()
    kind, payload = read_message(client)
    check(kind == b"N" and "cancelling it" in error_fields(payload)["M"], f"{kind} {payload}")
    check(time.monotonic() - started < 5.0, f"{time.monotonic() - started:.1f}s")
    check(sluice.wait_event("limit")["kind"] == "duration", "logged")
    other = sluice.connect()  # the proxy is not stuck: it accepts, and says the database is down
    other.sendall(startup_packet(user="agent", database="mydb"))
    check(read_message(other)[0] == b"E", "another client is answered at once")
    upstream.cancelled.set()
    client.close()
    other.close()
    check(sluice.stop() == 0, "clean shutdown")


def scenario_more_proxy_limits():
    """Things that only a proxy can enforce, because the session cannot lift them: a transaction left open is ended, a user
    may not hold more connections than the policy says; and the log can say how each statement ended."""
    # idle in a transaction
    policy = """
mode = "enforce"
[[rule]]
name = "no-idle-tx"
match = "any"
action = "limit"
max_idle_in_transaction = "1s"
"""
    upstream = FakeUpstream(many_rows_db(n=3), tolerate=True)
    sluice = Sluice(upstream.port, policy=policy)
    client = open_session(sluice, user="agent", database="mydb")
    client.sendall(q("select 1"))
    check(kinds(read_answer(client)) == b"CZ", "")
    time.sleep(1.6)  # not in a transaction: nothing happens however long it is idle
    client.sendall(q("select 1"))
    check(kinds(read_answer(client)) == b"CZ", "an idle connection outside a transaction is left alone")
    client.sendall(q("begin"))
    check(kinds(read_answer(client)) == b"CZ", "")
    started = time.monotonic()
    kind, payload = read_message(client)  # nothing was sent: this is the end
    fields = error_fields(payload)
    check(kind == b"E" and fields["S"] == "FATAL" and fields["C"] == "25P03" and "no-idle-tx" in fields["M"], f"{fields}")
    check(0.8 <= time.monotonic() - started < 8.0, f"after about a second: {time.monotonic() - started:.1f}s")
    check(at_eof(client), "and the connection is closed")
    event = sluice.wait_event("limit")
    check(event["kind"] == "idle_in_transaction", f"{event}")
    # a transaction that is used is not idle
    upstream = FakeUpstream(many_rows_db(n=3), tolerate=True)
    sluice2 = Sluice(upstream.port, policy=policy)
    client = open_session(sluice2, user="agent", database="mydb")
    client.sendall(q("begin"))
    read_answer(client)
    for _ in range(4):
        time.sleep(0.5)
        client.sendall(q("select 1"))
        check(kinds(read_answer(client)) == b"CZ", "a transaction in use is not idle")
    client.sendall(q("commit"))
    read_answer(client)
    client.close()
    check(sluice2.stop() == 0 and sluice.stop() == 0, "clean shutdown")

    # connections per user
    policy = """
mode = "enforce"
[[rule]]
name = "two-for-agents"
match = "any"
action = "limit"
users = ["agent"]
max_connections = "2"
"""
    upstream = CancelAwareUpstream()
    sluice = Sluice(upstream.port, policy=policy)

    def login(user):
        c = sluice.connect()
        c.sendall(startup_packet(user=user, database="mydb"))
        return c

    a, b = login("agent"), login("agent")
    check([read_message(a)[0] for _ in range(3)] == [b"R", b"K", b"Z"] and
          [read_message(b)[0] for _ in range(3)] == [b"R", b"K", b"Z"], "two connections are fine")
    third = login("agent")
    kind, payload = read_message(third)
    fields = error_fields(payload)
    check(kind == b"E" and fields["C"] == "53300" and "two-for-agents" in fields["M"], f"the third is refused: {fields}")
    other = login("someone-else")
    check(read_message(other)[0] == b"R", "another user is not concerned")
    a.close()
    time.sleep(0.3)
    again = login("agent")
    check(read_message(again)[0] == b"R", "a place is free again when one leaves")
    check(sluice.wait_event("limit", kind="connections")["rule"] == "two-for-agents", "logged")
    for c in (b, third, other, again):
        c.close()
    check(sluice.stop() == 0, "clean shutdown")
    upstream.close()

    # the outcome of each statement
    upstream = FakeUpstream(many_rows_db(n=30), tolerate=True)
    sluice = Sluice(upstream.port, extra_args=["--log-results", "on"], policy='mode = "enforce"\n')
    client = open_session(sluice, user="agent", database="mydb")
    client.sendall(q("select many"))
    check(kinds(read_answer(client))[-2:] == b"CZ", "the client is not disturbed")
    client.sendall(q("select boom"))
    check(kinds(read_answer(client)) == b"EZ", "")
    client.close()
    upstream.finish()
    results = [e for e in sluice.events if e["event"] == "result"]
    check(len(results) == 2, f"{results}")
    ok, bad = results
    check(ok["kind"] == "ok" and ok["tag"] == "SELECT 30" and ok["rows"] == 30 and ok["bytes"] == 30 * 31
          and ok["user"] == "agent" and "duration_ms" in ok, f"{ok}")
    check(bad["kind"] == "error" and bad["sqlstate"] == "22012" and bad["rows"] == 0, f"{bad}")
    check("secret-value-1234" not in sluice.raw_text(), "the text of an error can quote values: it is not logged")
    check(sluice.stop() == 0, "clean shutdown")

    # off by default
    upstream = FakeUpstream(many_rows_db(n=3), tolerate=True)
    sluice = Sluice(upstream.port, policy='mode = "enforce"\n')
    client = open_session(sluice, user="agent", database="mydb")
    client.sendall(q("select many"))
    read_answer(client)
    client.close()
    upstream.finish()
    check(not [e for e in sluice.events if e["event"] == "result"], "no result events unless asked for")
    check(sluice.stop() == 0, "clean shutdown")


def open_fds(pid):
    """How many descriptors a process holds, or None where this cannot be read."""
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        pass
    try:
        out = subprocess.run(["lsof", "-n", "-P", "-p", str(pid)], capture_output=True, text=True, timeout=20).stdout
        return max(0, len(out.splitlines()) - 1)
    except (OSError, subprocess.SubprocessError):
        return None


def mutate(rng, data):
    """A valid stream damaged in one of the ways a broken or hostile client would."""
    data = bytearray(data)
    how = rng.randrange(8)
    if not data:
        return bytes(data)
    if how == 0:  # flip some bytes
        for _ in range(rng.randrange(1, 6)):
            data[rng.randrange(len(data))] ^= 1 << rng.randrange(8)
    elif how == 1:  # cut it short
        del data[rng.randrange(len(data)):]
    elif how == 2:  # a length that lies
        i = rng.randrange(len(data))
        data[i:i + 4] = struct.pack("!I", rng.choice([0, 1, 3, 4, 5, 0x7FFFFFFF, 0xFFFFFFFF, len(data) * 3]))
    elif how == 3:  # repeated
        data = data * rng.randrange(2, 20)
    elif how == 4:  # random noise after
        data += os.urandom(rng.randrange(1, 300)) if False else bytes(rng.randrange(256) for _ in range(rng.randrange(1, 300)))
    elif how == 5:  # some bytes dropped from the middle
        a = rng.randrange(len(data))
        del data[a:a + rng.randrange(1, 20)]
    elif how == 6:  # a type byte that means nothing
        data[0] = rng.choice(b"ZzKkNn\x00\xff!?")
    else:  # a huge statement
        data = bytearray(q("select '" + "x" * rng.choice([2000, 70000, 1200000]) + "'"))
    return bytes(data)


def scenario_survives_garbage():
    """What a broken or hostile client sends after it has logged in: valid messages damaged in every way, repeated, cut,
    with lying lengths. The proxy must neither crash nor hang nor leak descriptors, and a good client must still be served."""
    import random

    valid = [
        q("select 1"), q("delete from t where id = 1"), q("update t set a = 1 where b = 2; select 3"),
        parse_msg(b"s", "select $1::int", (23,)) + bind_msg(b"", b"s") + describe_msg(b"P") + execute_msg() + SYNC,
        parse_msg(b"", "delete from t where n < 5") + bind_msg() + execute_msg() + SYNC,
        message(b"d", b"copy data") + message(b"c"), close_msg(b"S", b"s") + FLUSH, message(b"X"),
    ]
    policy = """
mode = "enforce"
[[rule]]
name = "confirm-deletes"
match = "delete"
action = "confirm"
over_rows = "1"
[[rule]]
name = "no-ddl"
match = "ddl"
"""
    rng = random.Random(20260118)
    upstream = CancelAwareUpstream()
    sluice = Sluice(upstream.port, policy=policy, extra_args=["--confirm-tty", "/nonexistent/tty"])
    baseline = None
    for round_no in range(300):
        client = sluice.connect()
        client.settimeout(5)
        try:
            client.sendall(startup_packet(user="agent", database="mydb"))
            [read_message(client) for _ in range(3)]
            pieces = [mutate(rng, rng.choice(valid)) for _ in range(rng.randrange(1, 4))]
            for piece in pieces:
                client.sendall(piece)
            # whatever it answers, it ends: either it answers and we close, or it closes
            client.shutdown(socket.SHUT_WR)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                data = client.recv(65536)
                if not data:
                    break
        except (OSError, EOFError):
            pass
        finally:
            client.close()
        check(sluice.proc.poll() is None, f"round {round_no}: sluice died")
        if round_no == 20:
            time.sleep(0.5)
            baseline = open_fds(sluice.proc.pid)
    time.sleep(1.0)
    check(sluice.proc.poll() is None, "sluice is alive after 300 damaged sessions")
    fds = open_fds(sluice.proc.pid)
    if baseline is not None and fds is not None:
        check(fds <= baseline + 6, f"no descriptor leaked: {baseline} after 20 rounds, {fds} after 300")
    # and a good client is served
    good = sluice.connect()
    good.sendall(startup_packet(user="agent", database="mydb"))
    check([read_message(good)[0] for _ in range(3)] == [b"R", b"K", b"Z"], "a good client is still served")
    good.sendall(q("select 1"))
    check(kinds(read_answer(good)) == b"CZ", "")
    good.close()
    check(sluice.stop() == 0, "clean shutdown")
    upstream.close()


def scenario_extended_defences():
    """The limits that keep the bookkeeping of prepared statements bounded, and what happens at each: names the server cannot
    compare the way sluice does, too many confirmable statements, a pipeline too long to follow."""
    long_name = b"n" * 70

    # a name longer than 63 bytes, once something is confirmable on the connection: refused, never guessed at
    upstream, sluice, client = ext_session(session=True)
    client.sendall(parse_msg(b"g1", DELETE_SQL) + SYNC)
    check(kinds(read_until_z(client)) == b"1Z", "a confirmable statement is prepared")
    for what, msg in (("Bind", bind_msg(b"", long_name)), ("Describe", describe_msg(b"S", long_name)),
                      ("Execute", execute_msg(long_name)), ("Close", close_msg(b"S", long_name))):
        client.sendall(msg + SYNC)
        answer = read_until_z(client)
        check(kinds(answer) == b"EZ" and "too long to follow" in error_fields(answer[0][1])["M"],
              f"{what}: {kinds(answer)} {error_fields(answer[0][1]) if answer[0][0] == b'E' else ''}")
    client.close()
    check(sluice.stop() == 0, "clean shutdown")

    # ... and when nothing is confirmable it is the server's business, and goes through as it is
    upstream, sluice, client = ext_session(session=True)
    client.sendall(bind_msg(b"", long_name) + SYNC)
    answer = read_until_z(client)
    check(kinds(answer) == b"EZ" and "prepared statement does not exist" in error_fields(answer[0][1])["M"],
          f"the server's own error: {answer}")
    client.close()
    check(sluice.stop() == 0, "clean shutdown")

    # more confirmable statements than can be followed: the next one is refused with the reason
    upstream, sluice, client = ext_session(session=True)
    batch = b"".join(parse_msg(b"s%d" % i, DELETE_SQL) for i in range(256)) + parse_msg(b"s256", DELETE_SQL) + SYNC
    client.sendall(batch)
    answer = read_until_z(client)
    check(kinds(answer) == b"1" * 256 + b"EZ", f"{kinds(answer)[:3]}... {kinds(answer)[-3:]}")
    check("as many confirmable statements as can be followed" in error_fields(answer[-2][1])["M"], f"{error_fields(answer[-2][1])}")
    client.sendall(parse_msg(b"s0", "select 1") + SYNC)  # a name that is there already is not new
    check(kinds(read_until_z(client))[-1:] == b"Z", "the connection works")
    client.close()
    check(sluice.stop() == 0, "clean shutdown")

    # a pipeline too long to follow: sluice stops following, refuses what needs it, and relays the rest
    upstream, sluice, client = ext_session(session=True)
    client.sendall(parse_msg(b"g1", DELETE_SQL) + SYNC)
    read_until_z(client)
    long_pipeline = b"".join(describe_msg(b"P") + execute_msg() for _ in range(600)) + SYNC
    client.sendall(long_pipeline)
    client.settimeout(15)
    got = b""
    while not got.endswith(b"Z\x00\x00\x00\x05I"):
        data = client.recv(1 << 20)
        check(data != b"", "the connection stays up")
        if not data:
            break
        got += data
    client.sendall(bind_msg(b"", b"g1") + execute_msg() + SYNC)
    answer = read_until_z(client)
    check(any(k == b"E" for k, _ in answer) and "too many messages are waiting for an answer" in
          next(error_fields(p)["M"] for k, p in answer if k == b"E"), f"refused, not guessed: {kinds(answer)}")
    client.sendall(parse_msg(b"g2", DELETE_SQL) + SYNC)  # a new confirmable statement: refused too
    answer = read_until_z(client)
    check(any(k == b"E" for k, _ in answer) and "cannot follow this session closely enough" in
          next(error_fields(p)["M"] for k, p in answer if k == b"E"), f"{kinds(answer)}")
    client.sendall(parse_msg(b"", "select 1") + bind_msg() + execute_msg() + SYNC)
    check(kinds(read_until_z(client)) == b"12DCZ", "and plain statements go on as usual")
    client.close()
    check(sluice.stop() == 0, "clean shutdown")


def scenario_confirm_in_the_session_times_out():
    """Nobody answers: the statement is undone, the client is told by a warning, and its next statement goes through."""
    policy = POLICY_CONFIRM.replace('"5s"', '"1s"')
    upstream, sluice, client = confirm_session(confirm_db(rows=3), policy=policy)
    client.sendall(q("delete from users where id < 5"))
    read_answer(client)
    kind, payload = read_message(client)  # nothing was sent: this is the warning when the time is up
    check(kind == b"N" and "was not confirmed in time" in error_fields(payload)["M"], f"{kind} {payload}")
    client.sendall(q("select 1"))
    check(kinds(read_answer(client)) == b"CZ", "the next statement is answered as usual: the rollback's answers did not reach it")
    client.sendall(q("select sluice_confirm()"))  # too late: an ordinary statement now, which the database answers
    check(kinds(read_answer(client)) == b"CZ", "no longer special: it goes to the database like any statement")
    client.close()
    upstream.finish()
    check(upstream.seen["queries"][:3] == ["BEGIN; delete from users where id < 5 RETURNING *", "ROLLBACK", "select 1"],
          f"{upstream.seen['queries']}")
    check(sluice.wait_event("confirm")["outcome"] == "timeout", "logged")
    check(sluice.stop() == 0, "clean shutdown")


def scenario_extended_in_the_session():
    """The same for a driver that prepares its statements: the cycle is answered with the question, its Sync by
    sluice, and the person's answer is a cycle of its own."""
    upstream, sluice, client = ext_session(session=True)
    client.sendall(parse_msg(b"", DELETE_SQL) + bind_msg() + describe_msg(b"P") + execute_msg() + SYNC)
    answer = read_until_z(client)
    check(kinds(answer) == b"12nEZ" and answer[4][1] == b"T", f"the question takes the place of the tag: {kinds(answer)}")
    check("DELETE 3 waiting for you" in error_fields(answer[3][1])["M"], "")
    time.sleep(0.2)
    check("S" not in [m[0] for m in upstream.seen["msgs"]], f"the database has not been synced: {upstream.seen['msgs']}")

    # another statement while it waits: refused, the rest of its cycle ignored, its Sync answered
    client.sendall(parse_msg(b"", "select 1") + bind_msg() + execute_msg() + SYNC)
    answer = read_until_z(client)
    check(kinds(answer) == b"EZ" and "waiting for your answer" in error_fields(answer[0][1])["M"], f"{kinds(answer)}")
    time.sleep(0.1)
    check(not any(m[1] == "select 1" for m in upstream.seen["msgs"]), "it never reached the database")

    # show, in a cycle of its own: the question again
    client.sendall(parse_msg(b"", "show") + bind_msg() + execute_msg() + SYNC)
    answer = read_until_z(client)
    check(kinds(answer) == b"EZ" and "waiting for you" in error_fields(answer[0][1])["M"], f"{kinds(answer)}")
    # yes
    client.sendall(parse_msg(b"", "yes") + bind_msg() + describe_msg(b"P") + execute_msg() + SYNC)
    answer = read_until_z(client)
    check(kinds(answer) == b"12nCZ" and answer[3][1] == b"DELETE 3\0",
          f"the answer of the statement that lets the cycle go on carries the tag of the DELETE: {answer}")
    client.sendall(q("select 1"))
    check(kinds(read_answer(client)) == b"CZ", "and the session goes on")
    client.close()
    upstream.finish()
    check(upstream.seen["commits"][0] == "commit", f"committed by the Sync of that cycle: {upstream.seen['commits']}")
    check(any(m == ("P", "SET sluice.confirmed = 'on'") for m in upstream.seen["msgs"]),
          f"the call became a harmless statement: {upstream.seen['msgs']}")
    check(sluice.wait_event("confirm")["outcome"] == "yes", "logged")
    check(sluice.stop() == 0, "clean shutdown")

    # a driver that rolls back: a message that fails is sent first (a ROLLBACK outside a transaction block
    # would only warn, and the next Sync would commit), its answers do not reach the client
    upstream, sluice, client = ext_session(session=True)
    client.sendall(parse_msg(b"", DELETE_SQL) + bind_msg() + execute_msg() + SYNC)
    read_until_z(client)
    client.sendall(q("rollback"))
    answer = read_answer(client)
    check(kinds(answer) == b"CZ" and answer[0][1] == b"ROLLBACK\0", f"{answer}")
    client.close()
    upstream.finish()
    queries_seen = [m[1] for m in upstream.seen["msgs"] if m[0] == "Q"]
    check(len(queries_seen) == 2 and "::int" in queries_seen[0] and queries_seen[1] == "rollback",
          f"the failing message, then the client's own: {queries_seen}")
    check(sluice.stop() == 0, "clean shutdown")

    # no
    upstream, sluice, client = ext_session(session=True)
    client.sendall(parse_msg(b"", DELETE_SQL) + bind_msg() + execute_msg() + SYNC)
    read_until_z(client)
    client.sendall(parse_msg(b"", "no") + bind_msg() + execute_msg() + SYNC)
    answer = read_until_z(client)
    check(kinds(answer) == b"EZ" and "nothing was changed" in error_fields(answer[0][1])["M"], f"{kinds(answer)}")
    client.close()
    upstream.finish()
    check(upstream.seen["commits"][0] == "rollback", f"{upstream.seen['commits']}")
    check(sluice.stop() == 0, "clean shutdown")


def scenario_extended_yes_and_no():
    """P B D E S in one go: the Execute is held, shown with the rows, and the Sync (the commit) waits for the
    answer. The client sees what it would have seen without sluice: NoData, and the command tag."""
    tty = Tty()
    try:
        upstream, sluice, client = ext_session(tty=tty)
        client.sendall(parse_msg(b"", DELETE_SQL) + bind_msg() + describe_msg(b"P") + execute_msg() + SYNC)
        text = tty.wait_for("commit? [y/N]")
        check("deleted 3 rows" in text and "agent@mydb" in text and "confirm-deletes" in text, text)
        check("user0@example.com" in text and "id" in text and "email" in text, f"rows and names shown: {text!r}")
        check("RETURNING" not in text, "the text added to the statement is not shown")
        # the Sync (which commits) has not reached the database while the person decides
        time.sleep(0.2)
        check("S" not in [m[0] for m in upstream.seen["msgs"]], f"held: {upstream.seen['msgs']}")
        tty.answer("y\n")
        answer = read_until_z(client)
        check(kinds(answer) == b"12nCZ" and answer[3][1] == b"DELETE 3\0" and answer[4][1] == b"I",
              f"the client sees ParseComplete, BindComplete, NoData, the tag, ReadyForQuery: {kinds(answer)}")
        client.sendall(q("select 1"))
        check(kinds(read_answer(client)) == b"CZ", "and the session goes on")
        client.close()
        upstream.finish()
        sent = upstream.seen["msgs"]
        check(sent[0] == ("P", DELETE_SQL + " RETURNING *"), f"the statement was given a RETURNING: {sent[0]}")
        check([m[0] for m in sent[:7]] == ["P", "B", "D", "D", "E", "H", "S"],
              f"Parse Bind Describe, sluice's Describe, Execute, Flush, then the held Sync: {sent}")
        check(upstream.seen["commits"] == ["commit"], f"committed by the Sync: {upstream.seen['commits']}")
        event = sluice.wait_event("confirm")
        check(event["outcome"] == "yes" and event["rows"] == 3 and event["protocol"] == "extended"
              and event["rule"] == "confirm-deletes" and event["detail"] is True, f"the log: {event}")
        check("user0@example.com" not in sluice.raw_text(), "the values of the rows are not in the log")
        check(sluice.stop() == 0, "clean shutdown")

        # no: an error of ours, the failing message sent, the cycle rolled back at the Sync
        tty.text = ""
        upstream, sluice, client = ext_session(tty=tty)
        client.sendall(parse_msg(b"", DELETE_SQL) + bind_msg() + describe_msg(b"P") + execute_msg() + SYNC)
        tty.wait_for("commit? [y/N]")
        tty.answer("n\n")
        answer = read_until_z(client)
        check(kinds(answer) == b"12nEZ" and answer[4][1] == b"I", f"an error and ReadyForQuery: {kinds(answer)}")
        fields = error_fields(answer[3][1])
        check(fields["C"] == "42501" and "not confirmed" in fields["M"] and "A person has to confirm" in fields["M"],
              f"the error is sluice's, not the server's: {fields}")
        client.sendall(q("select 1"))
        check(kinds(read_answer(client)) == b"CZ", "the session goes on after a no")
        client.close()
        upstream.finish()
        check(upstream.seen["commits"][0] == "rollback", f"rolled back: {upstream.seen['commits']}")
        check([m[0] for m in upstream.seen["msgs"][:7]] == ["P", "B", "D", "D", "E", "H", "P"]
              and "'::int" in upstream.seen["msgs"][6][1], f"a Parse that fails undoes it: {upstream.seen['msgs']}")
        check(sluice.wait_event("confirm")["outcome"] == "no", "logged as a no")
        check(sluice.stop() == 0, "clean shutdown")
    finally:
        tty.close()


def scenario_extended_prepared_and_reused():
    """A statement prepared once and run in later cycles, as ORMs do: each run is asked about, and Describe of the
    statement says there is no result."""
    tty = Tty()
    try:
        upstream, sluice, client = ext_session(tty=tty)
        client.sendall(parse_msg(b"stmt_1", DELETE_SQL) + describe_msg(b"S", b"stmt_1") + SYNC)
        answer = read_until_z(client)
        check(kinds(answer) == b"1tnZ", f"ParseComplete, parameters, NoData (not the RowDescription): {kinds(answer)}")
        for answer_with in ("y", "n", "y"):
            tty.text = ""
            client.sendall(bind_msg(b"", b"stmt_1") + execute_msg() + SYNC)
            tty.wait_for("commit? [y/N]")
            tty.answer(answer_with + "\n")
            answer = read_until_z(client)
            if answer_with == "y":
                check(kinds(answer) == b"2CZ", f"run: {kinds(answer)}")
            else:
                check(kinds(answer) == b"2EZ", f"refused: {kinds(answer)}")
        # a named portal, and Close
        tty.text = ""
        client.sendall(bind_msg(b"p1", b"stmt_1") + execute_msg(b"p1") + SYNC)
        tty.wait_for("commit? [y/N]")
        tty.answer("y\n")
        check(kinds(read_until_z(client)) == b"2CZ", "a named portal")
        client.sendall(close_msg(b"S", b"stmt_1") + SYNC)
        check(kinds(read_until_z(client)) == b"3Z", "Close")
        client.sendall(bind_msg(b"", b"stmt_1") + execute_msg() + SYNC)  # gone: the server says so, no question
        answer = read_until_z(client)
        check(kinds(answer) == b"EZ" and error_fields(answer[0][1])["C"] == "26000",
              f"after Close the statement is gone, and that is the server's own error: {kinds(answer)}")
        client.close()
        upstream.finish()
        check(upstream.seen["commits"][:5] == ["commit", "commit", "rollback", "commit", "commit"],
              f"commits: {upstream.seen['commits']}")
        check(sluice.stop() == 0, "clean shutdown")
    finally:
        tty.close()


def scenario_extended_pipeline_and_errors():
    """Several statements sent without waiting: the answers are matched to the right ones; an error before the
    guarded Execute means nothing is asked; a plain batch of thousands of Executes is not refused."""
    tty = Tty()
    try:
        upstream, sluice, client = ext_session(tty=tty)
        # a SELECT first, then the DELETE, in one batch
        client.sendall(parse_msg(b"", "select 1") + bind_msg() + describe_msg(b"P") + execute_msg()
                       + parse_msg(b"", DELETE_SQL) + bind_msg() + describe_msg(b"P") + execute_msg() + SYNC)
        tty.wait_for("commit? [y/N]")
        tty.answer("y\n")
        answer = read_until_z(client)
        check(kinds(answer) == b"12nDC" + b"12nCZ", f"answers in order: {kinds(answer)}")
        check(answer[4][1] == b"SELECT 1\0" and answer[8][1] == b"DELETE 3\0", "the right tags")

        # an error comes first: the DELETE is skipped by the server, so nothing is asked
        tty.text = ""
        client.sendall(parse_msg(b"", "select 'x'::int") + parse_msg(b"", DELETE_SQL) + bind_msg()
                       + execute_msg() + SYNC)
        answer = read_until_z(client)
        check(kinds(answer) == b"EZ", f"one error and ReadyForQuery: {kinds(answer)}")
        time.sleep(0.2)
        check(tty.text == "", f"nothing asked: {tty.text!r}")
        client.sendall(q("select 1"))
        check(kinds(read_answer(client)) == b"CZ", "the session goes on")
        client.sendall(parse_msg(b"", DELETE_SQL) + bind_msg() + execute_msg() + SYNC)
        tty.wait_for("commit? [y/N]")
        tty.answer("n\n")
        check(kinds(read_until_z(client)) == b"12EZ", "and the next one is asked about as usual")

        # an error when an earlier statement runs: the DELETE behind it was armed, and is not asked about
        tty.text = ""
        client.sendall(parse_msg(b"", "select boom") + bind_msg() + execute_msg()
                       + parse_msg(b"", DELETE_SQL) + bind_msg() + execute_msg() + SYNC)
        answer = read_until_z(client)
        check(kinds(answer) == b"12E" + b"Z" or kinds(answer) == b"1" + b"2EZ", f"{kinds(answer)}")
        check(sluice.wait_event("confirm", outcome="skipped")["protocol"] == "extended",
              "the confirmation that was armed is logged as skipped")
        time.sleep(0.2)
        check(tty.text == "", f"nothing asked: {tty.text!r}")
        client.sendall(q("select 1"))
        check(kinds(read_answer(client)) == b"CZ", "the session goes on")

        # a batch of 3000 plain Executes: not refused, answered in order
        n = 3000
        batch = b"".join(parse_msg(b"", "select 1") + bind_msg() + execute_msg() for _ in range(n)) + SYNC
        client.sendall(batch)
        answer = read_until_z(client)
        check(kinds(answer) == b"12DC" * n + b"Z", "a long batch is relayed and answered")
        client.close()
        upstream.finish()
        check(sluice.stop() == 0, "clean shutdown")
    finally:
        tty.close()


def scenario_extended_own_returning_and_refusals():
    """A statement with its own RETURNING keeps its rows; what cannot be confirmed is refused with a reason."""
    tty = Tty()
    try:
        upstream, sluice, client = ext_session(tty=tty)
        client.sendall(parse_msg(b"", DELETE_SQL + " returning id") + bind_msg() + describe_msg(b"P")
                       + execute_msg() + SYNC)
        text = tty.wait_for("commit? [y/N]")
        check("deleted 3 rows" in text, text)
        tty.answer("y\n")
        answer = read_until_z(client)
        check(kinds(answer) == b"12TDDDCZ", f"its own rows come back, with its own RowDescription: {kinds(answer)}")
        # a client's own RETURNING cannot be fetched a few rows at a time
        client.sendall(parse_msg(b"", DELETE_SQL + " returning id") + bind_msg() + execute_msg(b"", 5) + SYNC)
        answer = read_until_z(client)
        check(kinds(answer) == b"12EZ" and "row limit" in error_fields(answer[2][1])["M"],
              f"a row limit on its own RETURNING is refused with a reason: {answer}")
        # but the limit pgjdbc sends for every DELETE (1) means nothing for a statement sluice gave a RETURNING
        client.sendall(parse_msg(b"", DELETE_SQL) + bind_msg() + execute_msg(b"", 1) + SYNC)
        text = tty.wait_for("commit? [y/N]")
        tty.answer("y\n")
        answer = read_until_z(client)
        check(kinds(answer) == b"12CZ" and answer[2][1] == b"DELETE 3\0", f"run without the limit: {answer}")
        # a name too long to follow the way the server does
        long_name = b"n" * 70
        client.sendall(bind_msg(b"", long_name) + SYNC)
        answer = read_until_z(client)
        check(kinds(answer) == b"EZ" and "too long" in error_fields(answer[0][1])["M"], f"long name: {answer}")
        client.close()
        upstream.finish()
        check(upstream.seen["msgs"][0][1] == DELETE_SQL + " returning id", "the client's own RETURNING is untouched")
        check(sluice.stop() == 0, "clean shutdown")

        # in the client's own transaction: a no aborts it, as any failing statement would
        tty.text = ""
        upstream, sluice, client = ext_session(tty=tty)
        client.sendall(q("begin"))
        check(kinds(read_answer(client)) == b"CZ", "begin")
        client.sendall(parse_msg(b"", DELETE_SQL) + bind_msg() + execute_msg() + SYNC)
        tty.wait_for("commit? [y/N]")
        tty.answer("n\n")
        answer = read_until_z(client)
        check(kinds(answer) == b"12EZ" and answer[3][1] == b"E", f"the transaction is aborted: {answer}")
        client.sendall(q("rollback"))
        read_answer(client)
        client.close()
        upstream.finish()
        check(sluice.stop() == 0, "clean shutdown")
    finally:
        tty.close()


def scenario_extended_without_terminal_and_client_leaves():
    """No terminal: rolled back with the reason. The client leaves while it waits: the Sync never goes, so
    nothing is committed."""
    upstream, sluice, client = ext_session(tty=None)
    client.sendall(parse_msg(b"", DELETE_SQL) + bind_msg() + execute_msg() + SYNC)
    answer = read_until_z(client)
    check(kinds(answer) == b"12EZ" and "no terminal" in error_fields(answer[2][1])["M"], f"{answer}")
    client.close()
    upstream.finish()
    check("commit" not in upstream.seen["commits"], f"nothing committed: {upstream.seen['commits']}")
    check(sluice.wait_event("confirm")["outcome"] == "no_terminal", "logged")
    check(sluice.stop() == 0, "clean shutdown")

    tty = Tty()
    try:
        upstream, sluice, client = ext_session(tty=tty)
        client.sendall(parse_msg(b"", DELETE_SQL) + bind_msg() + execute_msg() + SYNC)
        tty.wait_for("commit? [y/N]")
        client.close()  # leaves while the question is on the terminal
        upstream.finish()
        check("S" not in [m[0] for m in upstream.seen["msgs"]], f"the held Sync never went: {upstream.seen['msgs']}")
        check(upstream.seen["commits"] == [], f"{upstream.seen['commits']}")
        check(sluice.stop() == 0, "clean shutdown")
    finally:
        tty.close()



def scenario_confirm_by_command():
    """The question can be put to a command instead of a terminal: it gets the question on its standard input, and its
    exit status is the answer. It inherits nothing of sluice's (no socket), and a failing command is a no."""
    with tempfile.TemporaryDirectory() as d:
        asked = os.path.join(d, "asked")
        mark = os.path.join(d, "approve")
        fds = os.path.join(d, "fds")
        script = os.path.join(d, "approver.sh")
        with open(script, "w") as f:
            f.write(f"#!/bin/sh\ncat > {asked}\n"
                    f"for i in 3 4 5 6 7 8 9; do test -e /dev/fd/$i && echo $i; done > {fds}\ntrue\ntest -f {mark}\n")
        os.chmod(script, 0o755)
        for protocol in ("simple", "extended"):
            for approve in (True, False):
                if os.path.exists(mark):
                    os.unlink(mark)
                if approve:
                    open(mark, "w").close()
                db = confirm_db(rows=3) if protocol == "simple" else ext_db(rows=3)
                upstream = FakeUpstream(db, tolerate=True)
                sluice = Sluice(upstream.port, policy=POLICY_CONFIRM, extra_args=["--confirm-command", script])
                client = open_session(sluice, user="agent", database="mydb")
                if protocol == "simple":
                    client.sendall(q("delete from users where id < 5"))
                    answer = read_answer(client)
                    want = b"CZ" if approve else b"EZ"
                else:
                    client.sendall(parse_msg(b"", DELETE_SQL) + bind_msg() + execute_msg() + SYNC)
                    answer = read_until_z(client)
                    want = b"12CZ" if approve else b"12EZ"
                check(kinds(answer) == want, f"{protocol}, approved={approve}: {kinds(answer)}")
                text = open(asked).read()
                check("deleted 3 rows" in text and "agent@mydb" in text, f"the question it was given: {text!r}")
                check(open(fds).read().strip() == "", f"it inherited nothing of sluice's: {open(fds).read()!r}")
                client.close()
                upstream.finish()
                event = sluice.wait_event("confirm")
                check(event["outcome"] == ("yes" if approve else "no"), f"logged: {event}")
                check(sluice.stop() == 0, "clean shutdown")

        # no command that can be run: a no, with the reason
        upstream = FakeUpstream(confirm_db(rows=3), tolerate=True)
        sluice = Sluice(upstream.port, policy=POLICY_CONFIRM, extra_args=["--confirm-command", "exit 7"])
        client = open_session(sluice, user="agent", database="mydb")
        client.sendall(q("delete from users where id < 5"))
        check(kinds(read_answer(client)) == b"EZ", "a failing command is a no")
        client.close()
        check(sluice.stop() == 0, "clean shutdown")

        # a command still running when the time is up is a no, and is killed
        policy = POLICY_CONFIRM.replace('"5s"', '"1s"')
        upstream = FakeUpstream(confirm_db(rows=3), tolerate=True)
        sluice = Sluice(upstream.port, policy=policy, extra_args=["--confirm-command", "sleep 30"])
        client = open_session(sluice, user="agent", database="mydb")
        started = time.monotonic()
        client.sendall(q("delete from users where id < 5"))
        answer = read_answer(client)
        check(kinds(answer) == b"EZ" and time.monotonic() - started < 10, "the time ran out: a no")
        check(sluice.wait_event("confirm")["outcome"] == "timeout", "logged as a timeout")
        client.close()
        check(sluice.stop() == 0, "clean shutdown")

    proc = subprocess.run([SLUICE, "--listen", "127.0.0.1:0", "--upstream", "127.0.0.1:1", "--confirm-command", "true",
                           "--confirm-tty", "/dev/null"], capture_output=True, text=True, timeout=TIMEOUT)
    check(proc.returncode == 2 and "choose one" in proc.stderr, f"both ways to ask: {proc.returncode} {proc.stderr!r}")


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
            check(sluice.stop() == 0, "clean shutdown")  # (it waits for the end of the log)
            adjusted = [e for e in sluice.events if e["event"] == "auth_adjusted"]
            return got, adjusted

    with tempfile.TemporaryDirectory() as probe_dir:  # its own directory: two test runs may overlap
        if make_cert(probe_dir, "probe", "DNS:localhost") is None:
            print("    (skipped: no openssl tool able to make a certificate)")
            return

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
        scenario_confirm_by_command,
        scenario_confirm_in_the_session,
        scenario_confirm_truncate_and_drop,
        scenario_limit_without_asking,
        scenario_check_policy_command,
        scenario_result_limits,
        scenario_merge_and_upsert_are_updates_and_deletes,
        scenario_undo_journal,
        scenario_undo_journal_update,
        scenario_undo_journal_keeps_what_a_mask_hides,
        scenario_undo_journal_rotation,
        scenario_duration_limit,
        scenario_budgets,
        scenario_confirm_via,
        scenario_budgets_survive_a_reload,
        scenario_masking_simple_protocol,
        scenario_masking_qualified_names,
        scenario_session_and_dangerous_guards,
        scenario_log_chain,
        scenario_admin_metrics,
        scenario_webhook_script,
        scenario_confirm_by_admin_and_event_command,
        scenario_learn_and_policy_tests,
        scenario_round_trip_budget_and_transaction_limit,
        scenario_application_name_is_tagged,
        scenario_masking_hash_is_stable,
        scenario_masking_extended_protocol,
        scenario_masking_cannot_be_got_around_by_the_session,
        scenario_masking_in_a_confirmation,
        scenario_masking_leaves_others_alone,
        scenario_more_proxy_limits,
        scenario_survives_garbage,
        scenario_extended_defences,
        scenario_confirm_in_the_session_times_out,
        scenario_extended_in_the_session,
        scenario_confirm_shows_side_effects,
        scenario_extended_yes_and_no,
        scenario_extended_prepared_and_reused,
        scenario_extended_pipeline_and_errors,
        scenario_extended_own_returning_and_refusals,
        scenario_extended_without_terminal_and_client_leaves,
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
