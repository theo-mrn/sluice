#!/usr/bin/env python3
"""sluice against a real PostgreSQL, in a throwaway Docker container.

The fake database of integration.py checks what sluice sends; this checks what a real server does with it, which
is what found the worst defects of this project (a statement that sluice read as one thing and the server as
another). It needs Docker and the image of PostgreSQL, so it is off unless asked for:

    SLUICE_REAL_PG=1 meson test -C build realpg
    SLUICE_REAL_PG=1 python3 tests/realpg.py build/sluice

SLUICE_PG_IMAGE chooses the image (default postgres:17-alpine). Nothing but the container it starts is touched.
Exit status 77 means skipped.
"""

import atexit
import base64
import hashlib
import hmac
import json
import os
import secrets
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

if os.environ.get("SLUICE_REAL_PG") != "1":
    print("skipped: set SLUICE_REAL_PG=1 to run against a real PostgreSQL (needs Docker)")
    sys.exit(77)

SLUICE = os.path.abspath(sys.argv[1])
IMAGE = os.environ.get("SLUICE_PG_IMAGE", "postgres:17-alpine")
TIMEOUT = 30.0
PASSWORD = secrets.token_hex(12)  # a login secret that must never reach the log

failures = []


def check(cond, what):
    if not cond:
        failures.append(what)
        print("FAIL:", what, file=sys.stderr)


def docker(*args, **kw):
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=120, **kw)


try:
    if docker("info").returncode != 0:
        raise OSError
except (OSError, subprocess.SubprocessError):
    print("skipped: Docker is not available")
    sys.exit(77)


# ---- the PostgreSQL protocol, just enough ----

def recv_exact(sock, n):
    chunks = []
    while n:
        data = sock.recv(min(n, 1 << 20))
        if not data:
            raise EOFError
        chunks.append(data)
        n -= len(data)
    return b"".join(chunks)


def read_message(sock):
    head = recv_exact(sock, 5)
    length = struct.unpack("!I", head[1:])[0]
    return head[:1], recv_exact(sock, length - 4)


def message(kind, payload=b""):
    return kind + struct.pack("!I", len(payload) + 4) + payload


def error_text(payload):
    for part in payload.split(b"\0"):
        if part[:1] == b"M":
            return part[1:].decode("utf-8", "replace")
    return "?"


class Pg:
    """One connection, logged in with SCRAM-SHA-256 (the default of a PostgreSQL with a password)."""

    def __init__(self, port, user="postgres", database="postgres", password=None, tls=False):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=TIMEOUT)
        if tls:  # as libpq with sslmode=require: no check of the certificate
            import ssl
            self.sock.sendall(struct.pack("!II", 8, 80877103))
            check(recv_exact(self.sock, 1) == b"S", "sluice agrees to TLS")
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self.sock = ctx.wrap_socket(self.sock, server_hostname="localhost")
            self.sock.settimeout(TIMEOUT)
        body = f"user\0{user}\0database\0{database}\0\0".encode()
        self.sock.sendall(struct.pack("!II", 8 + len(body), 196608) + body)
        kind, payload = read_message(self.sock)
        if kind == b"E":
            raise AssertionError("login refused: " + error_text(payload))
        assert kind == b"R" and struct.unpack("!I", payload[:4])[0] == 10, f"expected SASL, got {kind} {payload[:20]!r}"
        nonce = base64.b64encode(os.urandom(18)).decode()
        first_bare = f"n=,r={nonce}"
        init = b"SCRAM-SHA-256\0" + struct.pack("!I", len(first_bare) + 3) + b"n,," + first_bare.encode()
        self.sock.sendall(message(b"p", init))
        kind, payload = read_message(self.sock)
        server_first = payload[4:].decode()
        fields = dict(f.split("=", 1) for f in server_first.split(","))
        salted = hashlib.pbkdf2_hmac("sha256", (password or PASSWORD).encode(), base64.b64decode(fields["s"]), int(fields["i"]))
        client_key = hmac.new(salted, b"Client Key", "sha256").digest()
        final_no_proof = f"c=biws,r={fields['r']}"
        auth_message = f"{first_bare},{server_first},{final_no_proof}".encode()
        signature = hmac.new(hashlib.sha256(client_key).digest(), auth_message, "sha256").digest()
        proof = base64.b64encode(bytes(a ^ b for a, b in zip(client_key, signature))).decode()
        self.sock.sendall(message(b"p", f"{final_no_proof},p={proof}".encode()))
        while True:
            kind, payload = read_message(self.sock)
            if kind == b"E":
                raise AssertionError("login failed: " + error_text(payload))
            if kind == b"Z":
                break

    def results(self):
        """Reads up to ReadyForQuery: [(command tag or None, rows, error or None)]."""
        out, rows, error = [], [], None
        while True:
            kind, payload = read_message(self.sock)
            if kind == b"D":
                n = struct.unpack("!H", payload[:2])[0]
                pos, row = 2, []
                for _ in range(n):
                    length = struct.unpack("!i", payload[pos:pos + 4])[0]
                    pos += 4
                    if length < 0:
                        row.append(None)
                    else:
                        row.append(payload[pos:pos + length].decode("utf-8", "replace"))
                        pos += length
                rows.append(tuple(row))
            elif kind == b"C":
                out.append((payload.rstrip(b"\0").decode(), rows, None))
                rows = []
            elif kind == b"E":
                error = error_text(payload)
            elif kind == b"Z":
                if error is not None:
                    out.append((None, rows, error))
                return out

    def query(self, sql):
        sql = sql.encode() if isinstance(sql, str) else sql
        self.sock.sendall(message(b"Q", sql + b"\0"))
        return self.results()

    def extended(self, sql, params):
        """Parse, Bind (text parameters), Execute, Sync: the way drivers send a statement with arguments."""
        bind = b"\0\0" + struct.pack("!HH", 0, len(params))
        for p in params:
            bind += struct.pack("!I", len(p)) + p.encode()
        bind += struct.pack("!H", 0)
        self.sock.sendall(message(b"P", b"\0" + sql.encode() + b"\0" + struct.pack("!H", 0)) + message(b"B", bind) +
                          message(b"E", b"\0" + struct.pack("!I", 0)) + message(b"S"))
        out, rows, error = [], [], None
        while True:
            kind, payload = read_message(self.sock)
            if kind == b"D":
                length = struct.unpack("!i", payload[2:6])[0]
                rows.append((payload[6:6 + length].decode(),))
            elif kind == b"C":
                out.append((payload.rstrip(b"\0").decode(), rows, None))
                rows = []
            elif kind == b"E":
                error = error_text(payload)
            elif kind == b"Z":
                return out + ([(None, [], error)] if error else [])

    def close(self):
        try:
            self.sock.sendall(message(b"X"))
        except OSError:
            pass
        self.sock.close()


# ---- the database, and sluice in front of it ----

name = "sluice-itest-realpg-" + secrets.token_hex(3)
atexit.register(lambda: docker("stop", name))
started = docker("run", "-d", "--rm", "--name", name, "-e", f"POSTGRES_PASSWORD={PASSWORD}", "-p", "127.0.0.1::5432",
                 IMAGE)
if started.returncode != 0:
    print("cannot start the database container:", started.stderr.strip(), file=sys.stderr)
    sys.exit(1)
deadline = time.monotonic() + 90
while time.monotonic() < deadline:
    if docker("exec", name, "pg_isready", "-U", "postgres").returncode == 0:
        time.sleep(2)  # the image restarts the server once after its first start
        if docker("exec", name, "pg_isready", "-U", "postgres").returncode == 0:
            break
    time.sleep(0.5)
DB_PORT = int(docker("port", name, "5432/tcp").stdout.strip().rsplit(":", 1)[1])


def sql_direct(sql):
    out = docker("exec", name, "psql", "-U", "postgres", "-qAt", "-c", sql)
    return out.stdout.strip()


class Sluice:
    def __init__(self, policy=None, args=(), listen="127.0.0.1:0"):
        argv = [SLUICE, "--listen", listen, "--upstream", f"127.0.0.1:{DB_PORT}", *args]
        self.policy_path = None
        if policy is not None:
            handle = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
            handle.write(policy)
            handle.close()
            self.policy_path = handle.name
            argv += ["--policy", handle.name]
            atexit.register(lambda p=handle.name: os.path.exists(p) and os.unlink(p))
        self.proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        atexit.register(lambda: self.proc.poll() is None and self.proc.kill())
        self.lines = [self.proc.stdout.readline()]
        self.port = json.loads(self.lines[0])["port"]
        threading.Thread(target=lambda: [self.lines.append(line) for line in self.proc.stdout], daemon=True).start()

    def events(self):
        return [json.loads(line) for line in list(self.lines) if line.strip()]

    def wait_event(self, name):
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline:
            for e in self.events():
                if e["event"] == name:
                    return e
            time.sleep(0.05)
        check(False, f"no {name} event")

    def stop(self):
        self.proc.send_signal(signal.SIGTERM)
        self.proc.wait(TIMEOUT)

    def text(self):
        return "".join(self.lines)


ENFORCE = """
mode = "enforce"

[[rule]]
name = "no-unbounded-write"
match = "update_or_delete_without_where"
message = "add a WHERE clause"

[[rule]]
name = "no-ddl"
match = "ddl"
"""


def fresh_table(db_name="t", rows=5):
    sql_direct(f"drop table if exists {db_name}; create table {db_name} as select generate_series(1, {rows}) n")


def count(db_name="t"):
    return int(sql_direct(f"select count(*) from {db_name}"))


# ---- the scenarios ----

def scenario_login_and_queries():
    """SCRAM login, simple and extended queries, a COPY-free result set, through sluice."""
    sluice = Sluice()
    pg = Pg(sluice.port)
    check(pg.query("select 1 as one, 'two'") == [("SELECT 1", [("1", "two")], None)], "a simple query")
    check(pg.extended("select $1::int + 1", ["41"]) == [("SELECT 1", [("42",)], None)], "an extended query with a parameter")
    big = pg.query("select repeat('x', 5000000)")
    check(len(big[0][1][0][0]) == 5000000, "a result of 5 MB crosses intact")
    pg.close()
    check(not any(PASSWORD in line for line in sluice.lines), "the login password is nowhere in the log")
    sluice.stop()


def scenario_rules_hold():
    """A rule blocks what it says on a real server, and only that; the session goes on."""
    fresh_table()
    sluice = Sluice(ENFORCE)
    pg = Pg(sluice.port)
    check(pg.query("delete from t")[0][2] is not None and "no-unbounded-write" in pg.query("delete from t")[0][2],
          "a delete without WHERE is refused, with the reason")
    check(count() == 5, "and nothing was deleted")
    check(pg.query("delete from t where n = 1")[0][0] == "DELETE 1", "with a WHERE it runs")
    check(pg.query("create table z (i int)")[0][2] is not None, "DDL is refused by its rule")
    check(pg.query("select count(*) from t")[0][1] == [("4",)], "the same session still works")
    check(pg.extended("delete from t", [])[-1][2] is not None, "also through the extended protocol")
    check(count() == 4, "which deletes nothing either")
    pg.close()
    sluice.stop()


def scenario_strings_cannot_hide_a_statement():
    """The bypass found on a real server: after SET standard_conforming_strings = off, or with a multi-byte
    client_encoding, the server cuts a string where sluice does not. First proof that the attacks work on this
    server without sluice, then that they do not through it."""
    attacks = [
        ("set standard_conforming_strings = off", b"select 'x\\'\n'; delete from t; --'"),
        ("set client_encoding = 'SJIS'", b"select E'\x95\\'; delete from t; --'"),
    ]
    for setting, attack in attacks:
        fresh_table()
        # control: straight to the database, the delete runs. If it does not, this server version has closed the
        # hole itself and there is nothing to guard against here.
        direct_ok = True
        try:
            sluice = Sluice()  # without rules: relays everything, and reaches the same server
            pg = Pg(sluice.port)
            pg.query(setting)
            pg.query(attack)
            pg.close()
            sluice.stop()
            direct_ok = count() == 0
        except AssertionError:
            direct_ok = False
        print(f"    ({setting}: the attack {'works' if direct_ok else 'does not work'} against this server)")
        fresh_table()
        sluice = Sluice(ENFORCE)
        pg = Pg(sluice.port)
        pg.query(setting)
        refused = pg.query(attack)
        check(count() == 5, f"{setting}: the table is intact through sluice")
        check(refused and refused[-1][2] is not None, f"{setting}: the statement was refused")
        pg.close()
        sluice.stop()
    # the usual backslashes are not in the way
    sluice = Sluice(ENFORCE)
    pg = Pg(sluice.port)
    check(pg.query(r"select 'abc123' ~ '^\w+\d{3}$'")[0][1] == [("t",)], "a regular expression works")
    check(pg.query(r"select 'C:\\'")[0][1] == [("C:\\\\",)] or pg.query(r"select 'C:\\'")[0][0] == "SELECT 1", "a path works")
    check(pg.query(r"select E'it\'s'")[0][1] == [("it's",)], "an escape string works")
    pg.close()
    sluice.stop()


def scenario_tables_and_search_path():
    """A rule that keeps a client in one schema holds when the client moves its search_path."""
    sql_direct("create schema if not exists tenant_a; create schema if not exists tenant_b; "
               "drop table if exists tenant_a.orders; drop table if exists tenant_b.orders; "
               "create table tenant_a.orders as select 1 n; create table tenant_b.orders as select generate_series(1,2) n")
    policy = 'mode = "enforce"\n[[rule]]\nname = "tenant-a-only"\nmatch = "any"\noutside_tables = ["tenant_a.orders"]\n'
    sluice = Sluice(policy)
    pg = Pg(sluice.port)
    check(pg.query("select * from tenant_a.orders")[0][1] == [("1",)], "the allowed table is readable")
    check(pg.query("select * from tenant_b.orders")[0][2] is not None, "another schema is refused")
    pg.query("set search_path = tenant_b")
    refused = pg.query("select * from orders")
    check(refused and refused[-1][2] is not None, "orders without a schema is not trusted after the search_path moved")
    pg.close()
    sluice.stop()


def scenario_reload_on_a_live_connection():
    """SIGHUP changes the rules of a session that is already open, and a bad file changes nothing."""
    fresh_table()
    sluice = Sluice('mode = "enforce"\n[[rule]]\nname = "no-drop"\nmatch = "drop"\n')
    pg = Pg(sluice.port)
    check(pg.query("delete from t where n = 5")[0][0] == "DELETE 1", "allowed before")
    with open(sluice.policy_path, "w") as f:
        f.write(ENFORCE)
    sluice.proc.send_signal(signal.SIGHUP)
    sluice.wait_event("policy_reloaded")
    check(pg.query("delete from t")[0][2] is not None, "refused after the reload, on the same connection")
    with open(sluice.policy_path, "w") as f:
        f.write("this is not a policy\n")
    sluice.proc.send_signal(signal.SIGHUP)
    sluice.wait_event("policy_reload_failed")
    check(pg.query("delete from t")[0][2] is not None, "a bad file leaves the rules in force")
    check(count() == 4, "the data is untouched")
    pg.close()
    sluice.stop()


def scenario_secrets_stay_out_of_the_log():
    """--log-sql normalized and none, with real secrets in the statements, on a real server."""
    secret = "s3cr3t-" + secrets.token_hex(6)
    for mode in ("normalized", "none"):
        sluice = Sluice(args=["--log-sql", mode])
        pg = Pg(sluice.port)
        sql_direct("drop table if exists vault; create table vault (token text)")
        pg.query(f"create role eve_{mode} login password '{secret}'")
        pg.query(f"insert into vault values ('{secret}')")
        pg.query(f"select * from vault where token = '{secret}'")
        pg.query(f"comment on table vault is '{secret}'")
        pg.query(f"select 1 -- {secret}")
        pg.close()
        sql_direct(f"drop role if exists eve_{mode}")
        sluice.stop()
        check(secret not in sluice.text(), f"--log-sql {mode}: the secret is not in the log")
        check(PASSWORD not in sluice.text(), f"--log-sql {mode}: nor is the login password")
        check(sql_direct("select count(*) from vault") == "1", f"--log-sql {mode}: and the statements did run")


def scenario_tls_with_a_client_certificate():
    """verify-full to a database that requires a client certificate: the case that is hard to set up by hand."""
    tool = os.environ.get("SLUICE_OPENSSL") or "openssl"
    # in a directory that Docker can share (the temporary directory of macOS is not under /private/tmp)
    base = "/private/tmp" if os.path.isdir("/private/tmp") else tempfile.gettempdir()
    with tempfile.TemporaryDirectory(dir=base) as d:
        def cert(label, sans):
            try:
                subprocess.run([tool, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                                "-nodes", "-keyout", f"{d}/{label}.key", "-out", f"{d}/{label}.crt", "-days", "2",
                                "-subj", f"/CN={label}", "-addext", f"subjectAltName={sans}"],
                               check=True, capture_output=True, timeout=30)
            except (OSError, subprocess.SubprocessError):
                return False
            return True

        if not (cert("server", "DNS:localhost,IP:127.0.0.1") and cert("sluice-client", "DNS:sluice")):
            print("    (skipped: no openssl tool able to make a certificate)")
            return
        for f in ("server.key", "sluice-client.key"):
            os.chmod(f"{d}/{f}", 0o644)
        with open(f"{d}/pg_hba.conf", "w") as f:
            f.write("local all all trust\nhostssl all all all scram-sha-256 clientcert=verify-ca\nhost all all all reject\n")
        tname = name + "-tls"
        atexit.register(lambda: docker("stop", tname))
        script = ("mkdir -p /etc/pgssl && cp /certs/server.crt /certs/server.key /certs/sluice-client.crt "
                  "/certs/pg_hba.conf /etc/pgssl/ && chown postgres /etc/pgssl/* && chmod 600 /etc/pgssl/server.key && "
                  "exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/etc/pgssl/server.crt "
                  "-c ssl_key_file=/etc/pgssl/server.key -c ssl_ca_file=/etc/pgssl/sluice-client.crt "
                  "-c hba_file=/etc/pgssl/pg_hba.conf")
        started = docker("run", "-d", "--rm", "--name", tname, "-e", f"POSTGRES_PASSWORD={PASSWORD}", "-p",
                         "127.0.0.1::5432", "-v", f"{d}:/certs:ro", "--entrypoint", "sh", IMAGE, "-c", script)
        if started.returncode != 0:
            check(False, "cannot start the TLS database: " + started.stderr.strip())
            return
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if docker("exec", tname, "pg_isready", "-U", "postgres").returncode == 0:
                time.sleep(2)
                if docker("exec", tname, "pg_isready", "-U", "postgres").returncode == 0:
                    break
            time.sleep(0.5)
        port = int(docker("port", tname, "5432/tcp").stdout.strip().rsplit(":", 1)[1])

        def run_sluice(extra):
            argv = [SLUICE, "--listen", "127.0.0.1:0", "--upstream", f"127.0.0.1:{port}", "--upstream-tls",
                    "verify-full", "--upstream-ca", f"{d}/server.crt", *extra]
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            atexit.register(lambda: proc.poll() is None and proc.kill())
            first = json.loads(proc.stdout.readline())
            lines = []
            threading.Thread(target=lambda: [lines.append(line) for line in proc.stdout], daemon=True).start()
            return proc, first["port"], lines

        proc, sport, lines = run_sluice(["--upstream-cert", f"{d}/sluice-client.crt",
                                         "--upstream-key", f"{d}/sluice-client.key"])
        pg = Pg(sport)
        who = pg.query("select ssl, version, client_dn from pg_stat_ssl where pid = pg_backend_pid()")
        check(who and who[0][1] and who[0][1][0][0] == "t" and who[0][1][0][1].startswith("TLSv1") and
              "sluice-client" in who[0][1][0][2], f"the database sees TLS and the client certificate: {who}")
        pg.close()
        proc.send_signal(signal.SIGTERM)
        proc.wait(TIMEOUT)

        proc, sport, lines = run_sluice([])
        try:
            Pg(sport)
            check(False, "without the certificate the database must refuse the login")
        except (AssertionError, EOFError, OSError) as exc:
            check("certificate" in str(exc) or isinstance(exc, (EOFError, OSError)), f"refused without it: {exc}")
        proc.send_signal(signal.SIGTERM)
        proc.wait(TIMEOUT)


class Tty:
    """The terminal on which a person is asked: a pseudo-terminal, this test being the person."""

    def __init__(self):
        import pty
        self.master, self.slave = pty.openpty()
        self.path = os.ttyname(self.slave)
        os.set_blocking(self.master, False)
        self.text = ""

    def wait_for(self, needle):
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline:
            try:
                self.text += os.read(self.master, 4096).decode("utf-8", "replace")
            except BlockingIOError:
                time.sleep(0.02)
            if needle in self.text:
                return self.text
        check(False, f"{needle!r} never appeared on the terminal: {self.text!r}")
        return self.text

    def answer(self, line):
        self.text = ""
        os.write(self.master, line.encode())

    def close(self):
        os.close(self.master)
        os.close(self.slave)


CONFIRM_POLICY = """
mode = "enforce"
confirm_timeout = "20s"

[[rule]]
name = "confirm-writes"
match = "delete"
action = "confirm"
over_rows = "5"
message = "A person has to confirm this."

[[rule]]
name = "confirm-updates"
match = "update"
action = "confirm"
over_rows = "5"
"""


def ask_and_answer(pg, tty, sql, line):
    """Sends a statement that will make sluice ask, answers on the terminal, returns what the client gets."""
    pg.sock.sendall(message(b"Q", sql.encode() + b"\0"))
    text = tty.wait_for("commit? [y/N]")
    if os.environ.get("SLUICE_SHOW_PROMPTS"):
        print(text.replace("\r", ""))
    tty.answer(line)
    return text, pg.results()


def scenario_confirm_deletes():
    """A DELETE or UPDATE that touches many rows is run in a transaction, shown, and committed or rolled back as
    the person says. The statement is the client's own: the count and the rows are the real ones."""
    tty = Tty()
    try:
        fresh_table("t", 50)
        sluice = Sluice(CONFIRM_POLICY, args=["--confirm-tty", tty.path])
        pg = Pg(sluice.port)

        # few rows: nobody is asked
        check(pg.query("delete from t where n <= 3") == [("DELETE 3", [], None)], "under the threshold it just runs")
        check(count() == 47 and tty.text == "", "committed, and no question")

        # many rows, and a no: nothing changes
        text, res = ask_and_answer(pg, tty, "delete from t where n between 10 and 29", "n\n")
        check("deleted 20 rows" in text and "agent" not in text and "(not committed yet)" in text, f"the question: {text!r}")
        check(all(str(v) in text for v in (10, 11, 12)), "the rows that would go are shown")
        check(res[0][0] is None and "not confirmed" in res[0][2] and "A person has to confirm this" in res[0][2], f"{res}")
        check(count() == 47, "a no leaves all 47 rows")
        check(pg.query("select count(*) from t")[0][1] == [("47",)], "and the session works")

        # many rows, and a yes: committed, the client sees what it would have seen
        text, res = ask_and_answer(pg, tty, "delete from t where n between 10 and 29", "y\n")
        check(res == [("DELETE 20", [], None)], f"the client's own answer: {res}")
        check(count() == 27, "a yes makes it final")

        # an UPDATE
        text, res = ask_and_answer(pg, tty, "update t set n = n + 1000", "y\n")
        check("changed 27 rows" in text and res == [("UPDATE 27", [], None)], f"{text!r} {res}")
        check(sql_direct("select min(n) from t") == "1004", "the update is final")

        # a client's own RETURNING comes back, as written
        fresh_table("t", 50)
        pg.sock.sendall(message(b"Q", b"delete from t where n > 40 returning n\0"))
        tty.wait_for("commit? [y/N]")
        tty.answer("y\n")
        res = pg.results()
        check(res[0][0] == "DELETE 10" and len(res[0][1]) == 10, f"its rows are given back: {res}")

        # inside the client's own transaction: a savepoint, and the transaction goes on
        fresh_table("t", 50)
        check(pg.query("begin")[0][0] == "BEGIN", "begin")
        text, res = ask_and_answer(pg, tty, "delete from t where n between 10 and 29", "y\n")
        check(res == [("DELETE 20", [], None)], f"{res}")
        check(pg.query("select count(*) from t")[0][1] == [("30",)], "visible in the client's transaction")
        check(count() == 50, "but not final: the client's transaction is not over")
        text, res = ask_and_answer(pg, tty, "delete from t where n between 30 and 49", "n\n")
        check(res[0][2] is not None and "not confirmed" in res[0][2], "a refusal inside the transaction")
        check(pg.query("select count(*) from t")[0][1] == [("30",)], "the transaction is still usable")
        check(pg.query("rollback")[0][0] == "ROLLBACK" and count() == 50, "and the client can still roll it back")

        # a client that disappears while the question is shown: nothing is committed
        pg2 = Pg(sluice.port)
        pg2.sock.sendall(message(b"Q", b"delete from t where n between 1 and 30\0"))
        tty.wait_for("commit? [y/N]")
        tty.answer("")
        pg2.sock.close()
        time.sleep(1.0)
        check(count() == 50, "the rows are all there")
        check(sql_direct("select count(*) from pg_stat_activity where state like 'idle in transaction%'") == "0",
              "and no transaction was left open")

        # a role that may delete but not read: RETURNING cannot be used, the count is still shown
        sql_direct("drop table if exists blind; create table blind as select generate_series(1, 20) n; "
                   "drop role if exists blind_role; create role blind_role login password '" + PASSWORD + "'; "
                   "grant delete on blind to blind_role")
        pg3 = Pg(sluice.port, user="blind_role")
        pg3.sock.sendall(message(b"Q", b"delete from blind\0"))
        text = tty.wait_for("commit? [y/N]")
        check("deleted 20 rows" in text and "could not be read" in text, f"count only: {text!r}")
        tty.answer("y\n")
        check(pg3.results() == [("DELETE 20", [], None)], "and it works")
        check(sql_direct("select count(*) from blind") == "0", "final")
        pg3.close()

        events = [e for e in sluice.events() if e["event"] == "confirm"]
        check([e["outcome"] for e in events].count("yes") >= 4 and "no" in [e["outcome"] for e in events]
              and "auto" in [e["outcome"] for e in events], f"every decision is logged: {[e['outcome'] for e in events]}")
        check("1004" not in sluice.text() and "ana" not in sluice.text(), "the values of the rows are not in the log")
        check(PASSWORD not in sluice.text(), "nor the password")
        pg.close()
        sluice.stop()
        sql_direct("drop role if exists blind_role; drop table if exists blind")
    finally:
        tty.close()


def scenario_clients_over_tls():
    """The login and the rules through TLS toward the client: our own SCRAM client, then the real psql of the
    PostgreSQL image (sslmode=require, then sslmode=disable which must be refused)."""
    sluice = Sluice(policy=ENFORCE, args=["--listen-tls", "self-signed"])
    pg = Pg(sluice.port, tls=True)
    check(pg.query("select 1 as one") == [("SELECT 1", [("1",)], None)], "a query under TLS")
    big = pg.query("select repeat('x', 5000000)")
    check(len(big[0][1][0][0]) == 5000000, "a result of 5 MB crosses TLS intact")
    refused = pg.query("drop table if exists nothing_here")
    check(refused[0][2] is not None and "sluice" in refused[0][2], "the rules still apply under TLS")
    pg.close()
    sluice.stop()

    # the real psql, from the database's container, reaching sluice on the host
    sluice = Sluice(args=["--listen-tls", "self-signed"], listen="0.0.0.0:0")
    for mode, expect_ok in (("require", True), ("disable", False)):
        out = docker("exec", "-e", f"PGPASSWORD={PASSWORD}", "-e", f"PGSSLMODE={mode}", name, "psql", "-h",
                     "host.docker.internal", "-p", str(sluice.port), "-U", "postgres", "-qAt", "-c",
                     "select ssl from pg_stat_ssl where pid = pg_backend_pid()")
        if expect_ok:
            check(out.returncode == 0, f"psql sslmode=require logs in: {out.stderr.strip()!r}")
            check(out.stdout.strip() in ("t", "f"), f"psql gets its answer: {out.stdout!r}")
        else:
            check(out.returncode != 0 and "requires TLS" in out.stderr, f"psql sslmode=disable is refused: {out.stderr!r}")
    check(PASSWORD not in sluice.text(), "the password is nowhere in the log")
    sluice.stop()


for scenario in (scenario_login_and_queries, scenario_rules_hold, scenario_strings_cannot_hide_a_statement,
                 scenario_tables_and_search_path, scenario_reload_on_a_live_connection,
                 scenario_secrets_stay_out_of_the_log, scenario_confirm_deletes,
                 scenario_tls_with_a_client_certificate, scenario_clients_over_tls):
    started_at = time.monotonic()
    before = len(failures)
    try:
        scenario()
    except Exception as exc:  # a scenario that cannot even run is a failure, not a crash of the others
        check(False, f"{scenario.__name__} raised {exc!r}")
    print(f"{'ok ' if len(failures) == before else 'FAIL'} {scenario.__name__} ({time.monotonic() - started_at:.1f}s)")

docker("stop", name)
sys.exit(1 if failures else 0)
