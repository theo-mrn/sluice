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

    def __init__(self, port, user="postgres", database="postgres", password=None, tls=False, application_name=None):
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
        extra = f"application_name\0{application_name}\0" if application_name else ""
        body = f"user\0{user}\0database\0{database}\0{extra}\0".encode()
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
                 "--add-host", "host.docker.internal:host-gateway", IMAGE)  # psql and pgbench inside it reach sluice
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
        while json.loads(self.lines[-1])["event"] in ("chain_start", "admin_listening"):  # a chained log starts with its own line
            self.lines.append(self.proc.stdout.readline())
        self.port = json.loads(self.lines[-1])["port"]
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


def ext_send(pg, *msgs):
    pg.sock.sendall(b"".join(msgs))


def ext_read(pg):
    """The answer of one cycle: (the kinds of the messages up to ReadyForQuery, the command tags, the error text,
    the status of ReadyForQuery)."""
    kinds, tags, error = b"", [], None
    while True:
        kind, payload = read_message(pg.sock)
        kinds += kind
        if kind == b"C":
            tags.append(payload.rstrip(b"\0").decode())
        elif kind == b"E":
            error = error_text(payload)
        elif kind == b"Z":
            return kinds, tags, error, payload.decode()


def P(sql, name=b""):
    return message(b"P", name + b"\0" + sql.encode() + b"\0" + struct.pack("!H", 0))


def B(portal=b"", stmt=b""):
    return message(b"B", portal + b"\0" + stmt + b"\0" + struct.pack("!HHH", 0, 0, 0))


def D(kind, name=b""):
    return message(b"D", kind + name + b"\0")


def E(portal=b"", rows=0):
    return message(b"E", portal + b"\0" + struct.pack("!I", rows))


def scenario_confirm_extended_protocol():
    """The extended protocol against a real server: prepared statements, pipelines, the client's own transaction,
    and pgbench (a real client that prepares and re-runs its statements)."""
    tty = Tty()
    try:
        fresh_table("t", 50)
        sluice = Sluice(CONFIRM_POLICY, args=["--confirm-tty", tty.path], listen="0.0.0.0:0")
        pg = Pg(sluice.port)

        # P B D E S: asked, no -> rolled back at the Sync; yes -> committed at the Sync
        ext_send(pg, P("delete from t where n between 10 and 29"), B(), D(b"P"), E(), message(b"S"))
        text = tty.wait_for("commit? [y/N]")
        if os.environ.get("SLUICE_SHOW_PROMPTS"):
            print(text.replace("\r", ""))
        check("deleted 20 rows" in text and "(not committed yet)" in text and "n" in text, f"the question: {text!r}")
        check(count() == 50, "nothing is final while the person decides")
        tty.answer("n\n")
        kinds, tags, error, status = ext_read(pg)
        check(kinds == b"12nEZ" and "not confirmed" in error and status == "I", f"a no: {kinds} {error}")
        check(count() == 50, "a no leaves all 50 rows")
        ext_send(pg, P("delete from t where n between 10 and 29"), B(), D(b"P"), E(), message(b"S"))
        tty.wait_for("commit? [y/N]")
        tty.answer("y\n")
        kinds, tags, error, status = ext_read(pg)
        check(kinds == b"12nCZ" and tags == ["DELETE 20"] and status == "I", f"a yes: {kinds} {tags}")
        check(count() == 30, "a yes makes it final at the Sync")

        # a prepared statement re-run in later cycles, described as having no result
        fresh_table("t", 50)
        ext_send(pg, P("delete from t where n between 10 and 29", b"s1"), D(b"S", b"s1"), message(b"S"))
        kinds, tags, error, status = ext_read(pg)
        check(kinds == b"1tnZ", f"Describe of the statement says NoData: {kinds}")
        for answer, final in (("n\n", 50), ("y\n", 30)):
            ext_send(pg, B(b"", b"s1"), E(), message(b"S"))
            tty.wait_for("commit? [y/N]")
            tty.answer(answer)
            kinds, tags, error, status = ext_read(pg)
            check(count() == final, f"after {answer.strip()}: {count()} rows")
        check(kinds == b"2CZ", f"{kinds}")

        # a pipeline: a SELECT then the DELETE, no wait between them
        fresh_table("t", 50)
        ext_send(pg, P("select count(*) from t"), B(), D(b"P"), E(),
                 P("delete from t where n between 10 and 29"), B(), D(b"P"), E(), message(b"S"))
        tty.wait_for("commit? [y/N]")
        tty.answer("y\n")
        kinds, tags, error, status = ext_read(pg)
        check(kinds == b"12TDC12nCZ" and tags == ["SELECT 1", "DELETE 20"], f"{kinds} {tags}")

        # an error before the DELETE: the server skips it, nothing is asked
        tty.text = ""
        fresh_table("t", 50)
        ext_send(pg, P("select 1/0"), B(), E(), P("delete from t where n between 10 and 29"), B(), E(), message(b"S"))
        kinds, tags, error, status = ext_read(pg)
        check(kinds in (b"1EZ", b"12EZ") and "division by zero" in error, f"the server's own error: {kinds} {error}")
        time.sleep(0.3)
        check(tty.text == "" and count() == 50, "nothing asked, nothing deleted")
        check(pg.query("select 1")[0][0] == "SELECT 1", "the session goes on")

        # in the client's own transaction: a yes keeps the statement in it, a no aborts it like any error
        check(pg.query("begin")[0][0] == "BEGIN", "begin")
        ext_send(pg, P("delete from t where n between 10 and 29"), B(), E(), message(b"S"))
        tty.wait_for("commit? [y/N]")
        tty.answer("y\n")
        kinds, tags, error, status = ext_read(pg)
        check(kinds == b"12CZ" and status == "T", f"still in the transaction: {kinds} {status}")
        check(pg.query("select count(*) from t")[0][1] == [("30",)] and count() == 50, "visible only inside it")
        ext_send(pg, P("delete from t where n between 30 and 49"), B(), E(), message(b"S"))
        tty.wait_for("commit? [y/N]")
        tty.answer("n\n")
        kinds, tags, error, status = ext_read(pg)
        check(kinds == b"12EZ" and status == "E" and "not confirmed" in error, f"aborted: {kinds} {status}")
        check(pg.query("rollback")[0][0] == "ROLLBACK" and count() == 50, "rolled back, nothing lost")

        # a client's own RETURNING, and its rows
        ext_send(pg, P("delete from t where n > 40 returning n"), B(), D(b"P"), E(), message(b"S"))
        tty.wait_for("commit? [y/N]")
        tty.answer("y\n")
        kinds, tags, error, status = ext_read(pg)
        check(kinds == b"12T" + b"D" * 10 + b"CZ", f"its own rows come back: {kinds}")
        pg.close()

        # a role that may delete but not read: the added RETURNING is refused by the server, and that is what
        # the client is told (there is no fallback to the plain statement for a prepared one)
        sql_direct("drop table if exists blind; create table blind as select generate_series(1, 20) n; "
                   "drop role if exists blind_role; create role blind_role login password '" + PASSWORD + "'; "
                   "grant delete on blind to blind_role")
        pg3 = Pg(sluice.port, user="blind_role")
        ext_send(pg3, P("delete from blind"), B(), D(b"P"), E(), message(b"S"))
        kinds, tags, error, status = ext_read(pg3)
        check("permission denied" in (error or ""), f"the server's own refusal reaches the client: {kinds} {error}")
        check(sql_direct("select count(*) from blind") == "20", "and nothing was deleted")
        pg3.close()
        sql_direct("drop role if exists blind_role; drop table if exists blind")

        # pgbench: a real client with prepared statements (-M prepared), two DELETEs per transaction
        fresh_table("t", 50)
        script = "delete from t where n between 10 and 19;\ndelete from t where n between 30 and 39;\n"
        docker("exec", "-i", name, "sh", "-c", "cat > /tmp/del.sql", input=script)
        proc = subprocess.Popen(
            ["docker", "exec", "-e", f"PGPASSWORD={PASSWORD}", name, "pgbench", "-n", "-M", "prepared", "-f",
             "/tmp/del.sql", "-t", "1", "-h", "host.docker.internal", "-p", str(sluice.port), "-U", "postgres",
             "postgres"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        tty.wait_for("commit? [y/N]")
        tty.answer("y\n")
        tty.wait_for("commit? [y/N]")
        tty.answer("n\n")
        out, _ = proc.communicate(timeout=60)
        check(count() == 40, f"the first DELETE was confirmed, the second was not: {count()} rows; {out!r}")
        check(sql_direct("select count(*) from t where n between 10 and 19") == "0"
              and sql_direct("select count(*) from t where n between 30 and 39") == "10", "the right rows")
        check("not confirmed" in out, f"pgbench shows our error: {out!r}")
        events = [e for e in sluice.events() if e["event"] == "confirm"]
        check(all(e.get("protocol") == "extended" for e in events[-2:]), f"{events[-2:]}")
        check(PASSWORD not in sluice.text(), "the password is not in the log")
        sluice.stop()
    finally:
        tty.close()


def scenario_confirm_shows_cascades():
    """What a DELETE removes in other tables (a cascade) and what a trigger adds, shown before asking: from the
    statistics of the transaction on the real server, in both protocols, inside the client's own transaction too."""
    tty = Tty()
    try:
        sql_direct("drop table if exists casc_child, casc_audit, casc_parent cascade; "
                   "create table casc_parent (id int primary key); "
                   "create table casc_child (id serial primary key, pid int references casc_parent on delete cascade); "
                   "create table casc_audit (id serial primary key, what text); "
                   "create function casc_log() returns trigger language plpgsql as "
                   "$$ begin insert into casc_audit(what) values ('gone ' || old.id); return old; end $$; "
                   "create trigger casc_t after delete on casc_parent for each row execute function casc_log(); "
                   "insert into casc_parent select generate_series(1, 20); "
                   "insert into casc_child(pid) select (g % 20) + 1 from generate_series(1, 100) g")
        sluice = Sluice(CONFIRM_POLICY, args=["--confirm-tty", tty.path])
        pg = Pg(sluice.port)

        pg.sock.sendall(message(b"Q", b"delete from casc_parent where id <= 10\0"))
        text = tty.wait_for("commit? [y/N]")
        if os.environ.get("SLUICE_SHOW_PROMPTS"):
            print(text.replace("\r", ""))
        check("deleted 10 rows" in text and "tables changed in this transaction" in text, f"{text!r}")
        check("public.casc_child" in text and "50 deleted" in text, f"the cascade is shown: {text!r}")
        check("public.casc_audit" in text and "10 inserted" in text, f"and the trigger's work: {text!r}")
        tty.answer("n\n")
        res = pg.results()
        check(res[0][2] is not None and sql_direct("select count(*) from casc_child") == "100", "a no leaves the cascade undone")

        # the extended protocol
        ext_send(pg, P("delete from casc_parent where id <= 10"), B(), D(b"P"), E(), message(b"S"))
        text = tty.wait_for("commit? [y/N]")
        check("public.casc_child" in text and "50 deleted" in text and "public.casc_audit" in text, f"{text!r}")
        tty.answer("y\n")
        kinds, tags, error, status = ext_read(pg)
        check(kinds == b"12nCZ" and tags == ["DELETE 10"], f"{kinds} {tags}")
        check(sql_direct("select count(*) from casc_child") == "50", "committed: the children went with them")

        # inside the client's own transaction the numbers count what it did before, and say so
        check(pg.query("begin")[0][0] == "BEGIN", "begin")
        check(pg.query("delete from casc_parent where id = 11")[0][0] == "DELETE 1", "one row: not asked")
        pg.sock.sendall(message(b"Q", b"delete from casc_parent where id > 12\0"))
        text = tty.wait_for("commit? [y/N]")
        check("counting what it did before" in text and "public.casc_parent" in text, f"{text!r}")
        tty.answer("n\n")
        pg.results()
        check(pg.query("rollback")[0][0] == "ROLLBACK", "the transaction was usable")
        pg.close()

        # a rule can turn it off
        sluice.stop()
        sluice = Sluice(CONFIRM_POLICY.replace('over_rows = "5"', 'over_rows = "5"\nside_effects = "off"', 1),
                        args=["--confirm-tty", tty.path])
        pg = Pg(sluice.port)
        pg.sock.sendall(message(b"Q", b"delete from casc_parent where id > 12\0"))
        text = tty.wait_for("commit? [y/N]")
        check("tables changed" not in text, f"turned off: {text!r}")
        tty.answer("n\n")
        pg.results()
        pg.close()
        sluice.stop()
        sql_direct("drop table if exists casc_child, casc_audit, casc_parent cascade; drop function if exists casc_log()")
    finally:
        tty.close()


def scenario_confirm_in_the_session():
    """Nobody at the proxy: the person is asked in their own session, with the real server. Simple queries, a
    prepared statement, the client's own transaction, a refused statement, a cancel, and the time running out."""
    fresh_table("t", 50)
    sluice = Sluice(CONFIRM_POLICY.replace('confirm_timeout = "20s"', 'confirm_timeout = "2s"'), args=[])
    pg = Pg(sluice.port)

    # simple: question as an error, the transaction open and invisible, then confirm
    res = pg.query("delete from t where n between 10 and 29")
    check(res[0][0] is None and "waiting for you" in res[0][2], f"the question: {res}")
    check(count() == 50, "not final")
    res = pg.query("show;")
    check(res[0][0] is None and "waiting for you" in res[0][2], f"show: {res}")
    res = pg.query("select 1")
    check(res[0][0] is None and "waiting for your answer" in res[0][2], "anything else is refused")
    res = pg.query("yes;")
    check(res[0][0] == "DELETE 20", f"as psql shows a DELETE: {res}")
    check(count() == 30, "final")

    # cancel
    pg.query("delete from t where n between 30 and 49")
    res = pg.query("no;")
    check(res[0][0] == "ROLLBACK" and count() == 30, f"{res} {count()}")

    # inside the client's own transaction
    fresh_table("t", 50)
    check(pg.query("begin")[0][0] == "BEGIN", "begin")
    pg.query("delete from t where n between 10 and 29")
    check(pg.query("y")[0][0] == "DELETE 20", "the tag of the DELETE")
    check(pg.query("select count(*) from t")[0][1] == [("30",)] and count() == 50, "still the client's transaction")
    check(pg.query("rollback")[0][0] == "ROLLBACK" and count() == 50, "which it can roll back")

    # time runs out: undone, a warning, and the connection works
    pg.query("delete from t where n between 10 and 29")
    time.sleep(3)
    kind, payload = read_message(pg.sock)
    check(kind == b"N" and b"not confirmed in time" in payload, f"{kind} {payload}")
    check(pg.query("select count(*) from t")[0][1] == [("50",)], "undone, and the answers of that did not reach the client")
    check(sql_direct("select count(*) from pg_stat_activity where state like 'idle in transaction%'") == "0",
          "no transaction left open")

    # a prepared statement: P B D E S, then its confirmation as a cycle of its own
    ext_send(pg, P("delete from t where n between 10 and 29"), B(), D(b"P"), E(), message(b"S"))
    kinds, tags, error, status = ext_read(pg)
    check(kinds == b"12nEZ" and "waiting for you" in error and status == "T", f"{kinds} {error}")
    check(count() == 50, "not final")
    ext_send(pg, P("select 1"), B(), E(), message(b"S"))
    kinds, tags, error, status = ext_read(pg)
    check(kinds == b"EZ" and "waiting for your answer" in error, f"refused: {kinds}")
    ext_send(pg, P("yes"), B(), D(b"P"), E(), message(b"S"))
    kinds, tags, error, status = ext_read(pg)
    check(kinds == b"12nCZ" and tags == ["DELETE 20"] and error is None and status == "I", f"{kinds} {tags} {error}")
    check(count() == 30, "committed by the Sync of that cycle")

    # and cancelled
    ext_send(pg, P("delete from t where n between 30 and 49"), B(), E(), message(b"S"))
    ext_read(pg)
    ext_send(pg, P("select sluice_cancel()"), B(), E(), message(b"S"))  # the long form still works
    kinds, tags, error, status = ext_read(pg)
    check(b"E" in kinds and "nothing was changed" in error and status == "I", f"{kinds} {error} {status}")
    check(count() == 30, "undone")
    check(pg.query("select 1")[0][0] == "SELECT 1", "the connection works")

    check(PASSWORD not in sluice.text(), "the password is not in the log")
    pg.close()
    sluice.stop()


def scenario_confirm_truncate_and_drop():
    """TRUNCATE and DROP are transactional in PostgreSQL: run, shown, and kept or undone, in both protocols."""
    sql_direct("drop table if exists tr_child, tr_parent cascade; create table tr_parent as select generate_series(1, 30) id; "
               "alter table tr_parent add primary key (id); create table tr_child (pid int references tr_parent)")
    policy = ('mode = "enforce"\nconfirm_timeout = "20s"\n'
              '[[rule]]\nname = "confirm-truncate"\nmatch = "truncate"\naction = "confirm"\n'
              '[[rule]]\nname = "confirm-drop"\nmatch = "drop"\naction = "confirm"\n')
    sluice = Sluice(policy, args=[])
    pg = Pg(sluice.port)

    res = pg.query("truncate tr_parent cascade")
    check(res[0][0] is None and "TRUNCATE TABLE waiting for you" in res[0][2], f"{res}")
    # (the table is locked until the answer: another session's read would wait for it, so none is made)
    res = pg.query("no;")
    check(res[0][0] == "ROLLBACK" and sql_direct("select count(*) from tr_parent") == "30", f"{res}")
    pg.query("truncate tr_parent cascade")
    res = pg.query("yes;")
    check(res[0][0] == "TRUNCATE TABLE" and sql_direct("select count(*) from tr_parent") == "0", f"{res}")

    # prepared, with the row limit that pgjdbc sends
    sql_direct("insert into tr_parent select generate_series(1, 30)")
    ext_send(pg, P("drop table tr_child"), B(), E(b"", 1), message(b"S"))
    kinds, tags, error, status = ext_read(pg)
    check(kinds == b"12EZ" and "DROP TABLE waiting for you" in error, f"{kinds} {error}")
    ext_send(pg, P("yes"), B(), E(), message(b"S"))
    kinds, tags, error, status = ext_read(pg)
    check(kinds == b"12CZ" and tags == ["DROP TABLE"], f"{kinds} {tags}")
    check(sql_direct("select to_regclass('tr_child') is null") == "t", "dropped")

    # what cannot be undone is refused, with the reason
    res = pg.query("drop database postgres")
    check(res[0][0] is None and "one DELETE, UPDATE, TRUNCATE or DROP" in res[0][2], f"{res}")
    pg.close()
    sluice.stop()
    sql_direct("drop table if exists tr_child, tr_parent cascade")


def scenario_limit():
    """A limit on the rows of a statement, with nobody to ask, on the real server and both protocols."""
    fresh_table("t", 50)
    policy = ('mode = "enforce"\n[[rule]]\nname = "cap"\nmatch = "delete"\naction = "limit"\nmax_rows = "10"\n'
              'message = "Delete in smaller batches."\n')
    sluice = Sluice(policy, args=[])
    pg = Pg(sluice.port)
    res = pg.query("delete from t where n <= 5")
    check(res == [("DELETE 5", [], None)], f"under the limit: {res}")
    res = pg.query("delete from t where n <= 30")
    check(res[0][0] is None and "more than the limit of 10" in res[0][2] and "Delete in smaller batches" in res[0][2], f"{res}")
    check(count() == 45, "undone")
    res = pg.query("select 1")
    check(res[0][0] == "SELECT 1", "the connection works")
    ext_send(pg, P("delete from t where n <= 30"), B(), E(b"", 1), message(b"S"))
    kinds, tags, error, status = ext_read(pg)
    check(kinds == b"12EZ" and "more than the limit of 10" in error and status == "I", f"{kinds} {error}")
    check(count() == 45, "undone")
    ext_send(pg, P("delete from t where n <= 10"), B(), E(b"", 1), message(b"S"))
    kinds, tags, error, status = ext_read(pg)
    check(kinds == b"12CZ" and tags == ["DELETE 5"], f"under the limit: {kinds} {tags}")
    check(count() == 40, "committed")
    pg.close()
    sluice.stop()


def scenario_result_and_duration_limits():
    """What a result may carry out, what a connection may, and how long a statement may run, on the real server: the cancel
    really stops the work, and COPY is counted too."""
    policy = ('mode = "enforce"\n'
              '[[rule]]\nname = "rows"\nmatch = "any"\naction = "limit"\nmax_result_rows = "100"\n'
              '[[rule]]\nname = "short"\nmatch = "any"\naction = "limit"\nmax_duration = "2s"\n')
    sluice = Sluice(policy, args=[])
    pg = Pg(sluice.port)
    res = pg.query("select generate_series(1, 100000)")
    check(res[-1][0] is None and "more than 100 rows" in res[-1][2], f"{res[-1]}")
    res = pg.query("select generate_series(1, 100)")
    check(res == [("SELECT 100", [(str(i),) for i in range(1, 101)], None)] or res[0][0] == "SELECT 100", "100 rows are fine")
    # COPY is a way out too
    pg.sock.sendall(message(b"Q", b"copy (select generate_series(1, 100000)) to stdout\0"))
    seen = 0
    error = None
    while True:
        kind, payload = read_message(pg.sock)
        seen += kind == b"d"
        if kind == b"E":
            error = error_text(payload)
        if kind == b"Z":
            break
    check(seen == 100 and error is not None and "more than 100 rows" in error, f"COPY: {seen} pieces, {error}")

    # duration: the server is told to stop, and does
    started = time.monotonic()
    res = pg.query("select pg_sleep(30)")
    took = time.monotonic() - started
    check(res[-1][0] is None and "canceling statement" in res[-1][2], f"{res}")
    check(2.0 <= took < 6.0, f"cancelled after about 2 s, not 30: {took:.1f}s")
    check(sql_direct("select count(*) from pg_stat_activity where query like '%pg_sleep(30)%' and state = 'active' "
                     "and pid <> pg_backend_pid()") == "0", "the work really stopped")
    check(pg.query("select 1")[0][0] == "SELECT 1", "and the session goes on")
    events = [e for e in sluice.events() if e["event"] == "limit"]
    check({e["kind"] for e in events} >= {"result_rows", "duration"}, f"{events}")
    pg.close()
    sluice.stop()

    # a connection that has spent its volume
    sluice = Sluice('mode = "enforce"\n[[rule]]\nname = "volume"\nmatch = "any"\naction = "limit"\nmax_total_bytes = "100K"\n',
                    args=[])
    pg = Pg(sluice.port)
    res = pg.query("select generate_series(1, 1000)")
    check(res[0][0] == "SELECT 1000", "the first is under 100 KB")
    res = pg.query("select repeat('x', 1000) from generate_series(1, 1000)")
    check(res[-1][0] is None and "volume limit" in res[-1][2], f"{res[-1]}")
    try:
        pg.sock.settimeout(5)
        check(pg.sock.recv(1) == b"", "and the connection is closed")
    except (ConnectionResetError, OSError):
        pass
    sluice.stop()


def scenario_merge_and_upsert():
    """MERGE (with RETURNING, as the server of this version has it) and INSERT ... ON CONFLICT DO UPDATE are DELETEs
    and UPDATEs for the rules: held in a transaction, shown with their rows, committed on a yes and undone on a no,
    in the simple and the extended protocol. A rule that denies deletes refuses a MERGE that deletes."""
    fresh_table("t", 50)
    sql_direct("alter table t add primary key (n); drop table if exists s; create table s as select n from t where n <= 20")
    sluice = Sluice(CONFIRM_POLICY, args=[])
    pg = Pg(sluice.port)
    merge = "merge into t using s on t.n = s.n when matched then delete"
    res = pg.query(merge)
    check(res[0][0] is None and "MERGE 20 waiting for you" in res[0][2], f"the question: {res}")
    check(count() == 50, "not final")
    res = pg.query("no;")
    check(res[0][0] == "ROLLBACK" and count() == 50, f"undone: {res} {count()}")
    pg.query(merge)
    res = pg.query("yes;")
    check(res[0][0] == "MERGE 20" and count() == 30, f"as psql shows a MERGE: {res} {count()}")
    # the upsert: 20 rows updated and 5 inserted; the count is of both
    sql_direct("alter table t add column note text")
    res = pg.query("insert into t(n, note) select n, 'x' from generate_series(21, 60) n on conflict (n) do update set note = 'y'")
    check(res[0][0] is None and "INSERT 0 40 waiting for you" in res[0][2], f"the upsert asks: {res}")
    res = pg.query("yes;")
    check(res[0][0] == "INSERT 0 40" and count() == 40, f"{res} {count()}")  # 30 rows updated, 10 new
    # prepared (extended protocol)
    sql_direct("delete from s")
    sql_direct("insert into s select n from t where n between 30 and 49")
    ext_send(pg, P(merge), B(), D(b"P"), E(), message(b"S"))
    kinds, tags, error, status = ext_read(pg)
    check(kinds == b"12nEZ" and "MERGE 20 waiting for you" in error, f"{kinds} {error}")
    ext_send(pg, P("yes"), B(), D(b"P"), E(), message(b"S"))
    kinds, tags, error, status = ext_read(pg)
    check(error is None and tags == ["MERGE 20"] and count() == 20, f"{kinds} {tags} {error} {count()}")
    pg.close()
    sluice.stop()

    sluice = Sluice('mode = "enforce"\n[[rule]]\nname = "no-deletes"\nmatch = "delete"\n', args=[])
    pg = Pg(sluice.port)
    res = pg.query("merge into t using s on t.n = s.n when matched then delete")
    check(res[0][0] is None and "no-deletes" in res[0][2] and count() == 20, f"refused, nothing deleted: {res}")
    pg.close()
    sluice.stop()
    sql_direct("drop table s")


def scenario_undo_journal():
    """The rows of a DELETE kept for undo, on the real server: awkward values (quotes, newlines, a backslash, unicode,
    NULL, bytea, jsonb, arrays, timestamps, numerics), an identity column, a cascade; the script that `sluice --undo`
    prints puts the rows back exactly (compared by their JSON), and says what it cannot put back (the cascade)."""
    sql_direct("drop table if exists child; drop table if exists parent; "
               "create table parent (id int generated always as identity primary key, name text, n numeric(12,3), "
               "ts timestamptz, b bytea, j jsonb, a int[], flag boolean, t text); "
               "create table child (id int primary key, parent_id int references parent on delete cascade); "
               "insert into parent (name, n, ts, b, j, a, flag, t) values "
               "('it''s', 1.500, '2024-02-29 13:14:15.123456+02', '\\xdeadbeef', '{\"k\": [1, \"x\\ny\"]}', "
               "'{1,NULL,3}', true, E'two\\nlines \\\\ and \"quotes\" and \u2603 \U0001F600'), "
               "(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL), "
               "('', 0, 'infinity', '\\x', '[]', '{}', false, ''), "
               "('keep', 9, now(), NULL, NULL, NULL, NULL, 'x'); "
               "insert into child select g, ((g % 3) + 1) from generate_series(1, 9) g")
    before = sql_direct("select coalesce(jsonb_agg(to_jsonb(p) order by id), '[]') from parent p where id <= 3")
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "undo.jsonl")
        policy = ('mode = "enforce"\nconfirm_timeout = "20s"\n[[rule]]\nname = "confirm-deletes"\nmatch = "delete"\n'
                  'action = "confirm"\nover_rows = "2"\njournal = "required"\n')
        sluice = Sluice(policy, args=["--undo-journal", path])
        pg = Pg(sluice.port)
        res = pg.query("delete from parent where id <= 3")
        check(res[0][0] is None and "DELETE 3 waiting for you" in res[0][2], f"{res}")
        check(pg.query("yes;")[0][0] == "DELETE 3", "applied")
        check(sql_direct("select count(*) from parent where id <= 3") == "0", "gone")
        check(sql_direct("select count(*) from child") == "0", "the cascade took its children")
        # a few rows under the threshold: recorded too, with no question
        res = pg.query("delete from parent where id = 4")
        check(res[0][0] == "DELETE 1", f"{res}")
        pg.close()
        sluice.stop()
        entries = [json.loads(line) for line in open(path)]
        check(len(entries) == 2 and entries[0]["rows"] == 3 and entries[0]["complete"] is True, f"{entries[0]}")
        check(entries[0]["side_known"] is True and any(x["table"].endswith("child") and x["deleted"] == 9
                                                       for x in entries[0]["side"]), f"{entries[0]['side']}")
        out = subprocess.run([SLUICE, "--undo", path, "--id", entries[0]["id"]], capture_output=True, text=True, timeout=30)
        check(out.returncode == 0 and "child" in out.stdout and "NOT in this script" in out.stdout, f"{out.stdout} {out.stderr}")
        check("also changed public.parent" not in out.stdout, "the table the DELETE is on is not 'what else it changed'")
        run = docker("exec", "-i", name, "psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-q", input=out.stdout)
        check(run.returncode == 0, f"the script runs: {run.stderr}\n{out.stdout[:900]}")
        after = sql_direct("select coalesce(jsonb_agg(to_jsonb(p) order by id), '[]') from parent p where id <= 3")
        check(after == before, f"the rows are back, as they were:\n{before}\n{after}")
        check(sql_direct("select count(*) from child") == "0", "(the children are not: the script said so)")
    sql_direct("drop table child; drop table parent")


def scenario_undo_journal_update():
    """The old values of an UPDATE kept for undo (RETURNING OLD, PostgreSQL 18). On 18: the script puts the rows back
    (compared by their JSON), a row that no longer has the values the UPDATE gave it stops the script and changes
    nothing, and two rows that look alike do the same. Before 18 the rows cannot be had, so a rule that requires the
    journal refuses the UPDATE, and the table is left as it was."""
    version = int(sql_direct("show server_version_num"))
    sql_direct("drop table if exists dup; drop table if exists u; "
               "create table u (id int generated always as identity primary key, name text, n numeric(12,3), "
               "ts timestamptz, b bytea, j jsonb, a int[], t text); "
               "insert into u (name, n, ts, b, j, a, t) values "
               "('it''s', 1.500, '2024-02-29 13:14:15.123456+02', '\\xdeadbeef', '{\"k\": [1, \"x\\ny\"]}', "
               "'{1,NULL,3}', E'two\\nlines \\\\ and \"quotes\" and ☃ \U0001F600'), "
               "(NULL, NULL, NULL, NULL, NULL, NULL, NULL), "
               "('', 0, 'infinity', '\\x', '[]', '{}', ''), "
               "('keep', 9, now(), NULL, NULL, NULL, 'x'); "
               "create table dup (a int, b int); insert into dup values (1, 1), (1, 2), (2, 7)")
    snapshot = "select coalesce(jsonb_agg(to_jsonb(p) order by id), '[]') from u p"
    before = sql_direct(snapshot)
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "undo.jsonl")
        policy = ('mode = "enforce"\nconfirm_timeout = "20s"\n[[rule]]\nname = "confirm-updates"\nmatch = "update"\n'
                  'action = "confirm"\nover_rows = "2"\njournal = "required"\n')
        sluice = Sluice(policy, args=["--undo-journal", path])
        pg = Pg(sluice.port)
        stmt = ("update u set name = 'changed ' || coalesce(name, 'null'), n = null, ts = '2001-01-01', "
                "b = '\\x00ff', j = '{\"new\": true}', a = '{9}', t = case when id = 4 then t else null end "
                "where id <= 3")
        res = pg.query(stmt)
        if version < 180000:
            check(res[0][0] is None or res[0][0] != "UPDATE 3", f"before 18 the rows cannot be kept: {res}")
            check(sql_direct(snapshot) == before, "the table was not changed")
            check(not os.path.exists(path) or open(path).read() == "", "nothing was written")
            pg.close()
            sluice.stop()
            sql_direct("drop table dup; drop table u")
            return
        check(res[0][0] is None and "UPDATE 3 waiting for you" in res[0][2], f"{res}")
        check(pg.query("yes;")[0][0] == "UPDATE 3", "applied")
        check(sql_direct("select count(*) from u where name like 'changed%'") == "3", "changed")
        # an UPDATE that changes nothing in a row, under the threshold: recorded all the same
        res = pg.query("update u set t = t where id = 4")
        check(res[0][0] == "UPDATE 1", f"{res}")
        # two rows that will look alike
        res = pg.query("update dup set b = 0 where a = 1")
        check(res[0][0] == "UPDATE 2", f"{res}")
        # a prepared statement (the extended protocol), confirmed in the session
        sql_direct("drop table if exists x; create table x (id int primary key, v text); "
                   "insert into x select g, 'v' || g from generate_series(1, 5) g")
        before_x = sql_direct("select jsonb_agg(to_jsonb(x) order by id) from x")
        ext_send(pg, P("update x set v = upper(v) where id <= 4"), B(), D(b"P"), E(), message(b"S"))
        kinds, tags, error, status = ext_read(pg)
        check(kinds == b"12nEZ" and "waiting for you" in error, f"{kinds} {error}")
        ext_send(pg, P("yes"), B(), D(b"P"), E(), message(b"S"))
        kinds, tags, error, status = ext_read(pg)
        check(kinds == b"12nCZ" and tags == ["UPDATE 4"] and error is None, f"{kinds} {tags} {error}")
        check(sql_direct("select string_agg(v, ',' order by id) from x") == "V1,V2,V3,V4,v5", "applied")
        pg.close()
        sluice.stop()
        entries = [json.loads(line) for line in open(path)]
        check(len(entries) == 4 and entries[3]["protocol"] == "extended" and entries[3]["kind"] == "update"
              and entries[3]["complete"] is True and entries[3]["rows"] == 4, f"{entries[3:]}")
        out = subprocess.run([SLUICE, "--undo", path, "--id", entries[3]["id"]], capture_output=True, text=True, timeout=30)
        run = docker("exec", "-i", name, "psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-q", input=out.stdout)
        check(run.returncode == 0 and sql_direct("select jsonb_agg(to_jsonb(x) order by id) from x") == before_x,
              f"the prepared UPDATE is undone too: {run.stderr}")
        sql_direct("drop table x")
        check(entries[0]["kind"] == "update" and entries[0]["rows"] == 3
              and entries[0]["complete"] is True and len(entries[0]["data"]) == 3 and len(entries[0]["new"]) == 3
              and entries[0]["table"] == "u", f"{entries[0]}")
        # a row changed since: the script stops, and nothing is undone
        sql_direct("update u set name = 'edited later' where id = 2")
        out = subprocess.run([SLUICE, "--undo", path, "--id", entries[0]["id"]], capture_output=True, text=True, timeout=30)
        check(out.returncode == 0, f"{out.stdout} {out.stderr}")
        run = docker("exec", "-i", name, "psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-q", input=out.stdout)
        check(run.returncode != 0 and "matched 0 rows, not 1" in run.stderr, f"the script stops: {run.stderr}")
        check(sql_direct("select count(*) from u where name like 'changed%'") == "2", "and changes nothing")
        sql_direct("update u set name = 'changed null' where id = 2")  # as the UPDATE left it
        run = docker("exec", "-i", name, "psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-q", input=out.stdout)
        check(run.returncode == 0, f"the script runs: {run.stderr}\n{out.stdout[:900]}")
        check(sql_direct(snapshot) == before, "the rows have their old values back")
        # rows that look alike: it cannot tell them apart, so it does nothing
        out = subprocess.run([SLUICE, "--undo", path, "--id", entries[2]["id"]], capture_output=True, text=True, timeout=30)
        run = docker("exec", "-i", name, "psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-q", input=out.stdout)
        check(run.returncode != 0 and "matched 2 rows, not 1" in run.stderr, f"{run.stderr}")
        check(sql_direct("select string_agg(b::text, ',' order by b) from dup where a = 1") == "0,0", "unchanged")
    sql_direct("drop table dup; drop table u")


def scenario_session_and_dangerous_guards():
    """On the real server: SET ROLE and set_config() refused, the dangerous calls refused (also in a RETURNING list and
    behind a cursor), COPY to a file refused, an alert that lets the statement through, a kill that ends the
    connection, and the chain of the log checked with --verify-log."""
    sql_direct("drop table if exists g_t; create table g_t (id int, v text); insert into g_t values (1, 'a'), (2, 'b')")
    with tempfile.TemporaryDirectory() as d:
        key = os.path.join(d, "chain.key")
        open(key, "wb").write(os.urandom(32))
        policy = ('mode = "enforce"\n'
                  '[[rule]]\nname = "no-escalation"\nmatch = "set_session"\n'
                  '[[rule]]\nname = "watch"\nmatch = "any"\naction = "alert"\ntables = ["g_t"]\n'
                  '[[rule]]\nname = "no-danger"\nmatch = "dangerous"\naction = "kill"\n')
        sluice = Sluice(policy, args=["--log-chain-key-file", key])
        pg = Pg(sluice.port)
        for stmt in ("set role postgres", "select set_config('role', 'postgres', false)", "set session authorization postgres"):
            res = pg.query(stmt)
            check(res[0][0] is None and "no-escalation" in res[0][2], f"{stmt}: {res}")
        check(pg.query("show role")[0][1] == [("none",)], "the role did not change")
        check(pg.query("select v from g_t where id = 1")[0][1] == [("a",)], "an alert lets it through")
        check(pg.query("select current_setting('server_version_num')::int > 0")[0][1] == [("t",)], "an ordinary call")
        pg.close()
        # each of these ends its own connection
        for stmt in ("select pg_read_file('/etc/hostname')", "select pg_sleep(0)", "copy g_t to '/tmp/sluice_guard_test'",
                     "copy g_t to program 'true'", "delete from g_t where id = 99 returning pg_sleep(0)",
                     "declare c cursor for select pg_ls_dir('/')", "select * from dblink('x', 'select 1') as t(a int)"):
            pg = Pg(sluice.port)
            res = pg.query(stmt)
            check(res[0][0] is None and "no-danger" in res[0][2] and "closed" in res[0][2], f"{stmt}: {res}")
            try:
                pg.sock.settimeout(5)
                gone = pg.sock.recv(1) == b""
            except OSError:
                gone = True
            check(gone, f"the connection is closed after: {stmt}")
            pg.close()
        check(sql_direct("select count(*) from g_t") == "2", "nothing ran")
        check(sql_direct("select count(*) from pg_stat_activity where query like '%pg_read_file%' and state <> 'idle' "
                         "and pid <> pg_backend_pid()") == "0", "nothing is running")
        check(not os.path.exists("/tmp/sluice_guard_test"), "no file was written (on this machine)")
        text = sluice.text()
        check(text.count('"event":"alert"') >= 1, "the alert is in the log")
        sluice.stop()
        time.sleep(0.5)  # the reader of its output finishes
        log = os.path.join(d, "real.log")
        open(log, "w").write(sluice.text())
        run = subprocess.run([SLUICE, "--verify-log", log, "--log-chain-key-file", key], capture_output=True, text=True, timeout=30)
        check(run.returncode == 0, f"the log checks out: {run.stdout} {run.stderr}")
    sql_direct("drop table g_t")


def scenario_tag_budgets_and_transactions():
    """On the real server: the application_name the database sees carries the id of the connection in sluice's log,
    a budget of round trips ends the connection that spends it (and refuses the next statement of the user), and a
    transaction that stays open longer than max_transaction ends the connection."""
    policy = ('mode = "enforce"\n'
              '[[rule]]\nname = "trips"\nmatch = "any"\naction = "limit"\nusers = ["postgres"]\n'
              'budget_statements = "6"\nwindow = "1h"\n'
              '[[rule]]\nname = "short-tx"\nmatch = "any"\naction = "limit"\nusers = ["postgres"]\n'
              'max_transaction = "1s"\n')
    sluice = Sluice(policy, args=["--tag-application-name", "on"])
    pg = Pg(sluice.port, application_name="my agent")
    opened = sluice.wait_event("connection_open")
    res = pg.query("show application_name")
    check(res[0][1] == [(f"my agent [sluice {opened['id']}]",)], f"the database sees the tag: {res[0][1]}")
    seen = sql_direct("select string_agg(application_name, ',') from pg_stat_activity where application_name like 'my agent [sluice %'")
    check(f"my agent [sluice {opened['id']}]" in seen, f"and so does pg_stat_activity: {seen}")
    # a transaction open too long: ended between two statements, rolled back by the server
    check(pg.query("begin")[0][0] == "BEGIN", "begin")
    check(pg.query("select 1")[0][1] == [("1",)], "round trips so far: show, begin, select")
    time.sleep(1.6)
    kind, payload = read_message(pg.sock)
    check(kind == b"E" and "25P03" in repr(payload) and b"short-tx" in payload, f"{kind} {payload[:120]}")
    pg.close()
    # the round trips of this user were counted across connections: 3 used, the sixth ends the connection
    pg = Pg(sluice.port)
    answers = []
    for i in range(3):
        answers.append(pg.query("select 1")[0][0])
    check(answers == ["SELECT 1"] * 3, f"{answers}")
    pg.sock.settimeout(5)
    try:
        gone = pg.sock.recv(1) == b""
    except OSError:
        gone = True
    check(gone, "the connection that spent the budget is over")
    pg.close()
    pg = Pg(sluice.port)
    res = pg.query("select 1")
    check(res[0][0] is None and "round trips used up" in res[0][2], f"{res}")
    pg.close()
    sluice.stop()


def http_admin(port, method, path, token=None):
    import http.client
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request(method, path, headers={"Authorization": f"Bearer {token}"} if token else {})
    response = conn.getresponse()
    body = response.read().decode()
    conn.close()
    return response.status, body


def scenario_admin_confirmations_and_metrics():
    """On the real server: a DELETE that needs confirming waits (nobody at a terminal, nothing asked in the session),
    the question is read and answered over HTTP with the token, the rows are deleted only after the yes, a no undoes it,
    and the counters say what happened."""
    fresh_table("t", 40)
    token = "tok-" + secrets.token_hex(10)
    with tempfile.TemporaryDirectory() as d:
        tokfile = os.path.join(d, "t")
        open(tokfile, "w").write(token)
        policy = ('mode = "enforce"\nconfirm_timeout = "20s"\n[[rule]]\nname = "confirm-deletes"\nmatch = "delete"\n'
                  'action = "confirm"\nover_rows = "5"\n')
        sluice = Sluice(policy, args=["--admin", "127.0.0.1:0", "--admin-token-file", tokfile, "--confirm-admin", "on"])
        port = sluice.wait_event("admin_listening")["port"]
        pg = Pg(sluice.port)
        results = []
        worker = threading.Thread(target=lambda: results.append(pg.query("delete from t where n between 10 and 29")))
        worker.start()
        pending = sluice.wait_event("confirm_pending")
        check(pending["rows"] == 20 and pending["tag"] == "DELETE 20", f"{pending}")
        check(count() == 40, "nothing is final yet")
        status, text = http_admin(port, "GET", f"/pending/{pending['question']}", token)
        check(status == 200 and "20 rows" in text and "delete from t" in text, f"{text}")
        check(http_admin(port, "POST", f"/confirm/{pending['question']}/yes", token)[0] == 200, "yes")
        worker.join(15)
        check(results and results[0][0][0] == "DELETE 20" and count() == 20, f"{results} {count()}")
        # a no
        results.clear()
        worker = threading.Thread(target=lambda: results.append(pg.query("delete from t where n between 30 and 39")))
        worker.start()
        deadline = time.monotonic() + 10
        second = None
        while second is None and time.monotonic() < deadline:
            second = next((e for e in reversed(sluice.events()) if e["event"] == "confirm_pending"
                           and e["question"] != pending["question"]), None)
            time.sleep(0.05)
        check(second is not None, "a second question")
        check(http_admin(port, "POST", f"/confirm/{second['question']}/no", token)[0] == 200, "no")
        worker.join(15)
        check(results and results[0][0][0] is None and count() == 20, f"{results} {count()}")
        status, metrics = http_admin(port, "GET", "/metrics", token)
        check('sluice_confirmations_total{outcome="yes",channel="admin"} 1' in metrics
              and 'sluice_confirmations_total{outcome="no",channel="admin"} 1' in metrics
              and "sluice_pending_confirmations 0" in metrics, metrics)
        pg.close()
        sluice.stop()


def scenario_budgets():
    """A budget per user on the real server: rows read are cut at the budget in both protocols and whatever the
    connection, rows changed are counted from the real command tags and the writes refused once they are used up."""
    policy = ('mode = "enforce"\n'
              '[[rule]]\nname = "reads"\nmatch = "any"\naction = "limit"\nbudget_rows = "250"\nwindow = "1h"\n'
              '[[rule]]\nname = "writes"\nmatch = "any"\naction = "limit"\nbudget_changed = "100"\n')
    fresh_table("t", rows=300)
    sluice = Sluice(policy, args=[])
    pg = Pg(sluice.port)
    for _ in range(2):
        res = pg.query("select generate_series(1, 100)")
        check(res[0][0] == "SELECT 100", f"within the budget: {res[-1]}")
    res = pg.query("select generate_series(1, 100)")  # 200 used: 50 left
    check(len(res[0][1]) == 50 and res[-1][0] is None and "budget (rule reads)" in res[-1][2], f"{res[-1]}")
    # the extended protocol, on another connection of the same user: nothing is left
    other = Pg(sluice.port)
    ext_send(other, P("select generate_series(1, 5)"), B(), E(), message(b"S"))
    kinds, tags, error, status = ext_read(other)
    check(error is not None and "budget (rule reads)" in error and status == "I", f"{kinds} {tags} {error}")
    check(other.query("select 1 where false")[0][0] == "SELECT 0", "a statement with no row is not affected")
    other.close()

    # rows changed, as the server counts them (the real tag), in both protocols
    pg2 = Pg(sluice.port)
    res = pg2.query("update t set n = n where n <= 60")
    check(res[0][0] == "UPDATE 60", f"{res}")
    ext_send(pg2, P("update t set n = n where n between 61 and 120"), B(), E(), message(b"S"))
    kinds, tags, error, status = ext_read(pg2)
    check(tags == ["UPDATE 60"] and error is None, f"{tags} {error}")  # 120: over, the next write is refused
    res = pg2.query("update t set n = n where n = 200")
    check(res[0][0] is None and "budget of changed rows used up (rule writes: 100 rows in 1h)" in res[0][2], f"{res}")
    check(pg2.query("select 1 where false")[0][0] == "SELECT 0", "reading (here, no row) goes on")
    check(count("t") == 300, "and the refused write changed nothing")
    pg2.close()
    pg.close()
    events = [e for e in sluice.events() if e["event"] == "limit"]
    check(any(e["kind"] == "budget_rows" for e in events), f"{events}")
    sluice.stop()


def scenario_masking_qualified_names():
    """table.column on the real server: the OID of each column's table comes in the RowDescription and sluice reads
    the names of the tables once, after the login. users.email is hidden, orders.email is not, a join keeps them
    apart, a view is a table of its own, and a table made after the list was read is hidden (the safe way to be
    wrong), in both protocols."""
    sql_direct("drop view if exists v_users; drop table if exists q_users; drop table if exists q_orders; "
               "create table q_users (id int, email text); create table q_orders (id int, email text); "
               "insert into q_users values (1, 'ana@example.com'); insert into q_orders values (1, 'ana@shop.org'); "
               "create view v_users as select * from q_users")
    policy = ('mode = "enforce"\n[[rule]]\nname = "pii"\nmatch = "any"\naction = "mask"\n'
              'columns = ["q_users.email", "public.v_users.email"]\nhow = "redact"\n')
    sluice = Sluice(policy, args=[])
    pg = Pg(sluice.port)
    check(pg.query("select email from q_users")[0][1] == [("[masked]",)], "q_users.email is hidden")
    check(pg.query("select email from q_orders")[0][1] == [("ana@shop.org",)], "q_orders.email is not")
    res = pg.query("select u.email, o.email from q_users u join q_orders o using (id)")
    check(res[0][1] == [("[masked]", "ana@shop.org")], f"a join keeps them apart: {res[0][1]}")
    check(pg.query("select email from v_users")[0][1] == [("[masked]",)], "a view is named in the policy")
    # a table made after the login: the list does not have it, so the column is hidden
    sql_direct("drop table if exists q_new; create table q_new (id int, email text); insert into q_new values (1, 'x@y.org')")
    check(pg.query("select email from q_new")[0][1] == [("[masked]",)], "an unknown table is hidden")
    # a computed value comes from no table
    check(pg.query("select lower(email) as email from q_orders")[0][1] == [("[masked]",)], "computed: hidden")

    def ext_rows(sql):
        pg.sock.sendall(P(sql) + B() + D(b"P") + E() + message(b"S"))
        rows_ = []
        while True:
            kind, payload = read_message(pg.sock)
            if kind == b"D":
                n = struct.unpack("!H", payload[:2])[0]
                pos = 2
                row = []
                for _ in range(n):
                    length = struct.unpack("!i", payload[pos:pos + 4])[0]
                    pos += 4
                    row.append(None if length < 0 else payload[pos:pos + length].decode())
                    pos += max(length, 0)
                rows_.append(row)
            elif kind == b"Z":
                return rows_
    check(ext_rows("select email from q_users") == [["[masked]"]], "prepared: hidden")
    check(ext_rows("select email from q_orders") == [["ana@shop.org"]], "prepared: not")
    pg.close()
    check("ana@example.com" not in sluice.text(), "no value in the log")
    sluice.stop()
    sql_direct("drop view v_users; drop table q_users; drop table q_orders; drop table q_new")


def scenario_masking():
    """Values hidden on the real server: by the name of a column and by the look of a value, in both protocols
    (Execute through the Describe sluice adds, with the client's own Describe or without, text and binary), in the
    errors the server writes, and COPY refused. The numbers of the policy are unchanged for other users."""
    sql_direct("drop table if exists people; create table people (id int primary key, email text unique, "
               "ssn bigint, note text, card varchar(30), iban text); "
               "insert into people values (1, 'ana@example.com', 123456789, 'mail bob@example.org now', "
               "'4111 1111 1111 1111', 'FR7630006000011234567890189'), (2, 'carl@example.com', 987654321, "
               "'nothing', '', 'none'), (3, NULL, NULL, NULL, NULL, NULL)")
    policy = ('mode = "enforce"\n'
              '[[rule]]\nname = "pii"\nmatch = "any"\naction = "mask"\ncolumns = ["email", "ssn"]\n'
              'detect = ["email", "card", "iban"]\nhow = "redact"\n')
    sluice = Sluice(policy, args=[])
    pg = Pg(sluice.port)
    res = pg.query("select id, email, ssn, note, card, iban from people order by id")
    rows = res[0][1]
    check(rows[0] == ("1", "[masked]", None, "mail [masked] now", "[masked]", "[masked]"), f"{rows[0]}")
    check(rows[1] == ("2", "[masked]", None, "nothing", "", "none"), f"{rows[1]}")
    check(rows[2] == ("3", None, None, None, None, None), f"{rows[2]}")
    # an alias is a new name, but the pattern still finds an address; a number under a new name is not found
    res = pg.query("select email as e, ssn as s, lower(email) as l from people where id = 1")
    check(res[0][1][0] == ("[masked]", "123456789", "[masked]"), f"alias: {res[0][1]}")

    # the extended protocol, with and without the client's own Describe, then in binary
    def ext(*msgs):
        pg.sock.sendall(b"".join(msgs))
        kinds_, rows_, error = b"", [], None
        while True:
            kind, payload = read_message(pg.sock)
            kinds_ += kind
            if kind == b"D":
                n = struct.unpack("!H", payload[:2])[0]
                pos, row = 2, []
                for _ in range(n):
                    length = struct.unpack("!i", payload[pos:pos + 4])[0]
                    pos += 4
                    row.append(None if length < 0 else payload[pos:pos + length])
                    pos += max(length, 0)
                rows_.append(row)
            elif kind == b"E":
                error = error_text(payload)
            elif kind == b"Z":
                return kinds_, rows_, error

    sql = "select id, email, note from people where id <= 2 order by id"
    kinds_, rows_, error = ext(P(sql, b"s1"), D(b"S", b"s1"), message(b"S"))
    check(kinds_ == b"1tTZ", f"{kinds_}")
    kinds_, rows_, error = ext(B(b"", b"s1"), E(), message(b"S"))
    check(kinds_ == b"2DDCZ" and rows_[0][1] == b"[masked]" and rows_[1][2] == b"nothing", f"{kinds_} {rows_}")
    kinds_, rows_, error = ext(B(b"", b"s1"), D(b"P"), E(), B(b"", b"s1"), E(), message(b"S"))
    check(kinds_ == b"2TDDC2DDCZ" and all(r[1] == b"[masked]" for r in rows_), f"{kinds_}")
    binary = message(b"B", b"\0s1\0" + struct.pack("!HHH", 0, 0, 1) + struct.pack("!H", 1))  # every column in binary
    kinds_, rows_, error = ext(binary, D(b"P"), E(), message(b"S"))
    check(kinds_ == b"2TDDCZ" and rows_[0][1] == b"[masked]" and len(rows_[0][0]) == 4, f"binary: {kinds_} {rows_}")
    # a row to come with no result, and rows in the same pipeline
    kinds_, rows_, error = ext(P("update people set note = note where id = 3", b"u"), B(b"pu", b"u"), E(b"pu"),
                               B(b"", b"s1"), E(), message(b"S"))
    check(kinds_ == b"12C2DDCZ" or kinds_ == b"12C2DDCZ".replace(b"12C", b"1" + b"2C"), f"{kinds_}")

    # what the server says about a value is hidden too
    res = pg.query("insert into people (id, email) values (9, 'ana@example.com')")
    check(res[0][0] is None and "duplicate key" in res[0][2] and "ana@example.com" not in res[0][2], f"{res}")
    pg.sock.sendall(message(b"Q", b"insert into people (id, email) values (10, 'carl@example.com')\0"))
    detail = None
    while True:
        kind, payload = read_message(pg.sock)
        if kind == b"E":
            detail = [f[1:].decode() for f in payload.split(b"\0") if f[:1] == b"D"]
        if kind == b"Z":
            break
    check(detail == ["Key (email)=([masked]) already exists."], f"the detail of the error: {detail}")
    res = pg.query("insert into people (id, email, ssn) values (1, 'z@example.com', 5)")
    check(res[0][0] is None and "z@example.com" not in repr(res), f"{res}")
    res = pg.query("copy people to stdout")
    check(res[-1][0] is None and "COPY" in res[-1][2] and not any(r for _, r, _ in res), f"{res}")
    check(pg.query("select 1 where false")[0][0] == "SELECT 0", "and the session goes on")
    pg.close()
    check(sluice.wait_event("connection_close")["masked"] >= 8, "counted")
    check("987654321" not in sluice.text() and "123456789" not in sluice.text(), "the values of the rows are not in the log")
    sluice.stop()

    # the same client, another user: nothing is hidden. (The role of the test is `postgres`: a rule for someone else.)
    sluice = Sluice(policy.replace('action = "mask"', 'action = "mask"\nusers = ["someone"]'), args=[])
    pg = Pg(sluice.port)
    check(pg.query("select email from people where id = 1")[0][1] == [("ana@example.com",)], "not hidden for others")
    pg.close()
    sluice.stop()
    sql_direct("drop table people")


def scenario_proxy_only_limits_and_results():
    """What the session cannot lift: a transaction left open is ended and rolled back by the server, a user cannot
    hold more connections than allowed; and the log says how each statement ended, with no values in it."""
    sql_direct("drop table if exists uniq; create table uniq (n text primary key)")
    policy = ('mode = "enforce"\n'
              '[[rule]]\nname = "idle"\nmatch = "any"\naction = "limit"\nmax_idle_in_transaction = "2s"\n'
              '[[rule]]\nname = "two"\nmatch = "any"\naction = "limit"\nusers = ["postgres"]\nmax_connections = "2"\n')
    sluice = Sluice(policy, args=["--log-results", "on"])
    a = Pg(sluice.port)
    b = Pg(sluice.port)
    try:
        Pg(sluice.port)
        check(False, "a third connection of the same user should be refused")
    except AssertionError as exc:
        check("too many connections" in str(exc), f"{exc}")
    b.close()
    time.sleep(0.5)
    c = Pg(sluice.port)  # a place was freed
    c.close()

    check(a.query("insert into uniq values ('secret-xyz')")[0][0] == "INSERT 0 1", "")
    res = a.query("insert into uniq values ('secret-xyz')")
    check(res[-1][0] is None, f"{res}")
    check(a.query("select count(*) from uniq")[0][1] == [("1",)], "")

    check(a.query("begin")[0][0] == "BEGIN", "")
    a.query("insert into uniq values ('inside')")
    time.sleep(3.5)
    try:
        kind, payload = read_message(a.sock)
        check(kind == b"E" and b"25P03" in payload, f"{kind} {payload}")
    except (EOFError, OSError):
        check(False, "the idle transaction should have been ended with an error")
    time.sleep(0.5)
    check(sql_direct("select count(*) from pg_stat_activity where state like 'idle in transaction%'") == "0",
          "the server rolled the transaction back")
    check(sql_direct("select count(*) from uniq") == "1", "and what it had done is gone")

    results = [e for e in sluice.events() if e["event"] == "result"]
    kinds_seen = {(e["kind"], e.get("sqlstate")) for e in results}
    check(("ok", None) in kinds_seen and ("error", "23505") in kinds_seen, f"{kinds_seen}")
    check(any(e.get("tag") == "INSERT 0 1" for e in results), "the tag of an INSERT")
    check(any(e.get("tag") == "SELECT 1" and e["rows"] == 1 for e in results), "the rows of a SELECT")
    check("secret-xyz" not in json.dumps(results), "no value in a result event, not even through an error")
    sluice.stop()
    sql_direct("drop table if exists uniq")


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
                 scenario_tls_with_a_client_certificate, scenario_clients_over_tls,
                 scenario_confirm_extended_protocol, scenario_confirm_shows_cascades,
                 scenario_confirm_in_the_session, scenario_confirm_truncate_and_drop, scenario_limit,
                 scenario_result_and_duration_limits, scenario_proxy_only_limits_and_results,
                 scenario_budgets, scenario_masking, scenario_masking_qualified_names, scenario_merge_and_upsert, scenario_undo_journal,
                 scenario_undo_journal_update, scenario_session_and_dangerous_guards, scenario_tag_budgets_and_transactions,
                 scenario_admin_confirmations_and_metrics):
    started_at = time.monotonic()
    before = len(failures)
    try:
        scenario()
    except Exception as exc:  # a scenario that cannot even run is a failure, not a crash of the others
        check(False, f"{scenario.__name__} raised {exc!r}")
    print(f"{'ok ' if len(failures) == before else 'FAIL'} {scenario.__name__} ({time.monotonic() - started_at:.1f}s)")

docker("stop", name)
sys.exit(1 if failures else 0)
