#!/usr/bin/env python3
"""sluice with real client libraries, against a real PostgreSQL in a throwaway Docker container.

psql and pgbench are not what applications use: drivers prepare statements, pipeline them, wrap them in
transactions of their own and roll back when something raises. This runs the confirmation of a DELETE through
psycopg 3, asyncpg and SQLAlchemy (and JDBC, when Java is available), as an application would meet it.

Opt-in like realpg.py, and it needs the libraries (uv fetches them):

    SLUICE_REAL_PG=1 uvx --with "psycopg[binary]" --with asyncpg --with sqlalchemy python3 tests/drivers.py build/sluice

SLUICE_JDBC=1 adds the JDBC part (it downloads pgjdbc from Maven Central and uses an eclipse-temurin image).
Exit status 77 means skipped.
"""

import asyncio
import atexit
import hashlib
import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

if os.environ.get("SLUICE_REAL_PG") != "1":
    print("skipped: set SLUICE_REAL_PG=1 to run against a real PostgreSQL (needs Docker)")
    sys.exit(77)

try:
    import asyncpg
    import psycopg
    import sqlalchemy
except ImportError as exc:
    print(f"skipped: {exc} (run it with uvx --with 'psycopg[binary]' --with asyncpg --with sqlalchemy)")
    sys.exit(77)

SLUICE = os.path.abspath(sys.argv[1])
IMAGE = os.environ.get("SLUICE_PG_IMAGE", "postgres:17-alpine")
failures = []


def check(cond, what):
    if not cond:
        failures.append(what)
        print("FAIL:", what, file=sys.stderr)


def docker(*args, **kw):
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=300, **kw)


if docker("info").returncode != 0:
    print("skipped: Docker is not available")
    sys.exit(77)

# ---- the database, and sluice in front of it ----

NAME = "sluice-itest-drivers-" + secrets.token_hex(3)
atexit.register(lambda: docker("stop", NAME))
started = docker("run", "-d", "--rm", "--name", NAME, "-e", "POSTGRES_HOST_AUTH_METHOD=trust", "-p",
                 "127.0.0.1::5432", IMAGE)
if started.returncode != 0:
    print("skipped: cannot start the database:", started.stderr.strip())
    sys.exit(77)
for _ in range(120):
    if docker("exec", NAME, "pg_isready", "-U", "postgres").returncode == 0:
        time.sleep(1)
        if docker("exec", NAME, "pg_isready", "-U", "postgres").returncode == 0:
            break
    time.sleep(0.5)
DB_PORT = int(docker("port", NAME, "5432/tcp").stdout.strip().rsplit(":", 1)[1])


def sql_direct(sql):
    out = docker("exec", NAME, "psql", "-U", "postgres", "-qAt", "-c", sql)
    return out.stdout.strip()


_last = [time.monotonic()]


def fresh(rows=50):
    if os.environ.get("DRIVERS_TRACE"):
        print(f"    [{time.monotonic() - _last[0]:.1f}s since the last fresh()]")
        _last[0] = time.monotonic()
    sql_direct(f"drop table if exists t; create table t as select generate_series(1, {rows}) n")


def count():
    return int(sql_direct("select count(*) from t"))


POLICY = """
mode = "enforce"
confirm_timeout = "20s"

[[rule]]
name = "confirm-writes"
match = "delete"
action = "confirm"
over_rows = "5"

[[rule]]
name = "confirm-updates"
match = "update"
action = "confirm"
over_rows = "5"

[[rule]]
name = "confirm-truncate"
match = "truncate"
action = "confirm"
"""
handle = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
handle.write(POLICY)
handle.close()
atexit.register(lambda: os.path.exists(handle.name) and os.unlink(handle.name))
proc = subprocess.Popen([SLUICE, "--listen", "127.0.0.1:0", "--upstream", f"127.0.0.1:{DB_PORT}", "--policy",
                         handle.name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
atexit.register(lambda: proc.poll() is None and proc.kill())
lines = [proc.stdout.readline()]
SLUICE_PORT = json.loads(lines[0])["port"]
threading.Thread(target=lambda: [lines.append(x) for x in proc.stdout], daemon=True).start()
DSN = f"host=127.0.0.1 port={SLUICE_PORT} user=postgres dbname=postgres"


def log_text():
    return "".join(lines)


def spawn_sluice(policy_text, extra=()):
    """Another sluice in front of the same database: (process, port, log lines)."""
    f = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
    f.write(policy_text)
    f.close()
    atexit.register(lambda: os.path.exists(f.name) and os.unlink(f.name))
    p = subprocess.Popen([SLUICE, "--listen", "127.0.0.1:0", "--upstream", f"127.0.0.1:{DB_PORT}", "--policy",
                          f.name, *extra], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    atexit.register(lambda: p.poll() is None and p.kill())
    out = [p.stdout.readline()]
    port = json.loads(out[0])["port"]
    threading.Thread(target=lambda: [out.append(x) for x in p.stdout], daemon=True).start()
    return p, port, out


def open_fds(pid):
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        pass
    try:
        out = subprocess.run(["lsof", "-n", "-P", "-p", str(pid)], capture_output=True, text=True, timeout=20).stdout
        return max(0, len(out.splitlines()) - 1)
    except (OSError, subprocess.SubprocessError):
        return None


# ---- psycopg 3 ----

def scenario_psycopg():
    """Parameters travel with the extended protocol; a transaction of the driver's own wraps them."""
    fresh()
    # autocommit: the statement is the whole transaction
    with psycopg.connect(DSN, autocommit=True) as conn:
        cur = conn.cursor()
        try:
            cur.execute("delete from t where n <= %s", (20,))
            check(False, "psycopg: the DELETE should have been refused until confirmed")
        except psycopg.Error as exc:
            check("waiting for you" in str(exc), f"psycopg: the question: {exc}")
        check(count() == 50, "psycopg: nothing is final while it waits")
        cur.execute("yes")
        check(cur.statusmessage == "DELETE 20", f"psycopg: the answer is the DELETE's: {cur.statusmessage}")
        check(count() == 30, "psycopg: committed")
        cur.execute("select count(*) from t")
        check(cur.fetchone()[0] == 30, "psycopg: the connection works")

    # the driver's own transaction (BEGIN is sent for it)
    fresh()
    conn = psycopg.connect(DSN)
    try:
        with conn:
            cur = conn.cursor()
            try:
                cur.execute("delete from t where n <= %s", (20,))
            except psycopg.Error as exc:
                check("waiting for you" in str(exc), f"psycopg tx: the question: {exc}")
            try:
                cur.execute("show")  # more rows: the same question again
                check(False, "psycopg tx: show should carry the question")
            except psycopg.Error as exc:
                check("waiting for you" in str(exc), f"psycopg tx: show: {exc}")
        check(False, "psycopg tx: the commit at the end of the block should have been refused")
    except psycopg.Error as exc:
        check("COMMIT now would apply" in str(exc), f"psycopg tx: a commit before the answer is refused: {exc}")
    check(count() == 50, "psycopg tx: and nothing was applied")
    conn.close()  # the driver leaves the connection open after that error; closing it releases the locks

    fresh()
    with psycopg.connect(DSN) as conn:
        cur = conn.cursor()
        try:
            cur.execute("delete from t where n <= %s", (20,))
        except psycopg.Error:
            pass
        t0 = time.monotonic()
        try:
            cur.execute("yes")
        except psycopg.Error as exc:
            check(False, f"psycopg tx: yes failed: {exc}")
        t1 = time.monotonic()
        conn.commit()
        if os.environ.get("DRIVERS_TRACE"):
            print(f"    [yes {t1 - t0:.1f}s, commit {time.monotonic() - t1:.1f}s]")
    check(count() == 30, "psycopg tx: yes, then the driver's own commit")

    # a no
    fresh()
    with psycopg.connect(DSN, autocommit=True) as conn:
        cur = conn.cursor()
        try:
            cur.execute("delete from t where n <= %s", (20,))
        except psycopg.Error:
            pass
        try:
            cur.execute("no")
            check(False, "psycopg: no should be an error (nothing was done)")
        except psycopg.Error as exc:
            check("nothing was changed" in str(exc) or "cancelled" in str(exc), f"psycopg: {exc}")
        check(count() == 50, "psycopg: undone")
        cur.execute("select 1")
        check(cur.fetchone()[0] == 1, "psycopg: and the connection works")

    # a driver that rolls back as soon as something raises (what a context manager does)
    fresh()
    try:
        with psycopg.connect(DSN) as conn:
            cur = conn.cursor()
            cur.execute("delete from t where n <= %s", (20,))
    except psycopg.Error:
        pass  # leaving the block rolled back
    check(count() == 50, "psycopg: the rollback of the driver undoes the waiting statement")
    check(sql_direct("select count(*) from pg_stat_activity where state like 'idle in transaction%'") == "0",
          "psycopg: and nothing is left open")


def scenario_psycopg_truncate():
    """TRUNCATE has no rows to count: it is always asked about, and the statement is shown."""
    fresh()
    with psycopg.connect(DSN, autocommit=True) as conn:
        cur = conn.cursor()
        try:
            cur.execute("truncate t")
            check(False, "psycopg truncate: should wait")
        except psycopg.Error as exc:
            check("TRUNCATE TABLE waiting for you" in str(exc) and "truncate t" in str(exc), f"{exc}")
        cur.execute("yes")
        check(cur.statusmessage == "TRUNCATE TABLE", f"{cur.statusmessage}")
        cur.execute("select count(*) from t")
        check(cur.fetchone()[0] == 0, "psycopg truncate: done")


# ---- asyncpg ----

async def asyncpg_part():
    fresh()
    conn = await asyncpg.connect(host="127.0.0.1", port=SLUICE_PORT, user="postgres", database="postgres")
    try:
        await conn.execute("delete from t where n <= $1", 20)
        check(False, "asyncpg: should be refused until confirmed")
    except asyncpg.PostgresError as exc:
        check("waiting for you" in str(exc), f"asyncpg: {exc}")
    check(count() == 50, "asyncpg: not final")
    status = await conn.execute("yes")
    check(status == "DELETE 20", f"asyncpg: the answer: {status!r}")
    check(count() == 30, "asyncpg: committed")
    check(await conn.fetchval("select count(*) from t") == 30, "asyncpg: the connection works")

    # prepared once, run twice: asyncpg describes the statement first
    stmt = await conn.prepare("delete from t where n <= $1")
    try:
        await stmt.fetch(35)
        check(False, "asyncpg: prepared, should wait")
    except asyncpg.PostgresError as exc:
        check("waiting for you" in str(exc), f"asyncpg prepared: {exc}")
    try:
        await conn.execute("no")
    except asyncpg.PostgresError:
        pass
    check(count() == 30, "asyncpg: undone (the 15 rows were not deleted)")
    await conn.close()

    # inside a transaction block of the driver
    fresh()
    conn = await asyncpg.connect(host="127.0.0.1", port=SLUICE_PORT, user="postgres", database="postgres")
    tr = conn.transaction()
    await tr.start()
    try:
        await conn.execute("delete from t where n <= $1", 20)
    except asyncpg.PostgresError:
        pass
    status = await conn.execute("yes")
    check(status == "DELETE 20", f"asyncpg tx: {status!r}")
    await tr.commit()
    check(count() == 30, "asyncpg tx: committed with the driver's own commit")
    await conn.close()


def scenario_asyncpg():
    asyncio.run(asyncpg_part())


# ---- SQLAlchemy over psycopg ----

def scenario_sqlalchemy():
    fresh()
    engine = sqlalchemy.create_engine(f"postgresql+psycopg://postgres@127.0.0.1:{SLUICE_PORT}/postgres")
    # the usual way: a block that rolls back when something raises
    try:
        with engine.begin() as c:
            c.execute(sqlalchemy.text("delete from t where n <= :n"), {"n": 20})
    except sqlalchemy.exc.DBAPIError as exc:
        check("waiting for you" in str(exc), f"sqlalchemy: {exc}")
    check(count() == 50, "sqlalchemy: the block's rollback undid the waiting statement")

    # answering inside the block
    with engine.connect() as c:
        try:
            c.execute(sqlalchemy.text("delete from t where n <= :n"), {"n": 20})
        except sqlalchemy.exc.DBAPIError:
            pass
        r = c.exec_driver_sql("yes")
        check(r.rowcount == 20, f"sqlalchemy: rowcount of the DELETE: {r.rowcount}")
        c.commit()
    check(count() == 30, "sqlalchemy: committed")
    engine.dispose()


# ---- the proxy must be invisible: the same work, direct and through it, gives the same results ----

def workload(dsn):
    """A varied piece of work with a driver, as a list of what it saw: results, tags, error codes."""
    import random
    rng = random.Random(7)
    obs = []

    def rec(label, fn):
        try:
            obs.append((label, fn()))
        except psycopg.Error as exc:
            obs.append((label, "ERR", exc.sqlstate))

    with psycopg.connect(dsn, autocommit=True, prepare_threshold=0) as conn:  # every statement is prepared by name
        conn.execute("drop table if exists eq")
        conn.execute("create table eq (id int primary key, v text, b bytea, j jsonb, n numeric, check (n < 1000000))")
        cur = conn.cursor()
        rows = [(i, "v%d \u00e9\u4e2d" % i, bytes(rng.randrange(256) for _ in range(rng.randrange(0, 40))),
                 '{"a": %d, "b": [1, 2, {"c": null}]}' % i, rng.randrange(100000) / 7) for i in range(1, 301)]
        rec("insert many", lambda: cur.executemany("insert into eq values (%s, %s, %s, %s::jsonb, %s)", rows) or cur.rowcount)
        rec("count", lambda: (cur.execute("select count(*), sum(id), md5(string_agg(v, ',' order by id)) from eq"), cur.fetchone())[1])
        rec("param select", lambda: (cur.execute("select id, v, b, j, n from eq where id between %s and %s order by id", (10, 40)), cur.fetchall())[1])
        rec("description", lambda: (cur.execute("select id, v, b, j, n from eq limit 0"), [(c.name, c.type_code) for c in cur.description])[1])
        rec("nulls and types", lambda: (cur.execute("select null::int, true, 1.5::float8, now() - now(), '[1,2]'::int4range, array[1,2,null]"), cur.fetchone())[1])
        rec("update", lambda: (cur.execute("update eq set v = v || '!' where id % 7 = 0"), cur.rowcount)[1])
        rec("delete returning", lambda: (cur.execute("delete from eq where id > 290 returning id"), sorted(cur.fetchall()))[1])
        rec("unique violation", lambda: cur.execute("insert into eq (id, v) values (1, 'dup')"))
        rec("check violation", lambda: cur.execute("insert into eq (id, n) values (9999, 5000000)"))
        rec("syntax error", lambda: cur.execute("selec 1"))
        rec("division by zero", lambda: cur.execute("select 1 / (id - id) from eq"))
        rec("unknown table", lambda: cur.execute("select * from nothing_here"))
        rec("session still fine", lambda: (cur.execute("select 1"), cur.fetchone())[1])
        # binary results
        bc = conn.cursor(binary=True)
        rec("binary", lambda: (bc.execute("select id, v, b, n from eq where id < 20 order by id"), bc.fetchall())[1])
        # a big value both ways, and a big result
        blob = bytes(rng.randrange(256) for _ in range(3 << 20))
        rec("big bytea", lambda: (cur.execute("insert into eq (id, b) values (1000, %s)", (blob,)),
                                  cur.execute("select b from eq where id = 1000"), cur.fetchone()[0] == blob)[2])
        rec("big result", lambda: (cur.execute("select count(*), sum(g) from generate_series(1, 200000) g"), cur.fetchone())[1])
        rec("wide rows", lambda: (cur.execute("select repeat('x', 50000) from generate_series(1, 40)"), len(cur.fetchall()))[1])
        # transactions
        def tx():
            with conn.transaction():
                cur.execute("insert into eq (id) values (2001)")
                try:
                    with conn.transaction():  # a savepoint
                        cur.execute("insert into eq (id) values (2001)")
                except psycopg.errors.UniqueViolation:
                    pass
                cur.execute("insert into eq (id) values (2002)")
            cur.execute("select id from eq where id > 2000 order by id")
            return cur.fetchall()
        rec("transaction and savepoint", tx)

        def rolled():
            try:
                with conn.transaction():
                    cur.execute("insert into eq (id) values (3001)")
                    raise RuntimeError("x")
            except RuntimeError:
                pass
            cur.execute("select count(*) from eq where id = 3001")
            return cur.fetchone()
        rec("rollback", rolled)
        # server-side cursor
        def named():
            with conn.transaction():
                with conn.cursor(name="c1") as nc:
                    nc.execute("select id from eq order by id")
                    first = nc.fetchmany(5)
                    second = nc.fetchmany(5)
                    return first, second
        rec("named cursor", named)
        # COPY both ways
        def copy_in():
            with cur.copy("copy eq (id, v) from stdin") as cp:
                for i in range(4000, 4100):
                    cp.write_row((i, "copy %d" % i))
            cur.execute("select count(*) from eq where id >= 4000")
            return cur.fetchone()
        rec("copy in", copy_in)

        def copy_out():
            out = []
            with cur.copy("copy (select id, v from eq where id between 4000 and 4010 order by id) to stdout") as cp:
                for row in cp:
                    out.append(bytes(row))
            return out
        rec("copy out", copy_out)
        # simple protocol, several statements in one message
        def multi():
            results = conn.pgconn.exec_(b"select 1; select 2 as two; select count(*) from eq where id < 5")
            return results.status, results.get_value(0, 0)
        rec("several statements", multi)
        # notifications
        def notify():
            conn.execute("listen ch")
            conn.execute("notify ch, 'hello'")
            got = []
            for n in conn.notifies(timeout=2, stop_after=1):
                got.append((n.channel, n.payload))
            return got
        rec("notify", notify)
        # a pipeline
        def piped():
            with conn.pipeline():
                cs = [conn.cursor() for _ in range(3)]
                for i, c in enumerate(cs):
                    c.execute("select %s::int + 1", (i,))
            return [c.fetchone() for c in cs]
        rec("pipeline", piped)
        # many statements one after the other
        def many():
            total = 0
            for i in range(300):
                cur.execute("select %s::int", (i,))
                total += cur.fetchone()[0]
            return total
        rec("many round trips", many)
    return obs


def scenario_equivalence():
    """The proxy is invisible: the same work with a driver, direct, through sluice, and through sluice with TLS and result
    logging on, sees the same results, tags, descriptions and error codes."""
    inert = 'mode = "enforce"\non_uninspectable = "allow"\n[[rule]]\nname = "never"\nmatch = "procedural"\n'
    direct = workload(f"host=127.0.0.1 port={DB_PORT} user=postgres dbname=postgres")
    p1, port1, _ = spawn_sluice(inert)
    through = workload(f"host=127.0.0.1 port={port1} user=postgres dbname=postgres")
    p2, port2, lines2 = spawn_sluice(inert, ["--listen-tls", "self-signed", "--log-results", "on", "--log-sql", "normalized"])
    secure = workload(f"host=127.0.0.1 port={port2} user=postgres dbname=postgres sslmode=require")
    for name, other in (("through sluice", through), ("through sluice with TLS", secure)):
        check(len(other) == len(direct), f"{name}: {len(other)} observations, {len(direct)} direct")
        for a, b in zip(direct, other):
            check(a == b, f"{name}: {a[0]!r} differs: direct {str(a)[:200]!r}, through {str(b)[:200]!r}")
    check(any(o[1] == "ERR" and o[2] == "23505" for o in direct), "the workload really does raise a unique violation")
    check(len(direct) > 20, "and does a lot")
    check(sum(1 for x in lines2 if '"event":"result"' in x) > 300, "the results were logged")
    for p in (p1, p2):
        check(p.poll() is None, "sluice is alive")
        p.send_signal(signal.SIGTERM)


# ---- many clients at once, misbehaving ----

def scenario_soak():
    """Many clients at once: queries, writes, confirmations that are answered, refused or abandoned, connections cut in the
    middle. At the end nothing is half done, each table is what its client's model says, and sluice has leaked nothing."""
    import random
    threads_n = int(os.environ.get("SLUICE_SOAK_CLIENTS", "24"))
    rounds = int(os.environ.get("SLUICE_SOAK_ROUNDS", "40"))  # a longer run: 64 clients, 400 rounds
    for i in range(threads_n):
        sql_direct(f"drop table if exists soak_{i}; create table soak_{i} (id int primary key)")
    baseline = open_fds(proc.pid)
    models = {}
    failures_here = []

    def client(i):
        rng = random.Random(1000 + i)
        ids = set()
        models[i] = ids
        table = f"soak_{i}"
        conn = None
        next_id = 1
        try:
            for step in range(rounds):
                if conn is None or conn.closed:
                    conn = psycopg.connect(DSN, autocommit=True)
                cur = conn.cursor()
                op = rng.choice(["insert", "insert", "select", "small delete", "big delete yes", "big delete no",
                                 "big delete leave", "big delete rollback", "cut", "long select"])
                if op == "insert":
                    n = rng.randrange(1, 15)
                    cur.execute(f"insert into {table} select g from generate_series(%s::int, %s::int) g", (next_id, next_id + n - 1))
                    ids.update(range(next_id, next_id + n))
                    next_id += n
                elif op == "select":
                    cur.execute(f"select count(*) from {table}")
                    if cur.fetchone()[0] != len(ids):
                        failures_here.append(f"client {i}: count differs from its model")
                elif op == "small delete" and ids:
                    victims = sorted(ids)[:2]
                    cur.execute(f"delete from {table} where id = any(%s::int[])", (victims,))
                    ids.difference_update(victims)
                elif op.startswith("big delete") and len(ids) > 6:
                    victims = sorted(ids)[: len(ids) - 1]
                    try:
                        cur.execute(f"delete from {table} where id = any(%s::int[])", (victims,))
                        failures_here.append(f"client {i}: a big delete was not held")
                    except psycopg.Error as exc:
                        if "waiting for you" not in str(exc):
                            failures_here.append(f"client {i}: {exc}")
                            continue
                    if op == "big delete yes":
                        cur.execute("yes")
                        ids.difference_update(victims)
                    elif op == "big delete no":
                        try:
                            cur.execute("no")
                        except psycopg.Error:
                            pass
                    elif op == "big delete rollback":
                        conn.rollback()
                    else:  # leave: the connection goes away with the question unanswered
                        conn.close()
                        conn = None
                elif op == "cut":
                    try:
                        cur.execute("select pg_sleep(0.05)")
                    finally:
                        conn.close()
                        conn = None
                elif op == "long select":
                    cur.execute("select g, repeat('y', 100) from generate_series(1, 20000) g")
                    cur.fetchall()
        except psycopg.Error as exc:
            failures_here.append(f"client {i}: {type(exc).__name__}: {str(exc)[:200]}")
        except Exception as exc:  # noqa: BLE001
            failures_here.append(f"client {i}: unexpected {exc!r}")
        finally:
            if conn is not None and not conn.closed:
                conn.close()

    started = time.monotonic()
    ts = [threading.Thread(target=client, args=(i,)) for i in range(threads_n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(300)
    check(not any(t.is_alive() for t in ts), "every client finished")
    check(not failures_here, f"clients saw: {failures_here[:5]}")
    check(proc.poll() is None, "sluice survived")
    time.sleep(1.5)
    for i in range(threads_n):
        got = {int(x) for x in sql_direct(f"select id from soak_{i}").split()}
        check(got == models[i], f"soak_{i}: the table is not what its client's model says")
    check(sql_direct("select count(*) from pg_stat_activity where state like 'idle in transaction%'") == "0",
          "no transaction was left open")
    fds = open_fds(proc.pid)
    if baseline is not None and fds is not None:
        check(fds <= baseline + 4, f"no descriptor leaked: {baseline} before, {fds} after")
    print(f"    ({threads_n} clients, {rounds} operations each, {time.monotonic() - started:.0f}s)")


# ---- JDBC ----

JAVA = r"""
import java.sql.*;
public class T {
  public static void main(String[] a) throws Exception {
    String url = "jdbc:postgresql://host.docker.internal:" + a[0] + "/postgres?user=postgres&sslmode=disable";
    try (Connection c = DriverManager.getConnection(url)) {
      c.setAutoCommit(a[1].equals("auto"));
      try (PreparedStatement p = c.prepareStatement(a.length > 3 ? a[3] : "delete from t where n <= ?")) {
        if (a.length <= 3) p.setInt(1, 20);
        try { p.executeUpdate(); System.out.println("NOERROR"); }
        catch (SQLException e) { System.out.println("ERR " + e.getMessage().split("\n")[0]); }
      }
      try (Statement s = c.createStatement()) {
        try { int n = s.executeUpdate(a[2]); System.out.println("ANSWER " + n); }
        catch (SQLException e) { System.out.println("ERR2 " + e.getMessage().split("\n")[0]); }
      }
      if (!a[1].equals("auto")) { try { c.commit(); System.out.println("COMMITTED"); } catch (SQLException e) { System.out.println("ERR3 " + e.getMessage().split("\n")[0]); } }
    }
  }
}
"""
JDBC_URL = "https://repo1.maven.org/maven2/org/postgresql/postgresql/42.7.4/postgresql-42.7.4.jar"


def scenario_jdbc():
    if not docker_drivers_enabled():
        return
    with tempfile.TemporaryDirectory() as d:
        jar = os.path.join(d, "pg.jar")
        urllib.request.urlretrieve(JDBC_URL, jar)
        expected = urllib.request.urlopen(JDBC_URL + ".sha1").read().decode().strip()
        check(hashlib.sha1(open(jar, "rb").read()).hexdigest() == expected, "jdbc: the driver's checksum")
        with open(os.path.join(d, "T.java"), "w") as f:
            f.write(JAVA)
        for mode, answer in (("auto", "yes"), ("tx", "yes"), ("auto", "no")):
            fresh()
            out = docker("run", "--rm", "-v", f"{d}:/w:ro", "eclipse-temurin:21-jdk", "java", "-cp",
                         "/w/pg.jar", "/w/T.java", str(SLUICE_PORT), mode, answer)
            text = out.stdout + out.stderr
            check("ERR " in text and "waiting for you" in text, f"jdbc {mode}/{answer}: the question: {text!r}")
            if answer == "yes":
                check("ANSWER 20" in text, f"jdbc {mode}/{answer}: {text!r}")
                check(count() == 30, f"jdbc {mode}/{answer}: committed ({count()} rows)")
            else:
                check(count() == 50, f"jdbc {mode}/{answer}: undone")
        fresh()  # a TRUNCATE: the same driver sends Execute with a row limit of 1 for it too
        out = docker("run", "--rm", "-v", f"{d}:/w:ro", "eclipse-temurin:21-jdk", "java", "-cp", "/w/pg.jar",
                     "/w/T.java", str(SLUICE_PORT), "auto", "yes", "truncate t")
        text = out.stdout + out.stderr
        check("TRUNCATE TABLE waiting for you" in text and "ANSWER 0" in text and count() == 0,
              f"jdbc truncate: {text!r} ({count()} rows)")


# ---- node-postgres and pgx (Go), in throwaway containers ----

HERE = os.path.dirname(os.path.abspath(__file__))


JAVA_MASK = r"""
import java.sql.*;
public class M {
  public static void main(String[] a) throws Exception {
    String url = "jdbc:postgresql://host.docker.internal:" + a[0] + "/postgres?user=postgres&sslmode=disable";
    try (Connection c = DriverManager.getConnection(url)) {
      try (PreparedStatement p = c.prepareStatement("select id, email, note from people where id <= ? order by id")) {
        for (int round = 0; round < 3; round++) { // the driver switches to a named statement from the 5th run on; rounds run it again
          p.setInt(1, 3);
          try (ResultSet r = p.executeQuery()) { while (r.next()) System.out.println("ROW" + round + " " + r.getInt(1) + " " + r.getString(2) + " " + r.getString(3)); }
        }
      }
      c.setAutoCommit(false); // a cursor: the portal is run a few rows at a time
      try (PreparedStatement p = c.prepareStatement("select id, email, note from people order by id")) {
        p.setFetchSize(4);
        try (ResultSet r = p.executeQuery()) { int n = 0; while (r.next() && n++ < 10) System.out.println("CURSOR " + r.getInt(1) + " " + r.getString(2) + " " + r.getString(3)); }
      }
      c.commit();
    }
  }
}
"""


def docker_drivers_enabled():
    return os.environ.get("SLUICE_JDBC") == "1" or os.environ.get("SLUICE_DRIVERS") == "docker"


def scenario_node():
    if not docker_drivers_enabled():
        print("    (skipped: SLUICE_DRIVERS=docker adds node-postgres, pgx and JDBC)")
        return
    with tempfile.TemporaryDirectory() as d:
        shutil.copy(os.path.join(HERE, "drivers", "pg_node.js"), os.path.join(d, "t.js"))
        for first, second in (("yes", "yes"), ("no", "no")):
            fresh()
            out = docker("run", "--rm", "-v", f"{d}:/w", "-w", "/w", "node:22-alpine", "sh", "-c",
                         f"npm install pg --silent --no-audit --no-fund >/dev/null 2>&1; "
                         f"node t.js {SLUICE_PORT} '{first}' '{second}'")
            text = out.stdout + out.stderr
            check("ERR " in text and "waiting for you" in text, f"node {first}: the question: {text!r}")
            if first == "yes":
                check("ANSWER DELETE 20" in text, f"node yes: {text!r}")
                check("ERR3" in text and "ANSWER2 DELETE 15" in text,
                      f"node yes: the named statement (parsed once) is asked about, and answered: {text!r}")
            check("FATAL" not in text, f"node {first}: {text!r}")
        fresh()


def scenario_go():
    if not docker_drivers_enabled():
        return
    with tempfile.TemporaryDirectory() as d:
        shutil.copy(os.path.join(HERE, "drivers", "pg_go.go"), os.path.join(d, "main.go"))
        for answer in ("yes", "no"):
            fresh()
            out = docker("run", "--rm", "-v", f"{d}:/w", "-w", "/w", "-e", "GOFLAGS=-mod=mod", "-e", "GOPATH=/tmp/go",
                         "-e", "GOCACHE=/tmp/gocache", "golang:1.23-alpine", "sh", "-c",
                         "go mod init t >/dev/null 2>&1; go get github.com/jackc/pgx/v5@v5.7.1 >/dev/null 2>&1; "
                         f"go run . {SLUICE_PORT} '{answer}'")
            text = out.stdout + out.stderr
            check("ERR " in text and "waiting for you" in text, f"pgx {answer}: the question: {text!r}")
            if answer == "yes":
                check("ANSWER DELETE 20" in text and "COUNT 30" in text, f"pgx yes: {text!r}")
            else:
                check("COUNT 50" in text or "ERR3" in text, f"pgx no: {text!r}")
                check(count() == 50, f"pgx no: undone ({count()})")


# ---- masking, with the drivers: each sends its own variety of the protocol ----

MASK_POLICY = """
mode = "enforce"

[[rule]]
name = "pii"
match = "any"
action = "mask"
columns = ["email"]
detect = ["email", "card"]
how = "redact"
"""


def mask_table():
    sql_direct("drop table if exists people; create table people (id int primary key, email text, note text, "
               "n numeric); insert into people select g, 'user' || g || '@example.com', "
               "case when g % 2 = 0 then 'card 4111 1111 1111 1111 for user' || g else 'plain ' || g end, g "
               "from generate_series(1, 40) g")


def check_masked(rows, what):
    """rows: tuples (id, email, note, n)."""
    check(len(rows) > 0, f"{what}: rows")
    for r in rows:
        check(r[1] == "[masked]" or r[1] is None, f"{what}: email {r[1]!r}")
        check("@example.com" not in str(r) and "4111 1111" not in str(r), f"{what}: a value shows: {r!r}")
    check(any(r[2] and "card [masked]" in r[2] for r in rows) or len(rows) < 2, f"{what}: the card in a note: {rows[:2]}")


async def asyncpg_mask(port):
    conn = await asyncpg.connect(host="127.0.0.1", port=port, user="postgres", database="postgres")
    rows = await conn.fetch("select id, email, note, n from people where id <= $1 order by id", 10)
    check_masked([tuple(r.values()) for r in rows], "asyncpg")
    check(rows[0]["n"] == 1, "asyncpg: the other columns are as they were")
    stmt = await conn.prepare("select id, email, note, n from people where id > $1 order by id")
    check_masked([tuple(r.values()) for r in await stmt.fetch(30)], "asyncpg prepared")
    check_masked([tuple(r.values()) for r in await stmt.fetch(35)], "asyncpg prepared, run again")
    async with conn.transaction():
        cur = await conn.cursor("select id, email, note, n from people order by id")
        check_masked([tuple(r.values()) for r in await cur.fetch(7)], "asyncpg cursor")
        check_masked([tuple(r.values()) for r in await cur.fetch(7)], "asyncpg cursor, second batch")
    try:
        await conn.copy_from_query("select * from people", output=lambda b: None)
        check(False, "asyncpg: COPY should be refused")
    except asyncpg.PostgresError as exc:
        check("COPY" in str(exc), f"asyncpg copy: {exc}")
    await conn.close()


def scenario_masking():
    """Values hidden in what real drivers read: text and binary results, prepared statements run twice, server-side
    cursors, pipelines, an ORM; COPY is refused."""
    mask_table()
    p, port, out = spawn_sluice(MASK_POLICY)
    dsn = f"host=127.0.0.1 port={port} user=postgres dbname=postgres"
    for binary in (False, True):
        with psycopg.connect(dsn, autocommit=True) as conn:
            cur = conn.cursor(binary=binary)
            cur.execute("select id, email, note, n from people where id <= %s order by id", (10,))
            check_masked(cur.fetchall(), f"psycopg binary={binary}")
            cur.execute("select id, email, note, n from people where id <= %s order by id", (10,), prepare=True)
            cur.execute("select id, email, note, n from people where id <= %s order by id", (10,), prepare=True)
            check_masked(cur.fetchall(), f"psycopg prepared, binary={binary}")
        with psycopg.connect(dsn) as conn:  # a server-side cursor: DECLARE, then FETCH in batches
            cur = conn.cursor(name="c1", binary=binary)
            cur.execute("select id, email, note, n from people order by id")
            check_masked(cur.fetchmany(5), f"psycopg named cursor, binary={binary}")
            check_masked(cur.fetchmany(5), f"psycopg named cursor, second batch, binary={binary}")
    with psycopg.connect(dsn, autocommit=True) as conn:
        with conn.pipeline():
            cursors = [conn.execute("select id, email, note, n from people where id = %s", (i,)) for i in range(1, 30)]
        for c in cursors:
            check_masked(c.fetchall(), "psycopg pipeline")
        try:
            with conn.cursor().copy("copy (select * from people) to stdout") as copy:
                for _ in copy:
                    pass
            check(False, "psycopg: COPY should be refused")
        except psycopg.Error as exc:
            check("COPY" in str(exc), f"psycopg copy: {exc}")
        cur = conn.execute("select id, email as e, lower(email) as l from people where id = 1")
        row = cur.fetchone()
        check(row[1] == "[masked]" and row[2] == "[masked]", f"an alias, found by its look: {row}")
        try:
            conn.execute("insert into people (id, email) values (1, 'dup@example.com')")
        except psycopg.Error as exc:
            check("people_pkey" in str(exc) and "user1@" not in str(exc), f"psycopg error: {exc}")
    asyncio.run(asyncpg_mask(port))
    engine = sqlalchemy.create_engine(f"postgresql+psycopg://postgres@127.0.0.1:{port}/postgres")
    with engine.connect() as c:
        rows = c.execute(sqlalchemy.text("select id, email, note, n from people where id <= :n order by id"),
                         {"n": 12}).fetchall()
        check_masked([tuple(r) for r in rows], "sqlalchemy")
    engine.dispose()
    text = "".join(out)
    check("user1@example.com" not in text and "4111 1111" not in text, "no value in the log")
    p.send_signal(signal.SIGTERM)
    p.wait(30)
    sql_direct("drop table people")


def scenario_masking_docker_drivers():
    if not docker_drivers_enabled():
        return
    mask_table()
    p, port, out = spawn_sluice(MASK_POLICY)

    def clean(text, what, marks):
        check("FATAL" not in text and "Exception" not in text and "ERR" not in text, f"{what}: {text!r}")
        check("@example.com" not in text and "4111 1111" not in text, f"{what}: a value shows: {text!r}")
        for mark in marks:
            check(mark in text, f"{what}: missing {mark!r} in {text!r}")

    with tempfile.TemporaryDirectory() as d:
        jar = os.path.join(d, "pg.jar")
        urllib.request.urlretrieve(JDBC_URL, jar)
        with open(os.path.join(d, "M.java"), "w") as f:
            f.write(JAVA_MASK)
        o = docker("run", "--rm", "-v", f"{d}:/w:ro", "eclipse-temurin:21-jdk", "java", "-cp", "/w/pg.jar", "/w/M.java", str(port))
        clean(o.stdout + o.stderr, "jdbc", ["ROW0 1 [masked] plain 1", "ROW2 2 [masked] card [masked]", "CURSOR 9 [masked] plain 9"])
    with tempfile.TemporaryDirectory() as d:
        shutil.copy(os.path.join(HERE, "drivers", "mask_node.js"), os.path.join(d, "t.js"))
        o = docker("run", "--rm", "-v", f"{d}:/w", "-w", "/w", "node:22-alpine", "sh", "-c",
                   f"npm install pg --silent --no-audit --no-fund >/dev/null 2>&1; node t.js {port}")
        clean(o.stdout + o.stderr, "node", ["SIMPLE 1 [masked] plain 1", "NAMED2 40 [masked] card [masked]", "ARRAY 2 [masked]"])
    with tempfile.TemporaryDirectory() as d:
        shutil.copy(os.path.join(HERE, "drivers", "mask_go.go"), os.path.join(d, "main.go"))
        o = docker("run", "--rm", "-v", f"{d}:/w", "-w", "/w", "-e", "GOFLAGS=-mod=mod", "-e", "GOPATH=/tmp/go",
                   "-e", "GOCACHE=/tmp/gocache", "golang:1.23-alpine", "sh", "-c",
                   "go mod init t >/dev/null 2>&1; go get github.com/jackc/pgx/v5@v5.7.1 >/dev/null 2>&1; "
                   f"go run . {port}")
        clean(o.stdout + o.stderr, "pgx", ["AGAIN 3 [masked] plain 3", "BATCH 2 [masked] card [masked]"])
    p.send_signal(signal.SIGTERM)
    p.wait(30)
    sql_direct("drop table people")


for scenario in (scenario_psycopg, scenario_psycopg_truncate, scenario_asyncpg, scenario_sqlalchemy,
                 scenario_equivalence, scenario_soak, scenario_masking, scenario_masking_docker_drivers, scenario_jdbc,
                 scenario_node, scenario_go):
    started_at = time.monotonic()
    before = len(failures)
    try:
        scenario()
    except Exception as exc:  # a scenario that cannot even run is a failure
        check(False, f"{scenario.__name__} raised {exc!r}")
    print(f"{'ok ' if len(failures) == before else 'FAIL'} {scenario.__name__} ({time.monotonic() - started_at:.1f}s)")

proc.send_signal(signal.SIGTERM)
docker("stop", NAME)
sys.exit(1 if failures else 0)
