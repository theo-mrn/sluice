#!/usr/bin/env python3
"""Writes the seed corpus of the fuzz targets into fuzz/corpus/.

Every seed is one byte that picks the target (see targets.c) followed by that target's input. The seeds are
valid inputs and edge cases: the fuzzer starts from them and mutates. Run it again to rebuild the corpus."""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "corpus")

STARTUP, MESSAGE, STATEMENTS, BLOCKING, JSON, ADDRESS, POLICY, SQL, BUF, SASL, SCANNER, SRVSCAN, CONFIRM = range(13)

# the scanner target: one byte of options, one byte that seeds the cuts, then the client's stream.
# options: bit 0 block statements, 1 block unreadable, 2 close on frame error, 3 judge fast-path calls,
# bits 4-5 the size limit (8, 32, 256, 4096 bytes)
def scan(options, stream):
    return bytes([options, 5]) + stream


def startup(**params):
    body = struct.pack("!I", 196608)
    for k, v in params.items():
        body += k.encode() + b"\0" + v.encode() + b"\0"
    body += b"\0"
    return struct.pack("!I", len(body) + 4) + body


def msg(kind, payload=b""):
    return kind + struct.pack("!I", len(payload) + 4) + payload


seeds = {
    "startup-v3": (STARTUP, startup(user="alice", database="db1", application_name="psql")),
    "startup-replication": (STARTUP, startup(user="r", replication="database")),
    "startup-empty-params": (STARTUP, struct.pack("!II", 9, 196608) + b"\0"),
    "ssl-request": (STARTUP, struct.pack("!II", 8, 80877103)),
    "gssenc-request": (STARTUP, struct.pack("!II", 8, 80877104)),
    "cancel-request": (STARTUP, struct.pack("!IIII", 16, 80877102, 4242, 0xDEADBEEF)),
    "startup-huge-length": (STARTUP, struct.pack("!II", 0xFFFFFFFF, 196608)),
    "startup-truncated": (STARTUP, struct.pack("!II", 40, 196608) + b"user\0al"),

    "query-message": (MESSAGE, msg(b"Q", b"select 1\0")),
    "parse-message": (MESSAGE, msg(b"P", b"s1\0select $1::int\0" + struct.pack("!HI", 1, 23))),
    "terminate": (MESSAGE, msg(b"X")),
    "message-length-3": (MESSAGE, b"Q" + struct.pack("!I", 3)),
    "message-length-max": (MESSAGE, b"Q" + struct.pack("!I", 0x3FFFFFFF) + b"x"),
    "message-two": (MESSAGE, msg(b"Q", b"a\0") + msg(b"S")),

    "stmt-query": (STATEMENTS, b"select 1\0"),
    "stmt-query-empty": (STATEMENTS, b"\0"),
    "stmt-query-inner-nul": (STATEMENTS, b"sel\0ect\0"),
    "stmt-parse": (STATEMENTS, b"name\0select $1\0" + struct.pack("!HII", 2, 23, 25)),
    "stmt-parse-unnamed": (STATEMENTS, b"\0select 1\0" + struct.pack("!H", 0)),
    "stmt-parse-short": (STATEMENTS, b"\0\0\0"),

    "reason-plain": (BLOCKING, b"sluice: blocked by rule no-ddl: schema changes go through migrations"),
    "reason-quote": (BLOCKING, b"it's a ' test ''"),
    "reason-backslash": (BLOCKING, b"back\\slash and \\' then ; drop table t; --"),
    "reason-control": (BLOCKING, b"line\nbreak\ttab\x00nul\x1b"),
    "reason-utf8": (BLOCKING, "café € \U0001F600".encode()),
    "reason-invalid-utf8": (BLOCKING, b"bad \xff\xfe \xc3"),

    "json-plain": (JSON, b"hello"),
    "json-escapes": (JSON, b'a"b\\c\nd\re\tf\x08\x0c\x01\x1f\x7f'),
    "json-utf8": (JSON, "café € \U0001F600".encode()),
    "json-invalid-utf8": (JSON, b"\x80\xc0\x80\xed\xa0\x80\xf4\x90\x80\x80\xff a\xc3"),
    "json-nul": (JSON, b"a\0b"),

    "addr-v4": (ADDRESS, b"127.0.0.1:5432"),
    "addr-name": (ADDRESS, b"db.internal:0"),
    "addr-v6": (ADDRESS, b"[::1]:5433"),
    "addr-bad-v6": (ADDRESS, b"::1:5432"),
    "addr-port-too-big": (ADDRESS, b"host:65536"),
    "addr-no-port": (ADDRESS, b"host"),

    "policy-readme": (POLICY, b'''mode = "audit"

[[rule]]
name    = "no-unbounded-write"
match   = "update_or_delete_without_where"
message = "add a WHERE clause"

[[rule]]
name  = "agent-read-only"
match = "not_read_only"
users = ["agent"]
'''),
    "policy-full": (POLICY, b'''# comment
mode = 'enforce'
on_uninspectable = "allow"
[[rule]]
name = "a.b:c-d_e"
match = "ddl"
action = "allow"
users = ["x", 'y',]
databases = ["prod"]
message = "ok"
[[rule]]
name = "z"
match = "multi_statement"
'''),
    "policy-tables": (POLICY, b'''mode = "enforce"
[[rule]]
name = "agent-sales-only"
match = "any"
users = ["agent"]
outside_tables = ["orders", "public.products"]
[[rule]]
name = "ledger"
match = "not_read_only"
tables = ["ledger", "archive.ledger"]
[[rule]]
name = "scratch"
match = "ddl"
action = "allow"
tables = ["scratch"]
'''),
    "policy-bad-table": (POLICY, b'[[rule]]\nname = "x"\nmatch = "any"\ntables = ["a.b.c"]\n'),
    "policy-bad-key": (POLICY, b'[[rule]]\nname = "x"\nmatch = "ddl"\nbogus = "1"\n'),
    "policy-multiline": (POLICY, b'mode = """multi\nline"""\n'),
    "policy-crlf": (POLICY, b'mode = "audit"\r\n[[rule]]\r\nname = "a"\r\nmatch = "drop"'),

    "sql-select": (SQL, b"select * from t where id = 1"),
    "sql-delete": (SQL, b"delete from t"),
    "sql-cte-delete": (SQL, b"with d as (delete from t returning *) select * from d"),
    "sql-explain-analyze": (SQL, b"explain analyze update t set a = 1"),
    "sql-ddl": (SQL, b"create table t (i int); drop table t; truncate t"),
    "sql-do": (SQL, b"do $$ begin delete from t; end $$"),
    "sql-set": (SQL, b"set role admin; set application_name = 'x'; reset all"),
    "sql-prepare": (SQL, b"prepare p as delete from t; execute p"),
    "sql-copy": (SQL, b"copy (delete from t returning *) to stdout"),
    "sql-tables-join": (SQL, b"\x01select * from a join b.c on true where exists (select 1 from d)"),
    "sql-tables-many": (SQL, b"\x01select * from a; delete from b where x = 1;\n  update c set y = 2 where z = 3 ; select 1"),
    "sql-tables-merge": (SQL, b"\x01merge into t using s on t.id = s.id when matched then delete"),
    "sql-tables-ddl": (SQL, b"\x01create table x (i int); drop table y, z; comment on table x is 'c'"),
    "sql-syntax-error": (SQL, b"selec 1 from"),
    "sql-backslash-attack": (SQL, b"select 'x\\'\n'; delete from t; --'"),
    "sql-backslash-sjis": (SQL, b"select E'\x95\\'; delete from t; --'"),
    "sql-backslash-fine": (SQL, b"select 'C:\\\\', E'it\\'s', $$a\\'b$$, x ~ '\\d+' from t -- \\'"),
    "srv-pass-z": (SRVSCAN, bytes([0b00000001]) + msg(b"T", b"x") + msg(b"D", b"\0\1\0\0\0\1a") + msg(b"C", b"DELETE 1\0") + msg(b"Z", b"I")),
    "srv-read-drop": (SRVSCAN, bytes([0b00010111]) + msg(b"C", b"BEGIN\0") + msg(b"D", b"\0\0") + msg(b"C", b"DELETE 0\0") + msg(b"Z", b"T")),
    "srv-skip-error": (SRVSCAN, bytes([0b00100001]) + msg(b"E", b"SERROR\0\0") + msg(b"Z", b"E")),
    "srv-oversize": (SRVSCAN, bytes([0b01000100]) + msg(b"D", b"x" * 200) + msg(b"Z", b"I")),
    "srv-garbage": (SRVSCAN, bytes([0b00000001]) + msg(b"Z", b"I") + b"D\0\0\0\1" + msg(b"Z", b"T")),
    "confirm-delete-rows": (CONFIRM, bytes([0b00000000]) + b"\0\0" + b"\1\x0a" + b"\0\2\0id\0" + b"\1\2" + b"AB" + b"\0\0" + b"\4\3" + b"\0\0\0"),
    "confirm-error": (CONFIRM, bytes([0b00000001]) + b"\3\x30" + b"SERROR\0\0" + b"\4\1I"),
    "sql-deep": (SQL, b"select " + b"(" * 300 + b"1" + b")" * 300),

    "sasl-both": (SASL, struct.pack("!I", 10) + b"SCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0\0"),
    "sasl-plus-last": (SASL, struct.pack("!I", 10) + b"SCRAM-SHA-256\0SCRAM-SHA-256-PLUS\0\0"),
    "sasl-only-plus": (SASL, struct.pack("!I", 10) + b"SCRAM-SHA-256-PLUS\0\0"),
    "sasl-three": (SASL, struct.pack("!I", 10) + b"A\0SCRAM-SHA-256-PLUS\0B\0SCRAM-SHA-256-PLUS\0\0"),
    "sasl-no-terminator": (SASL, struct.pack("!I", 10) + b"SCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0"),
    "sasl-other-code": (SASL, struct.pack("!I", 11) + b"SCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0\0"),
    "scan-batch": (SCANNER, scan(0b00100001, msg(b"p", b"pw\0") + msg(b"Q", b"select 1\0") + msg(b"Q", b"Bad\0")
                                 + msg(b"P", b"Bs\0select 1\0\0\0") + msg(b"B", b"\0s\0\0\0\0\0\0\0\0\0")
                                 + msg(b"E", b"\0\0\0\0\0") + msg(b"S") + msg(b"X"))),
    "scan-big-blocked": (SCANNER, scan(0b00000011, msg(b"Q", b"x" * 100 + b"\0") + msg(b"Q", b"after\0")
                                       + msg(b"P", b"y" * 33))),
    "scan-big-relayed": (SCANNER, scan(0b00000000, msg(b"Q", b"x" * 100 + b"\0") + msg(b"Q", b"after\0"))),
    "scan-fastpath": (SCANNER, scan(0b00001010, msg(b"F", struct.pack("!IHHH", 1234, 0, 0, 0)) + msg(b"Q", b"x\0"))),
    "scan-garbage-close": (SCANNER, scan(0b00000101, msg(b"Q", b"select 1\0") + b"Z\x00\x00\x00\x02junk" + msg(b"Q", b"Bx\0"))),
    "scan-garbage-relay": (SCANNER, scan(0b00000001, msg(b"Q", b"select 1\0") + b"\xff\xff\xff\xff\xffjunk" + msg(b"Q", b"Bx\0"))),
    "scan-cut-message": (SCANNER, scan(0b00010001, msg(b"Q", b"Bselect 1\0")[:7])),
    "buf-ops": (BUF, bytes([0, 5]) + b"hello" + bytes([1, 2, 2, 1, 2, 3]) + bytes([3, 10, 0, 40, 1, 7])),
    "buf-random": (BUF, bytes((i * 37 + 11) % 256 for i in range(200))),
}


def main():
    os.makedirs(OUT, exist_ok=True)
    for name in os.listdir(OUT):
        os.unlink(os.path.join(OUT, name))
    for name, (target, data) in sorted(seeds.items()):
        with open(os.path.join(OUT, name + ".bin"), "wb") as f:
            f.write(bytes([target]) + data)
    print(f"{len(seeds)} seeds written to {OUT}")


if __name__ == "__main__":
    sys.exit(main())
