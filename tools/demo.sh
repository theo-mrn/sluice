#!/bin/sh
# Try sluice by hand against a throwaway PostgreSQL in Docker. Nothing of yours is touched: the container
# is called sluice-demo-pg, listens on 127.0.0.1:56500 only, uses no password, and `down` removes it.
#
#   tools/demo.sh up        start the database, with tables that cascade and a trigger
#   tools/demo.sh sluice    run sluice in front of it, in this terminal (it only shows its log)
#   tools/demo.sh psql      (in another terminal) a psql through sluice (TLS)
#   tools/demo.sh pgbench   (in another terminal) a real client that prepares its statements
#   tools/demo.sh direct    a psql straight to the database, to look at what is really there
#   tools/demo.sh undo      list the DELETEs sluice kept for undo and print the SQL that puts the last one back
#   tools/demo.sh undo run  ... and run it against the database (the deleted rows come back)
#   tools/demo.sh down      remove the container
#
# Needs Docker, and a build: meson setup build && meson compile -C build

set -eu

# Overridable, to run a second copy next to the first: DEMO_NAME, DEMO_DB_PORT, DEMO_SLUICE_PORT.
NAME=${DEMO_NAME:-sluice-demo-pg}
DB_PORT=${DEMO_DB_PORT:-56500}
SLUICE_PORT=${DEMO_SLUICE_PORT:-56501}
HERE=$(cd "$(dirname "$0")/.." && pwd)
BIN=${SLUICE_BIN:-$HERE/build/sluice}
POLICY=${TMPDIR:-/tmp}/$NAME-policy.toml
JOURNAL=${TMPDIR:-/tmp}/$NAME-undo.jsonl

sql() { docker exec -i "$NAME" psql -U postgres -q -v ON_ERROR_STOP=1 "$@"; }

case "${1:-}" in
up)
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker run -d --rm --name "$NAME" -e POSTGRES_HOST_AUTH_METHOD=trust \
        -p 127.0.0.1:$DB_PORT:5432 postgres:17-alpine >/dev/null
    printf 'waiting for the database'
    until docker exec "$NAME" pg_isready -U postgres >/dev/null 2>&1; do printf .; sleep 0.5; done
    sleep 1
    echo
    sql <<'EOF'
create table customers (id int primary key, email text);
create table orders (id serial primary key, customer_id int references customers on delete cascade, total int);
create table audit (id serial primary key, what text);
create function log_gone() returns trigger language plpgsql as
  $$ begin insert into audit(what) values ('customer ' || old.id || ' deleted'); return old; end $$;
create trigger customers_gone after delete on customers for each row execute function log_gone();
insert into customers select g, 'user' || g || '@example.com' from generate_series(1, 200) g;
insert into orders(customer_id, total) select (g % 200) + 1, g from generate_series(1, 1000) g;
EOF
    cat <<EOF

database up: 200 customers, 1000 orders (they cascade), an audit trigger.
next:  tools/demo.sh sluice        (leave it running, in this terminal)
then:  tools/demo.sh psql          (in another terminal)

things to try in that psql:
  delete from customers where id <= 3;            -- 3 rows: goes through, no question
  delete from customers where id <= 20;           -- asks, here in psql: the rows and the cascade into orders
                                                  -- and audit; then answer:  yes;  no;  or  show;  (more rows)
  update orders set total = 0 where id < 100;     -- asks: 99 rows
  delete from customers;                          -- refused: no WHERE
  drop table audit;                               -- refused: DDL
the deletes are kept for undo:  tools/demo.sh undo   (and  tools/demo.sh undo run  puts the last one back)
then, with a prepared-statement client:  tools/demo.sh pgbench
and to see what is really in the database:  tools/demo.sh direct   (select count(*) from customers;)
EOF
    ;;
sluice)
    [ -x "$BIN" ] || { echo "no $BIN: build first (meson setup build && meson compile -C build)" >&2; exit 1; }
    cat >"$POLICY" <<'EOF'
mode = "enforce"
confirm_timeout = "5m"

# schema changes and writes without WHERE are refused
[[rule]]
name = "no-ddl"
match = "ddl"

[[rule]]
name = "no-unbounded-write"
match = "update_or_delete_without_where"
message = "add a WHERE clause"

# a DELETE or UPDATE that touches more than 5 rows asks a person (you, here)
[[rule]]
name = "confirm-deletes"
match = "delete"
action = "confirm"
over_rows = "5"
journal = "on"      # the rows a DELETE removes are written to a file first: tools/demo.sh undo puts them back

[[rule]]
name = "confirm-updates"
match = "update"
action = "confirm"
over_rows = "5"
EOF
    echo "sluice on 127.0.0.1:$SLUICE_PORT (TLS) -> database on 127.0.0.1:$DB_PORT. It only shows its JSON log here:"
    echo "the questions are asked in the psql of whoever sent the statement. Ctrl-C stops it."
    echo
    exec "$BIN" --listen "127.0.0.1:$SLUICE_PORT" --listen-tls self-signed \
        --upstream "127.0.0.1:$DB_PORT" --policy "$POLICY" --undo-journal "$JOURNAL"
    ;;
psql)
    # psql runs in the container (the image has it), so it reaches sluice, which runs on this machine, as
    # host.docker.internal. TLS is on, so sslmode=require works (and the demo shows that too).
    exec docker exec -it -e PGSSLMODE=require "$NAME" psql -h host.docker.internal -p "$SLUICE_PORT" -U postgres
    ;;
pgbench)
    cat <<EOF
pgbench prepares its statements (the extended protocol, like an ORM). This runs two prepared DELETEs through
sluice. pgbench cannot answer a question, so each one comes back as an error (the statement waits, then is
undone): that is what a client that cannot confirm sees. See the pending ones with the sluice log.
EOF
    printf 'delete from orders where id between 1 and 20;\ndelete from orders where id between 100 and 120;\n' |
        docker exec -i "$NAME" sh -c 'cat > /tmp/del.sql'
    docker exec -e PGSSLMODE=require "$NAME" pgbench -n -M prepared -f /tmp/del.sql -t 1 \
        -h host.docker.internal -p $SLUICE_PORT -U postgres postgres || true
    ;;
direct)
    exec docker exec -it "$NAME" psql -U postgres
    ;;
undo)
    [ -x "$BIN" ] || { echo "no $BIN: build first" >&2; exit 1; }
    [ -s "$JOURNAL" ] || { echo "nothing kept yet: run a DELETE through sluice first (tools/demo.sh psql)" >&2; exit 1; }
    "$BIN" --undo "$JOURNAL"
    last=$("$BIN" --undo "$JOURNAL" | awk 'NR > 1 { id = $1 } END { print id }')
    echo
    if [ "${2:-}" = run ]; then
        "$BIN" --undo "$JOURNAL" --id "$last" --partial | sql
        echo "ran it: the rows are back (tools/demo.sh direct)"
    else
        "$BIN" --undo "$JOURNAL" --id "$last" --partial
        echo "-- to run it: tools/demo.sh undo run"
    fi
    ;;
down)
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    rm -f "$POLICY" "$JOURNAL"
    echo removed
    ;;
*)
    sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
