/* sluice: a guard proxy for PostgreSQL. */

#include <stdio.h>
#include <string.h>

#include "check.h"
#include "config.h"
#include <openssl/crypto.h>
#include <pg_query.h>

#include "learn.h"
#include "log.h"
#include "server.h"
#include "testpolicy.h"
#include "undo.h"

#ifndef SLUICE_VERSION
#define SLUICE_VERSION "0.0.0"
#endif
#ifndef SLUICE_COMMIT
#define SLUICE_COMMIT "unknown"
#endif
#ifndef SLUICE_STATIC
#define SLUICE_STATIC 0
#endif

static void usage(FILE *out)
{
    fputs(
        "usage: sluice --listen HOST:PORT --upstream HOST:PORT [--policy FILE]\n"
        "              [--upstream-tls off|require|verify-full] [--upstream-ca FILE]\n"
        "              [--upstream-cert FILE --upstream-key FILE] [--log-sql "
        "full|normalized|none]\n"
        "       sluice --check-policy FILE [--sql TEXT]... [--user NAME] [--database NAME]\n"
        "       sluice --undo FILE [--id ID] [--partial]\n"
        "       sluice --verify-log FILE --log-chain-key-file KEY\n"
        "       sluice --test-policy POLICY TESTS\n"
        "       sluice --learn LOG [--user NAME] [--database NAME] [--action deny|confirm|alert]\n"
        "       sluice --version | --help\n"
        "\n"
        "  --listen HOST:PORT    where clients connect (IPv6: [::1]:5433)\n"
        "  --upstream HOST:PORT  the PostgreSQL server to forward to\n"
        "  --check-policy FILE   no server: read the policy and say what it does with each --sql\n"
        "                        (exit 0 allowed, 1 invalid policy, 3 refused, 4 held for an "
        "answer);\n"
        "                        --at 2026-12-01T18:30Z judges the rules that depend on the time "
        "then\n"
        "  --learn LOG           no server: print a rule that accepts the shapes of statements "
        "that went\n"
        "                        through in a log (outside_fingerprints) and treats others as "
        "--action says\n"
        "  --test-policy FILE TESTS   no server: check the policy against a file of expectations "
        "(one\n"
        "                        `deny RULE :: SQL` per line; exit 0 all as wanted, 1 not)\n"
        "  --undo FILE           no server: list the entries of an undo journal, or with --id "
        "print "
        "the SQL\n"
        "                        that puts back the rows of one (a DELETE's rows, or the old "
        "values "
        "of an\n"
        "                        UPDATE; --partial: even when not all are there)\n"
        "  --undo-journal FILE   where rules with journal = \"on\" or \"required\" write the rows "
        "their\n"
        "                        DELETEs remove or UPDATEs change (owner-only; it holds the data "
        "itself); "
        "--undo-journal-max\n"
        "                        SIZE stops it growing past that (default 256MB)\n"
        "  --policy FILE         rules to apply to statements (see docs/policy.md); without it "
        "sluice\n"
        "                        only relays and logs\n"
        "  --upstream-tls MODE   encrypt the connection to the database: off (default), require "
        "(no\n"
        "                        certificate check) or verify-full (certificate and host name)\n"
        "  --upstream-ca FILE    CA certificates to trust with verify-full (default: the system "
        "store)\n"
        "  --upstream-cert FILE  client certificate (PEM) to show to the database, for a server "
        "that asks for\n"
        "  --upstream-key FILE   one; and its private key (PEM, not encrypted). Both or neither.\n"
        "  --log-sql MODE        what the log keeps of the SQL: full (default), normalized (values "
        "replaced\n"
        "                        by $1, $2...) or none (only a fingerprint of the query)\n"
        "  --listen-tls self-signed   encrypt the clients' side too, with a certificate made at "
        "startup\n"
        "                        (enough for sslmode=require; clients that check who sluice is "
        "need "
        "a real one)\n"
        "  --listen-tls-cert FILE --listen-tls-key FILE   the same with a certificate of your own "
        "(PEM,\n"
        "                        key not encrypted). With either, clients must use TLS.\n"
        "  --tag-application-name on|off   add \" [sluice N]\" to the application_name the "
        "database "
        "sees\n"
        "                        (N is the connection's id in this log), to find one in the other "
        "(default off)\n"
        "  --log-results on|off  one `result` event per statement: outcome, rows, bytes, time "
        "(default off)\n"
        "  --log-chain-key-file FILE   chain the lines of the log (seq and chain on each) with an "
        "HMAC\n"
        "                        under this key (16 to 1024 bytes); `sluice --verify-log FILE "
        "--log-chain-key-file\n"
        "                        KEY` finds a line taken out, changed or added afterwards\n",
        out);
    fputs(
        "  --admin HOST:PORT     an HTTP listener (no TLS): /metrics for Prometheus, /healthz, and "
        "the\n"
        "                        confirmations waiting (/pending); --admin-token-file FILE makes "
        "it "
        "need a\n"
        "                        Bearer token (required beyond loopback and with --confirm-admin)\n"
        "  --confirm-admin on    ask the operator's confirmations there: POST /confirm/ID/yes or "
        "/no "
        "(exclusive\n"
        "                        with --confirm-tty and --confirm-command)\n"
        "  --event-command CMD   run CMD for the events of --event-filter (default alert,kill,"
        "confirm_pending,\n"
        "                        admin_denied,policy_reload_failed), the log line on stdin, the "
        "event "
        "in\n"
        "                        $SLUICE_EVENT: a webhook, a chat (see tools/webhook.sh)\n"
        "  --mask-key-file FILE  the key of the tokens that rules with action = \"mask\" and how = "
        "\"hash\" make\n"
        "                        (16 to 1024 bytes of anything secret); without it a key is made "
        "at "
        "startup\n"
        "                        and the tokens change when sluice restarts\n"
        "  --confirm-command CMD ask a command instead: it is run by the shell with the question "
        "on its\n"
        "                        standard input, and exit status 0 means yes (anything else, no)\n"
        "  --confirm-tty FILE    where a person is asked to confirm a DELETE or UPDATE (rules "
        "with\n"
        "                        action = \"confirm\"); default /dev/tty\n"
        "\n"
        "Events are written to stdout, one JSON object per line.\n",
        out);
}

int main(int argc, char **argv)
{
    sl_config cfg;
    char err[256];

    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("sluice %s (commit %s; %s; PostgreSQL parser %s; %s)\n", SLUICE_VERSION,
               SLUICE_COMMIT, OpenSSL_version(OPENSSL_VERSION), PG_VERSION,
               SLUICE_STATIC ? "static" : "dynamic");
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        usage(stdout);
        return 0;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--check-policy") == 0) {
            return sl_check_main(argc, argv);
        }
        if (strcmp(argv[i], "--learn") == 0) {
            return sl_learn_main(argc - i - 1, argv + i + 1);
        }
        if (strcmp(argv[i], "--test-policy") == 0) {
            return sl_test_policy_main(argc - i - 1, argv + i + 1);
        }
        if (strcmp(argv[i], "--verify-log") == 0) {
            return sl_log_verify_main(argc - i - 1, argv + i + 1);
        }
        if (strcmp(argv[i], "--undo") == 0) {
            return sl_undo_main(argc - i - 1, argv + i + 1);
        }
    }
    if (sl_config_parse(&cfg, argc, argv, err, sizeof err) != 0) {
        fprintf(stderr, "sluice: %s\n\n", err);
        usage(stderr);
        return 2;
    }
    return sl_server_run(&cfg);
}
