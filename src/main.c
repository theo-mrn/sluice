/* sluice: a guard proxy for PostgreSQL. */

#include <stdio.h>
#include <string.h>

#include "config.h"
#include "server.h"

#ifndef SLUICE_VERSION
#define SLUICE_VERSION "0.0.0"
#endif

static void usage(FILE *out)
{
    fputs(
        "usage: sluice --listen HOST:PORT --upstream HOST:PORT [--policy FILE]\n"
        "              [--upstream-tls off|require|verify-full] [--upstream-ca FILE]\n"
        "              [--upstream-cert FILE --upstream-key FILE] [--log-sql "
        "full|normalized|none]\n"
        "       sluice --version | --help\n"
        "\n"
        "  --listen HOST:PORT    where clients connect (IPv6: [::1]:5433)\n"
        "  --upstream HOST:PORT  the PostgreSQL server to forward to\n"
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
        printf("sluice %s\n", SLUICE_VERSION);
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        usage(stdout);
        return 0;
    }

    if (sl_config_parse(&cfg, argc, argv, err, sizeof err) != 0) {
        fprintf(stderr, "sluice: %s\n\n", err);
        usage(stderr);
        return 2;
    }
    return sl_server_run(&cfg);
}
