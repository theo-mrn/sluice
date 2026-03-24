#include "check.h"
#include "config.h"

static int parse(char *const argv[], int argc, sl_config *cfg, char *err, size_t errcap)
{
    return sl_config_parse(cfg, argc, argv, err, errcap);
}

#define PARSE(cfg, err, ...)                                                                       \
    parse((char *const[]){"sluice", __VA_ARGS__},                                                  \
          (int)(sizeof((char *const[]){"sluice", __VA_ARGS__}) / sizeof(char *)), (cfg), (err),    \
          sizeof(err))

static void test_addr(void)
{
    char host[64];
    char port[8];

    CHECK(sl_addr_parse("127.0.0.1:5432", host, sizeof host, port, sizeof port) == 0);
    CHECK_STR(host, "127.0.0.1");
    CHECK_STR(port, "5432");

    CHECK(sl_addr_parse("db.internal:5432", host, sizeof host, port, sizeof port) == 0);
    CHECK_STR(host, "db.internal");

    CHECK(sl_addr_parse("[::1]:5433", host, sizeof host, port, sizeof port) == 0);
    CHECK_STR(host, "::1");
    CHECK_STR(port, "5433");

    CHECK(sl_addr_parse("localhost:0", host, sizeof host, port, sizeof port) == 0);
    CHECK_STR(port, "0");
    CHECK(sl_addr_parse("localhost:65535", host, sizeof host, port, sizeof port) == 0);

    CHECK(sl_addr_parse(NULL, host, sizeof host, port, sizeof port) == -1);
    CHECK(sl_addr_parse("", host, sizeof host, port, sizeof port) == -1);
    CHECK(sl_addr_parse("localhost", host, sizeof host, port, sizeof port) == -1); /* no port */
    CHECK(sl_addr_parse(":5432", host, sizeof host, port, sizeof port) == -1);     /* no host */
    CHECK(sl_addr_parse("localhost:", host, sizeof host, port, sizeof port) == -1);
    CHECK(sl_addr_parse("localhost:65536", host, sizeof host, port, sizeof port) == -1);
    CHECK(sl_addr_parse("localhost:123456", host, sizeof host, port, sizeof port) == -1);
    CHECK(sl_addr_parse("localhost:http", host, sizeof host, port, sizeof port) == -1);
    CHECK(sl_addr_parse("localhost:-1", host, sizeof host, port, sizeof port) == -1);
    CHECK(sl_addr_parse("::1:5432", host, sizeof host, port, sizeof port) ==
          -1); /* needs brackets */
    CHECK(sl_addr_parse("[::1]5432", host, sizeof host, port, sizeof port) == -1);
    CHECK(sl_addr_parse("[::1:5432", host, sizeof host, port, sizeof port) == -1);
    CHECK(sl_addr_parse("[]:5432", host, sizeof host, port, sizeof port) == -1);

    /* a host is a name or an address, nothing that could break a message or a log line */
    CHECK(sl_addr_parse("my_db-1.example.com:5432", host, sizeof host, port, sizeof port) == 0);
    CHECK(sl_addr_parse("[fe80::1%en0]:5432", host, sizeof host, port, sizeof port) == 0);
    CHECK_STR(host, "fe80::1%en0");
    CHECK(sl_addr_parse("bad host:5432", host, sizeof host, port, sizeof port) == -1);
    CHECK(sl_addr_parse("bad\nhost:5432", host, sizeof host, port, sizeof port) == -1);
    CHECK(sl_addr_parse("bad\"host:5432", host, sizeof host, port, sizeof port) == -1);
    CHECK(sl_addr_parse("a]b:5432", host, sizeof host, port, sizeof port) == -1);
    CHECK(sl_addr_parse("a[b:5432", host, sizeof host, port, sizeof port) == -1);
    CHECK(sl_addr_parse("[a b]:5432", host, sizeof host, port, sizeof port) == -1);
    CHECK(sl_addr_parse("[::1\x01]:5432", host, sizeof host, port, sizeof port) == -1);
    CHECK(sl_addr_parse("h\xc3\xa9:5432", host, sizeof host, port, sizeof port) == -1);

    /* does not fit in the destination */
    CHECK(sl_addr_parse("a-long-host-name:5432", host, 8, port, sizeof port) == -1);
    CHECK(sl_addr_parse("localhost:5432", host, sizeof host, port, 4) == -1);
}

static void test_config(void)
{
    sl_config cfg;
    char err[256];

    CHECK(PARSE(&cfg, err, "--listen", "127.0.0.1:5433", "--upstream", "db:5432") == 0);
    CHECK_STR(cfg.listen_host, "127.0.0.1");
    CHECK_STR(cfg.listen_port, "5433");
    CHECK_STR(cfg.upstream_host, "db");
    CHECK_STR(cfg.upstream_port, "5432");

    /* --name=value, and any order */
    CHECK(PARSE(&cfg, err, "--upstream=[::1]:5432", "--listen=0.0.0.0:6000") == 0);
    CHECK_STR(cfg.upstream_host, "::1");
    CHECK_STR(cfg.listen_host, "0.0.0.0");

    /* the last occurrence wins */
    CHECK(PARSE(&cfg, err, "--listen", "a:1", "--listen", "b:2", "--upstream", "c:3") == 0);
    CHECK_STR(cfg.listen_host, "b");

    /* errors, each with a message */
    CHECK(PARSE(&cfg, err, "--upstream", "db:5432") == -1);
    CHECK(strstr(err, "--listen") != NULL);
    CHECK(PARSE(&cfg, err, "--listen", "127.0.0.1:5433") == -1);
    CHECK(strstr(err, "--upstream") != NULL);
    CHECK(PARSE(&cfg, err, "--listen") == -1);
    CHECK(strstr(err, "needs a value") != NULL);
    CHECK(PARSE(&cfg, err, "--listen", "nope", "--upstream", "db:1") == -1);
    CHECK(strstr(err, "invalid --listen") != NULL);
    CHECK(PARSE(&cfg, err, "--listen", "a:1", "--upstream", "nope") == -1);
    CHECK(strstr(err, "invalid --upstream") != NULL);
    CHECK(PARSE(&cfg, err, "--listen", "a:1", "--upstream", "b:2", "--wat") == -1);
    CHECK(strstr(err, "unknown argument") != NULL);
    CHECK(PARSE(&cfg, err, "--listens", "a:1", "--upstream", "b:2") == -1); /* not a prefix match */

    /* a client certificate for the database: both files, and only when the hop is encrypted */
    CHECK(PARSE(&cfg, err, "--listen", "a:1", "--upstream", "b:2", "--upstream-tls", "verify-full",
                "--upstream-cert", "c.pem", "--upstream-key", "k.pem") == 0);
    CHECK_STR(cfg.upstream_cert, "c.pem");
    CHECK_STR(cfg.upstream_key, "k.pem");
    CHECK(PARSE(&cfg, err, "--listen", "a:1", "--upstream", "b:2", "--upstream-tls=require",
                "--upstream-key=/k", "--upstream-cert=/c") == 0);
    CHECK(PARSE(&cfg, err, "--listen", "a:1", "--upstream", "b:2", "--upstream-tls", "require",
                "--upstream-cert", "c.pem") == -1);
    CHECK(strstr(err, "go together") != NULL);
    CHECK(PARSE(&cfg, err, "--listen", "a:1", "--upstream", "b:2", "--upstream-tls", "require",
                "--upstream-key", "k.pem") == -1);
    CHECK(strstr(err, "go together") != NULL);
    CHECK(PARSE(&cfg, err, "--listen", "a:1", "--upstream", "b:2", "--upstream-cert", "c.pem",
                "--upstream-key", "k.pem") == -1);
    CHECK(strstr(err, "does nothing without --upstream-tls") != NULL);
    CHECK(PARSE(&cfg, err, "--listen", "a:1", "--upstream", "b:2", "--upstream-tls", "require",
                "--upstream-cert=", "--upstream-key", "k") == -1);
    CHECK(strstr(err, "invalid --upstream-cert path") != NULL);

    /* the CA of the database, and TLS spelled out as off */
    CHECK(PARSE(&cfg, err, "--listen", "a:1", "--upstream", "b:2", "--upstream-tls", "verify-full",
                "--upstream-ca", "") == -1);
    CHECK(strstr(err, "invalid --upstream-ca path") != NULL);
    CHECK(PARSE(&cfg, err, "--listen", "a:1", "--upstream", "b:2", "--upstream-tls", "off") == 0 &&
          cfg.upstream_tls == SL_TLS_OFF);

    /* sluice as a TLS server for its clients */
    CHECK(PARSE(&cfg, err, "--listen", "a:1", "--upstream", "b:2", "--listen-tls", "self-signed") ==
              0 &&
          cfg.listen_tls_self_signed == 1);
    CHECK(PARSE(&cfg, err, "--listen", "a:1", "--upstream", "b:2", "--listen-tls=off") == 0 &&
          cfg.listen_tls_self_signed == 0);
    CHECK(PARSE(&cfg, err, "--listen", "a:1", "--upstream", "b:2", "--listen-tls-cert", "c.pem",
                "--listen-tls-key", "k.pem") == 0);
    CHECK_STR(cfg.listen_tls_cert, "c.pem");
    CHECK_STR(cfg.listen_tls_key, "k.pem");
    CHECK(PARSE(&cfg, err, "--listen", "a:1", "--upstream", "b:2", "--listen-tls-cert", "c.pem") ==
          -1);
    CHECK(strstr(err, "go together") != NULL);
    CHECK(PARSE(&cfg, err, "--listen", "a:1", "--upstream", "b:2", "--listen-tls-key", "k.pem") ==
          -1);
    CHECK(PARSE(&cfg, err, "--listen", "a:1", "--upstream", "b:2", "--listen-tls", "self-signed",
                "--listen-tls-cert", "c.pem", "--listen-tls-key", "k.pem") == -1);
    CHECK(strstr(err, "choose one") != NULL);
    CHECK(PARSE(&cfg, err, "--listen", "a:1", "--upstream", "b:2", "--listen-tls", "yes") == -1);
    CHECK(strstr(err, "self-signed or off") != NULL);
    CHECK(PARSE(&cfg, err, "--listen", "a:1", "--upstream", "b:2",
                "--listen-tls-cert=", "--listen-tls-key", "k") == -1);

    /* what the log keeps of the SQL */
    CHECK(PARSE(&cfg, err, "--listen", "a:1", "--upstream", "b:2") == 0 &&
          cfg.log_sql == SL_LOGSQL_FULL);
    CHECK(PARSE(&cfg, err, "--listen", "a:1", "--upstream", "b:2", "--log-sql", "normalized") == 0);
    CHECK(cfg.log_sql == SL_LOGSQL_NORMALIZED);
    CHECK(PARSE(&cfg, err, "--listen", "a:1", "--upstream", "b:2", "--log-sql=none") == 0 &&
          cfg.log_sql == SL_LOGSQL_NONE);
    CHECK(PARSE(&cfg, err, "--listen", "a:1", "--upstream", "b:2", "--log-sql", "full") == 0 &&
          cfg.log_sql == SL_LOGSQL_FULL);
    CHECK(PARSE(&cfg, err, "--listen", "a:1", "--upstream", "b:2", "--log-sql", "some") == -1);
    CHECK(strstr(err, "must be full, normalized or none") != NULL);

    /* the policy file */
    CHECK(PARSE(&cfg, err, "--listen", "a:1", "--upstream", "b:2") == 0);
    CHECK_STR(cfg.policy_path, ""); /* none: relay and log only */
    CHECK(PARSE(&cfg, err, "--listen", "a:1", "--upstream", "b:2", "--policy", "p.toml") == 0);
    CHECK_STR(cfg.policy_path, "p.toml");
    CHECK(PARSE(&cfg, err, "--policy=/etc/sluice/policy.toml", "--listen", "a:1", "--upstream",
                "b:2") == 0);
    CHECK_STR(cfg.policy_path, "/etc/sluice/policy.toml");
    CHECK(PARSE(&cfg, err, "--listen", "a:1", "--upstream", "b:2", "--policy") == -1);
    CHECK(strstr(err, "needs a value") != NULL);
    CHECK(PARSE(&cfg, err, "--listen", "a:1", "--upstream", "b:2", "--policy=") == -1);
    CHECK(strstr(err, "invalid --policy") != NULL);
}

int main(void)
{
    test_addr();
    test_config();
    return TEST_RESULT();
}
