#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int sl_addr_parse(const char *spec, char *host, size_t hostcap, char *port, size_t portcap)
{
    const char *h;
    const char *h_end;
    const char *p;
    size_t hl;
    size_t pl;

    if (spec == NULL || spec[0] == '\0') {
        return -1;
    }

    if (spec[0] == '[') {
        h = spec + 1;
        h_end = strchr(h, ']');
        if (h_end == NULL || h_end[1] != ':') {
            return -1;
        }
        p = h_end + 2;
    } else {
        const char *colon = strrchr(spec, ':');

        if (colon == NULL) {
            return -1;
        }
        h = spec;
        h_end = colon;
        p = colon + 1;
        if (memchr(h, ':', (size_t)(h_end - h)) != NULL) {
            return -1; /* an IPv6 address needs brackets */
        }
    }

    hl = (size_t)(h_end - h);
    pl = strlen(p);
    if (hl == 0 || pl == 0 || pl > 5) {
        return -1;
    }
    /* A host name or an IPv4 address: letters, digits, '.', '-', '_'. An IPv6 address, between
     * brackets: hexadecimal digits, ':', '.', and '%' for a zone ("fe80::1%en0"). Nothing else can
     * be a host, and the value ends up in error messages and in the log. */
    for (size_t i = 0; i < hl; i++) {
        unsigned char ch = (unsigned char)h[i];
        int alnum =
            (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z');
        int ok = spec[0] == '['
                     ? (alnum || ch == ':' || ch == '.' || ch == '%' || ch == '_' || ch == '-')
                     : (alnum || ch == '.' || ch == '-' || ch == '_');

        if (!ok) {
            return -1;
        }
    }
    for (size_t i = 0; i < pl; i++) {
        if (p[i] < '0' || p[i] > '9') {
            return -1;
        }
    }
    if (strtol(p, NULL, 10) > 65535) {
        return -1;
    }
    if (hl >= hostcap || pl >= portcap) {
        return -1;
    }

    memcpy(host, h, hl);
    host[hl] = '\0';
    memcpy(port, p, pl);
    port[pl] = '\0';
    return 0;
}

static int opt_is(const char *arg, size_t namelen, const char *opt)
{
    return strlen(opt) == namelen && strncmp(arg, opt, namelen) == 0;
}

int sl_config_parse(sl_config *cfg, int argc, char *const argv[], char *err, size_t errcap)
{
    const char *listen_spec = NULL;
    const char *upstream_spec = NULL;

    memset(cfg, 0, sizeof *cfg);

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        const char *eq = strchr(arg, '=');
        size_t namelen = eq ? (size_t)(eq - arg) : strlen(arg);
        int is_listen = opt_is(arg, namelen, "--listen");
        int is_upstream = opt_is(arg, namelen, "--upstream");
        int is_policy = opt_is(arg, namelen, "--policy");
        int is_tls = opt_is(arg, namelen, "--upstream-tls");
        int is_ca = opt_is(arg, namelen, "--upstream-ca");
        int is_logsql = opt_is(arg, namelen, "--log-sql");
        int is_cert = opt_is(arg, namelen, "--upstream-cert");
        int is_key = opt_is(arg, namelen, "--upstream-key");
        int is_tty = opt_is(arg, namelen, "--confirm-tty");
        int is_ltls = opt_is(arg, namelen, "--listen-tls");
        int is_lcert = opt_is(arg, namelen, "--listen-tls-cert");
        int is_lkey = opt_is(arg, namelen, "--listen-tls-key");
        const char *val;

        if (!is_listen && !is_upstream && !is_policy && !is_tls && !is_ca && !is_logsql &&
            !is_cert && !is_key && !is_tty && !is_ltls && !is_lcert && !is_lkey) {
            snprintf(err, errcap, "unknown argument '%s'", arg);
            return -1;
        }

        val = eq ? eq + 1 : NULL;
        if (val == NULL) {
            if (i + 1 >= argc) {
                snprintf(err, errcap, "%s needs a value", arg);
                return -1;
            }
            val = argv[++i];
        }

        if (is_ltls) {
            if (strcmp(val, "self-signed") == 0) {
                cfg->listen_tls_self_signed = 1;
            } else if (strcmp(val, "off") == 0) {
                cfg->listen_tls_self_signed = 0;
            } else {
                snprintf(err, errcap,
                         "--listen-tls must be self-signed or off (or use --listen-tls-cert)");
                return -1;
            }
            continue;
        }
        if (is_lcert || is_lkey) {
            char *dst = is_lcert ? cfg->listen_tls_cert : cfg->listen_tls_key;
            size_t cap = is_lcert ? sizeof cfg->listen_tls_cert : sizeof cfg->listen_tls_key;

            if (strlen(val) == 0 || strlen(val) >= cap) {
                snprintf(err, errcap, "invalid %s path",
                         is_lcert ? "--listen-tls-cert" : "--listen-tls-key");
                return -1;
            }
            strcpy(dst, val);
            continue;
        }
        if (is_tty) {
            if (strlen(val) == 0 || strlen(val) >= sizeof cfg->confirm_tty) {
                snprintf(err, errcap, "invalid --confirm-tty path");
                return -1;
            }
            strcpy(cfg->confirm_tty, val);
            continue;
        }
        if (is_policy) {
            if (strlen(val) == 0 || strlen(val) >= sizeof cfg->policy_path) {
                snprintf(err, errcap, "invalid --policy path");
                return -1;
            }
            strcpy(cfg->policy_path, val);
            continue;
        }
        if (is_cert || is_key) {
            char *dst = is_cert ? cfg->upstream_cert : cfg->upstream_key;
            size_t cap = is_cert ? sizeof cfg->upstream_cert : sizeof cfg->upstream_key;

            if (strlen(val) == 0 || strlen(val) >= cap) {
                snprintf(err, errcap, "invalid %s path",
                         is_cert ? "--upstream-cert" : "--upstream-key");
                return -1;
            }
            strcpy(dst, val);
            continue;
        }
        if (is_logsql) {
            if (strcmp(val, "full") == 0) {
                cfg->log_sql = SL_LOGSQL_FULL;
            } else if (strcmp(val, "normalized") == 0) {
                cfg->log_sql = SL_LOGSQL_NORMALIZED;
            } else if (strcmp(val, "none") == 0) {
                cfg->log_sql = SL_LOGSQL_NONE;
            } else {
                snprintf(err, errcap, "--log-sql must be full, normalized or none");
                return -1;
            }
            continue;
        }
        if (is_ca) {
            if (strlen(val) == 0 || strlen(val) >= sizeof cfg->upstream_ca) {
                snprintf(err, errcap, "invalid --upstream-ca path");
                return -1;
            }
            strcpy(cfg->upstream_ca, val);
            continue;
        }
        if (is_tls) {
            if (strcmp(val, "off") == 0) {
                cfg->upstream_tls = SL_TLS_OFF;
            } else if (strcmp(val, "require") == 0) {
                cfg->upstream_tls = SL_TLS_REQUIRE;
            } else if (strcmp(val, "verify-full") == 0) {
                cfg->upstream_tls = SL_TLS_VERIFY_FULL;
            } else {
                snprintf(err, errcap, "--upstream-tls must be off, require or verify-full");
                return -1;
            }
            continue;
        }
        if (is_listen) {
            listen_spec = val;
        } else {
            upstream_spec = val;
        }
    }

    if (listen_spec == NULL) {
        snprintf(err, errcap, "missing --listen");
        return -1;
    }
    if (upstream_spec == NULL) {
        snprintf(err, errcap, "missing --upstream");
        return -1;
    }
    if ((cfg->upstream_cert[0] != '\0') != (cfg->upstream_key[0] != '\0')) {
        snprintf(err, errcap, "--upstream-cert and --upstream-key go together");
        return -1;
    }
    if (cfg->upstream_cert[0] != '\0' && cfg->upstream_tls == SL_TLS_OFF) {
        snprintf(err, errcap,
                 "--upstream-cert does nothing without --upstream-tls require or verify-full");
        return -1;
    }
    if ((cfg->listen_tls_cert[0] != '\0') != (cfg->listen_tls_key[0] != '\0')) {
        snprintf(err, errcap, "--listen-tls-cert and --listen-tls-key go together");
        return -1;
    }
    if (cfg->listen_tls_self_signed && cfg->listen_tls_cert[0] != '\0') {
        snprintf(err, errcap,
                 "--listen-tls self-signed and --listen-tls-cert are two ways to the same thing: "
                 "choose one");
        return -1;
    }
    if (cfg->upstream_ca[0] != '\0' && cfg->upstream_tls == SL_TLS_OFF) {
        snprintf(err, errcap,
                 "--upstream-ca does nothing without --upstream-tls require or verify-full");
        return -1;
    }
    if (cfg->upstream_ca[0] != '\0' && cfg->upstream_tls == SL_TLS_REQUIRE) {
        snprintf(err, errcap, "--upstream-ca is only used with --upstream-tls verify-full");
        return -1;
    }
    if (sl_addr_parse(listen_spec, cfg->listen_host, sizeof cfg->listen_host, cfg->listen_port,
                      sizeof cfg->listen_port) != 0) {
        snprintf(err, errcap, "invalid --listen address '%s' (expected HOST:PORT or [IPV6]:PORT)",
                 listen_spec);
        return -1;
    }
    if (sl_addr_parse(upstream_spec, cfg->upstream_host, sizeof cfg->upstream_host,
                      cfg->upstream_port, sizeof cfg->upstream_port) != 0) {
        snprintf(err, errcap, "invalid --upstream address '%s' (expected HOST:PORT or [IPV6]:PORT)",
                 upstream_spec);
        return -1;
    }
    return 0;
}
