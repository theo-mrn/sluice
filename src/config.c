#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "net.h"

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
    const char *admin_spec = NULL;
    const char *upstream_spec = NULL;

    memset(cfg, 0, sizeof *cfg);
    cfg->undo_journal_max = 256ULL << 20;

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
        int is_cmd = opt_is(arg, namelen, "--confirm-command");
        int is_logres = opt_is(arg, namelen, "--log-results");
        int is_tag = opt_is(arg, namelen, "--tag-application-name");
        int is_admin = opt_is(arg, namelen, "--admin");
        int is_atok = opt_is(arg, namelen, "--admin-token-file");
        int is_cadm = opt_is(arg, namelen, "--confirm-admin");
        int is_evcmd = opt_is(arg, namelen, "--event-command");
        int is_evflt = opt_is(arg, namelen, "--event-filter");
        int is_mkey = opt_is(arg, namelen, "--mask-key-file");
        int is_lck = opt_is(arg, namelen, "--log-chain-key-file");
        int is_ujr = opt_is(arg, namelen, "--undo-journal");
        int is_ujm = opt_is(arg, namelen, "--undo-journal-max");
        int is_ltls = opt_is(arg, namelen, "--listen-tls");
        int is_lcert = opt_is(arg, namelen, "--listen-tls-cert");
        int is_lkey = opt_is(arg, namelen, "--listen-tls-key");
        const char *val;

        if (!is_listen && !is_upstream && !is_policy && !is_tls && !is_ca && !is_logsql &&
            !is_cert && !is_key && !is_tty && !is_cmd && !is_logres && !is_tag && !is_admin &&
            !is_atok && !is_cadm && !is_evcmd && !is_evflt && !is_ltls && !is_lcert && !is_lkey &&
            !is_mkey && !is_lck && !is_ujr && !is_ujm) {
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
        if (is_ujr) {
            if (strlen(val) == 0 || strlen(val) >= sizeof cfg->undo_journal) {
                snprintf(err, errcap, "invalid --undo-journal path");
                return -1;
            }
            strcpy(cfg->undo_journal, val);
            continue;
        }
        if (is_ujm) {
            char *endp = NULL;
            unsigned long long v = strtoull(val, &endp, 10);

            if (endp == val || v == 0 || v > (1ULL << 40)) {
                snprintf(err, errcap, "--undo-journal-max is a size like 256MB or 2G");
                return -1;
            }
            if (strcmp(endp, "") == 0 || strcmp(endp, "B") == 0) {
            } else if (strcmp(endp, "K") == 0 || strcmp(endp, "KB") == 0) {
                v <<= 10;
            } else if (strcmp(endp, "M") == 0 || strcmp(endp, "MB") == 0) {
                v <<= 20;
            } else if (strcmp(endp, "G") == 0 || strcmp(endp, "GB") == 0) {
                v <<= 30;
            } else {
                snprintf(err, errcap, "--undo-journal-max is a size like 256MB or 2G");
                return -1;
            }
            if (v > (1ULL << 40)) {
                snprintf(err, errcap, "--undo-journal-max is at most 1TB");
                return -1;
            }
            cfg->undo_journal_max = v;
            continue;
        }
        if (is_lck) {
            if (strlen(val) == 0 || strlen(val) >= sizeof cfg->log_chain_key_file) {
                snprintf(err, errcap, "invalid --log-chain-key-file path");
                return -1;
            }
            strcpy(cfg->log_chain_key_file, val);
            continue;
        }
        if (is_mkey) {
            if (strlen(val) == 0 || strlen(val) >= sizeof cfg->mask_key_file) {
                snprintf(err, errcap, "invalid --mask-key-file path");
                return -1;
            }
            strcpy(cfg->mask_key_file, val);
            continue;
        }
        if (is_cmd) {
            if (strlen(val) == 0 || strlen(val) >= sizeof cfg->confirm_command) {
                snprintf(err, errcap, "invalid --confirm-command");
                return -1;
            }
            strcpy(cfg->confirm_command, val);
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
        if (is_admin) {
            admin_spec = val;
            continue;
        }
        if (is_atok) {
            if (strlen(val) == 0 || strlen(val) >= sizeof cfg->admin_token_file) {
                snprintf(err, errcap, "invalid --admin-token-file path");
                return -1;
            }
            strcpy(cfg->admin_token_file, val);
            continue;
        }
        if (is_cadm) {
            if (strcmp(val, "on") != 0 && strcmp(val, "off") != 0) {
                snprintf(err, errcap, "--confirm-admin must be on or off");
                return -1;
            }
            cfg->confirm_admin = strcmp(val, "on") == 0;
            continue;
        }
        if (is_evcmd || is_evflt) {
            char *to = is_evcmd ? cfg->event_command : cfg->event_filter;
            size_t cap = is_evcmd ? sizeof cfg->event_command : sizeof cfg->event_filter;

            if (strlen(val) == 0 || strlen(val) >= cap) {
                snprintf(err, errcap, "invalid %s",
                         is_evcmd ? "--event-command" : "--event-filter");
                return -1;
            }
            strcpy(to, val);
            continue;
        }
        if (is_tag) {
            if (strcmp(val, "on") != 0 && strcmp(val, "off") != 0) {
                snprintf(err, errcap, "--tag-application-name must be on or off");
                return -1;
            }
            cfg->tag_application = strcmp(val, "on") == 0;
            continue;
        }
        if (is_logres) {
            if (strcmp(val, "on") != 0 && strcmp(val, "off") != 0) {
                snprintf(err, errcap, "--log-results must be on or off");
                return -1;
            }
            cfg->log_results = strcmp(val, "on") == 0;
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
    if (admin_spec != NULL) {
        if (sl_addr_parse(admin_spec, cfg->admin_host, sizeof cfg->admin_host, cfg->admin_port,
                          sizeof cfg->admin_port) != 0) {
            snprintf(err, errcap, "invalid --admin address '%s' (expected HOST:PORT)", admin_spec);
            return -1;
        }
        if (cfg->admin_token_file[0] == '\0' &&
            (cfg->confirm_admin || !sl_net_host_is_local(cfg->admin_host))) {
            snprintf(err, errcap,
                     "--admin needs --admin-token-file when it listens beyond this machine or "
                     "when it answers confirmations (--confirm-admin)");
            return -1;
        }
    } else if (cfg->admin_token_file[0] != '\0' || cfg->confirm_admin) {
        snprintf(err, errcap, "--admin-token-file and --confirm-admin need --admin");
        return -1;
    }
    if (cfg->confirm_admin && (cfg->confirm_command[0] != '\0' || cfg->confirm_tty[0] != '\0')) {
        snprintf(err, errcap,
                 "--confirm-admin, --confirm-command and --confirm-tty are three ways to be "
                 "asked: choose one");
        return -1;
    }
    if (cfg->event_filter[0] != '\0' && cfg->event_command[0] == '\0') {
        snprintf(err, errcap, "--event-filter needs --event-command");
        return -1;
    }
    if (cfg->confirm_command[0] != '\0' && cfg->confirm_tty[0] != '\0') {
        snprintf(err, errcap,
                 "--confirm-command and --confirm-tty are two ways to be asked: choose one");
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
