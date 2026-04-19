#ifndef SLUICE_CONFIG_H
#define SLUICE_CONFIG_H

#include <stddef.h>

/* How sluice talks to the upstream database. */
typedef enum {
    SL_TLS_OFF,         /* plain text (the default) */
    SL_TLS_REQUIRE,     /* encrypted; the server's certificate is not checked */
    SL_TLS_VERIFY_FULL, /* encrypted, certificate chain and host name verified */
} sl_tls_mode;

/* What the log keeps of the SQL of a statement. */
typedef enum {
    SL_LOGSQL_FULL,       /* the SQL as sent (the default) */
    SL_LOGSQL_NORMALIZED, /* values replaced by $1, $2...; withheld when that cannot be done safely
                           */
    SL_LOGSQL_NONE        /* no SQL, only its fingerprint */
} sl_log_sql_mode;

typedef struct {
    char listen_host[256];
    char listen_port[8]; /* decimal string, "0" asks the system for a free port */
    char upstream_host[256];
    char upstream_port[8];
    char policy_path[1024]; /* empty: no policy, sluice only relays and logs */
    sl_tls_mode upstream_tls;
    char upstream_ca[1024];   /* PEM file of trusted CAs; empty: the system store */
    char upstream_cert[1024]; /* client certificate (PEM, with its chain) shown to the database;
                                 empty: none */
    char upstream_key[1024];  /* its private key (PEM, not encrypted) */
    sl_log_sql_mode log_sql;
    char admin_host[256]; /* --admin: where /metrics and the answers to confirmations are served */
    char admin_port[8];
    char admin_token_file[1024];
    int confirm_admin;        /* the operator's questions are answered at the admin listener */
    char event_command[1024]; /* run for the events of event_filter, the line of the log on stdin */
    char event_filter[256];   /* comma-separated names of events; empty: the default */
    int tag_application; /* application_name gets " [sluice N]" (N: the connection's id in the log)
                          */
    int log_results;     /* a `result` event for every statement: its outcome, rows and time */
    char listen_tls_cert[1024]; /* sluice as a TLS server for its clients: certificate (PEM), */
    char listen_tls_key[1024];  /* its private key (not encrypted), */
    int listen_tls_self_signed; /* or a certificate made at startup */
    char confirm_tty[1024];     /* where a person is asked to confirm; empty: /dev/tty */
    char undo_journal[1024];    /* where the rows of DELETEs are kept for undo; empty: none */
    unsigned long long undo_journal_max; /* bytes; 0: no limit */
    char log_chain_key_file[1024]; /* the key that chains the lines of the log; empty: no chain */
    char mask_key_file[1024];   /* the key of the tokens of "hash" masks; empty: made at startup */
    char confirm_command[1024]; /* or a command that is asked instead; empty: the terminal */
} sl_config;

/* Splits "HOST:PORT" or "[IPV6]:PORT" into host and port (without the brackets). The port must be a
 * decimal number from 0 to 65535. Returns 0, or -1 if the text is not valid or does not fit. */
int sl_addr_parse(const char *spec, char *host, size_t hostcap, char *port, size_t portcap);

/* Parses the command line (argv[0] is skipped). Returns 0, or -1 with a message in err. */
int sl_config_parse(sl_config *cfg, int argc, char *const argv[], char *err, size_t errcap);

#endif
